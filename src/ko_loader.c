#define _GNU_SOURCE
#include "ko_loader.h"

#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#define KPTR_PATH "/proc/sys/kernel/kptr_restrict"

struct ksym {
    char *name;
    unsigned long long addr;
};

static int ksym_cmp(const void *a, const void *b)
{
    return strcmp(((const struct ksym *)a)->name,
                  ((const struct ksym *)b)->name);
}

static void kptr_begin(char *old, size_t oldsz)
{
    old[0] = 0;
    int fd = open(KPTR_PATH, O_RDONLY | O_CLOEXEC);
    if (fd >= 0) {
        ssize_t n = read(fd, old, oldsz - 1);
        close(fd);
        if (n > 0) {
            old[n] = 0;
            char *nl = strchr(old, '\n');
            if (nl)
                *nl = 0;
        }
    }
    fd = open(KPTR_PATH, O_WRONLY | O_CLOEXEC);
    if (fd >= 0) {
        (void)!write(fd, "1", 1);
        close(fd);
    }
}

static void kptr_end(const char *old)
{
    if (!old || !old[0])
        return;
    int fd = open(KPTR_PATH, O_WRONLY | O_CLOEXEC);
    if (fd >= 0) {
        (void)!write(fd, old, strlen(old));
        close(fd);
    }
}

static int read_kallsyms(struct ksym **out, size_t *outn)
{
    char old[32];
    kptr_begin(old, sizeof(old));

    FILE *f = fopen("/proc/kallsyms", "r");
    if (!f) {
        int saved_errno = errno;
        kptr_end(old);
        errno = saved_errno;
        return -1;
    }

    size_t cap = 1u << 16, n = 0;
    struct ksym *arr = malloc(cap * sizeof(*arr));
    if (!arr) {
        fclose(f);
        kptr_end(old);
        errno = ENOMEM;
        return -1;
    }

    char line[512];
    while (fgets(line, sizeof(line), f)) {
        unsigned long long addr;
        char type;
        char name[256];
        if (sscanf(line, "%llx %c %255s", &addr, &type, name) != 3)
            continue;
        (void)type;

        char extra[64];
        if (sscanf(line, "%*llx %*c %*255s %63s", extra) == 1)
            continue;
        if (!addr)
            continue;

        char *dollar = strchr(name, '$');
        char *llvm = strstr(name, ".llvm.");
        char *cut = dollar;
        if (llvm && (!cut || llvm < cut))
            cut = llvm;
        if (cut)
            *cut = 0;
        if (!name[0])
            continue;

        if (n == cap) {
            size_t ncap = cap * 2;
            struct ksym *grown = realloc(arr, ncap * sizeof(*arr));
            if (!grown)
                break;
            arr = grown;
            cap = ncap;
        }
        arr[n].name = strdup(name);
        if (!arr[n].name)
            break;
        arr[n].addr = addr;
        n++;
    }

    fclose(f);
    kptr_end(old);

    qsort(arr, n, sizeof(*arr), ksym_cmp);
    *out = arr;
    *outn = n;
    return 0;
}

static unsigned long long ksym_lookup(const struct ksym *arr, size_t n,
                                      const char *name)
{
    struct ksym key = { .name = (char *)name, .addr = 0 };
    const struct ksym *hit = bsearch(&key, arr, n, sizeof(*arr), ksym_cmp);
    return hit ? hit->addr : 0;
}

static int relocate_symbols(unsigned char *buf, size_t size, size_t *patched,
                            size_t *unresolved)
{
    if (size < sizeof(Elf64_Ehdr))
        return -1;
    const Elf64_Ehdr *eh = (const Elf64_Ehdr *)buf;
    if (memcmp(eh->e_ident, ELFMAG, SELFMAG) != 0 ||
        eh->e_ident[EI_CLASS] != ELFCLASS64 ||
        eh->e_type != ET_REL || eh->e_machine != EM_AARCH64)
        return -1;
    if (eh->e_shoff == 0 || eh->e_shnum == 0 ||
        eh->e_shentsize < sizeof(Elf64_Shdr))
        return -1;
    if ((size_t)eh->e_shoff + (size_t)eh->e_shnum * eh->e_shentsize > size)
        return -1;

    Elf64_Shdr *sh = (Elf64_Shdr *)(buf + eh->e_shoff);
    struct ksym *syms = NULL;
    size_t nsyms = 0;
    int have_syms = 0;

    for (unsigned int i = 0; i < eh->e_shnum; i++) {
        if (sh[i].sh_type != SHT_SYMTAB)
            continue;
        if (sh[i].sh_link >= eh->e_shnum)
            continue;
        Elf64_Shdr *strh = &sh[sh[i].sh_link];
        if ((size_t)sh[i].sh_offset + sh[i].sh_size > size ||
            (size_t)strh->sh_offset + strh->sh_size > size)
            continue;

        const char *strtab = (const char *)buf + strh->sh_offset;
        size_t entsz = sh[i].sh_entsize ? sh[i].sh_entsize : sizeof(Elf64_Sym);
        if (entsz < sizeof(Elf64_Sym))
            continue;

        for (size_t off = 0; off + sizeof(Elf64_Sym) <= sh[i].sh_size;
             off += entsz) {
            Elf64_Sym *sym = (Elf64_Sym *)(buf + sh[i].sh_offset + off);
            if (sym->st_shndx != SHN_UNDEF || sym->st_name == 0)
                continue;
            if (sym->st_name >= strh->sh_size)
                continue;
            const char *name = strtab + sym->st_name;
            if (!memchr(name, 0, strh->sh_size - sym->st_name))
                continue;

            if (!have_syms) {
                if (read_kallsyms(&syms, &nsyms) < 0)
                    return -1;
                have_syms = 1;
            }

            unsigned long long addr = ksym_lookup(syms, nsyms, name);
            if (addr) {
                sym->st_shndx = SHN_ABS;
                sym->st_value = addr;
                (*patched)++;
            } else {
                (*unresolved)++;
            }
        }
    }

    free(syms);
    return 0;
}

int ksu_load_module(const char *path, const char *params)
{
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return -1;

    struct stat st;
    if (fstat(fd, &st) < 0 || st.st_size <= 0 ||
        st.st_size > (1 << 26)) {
        int saved_errno = errno ? errno : EINVAL;
        close(fd);
        errno = saved_errno;
        return -1;
    }

    size_t size = (size_t)st.st_size;
    unsigned char *buf = malloc(size);
    if (!buf) {
        close(fd);
        errno = ENOMEM;
        return -1;
    }

    size_t got = 0;
    while (got < size) {
        ssize_t n = read(fd, buf + got, size - got);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            int saved_errno = errno;
            free(buf);
            close(fd);
            errno = saved_errno;
            return -1;
        }
        if (n == 0)
            break;
        got += (size_t)n;
    }
    close(fd);
    if (got != size) {
        free(buf);
        errno = EIO;
        return -1;
    }

    size_t patched = 0, unresolved = 0;
    if (relocate_symbols(buf, size, &patched, &unresolved) < 0) {
        int saved_errno = errno ? errno : ENOEXEC;
        free(buf);
        errno = saved_errno;
        return -1;
    }
    printf("[*] ko relocate: %zu bound, %zu unresolved\n", patched, unresolved);

    long rc = syscall(SYS_init_module, buf, size, params ? params : "");
    int saved_errno = errno;
    free(buf);
    errno = saved_errno;
    return rc < 0 ? -1 : 0;
}

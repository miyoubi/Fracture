// kmunlock_a002so.c — Xperia Keymaster DeviceInfo read/write stage.
// Read is always performed first. Write 0x203 only with --write and only after
// a real ANDROID-BOOT! record with is_unlocked=0/is_unlock_critical=0 is seen.
// Uses legacy /dev/ion because this device has no dma-heap.
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/system_properties.h>
#include <unistd.h>

/* ---- legacy ION ABI (drivers/staging/android/uapi/ion.h) ---- */
struct ion_allocation_data {
    uint64_t len;
    uint32_t heap_id_mask;
    uint32_t flags;
    int32_t fd;
    uint32_t unused;
};
struct ion_heap_data {
    char name[32];
    uint32_t type;
    uint32_t heap_id;
    uint32_t reserved0, reserved1, reserved2;
};
struct ion_heap_query {
    uint32_t cnt;
    uint32_t reserved0;
    uint64_t heaps;
    uint32_t reserved1, reserved2;
};
#define ION_IOC_MAGIC 'I'
#define ION_IOC_ALLOC _IOWR(ION_IOC_MAGIC, 0, struct ion_allocation_data)
#define ION_IOC_HEAP_QUERY _IOWR(ION_IOC_MAGIC, 8, struct ion_heap_query)

/* ---- QSEECom ABI ---- */
struct QSEECom_handle { unsigned char *ion_sbuffer; };
struct QSEECom_ion_fd_data { int32_t fd; uint32_t cmd_buf_offset; };
struct QSEECom_ion_fd_info { struct QSEECom_ion_fd_data data[4]; };

typedef int (*start_app_v2_fn)(struct QSEECom_handle **h, const char *appname,
                               void *trustlet, uint32_t len, uint32_t arch);
typedef int (*shutdown_app_fn)(struct QSEECom_handle **h);
typedef int (*send_cmd_fn)(struct QSEECom_handle *h, void *sb, uint32_t sl,
                           void *rb, uint32_t rl);
typedef int (*send_modified_cmd_64_fn)(struct QSEECom_handle *h, void *sb, uint32_t sl,
                                       void *rb, uint32_t rl,
                                       struct QSEECom_ion_fd_info *ifd);

/* ---- Keymaster ABI ---- */
#define KM_GET_VERSION 0x200u
#define KM_READ_KM_DEVICE_STATE 0x202u
#define KM_WRITE_KM_DEVICE_STATE 0x203u
#define REQ_OFF 0x000u
#define RSP_OFF 0x040u
#define SB_RSVD 0x080u
#define DATA_LEN 0x2000u
#define DEVICE_MAGIC "ANDROID-BOOT!"
#define DEVICE_MAGIC_SIZE 13
#define DEVICE_INFO_SIZE 0xca8u
#define DEVINFO_UNLOCK_OFF 13
#define DEVINFO_CRIT_OFF 14

typedef struct { uint32_t cmd_id; } km_ver_req_t;
typedef struct { int32_t status; uint32_t major, minor, app_major, app_minor; } km_ver_rsp_t;
typedef struct { uint32_t cmd_id; uint64_t shared_buf_ptr; uint32_t buf_size; }
        __attribute__((packed)) km_rw_req_t;
typedef struct { int32_t status; uint32_t unknown; int32_t rsp_status; }
        __attribute__((packed)) km_rw_rsp_t;

_Static_assert(sizeof(struct ion_allocation_data) == 24, "ion_allocation_data");
_Static_assert(sizeof(struct ion_heap_data) == 52, "ion_heap_data");
_Static_assert(sizeof(km_rw_req_t) == 16, "km_rw_req_t");
_Static_assert(sizeof(km_rw_rsp_t) == 12, "km_rw_rsp_t");

#ifndef BLKGETSIZE64
#define BLKGETSIZE64 _IOR(0x12, 114, uint64_t)
#endif

static int slurp(const char *path, unsigned char **out, size_t *outlen)
{
    struct stat st;
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) { fprintf(stderr, "[ta] open %s: %s\n", path, strerror(errno)); return -1; }
    uint64_t size = 0;
    if (fstat(fd, &st) == 0 && st.st_size > 0) size = (uint64_t)st.st_size;
    if (size == 0 && ioctl(fd, BLKGETSIZE64, &size) < 0) size = 0;
    if (size == 0) {
        off_t e = lseek(fd, 0, SEEK_END);
        if (e > 0 && lseek(fd, 0, SEEK_SET) == 0) size = (uint64_t)e;
    }
    if (size == 0 || size > (16u << 20)) {
        fprintf(stderr, "[ta] bad size %s (%llu)\n", path, (unsigned long long)size);
        close(fd); return -1;
    }
    unsigned char *b = malloc((size_t)size);
    if (!b) { close(fd); return -1; }
    ssize_t got = 0, n;
    while ((uint64_t)got < size) {
        n = read(fd, b + got, (size_t)((uint64_t)size - (uint64_t)got));
        if (n <= 0) { if (n < 0 && errno == EINTR) continue; break; }
        got += n;
    }
    close(fd);
    if ((uint64_t)got != size) { free(b); return -1; }
    *out = b; *outlen = (size_t)size;
    printf("[ta] %s bytes=%zu\n", path, *outlen);
    return 0;
}

static int ion_heaps(void)
{
    int fd = open("/dev/ion", O_RDONLY | O_CLOEXEC);
    if (fd < 0) { fprintf(stderr, "[ion] open: %s\n", strerror(errno)); return -1; }
    struct ion_heap_data heaps[32];
    memset(heaps, 0, sizeof heaps);
    struct ion_heap_query q;
    memset(&q, 0, sizeof q);
    q.cnt = 32;
    q.heaps = (uint64_t)(uintptr_t)heaps;
    if (ioctl(fd, ION_IOC_HEAP_QUERY, &q) < 0) {
        fprintf(stderr, "[ion] heap query: %s\n", strerror(errno));
        close(fd); return -1;
    }
    printf("[ion] heaps=%u\n", q.cnt);
    for (uint32_t i = 0; i < q.cnt && i < 32; i++) {
        printf("[ion] id=%u type=%u mask=0x%x name=%s\n",
               heaps[i].heap_id, heaps[i].type,
               1u << heaps[i].heap_id, heaps[i].name);
    }
    close(fd);
    return 0;
}

static int ion_alloc(size_t len, uint32_t mask, int *fdp, void **mapp)
{
    int fd = open("/dev/ion", O_RDONLY | O_CLOEXEC);
    if (fd < 0) { fprintf(stderr, "[ion] open: %s\n", strerror(errno)); return -1; }
    struct ion_allocation_data a;
    memset(&a, 0, sizeof a);
    a.len = len;
    a.heap_id_mask = mask;
    a.flags = 0;
    a.fd = -1;
    if (ioctl(fd, ION_IOC_ALLOC, &a) < 0 || a.fd < 0) {
        fprintf(stderr, "[ion] alloc mask=0x%x: %s\n", mask, strerror(errno));
        close(fd); return -1;
    }
    close(fd);
    void *m = mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_SHARED, a.fd, 0);
    if (m == MAP_FAILED) {
        fprintf(stderr, "[ion] mmap: %s\n", strerror(errno));
        close(a.fd); return -1;
    }
    memset(m, 0, len);
    *fdp = a.fd; *mapp = m;
    printf("[ion] alloc len=%zu mask=0x%x fd=%d ptr=%p\n", len, mask, a.fd, m);
    return 0;
}

static int save_dump(const char *path, const void *data, size_t len)
{
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (fd < 0) return -1;
    if (fchmod(fd, 0600) < 0) { close(fd); return -1; }
    const unsigned char *p = data;
    size_t done = 0;
    while (done < len) {
        ssize_t n = write(fd, p + done, len - done);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) {
            if (n == 0) errno = EIO;
            close(fd);
            return -1;
        }
        done += (size_t)n;
    }
    int rc = fsync(fd);
    int saved_errno = errno;
    if (close(fd) < 0 && rc == 0) { rc = -1; saved_errno = errno; }
    errno = saved_errno;
    return rc;
}

static int find_device_info(const unsigned char *data, size_t length,
                            size_t *offset)
{
    if (!data || !offset || length < DEVICE_INFO_SIZE) return -1;
    for (size_t off = 0; off + DEVICE_INFO_SIZE <= length; off += 4) {
        if (memcmp(data + off, DEVICE_MAGIC, DEVICE_MAGIC_SIZE) == 0) {
            *offset = off;
            return 0;
        }
    }
    return -1;
}

int keymaster_device_state_validate(const unsigned char *data, size_t length,
                                    uint8_t unlocked, uint8_t unlock_critical)
{
    size_t offset;
    if (find_device_info(data, length, &offset) < 0 ||
        data[offset + DEVINFO_UNLOCK_OFF] != unlocked ||
        data[offset + DEVINFO_CRIT_OFF] != unlock_critical) {
        errno = EINVAL;
        return -1;
    }
    return 0;
}

int keymaster_device_state_save_backup(const char *path,
                                       const unsigned char *data,
                                       size_t length)
{
    size_t offset;
    if (!path || !*path || !data || length != DATA_LEN ||
        find_device_info(data, length, &offset) < 0) {
        errno = EINVAL;
        return -1;
    }
    return save_dump(path, data, length);
}

static int parse_buffer_env(const char *name, unsigned char **buffer)
{
    const char *raw = getenv(name);
    if (!raw || !*raw) {
        *buffer = NULL;
        return 0;
    }
    char *end = NULL;
    errno = 0;
    unsigned long long address = strtoull(raw, &end, 0);
    if (errno || end == raw || *end || !address) {
        errno = EINVAL;
        return -1;
    }
    *buffer = (unsigned char *)(uintptr_t)address;
    return 0;
}

static const char *default_ta_path(void)
{
    static char path[128];
    char slot[PROP_VALUE_MAX] = {0};
    __system_property_get("ro.boot.slot_suffix", slot);
    const char *s = (slot[0] == '_' && (slot[1] == 'a' || slot[1] == 'b')) ? slot : "_a";
    snprintf(path, sizeof path, "/dev/block/bootdevice/by-name/keymaster%s", s);
    return path;
}

int keymaster_device_state_main(int argc, char **argv)
{
    int do_write = 0;
    const char *ta_path = NULL;
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--write")) do_write = 1;
        else if (!ta_path) ta_path = argv[i];
    }
    if (!ta_path) ta_path = default_ta_path();
    const char *dump_path = getenv("KM_DUMP");
    unsigned char *dump_buffer = NULL, *expected_buffer = NULL;
    int backup_prevalidated = 0;
    const char *prebacked = getenv("KM_DUMP_PREBACKED");
    if (parse_buffer_env("KM_DUMP_BUFFER", &dump_buffer) < 0 ||
        parse_buffer_env("KM_EXPECTED_BUFFER", &expected_buffer) < 0) {
        fprintf(stderr, "[km] invalid shared buffer address\n");
        return 1;
    }
    backup_prevalidated = prebacked && strcmp(prebacked, "1") == 0;
    if (do_write &&
        (!expected_buffer || !backup_prevalidated || !dump_path || !*dump_path ||
         keymaster_device_state_validate(expected_buffer, DATA_LEN, 0, 0) < 0)) {
        fprintf(stderr, "[km] refusing write without a valid saved pre-state\n");
        return 1;
    }
    unsigned char *ta = NULL;
    size_t ta_len = 0;
    struct QSEECom_handle *h = NULL;
    void *lib = NULL;
    int rc = 1, ionfd = -1, owns_handle = 0;
    int state_unlocked = 0, write_verified = 0;
    void *data = NULL;

    ion_heaps();

    lib = dlopen("/vendor/lib64/libQSEEComAPI.so", RTLD_NOW | RTLD_GLOBAL);
    if (!lib) lib = dlopen("libQSEEComAPI.so", RTLD_NOW | RTLD_GLOBAL);
    if (!lib) { fprintf(stderr, "[lib] dlopen: %s\n", dlerror()); goto out; }

    struct { const char *name; void *p; } syms[] = {
        {"QSEECom_start_app_V2", NULL},
        {"QSEECom_shutdown_app", NULL},
        {"QSEECom_send_cmd", NULL},
        {"QSEECom_send_modified_cmd_64", NULL},
        {"QSEECom_send_modified_cmd", NULL},
    };
    for (size_t i = 0; i < sizeof(syms)/sizeof(syms[0]); i++) {
        dlerror();
        syms[i].p = dlsym(lib, syms[i].name);
        if (!syms[i].p) { fprintf(stderr, "[lib] dlsym %s: %s\n", syms[i].name, dlerror()); goto out; }
    }
    start_app_v2_fn start_v2 = (start_app_v2_fn)syms[0].p;
    shutdown_app_fn shutdown_app = (shutdown_app_fn)syms[1].p;
    send_cmd_fn send_cmd = (send_cmd_fn)syms[2].p;
    send_modified_cmd_64_fn send_mod = (send_modified_cmd_64_fn)syms[3].p;
    send_modified_cmd_64_fn send_mod32 = (send_modified_cmd_64_fn)syms[4].p;
    printf("[lib] libQSEEComAPI.so loaded\n");

    if (slurp(ta_path, &ta, &ta_len)) goto out;
    int lr = start_v2(&h, "keymaster64", ta, (uint32_t)ta_len, 2);
    printf("[load] QSEECom_start_app_V2(\"keymaster64\") = %d\n", lr);
    if (lr != 0 && lr != -4) { fprintf(stderr, "[load] fatal: %d\n", lr); goto out; }
    if (!h) { fprintf(stderr, "[load] null handle\n"); goto out; }
    owns_handle = (lr == 0);

    unsigned char *sb = *(unsigned char **)h;
    if (!sb) { fprintf(stderr, "[abi] null shared buffer\n"); goto out; }
    printf("[abi] shared buffer @ %p\n", (void *)sb);

    {
        km_ver_req_t *q = (km_ver_req_t *)(sb + REQ_OFF);
        km_ver_rsp_t *p = (km_ver_rsp_t *)(sb + RSP_OFF);
        memset(sb + REQ_OFF, 0, SB_RSVD);
        q->cmd_id = KM_GET_VERSION;
        int r = send_cmd(h, q, sizeof *q, p, sizeof *p);
        if (r != 0) { fprintf(stderr, "[km] GET_VERSION transport rc=%d\n", r); goto out; }
        printf("[km] GET_VERSION rc=%d status=%d ver=%u.%u app=%u.%u\n",
               r, p->status, p->major, p->minor, p->app_major, p->app_minor);
    }

    {
        const char *em = getenv("ION_MASK");
        uint32_t mask = em ? (uint32_t)strtoul(em, NULL, 0) : 0;
        if (mask) {
            if (ion_alloc(DATA_LEN, mask, &ionfd, &data)) goto out;
        } else {
            uint32_t masks[] = { 0x8000000u, 0x80000u, 0x4000000u, 0x2000000u };
            int ok = 0;
            for (size_t i = 0; i < sizeof(masks)/sizeof(masks[0]) && !ok; i++)
                if (ion_alloc(DATA_LEN, masks[i], &ionfd, &data) == 0) ok = 1;
            if (!ok) goto out;
        }
    }

    {
        km_rw_req_t *q = (km_rw_req_t *)(sb + REQ_OFF);
        km_rw_rsp_t *p = (km_rw_rsp_t *)(sb + RSP_OFF);
        struct QSEECom_ion_fd_info ifd;
        memset(&ifd, 0, sizeof ifd);
        memset(sb + REQ_OFF, 0, SB_RSVD);
        q->cmd_id = KM_READ_KM_DEVICE_STATE;
        q->shared_buf_ptr = 0;
        q->buf_size = DATA_LEN;
        ifd.data[0].fd = ionfd;
        const char *offenv = getenv("KM_OFF");
        ifd.data[0].cmd_buf_offset = offenv ? (uint32_t)strtoul(offenv, NULL, 0) : 4;
        const char *u32 = getenv("KM_USE32");
        send_modified_cmd_64_fn fn = (u32 && *u32 == '1') ? send_mod32 : send_mod;
        int r = fn(h, q, sizeof *q, p, sizeof *p, &ifd);
        printf("[km] READ_KM_DEVICE_STATE transport rc=%d status=%d rsp_status=%d\n",
               r, p->status, p->rsp_status);
        printf("[km] patched shared_buf_ptr=0x%llx\n",
               (unsigned long long)q->shared_buf_ptr);
        if (r == 0 && p->status == 0 && p->rsp_status == 0) {
            unsigned char *d = (unsigned char *)data;
            int found = 0;
            size_t off = 0;
            for (off = 0; off + DEVICE_INFO_SIZE <= DATA_LEN; off += 4) {
                if (!memcmp(d + off, DEVICE_MAGIC, DEVICE_MAGIC_SIZE)) {
                    printf("[km] DeviceInfo @ +0x%zx is_unlocked=%u is_unlock_critical=%u\n",
                           off, d[off + DEVINFO_UNLOCK_OFF], d[off + DEVINFO_CRIT_OFF]);
                    printf("[km] raw:");
                    for (int i = 0; i < 48; i++) printf(" %02x", d[off + i]);
                    printf("\n");
                    if (dump_buffer) {
                        memcpy(dump_buffer, d, DATA_LEN);
                        __sync_synchronize();
                    } else if (dump_path && save_dump(dump_path, d, DATA_LEN) < 0) {
                        fprintf(stderr, "[km] save backup %s: %s\n",
                                dump_path, strerror(errno));
                        goto out;
                    }
                    found = 1;
                    break;
                }
            }
            if (!found) { printf("[km] success but no ANDROID-BOOT! record\n"); goto out; }
            if (!do_write) { printf("[km] read-only (no --write)\n"); rc = 0; goto out; }
            if (!dump_path || !*dump_path) {
                fprintf(stderr, "[km] refusing --write without KM_DUMP backup path\n");
                goto out;
            }
            if (expected_buffer) {
                size_t expected_off;
                if (find_device_info(expected_buffer, DATA_LEN, &expected_off) < 0 ||
                    expected_off != off ||
                    expected_buffer[expected_off + DEVINFO_UNLOCK_OFF] != 0 ||
                    expected_buffer[expected_off + DEVINFO_CRIT_OFF] != 0 ||
                    memcmp(expected_buffer + expected_off, d + off,
                           DEVICE_INFO_SIZE) != 0) {
                    fprintf(stderr, "[km] current DeviceInfo differs from saved pre-state\n");
                    goto out;
                }
                printf("[km] current DeviceInfo matches saved pre-state\n");
            } else if (save_dump(dump_path, d, DATA_LEN) < 0) {
                fprintf(stderr, "[km] save backup %s: %s\n",
                        dump_path, strerror(errno));
                goto out;
            }
            if (d[off + DEVINFO_UNLOCK_OFF] == 1 &&
                d[off + DEVINFO_CRIT_OFF] == 1) {
                printf("[km] unlock flags are already set\n");
                state_unlocked = 1;
                rc = 0;
                goto out;
            }
            if (d[off + DEVINFO_UNLOCK_OFF] || d[off + DEVINFO_CRIT_OFF]) {
                fprintf(stderr, "[km] refusing inconsistent unlock flags\n");
                goto out;
            }
            d[off + DEVINFO_UNLOCK_OFF] = 1;
            d[off + DEVINFO_CRIT_OFF] = 1;
            memset(sb + REQ_OFF, 0, SB_RSVD);
            q->cmd_id = KM_WRITE_KM_DEVICE_STATE;
            q->shared_buf_ptr = 0;
            q->buf_size = DATA_LEN;
            r = fn(h, q, sizeof *q, p, sizeof *p, &ifd);
            printf("[km] WRITE_KM_DEVICE_STATE transport rc=%d status=%d rsp_status=%d\n",
                   r, p->status, p->rsp_status);
            if (r != 0 || p->status != 0 || p->rsp_status != 0) goto out;
            memset(sb + REQ_OFF, 0, SB_RSVD);
            q->cmd_id = KM_READ_KM_DEVICE_STATE;
            q->shared_buf_ptr = 0;
            q->buf_size = DATA_LEN;
            r = fn(h, q, sizeof *q, p, sizeof *p, &ifd);
            if (r == 0 && p->status == 0 && p->rsp_status == 0 && dump_buffer) {
                memcpy(dump_buffer, d, DATA_LEN);
                __sync_synchronize();
            }
            printf("[km] verify READ rc=%d status=%d rsp_status=%d is_unlocked=%u is_unlock_critical=%u\n",
                   r, p->status, p->rsp_status,
                   d[off + DEVINFO_UNLOCK_OFF], d[off + DEVINFO_CRIT_OFF]);
            if (r != 0 || p->status != 0 || p->rsp_status != 0 ||
                d[off + DEVINFO_UNLOCK_OFF] != 1 ||
                d[off + DEVINFO_CRIT_OFF] != 1)
                goto out;
            state_unlocked = 1;
            write_verified = 1;
            rc = 0;
        } else {
            printf("[km] refusal (status/rsp_status nonzero or transport error)\n");
            goto out;
        }
    }

out:
    if (data && data != MAP_FAILED) munmap(data, DATA_LEN);
    if (ionfd >= 0) close(ionfd);
    if (owns_handle && h && shutdown_app) shutdown_app(&h);
    free(ta);
    if (lib) dlclose(lib);
    if (rc == 0 && do_write && write_verified)
        printf("[done] Keymaster unlock state write verified\n");
    else if (rc == 0 && do_write && state_unlocked)
        printf("[done] Keymaster unlock state was already set\n");
    else if (rc == 0)
        printf("[done] read-only query complete\n");
    else
        printf("[done] Keymaster state operation failed\n");
    return rc;
}

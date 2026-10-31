#ifndef SELINUX_HANDOFF_H
#define SELINUX_HANDOFF_H

#include "target_profile.h"

#include <sched.h>
#include <stdint.h>
#include <sys/socket.h>
#include <sys/types.h>

#define SELINUX_HANDOFF_IO_PROBE 1
#define SELINUX_HANDOFF_IO_CLEAR 2
#define SELINUX_HANDOFF_IO_ACTIVATE 3

struct selinux_handoff_state {
    volatile int ready;
    volatile int start;
    volatile int done;
    volatile int resume;
    volatile int status;
    volatile int abort_requested;
    int stage;
    uint64_t current_security;
    uint32_t sid_limit;
    uint32_t target_sid;
    volatile int io_active;
    volatile int io_released;
    volatile int migration_done;
    int migration_status;
    volatile int candidate_done;
    volatile int candidate_ack;
    volatile int helper_sent;
    volatile int helper_done;
    volatile int helper_exit;
    volatile int helper_exit_after_send;
    int io_operation;
    int io_status;
    int helper_status;
    int candidate_result;
    uint32_t io_candidate_sid;
    uint32_t probe_index;
    pid_t main_tid;
    int receiver_fd;
    socklen_t receiver_address_length;
    char receiver_name[64];
};

pid_t selinux_handoff_find_pid(const char *context);
int selinux_handoff_pid_has_context(pid_t pid, const char *expected);
int selinux_handoff_pid_has_attribute_context(pid_t pid, const char *attribute,
                                              const char *expected);
int selinux_handoff_verify_context(const char *expected);
int selinux_handoff_patch_child(struct selinux_handoff_state *state,
                                const struct target_profile *profile,
                                const cpu_set_t *allowed_cpus,
                                int park_cpu);

#endif

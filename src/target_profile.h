#ifndef TARGET_PROFILE_H
#define TARGET_PROFILE_H

#include <stddef.h>
#include <stdint.h>

struct target_profile {
    const char *model;
    const char *fingerprint;
    const char *kernel_release;
    uint64_t user_ds;
    uint32_t task_stride;
    uint32_t task_addr_limit;
    uint32_t task_real_cred;
    uint32_t task_cred;
    uint32_t task_comm;
    uint32_t task_tasks;
    uint32_t task_pid;
    uint32_t task_tgid;
    uint32_t task_security;
    uint32_t task_fake_sec;
    uint32_t task_group_leader;
    uint32_t cred_security;
    const char *qsee_context;
    uint32_t cred_ids;
    uint32_t cred_caps;
    uint32_t cap_last_cap;
};

const struct target_profile *target_profile_get(void);

#endif

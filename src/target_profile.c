#define _GNU_SOURCE
#include "target_profile.h"

#include "offset.h"

static const struct target_profile profile = {
    .model = TARGET_MODEL,
    .fingerprint = TARGET_FINGERPRINT,
    .kernel_release = TARGET_KERNEL_RELEASE,
    .user_ds = TARGET_USER_DS,
    .task_stride = TARGET_TASK_STRIDE,
    .task_addr_limit = TARGET_TASK_ADDR_LIMIT,
    .task_real_cred = TARGET_TASK_REAL_CRED,
    .task_cred = TARGET_TASK_CRED,
    .task_comm = TARGET_TASK_COMM,
    .task_tasks = TARGET_TASK_TASKS,
    .task_pid = TARGET_TASK_PID,
    .task_tgid = TARGET_TASK_TGID,
    .cred_security = TARGET_CRED_SECURITY,
    .qsee_context = TARGET_QSEE_CONTEXT,
    .cred_ids = TARGET_CRED_IDS,
    .cred_caps = TARGET_CRED_CAPS,
    .cap_last_cap = TARGET_CAP_LAST_CAP,
};

const struct target_profile *target_profile_get(void) {
    return &profile;
}

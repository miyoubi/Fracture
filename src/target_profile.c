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
    .task_security = TARGET_TASK_SECURITY,
    .task_fake_sec = TARGET_TASK_FAKE_SEC,
    .task_group_leader = TARGET_TASK_GROUP_LEADER,
    .cred_security = TARGET_CRED_SECURITY,
    .qsee_context = TARGET_QSEE_CONTEXT,
    .cred_ids = TARGET_CRED_IDS,
    .cred_caps = TARGET_CRED_CAPS,
    .cap_last_cap = TARGET_CAP_LAST_CAP,
    .kernel_text_va = TARGET_KERNEL_TEXT_VA,
    .selinux_state_off = TARGET_SELINUX_STATE_OFF,
    .selinux_word = TARGET_SELINUX_WORD,
    .task_state = TARGET_TASK_STATE,
    .task_cpu_context = TARGET_TASK_CPU_CONTEXT,
    .task_fpsimd = TARGET_TASK_FPSIMD,
    .switch_continuation_off = TARGET_SWITCH_CONTINUATION_OFF,
    .gadget_store_off = TARGET_GADGET_STORE_OFF,
    .gadget_switch_return_off = TARGET_GADGET_SWITCH_RETURN_OFF,
};

const struct target_profile *target_profile_get(void) {
    return &profile;
}

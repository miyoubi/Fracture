#define _GNU_SOURCE
#include "target_profile.h"

#ifdef TARGET_UNIFIED

#include <string.h>
#include <sys/system_properties.h>

/*
 * One loader for every supported Xperia.  The table repeats the per-project
 * target headers; the active entry is selected from the device's model and
 * firmware build at runtime.
 */
#define COMMON_PROFILE_FIELDS                                                 \
    .kernel_release = "4.19.157-perf+",                                       \
    .user_ds = 0x0000007fffffffffULL,                                         \
    .task_stride = 0xec0,                                                     \
    .task_addr_limit = 0x40,                                                  \
    .task_real_cred = 0x7d8,                                                  \
    .task_cred = 0x7e0,                                                       \
    .task_comm = 0x7e8,                                                       \
    .task_tasks = 0x530,                                                      \
    .task_pid = 0x630,                                                        \
    .task_tgid = 0x634,                                                       \
    .task_security = 0xad8,                                                   \
    .task_fake_sec = 0xae0,                                                   \
    .task_group_leader = 0x670,                                               \
    .cred_security = 0x78,                                                    \
    .qsee_context = "u:r:vendor_hal_keymaster_qti:s0",                        \
    .cred_ids = 0x04,                                                         \
    .cred_caps = 0x30,                                                        \
    .cap_last_cap = 37,                                                       \
    .kernel_text_va = 0xffffff8008080000ULL,                                  \
    .selinux_word = 0x01000000U,                                              \
    .task_state = 0x58,                                                       \
    .task_cpu_context = 0xaf0,                                                \
    .task_fpsimd = 0xb70,                                                     \
    .switch_continuation_off = 0x89fcULL,                                     \
    .gadget_switch_return_off = 0x117228ULL

static const struct target_profile g_profiles[] = {
    {
        .model = "SOG02",
        .build = "58.2.C.3.127",
        .fingerprint = "KDDI/SOG02_jp_kdi/SOG02:12/58.2.C.3.127/"
                       "058002C003012704213379541:user/release-keys",
        COMMON_PROFILE_FIELDS,
        .selinux_state_off = 0x31ad000ULL,
        .gadget_store_off = 0x427410ULL,
    },
    {
        .model = "SO-52A",
        .build = "58.2.B.0.520",
        .fingerprint = "SO-52A/58.2.B.0.520",
        COMMON_PROFILE_FIELDS,
        .selinux_state_off = 0x31ad000ULL,
        .gadget_store_off = 0x427410ULL,
    },
    {
        .model = "SO-51A",
        .build = "58.2.B.0.520",
        .fingerprint = "SO-51A/58.2.B.0.520",
        COMMON_PROFILE_FIELDS,
        .selinux_state_off = 0x31ae000ULL,
        .gadget_store_off = 0x424350ULL,
    },
    {
        .model = "SOG01",
        .build = "58.2.C.5.10",
        .fingerprint = "SOG01/58.2.C.5.10",
        COMMON_PROFILE_FIELDS,
        .selinux_state_off = 0x31ae000ULL,
        .gadget_store_off = 0x424350ULL,
    },
    /* XQ-AT42, XQ-AT51, XQ-AT52, XQ-AT72 (Xperia 1 II) and XQ-AS42,
     * XQ-AS52, XQ-AS62, XQ-AS72 (Xperia 5 II) global variants.  Offsets
     * derived from split boot kernels (4.19.157-perf+).  Where the
     * ro.build.display.id is known it is pinned; selection still falls back
     * to a model match for other builds of the same model. */
    {
        .model = "XQ-AT42",
        .build = "58.2.A.10.102",
        .fingerprint = "XQ-AT42/58.2.A.10.102",
        COMMON_PROFILE_FIELDS,
        .selinux_state_off = 0x31ae000ULL,
        .gadget_store_off = 0x424350ULL,
    },
    {
        .model = "XQ-AT51",
        .build = "58.2.A.7.93",
        .fingerprint = "XQ-AT51/58.2.A.7.93",
        COMMON_PROFILE_FIELDS,
        .selinux_state_off = 0x31ac000ULL,
        .gadget_store_off = 0x4282d8ULL,
    },
    {
        .model = "XQ-AT52",
        .build = "58.2.A.7.93",
        .fingerprint = "XQ-AT52/58.2.A.7.93",
        COMMON_PROFILE_FIELDS,
        .selinux_state_off = 0x31ac000ULL,
        .gadget_store_off = 0x4282d8ULL,
    },
    {
        .model = "XQ-AT72",
        .build = "58.2.A.10.44A",
        .fingerprint = "XQ-AT72/58.2.A.10.44A",
        COMMON_PROFILE_FIELDS,
        .selinux_state_off = 0x31ac000ULL,
        .gadget_store_off = 0x4282d8ULL,
    },
    {
        .model = "XQ-AS42",
        .build = "58.2.A.10.163",
        .fingerprint = "XQ-AS42/58.2.A.10.163",
        COMMON_PROFILE_FIELDS,
        .selinux_state_off = 0x31ad000ULL,
        .gadget_store_off = 0x427410ULL,
    },
    {
        .model = "XQ-AS52",
        .build = "58.2.A.10.126",
        .fingerprint = "XQ-AS52/58.2.A.10.126",
        COMMON_PROFILE_FIELDS,
        .selinux_state_off = 0x31ad000ULL,
        .gadget_store_off = 0x427410ULL,
    },
    {
        .model = "XQ-AS62",
        .build = "58.2.A.10.126",
        .fingerprint = "XQ-AS62/58.2.A.10.126",
        COMMON_PROFILE_FIELDS,
        .selinux_state_off = 0x31ad000ULL,
        .gadget_store_off = 0x427410ULL,
    },
    {
        .model = "XQ-AS72",
        .build = "58.2.A.10.126",
        .fingerprint = "XQ-AS72/58.2.A.10.126",
        COMMON_PROFILE_FIELDS,
        .selinux_state_off = 0x31ad000ULL,
        .gadget_store_off = 0x427410ULL,
    },
};

const struct target_profile *target_profile_get(void) {
    char model[PROP_VALUE_MAX] = {0};
    char build[PROP_VALUE_MAX] = {0};
    __system_property_get("ro.product.model", model);
    __system_property_get("ro.build.display.id", build);

    const struct target_profile *model_match = NULL;
    for (size_t i = 0; i < sizeof(g_profiles) / sizeof(g_profiles[0]); i++) {
        if (strcmp(model, g_profiles[i].model) != 0)
            continue;
        if (g_profiles[i].build && strcmp(build, g_profiles[i].build) == 0)
            return &g_profiles[i];
        if (!model_match)
            model_match = &g_profiles[i];
    }
    if (model_match)
        return model_match;
    return NULL;
}

#else

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

#endif

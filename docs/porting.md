# Porting to another 4.19.157 Sony (SO-51A / SO-52A)

There are no SO-51A / SO-52A (or 58.2.B.0.520) test results yet; the
only profile in the repository is `sog02-58.2.C.3.127`.

## Reusable, but not plug-and-play

The vulnerability and primitive live in the shared 4.19.157 vendor
kernel + KGSL driver, so the logic (KGSL UAF → arbitrary R/W → cred
patch → SELinux permissive via the forged `thread.cpu_context`) should
port. The target data does not: every address, gadget and struct offset
is derived from a specific kernel image and must be recalculated from
the SO-51A image.

## What to recalculate

Kernel symbols / gadgets (offsets from the kernel image base):

- the `__switch_to` continuation used for the KASLR leak,
- the `str w20, [x19]` store gadget,
- the `__switch_to` epilogue/return gadget,
- `selinux_state` (and the `enforcing` byte at `+1`; the word written is
  `0x01000000`).

`task_struct`:

- `addr_limit`, `cpu_context`, `fpsimd`/thread, `comm`, stride/size,
  `tasks`, `cred`, `real_cred`, `security`.

`cred`:

- uid/gid/euid/egid/suid/sgid/fsuid/fsgid offsets,
- the cap sets, `security`, `cap_last_cap`.

SELinux:

- `task_security_struct` / `cred->security`, the fake security struct
  used for the SID, the SID values scanned.

If used:

- `init_user_ns`, `init_cred`, the `USER_DS` value.

KGSL:

- ioctl numbers and struct layouts (`kgsl_map_user_mem`,
  `kgsl_mem_entry`, the pool), and the GPU/IB addresses.

Then add `src/targets/<project>/target.h` and a `target_profile` entry
and build with `PROJECT=<project>`.

The SOG02 values (cpu_context `0xaf0`, fpsimd `0xb70`, continuation
`0x89fc`, store gadget `0x427410`, switch return `0x117228`, etc.) are
for this build; do not assume them.

## Deriving the offsets

Use the firmware's `boot.img-kernel` / `Image`, convert with
`vmlinux-to-elf`, then `nm`/`objdump` for symbols and gadgets; use
DWARF/BTF if the image has it for struct offsets. The stock `vmlinux`
symbols used here were `selinux_state`, `init_user_ns`,
`fair_sched_class`, `switch_to`, etc.

## KGSL race parameters

Mostly not firmware-specific. Children/pressure are derived from
`/proc/meminfo`; racers/delay/rounds are heuristics. Start with the
defaults and tune with `KGSL_CHILDREN`, `KGSL_PRESSURE_MB`,
`KGSL_RACERS`, `KGSL_RACE_CPU`, `KGSL_RACE_DELAY_US`, `KGSL_ROUNDS`.

## Safe probe

`SEC_PERM_TRIGGER=0` is the dry run: it leaks KASLR, derives and prints
the addresses, and leaves the forged `thread.cpu_context` untouched.
It still goes through the KGSL race/UAF, so it is not risk-free; wrong
derived addresses can crash the device. There is no truly read-only
mode because the primitive itself is the UAF.

`SEC_PERMISSIVE=0` only skips the SELinux hijack. (The custom su daemon
was removed in the KSU-only tree; `INJECT_KO` is the KernelSU path.)

## Firmware/device notes

- Same SoC (SM8250 / Snapdragon 865, Adreno 650) and 4.19.157-perf+
  family makes porting plausible, but the vendor kernel build and the
  firmware offsets still differ.
- Keep a recovery path: a wrong offset or a lost race can panic/crash
  the device. Prefer a device you can restore.

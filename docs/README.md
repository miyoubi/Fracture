# CVE-2023-33107 Xperia — notes

Targets: Sony Xperia 1 II / 5 II family (SO-51A, SO-52A, SOG01, SOG02),
kernel 4.19.157-perf+ (SM8250 / Snapdragon 865), locked bootloader. The
per-device builds are listed in the [root README](../README.md).

These notes are the working findings from porting the exploit and the
late-load KernelSU LKM; start with [exploit.md](exploit.md) for the
end-to-end description and [troubleshooting.md](troubleshooting.md) for
failure modes.

## Documents

- [exploit.md](exploit.md) — end-to-end mechanics: KGSL UAF race,
  reclaim, credential patch, forged `thread.cpu_context`, KernelSU
  late-load, profiles, and the runtime output.
- [troubleshooting.md](troubleshooting.md) — symptoms, diagnosis and
  tuning (`[exit] 137`, `ENOMEM`, failed alias scan, permissive, LKM).
- [primitive.md](primitive.md) — KGSL UAF, credential patch, SELinux
  permissive via `thread.cpu_context`, and the userspace AVC problem.
- [kernelsu-late-load.md](kernelsu-late-load.md) — building and loading
  `kernelsu.ko` from the backslashxx fork on this 4.19 vendor kernel.
- [porting.md](porting.md) — profiles and what to re-derive for another
  4.19.157 Sony (SO-51A / SO-52A / SOG01).

## Current shape of the tree

- The exploit patches creds, switches SELinux permissive, and (with
  `INJECT_KO`) late-loads `kernelsu.ko` from the full-capability root
  child. The custom su client/daemon was removed; root is expected to
  come from the KernelSU userspace.
- `tools/build_kernelsu_lkm.sh` builds the LKM from
  `backslashxx/KernelSU` against `kernel_sony_sm8250` (the existing
  checkout; `--pull` updates it). The SO-51A/SO-52A/SOG01 kernels share
  identical `Module.symvers`, so one module covers them.
- `tools/policy_fix.sh` + `tools/sepolicy.rule` + `tools/su_env` cover
  the SELinux/property-service side.

## Credits

- **Risuntsy** — author of the exploit, including the `thread.cpu_context`
  SELinux permissive switch-in (`cdb4832`).
- **Keto (`keto0422`)** — original CVE-2023-33107 KGSL UAF exploit.
- **backslashxx** — KernelSU fork used for the late-load LKM, the
  `dd352cb` modpost/KALLSYMS_ALL tweak, and the staging
  `kallsyms_common.h` / `kernel_umount.c` updates.
- The ghostlock references were read for technique only; no ghostlock
  code is included.

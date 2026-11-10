# CVE-2023-33107 Xperia — port notes

Target: Sony Xperia 5 II (SOG02), firmware 58.2.C.3.127, kernel
4.19.157-perf+ (SM8250 / Snapdragon 865). Locked bootloader.

These notes are the working findings from porting the exploit and the
late-load KernelSU LKM; they are not a polished write-up.

## Documents

- [primitive.md](primitive.md) — KGSL UAF, credential patch, SELinux
  permissive via `thread.cpu_context`, and the userspace AVC problem.
- [kernelsu-late-load.md](kernelsu-late-load.md) — building and loading
  `kernelsu.ko` from the backslashxx fork on this 4.19 vendor kernel.
- [porting.md](porting.md) — what to re-derive for another 4.19.157
  Sony (e.g. Xperia 1 II SO-51A / SO-52A, 58.2.B.0.520).

## Current shape of the tree

- The exploit patches creds, switches SELinux permissive, and (with
  `INJECT_KO`) late-loads `kernelsu.ko` from the full-capability root
  child. The custom su client/daemon was removed; root is expected to
  come from the KernelSU userspace.
- `tools/build_kernelsu_lkm.sh` builds the LKM from
  `backslashxx/KernelSU` (the existing checkout; `--pull` updates it).
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

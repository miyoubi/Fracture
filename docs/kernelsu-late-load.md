# KernelSU late-load on the 4.19 Sony kernel

## Why late-load

The bootloader is locked, so an in-tree KernelSU (custom boot image) is
not an option. The LKM is built as `CONFIG_KSU=m` from the
[backslashxx fork](https://github.com/backslashxx/KernelSU) and loaded at
runtime by the exploit's full-capability root child.

The KernelSU userspace (`ksud` / manager / its `su`) is still required
for a usable `su`; this repository only late-loads the kernel module.

## Build recipe (`tools/build_kernelsu_lkm.sh`)

The script automates:

1. clone/use `backslashxx/KernelSU` in `KernelSU/`; with `--pull` fetch and
   check out `origin/staging` (staging is force-updated, the local branch
   can be stale). Without `--pull` the current checkout is built as-is.
2. copy `kernel/` into `kernel_sony_sm8250/KernelSU/kernel`
   and source its Kconfig from the tree Kconfig.
3. `.config`: `CONFIG_KSU=m`, `CONFIG_KSU_HACK_ARM64_BRANCH_LINK=y`,
   `CONFIG_KSU_LSM_SECURITY_HOOKS=y`; `KALLSYMS_ALL=y` is already in the
   device config. `CONFIG_MODVERSIONS=y` is kept.
4. **Full device `Module.symvers`** via `gen_symvers.py` (walks
   `__ksymtab` / `__ksymtab_gpl` and `__kcrctab{,_gpl}`). The
   `__ksymtab` name offset is relative to `entry+4`, not `entry`. The
   device is `CONFIG_MODVERSIONS=y`, so `module_layout` and every
   imported CRC must match exactly; the changelog's
   `CONFIG_MODVERSIONS=n` is optional and not used here.
5. generate `include/generated/compile.h` (`scripts/mkcompile_h`) and
   `security/selinux/flask.h` / `av_permissions.h`
   (`scripts/selinux/genheaders`).
6. build with:
   ```
   KCFLAGS="-march=armv8-a+lse -DCONFIG_AS_LSE=1 -mbranch-protection=none"
   KBUILD_MODPOST_WARN=1
   M=$PWD/KernelSU/kernel modules
   ```
   `-mbranch-protection=none` avoids the PAuth relocations clang 17
   emits for function-pointer tables.
7. verify no GOT/PAuth relocations remain.

### Gotchas

- The vendor `Makefile` line 412 forces
  `CC = $(PYTHON) scripts/gcc-wrapper.py $(REAL_CC)`. Toolchain
  variables must be passed as **make arguments**, not environment
  variables, or the Python-2 wrapper breaks Kconfig's `$(CC)` probes
  (`init/Kconfig:17` parse error).
- `modules_prepare` does not generate `compile.h` or the SELinux
  `flask.h`; generate them explicitly.
- `CONFIG_MODVERSIONS=y` means a complete device-derived
  `Module.symvers`; a short file fails on `module_layout`/CRC mismatch.

### path_umount / GOT relocations

The 4.19 arm64 module loader does not implement the GOT relocations
(`R_AARCH64_ADR_GOT_PAGE`, `R_AARCH64_LD64_GOT_LO12_NC`). Older
`kernel/feature/kernel_umount.c` used a weak extern `path_umount`,
which the compiler lowered through the GOT and the loader rejected with
`unsupported RELA relocation: 311`.

The staging source now wraps the weak `path_umount` in `#ifndef MODULE`
and uses `ksyscall(umount)` for modules, so the module emits no GOT
reference. The build script follows `origin/staging` and no longer needs
the runtime-lookup source patch. (On older sources the workaround was to
resolve `path_umount` at runtime through `kallsyms_lookup_name`.)

## Loader (`src/ko_loader.c`)

The exploit's loader mirrors `ksuinit`:

- temporarily sets `kptr_restrict=1` and reads `/proc/kallsyms`,
- for every `SHN_UNDEF` symbol, resolves its address and patches the
  symtab entry to `SHN_ABS`/`st_value`,
- calls `init_module` with the module parameters (`allow_shell=1` by
  default, `INJECT_KO_PARAMS` overrides).

Unresolved names are left for the kernel's own exports. The root child
runs the loader while it still has full capabilities.

## Module init (`e2f2e397` and later)

The commit enables the late-load `#if 1` block in `ksu.c`:
`ksu_late_loaded = true`, `escape_to_root_forced()`,
`stop_init_rc_hook()`, `apply_kernelsu_rules()`, `cache_sid()`,
`setup_ksu_cred()`. `supercall/dispatch.c` reports
`KSU_GET_INFO_FLAG_LATE_LOAD` so the manager can see it. The
`current->pid == 1` early return is kept for the init case (our loader
runs from the root child, not PID 1).

## Userspace / SELinux

- The KernelSU userspace (`ksud`, the manager APK) still has to be
  installed; the device currently has no `/data/adb/ksu`.
- For the property service, the exploit also writes the selinuxfs
  `enforce` node from the root child and ships `tools/policy_fix.sh` +
  `tools/sepolicy.rule` (see [primitive.md](primitive.md)).
- The KSU-side `sepolicy.rule` is applied by `ksud`/the module
  (`sepolicy::apply_file`); on a device without the userspace, the
  exploit's selinuxfs write + policy script + `runcon` wrapper are what
  take effect.

## Load order / manager detection

The root child loads the module **first** and then backgrounds the slow
policy fix. Previously the policy copy + `load_policy`/`cat` ran before
`init_module`, delaying the KSU supercall (and the manager's probe).
The remaining latency, if any, is the manager's own polling interval.

## Tested artifacts

- KernelSU `49f048c0` (`origin/staging`): `kernelsu.ko`, 349,256 bytes,
  no GOT/PAuth relocations, no `path_umount` reference.
- Earlier `e2f2e397` also builds, with the `#if 1` late-load init.

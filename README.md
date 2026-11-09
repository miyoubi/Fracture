# CVE-2023-33107 Xperia root

KGSL UAF temporary-root exploit for the Sony Xperia 5 II (SOG02).  It
patches the process credentials, switches SELinux to permissive through the
forged `thread.cpu_context` switch-in, and can late-load a KernelSU LKM.

| Project | Device | Firmware | Kernel |
| --- | --- | --- | --- |
| `sog02-58.2.C.3.127` | Sony Xperia 5 II (SOG02, KDDI) | `58.2.C.3.127` | `4.19.157-perf+` |

## Build and run

```sh
make PROJECT=sog02-58.2.C.3.127 NDK_ROOT="$NDK"
adb push build/sog02-58.2.C.3.127/kgsl_root_su /data/local/tmp/kgsl_root_su
adb push kernelsu.ko /data/local/tmp/kernelsu.ko      # see KernelSU late-load
adb shell 'chmod 755 /data/local/tmp/kgsl_root_su; \
  INJECT_KO=/data/local/tmp/kernelsu.ko INJECT_KO_PARAMS=allow_shell=1 \
  /data/local/tmp/kgsl_root_su'
adb shell 'getenforce'                                 # Permissive
adb shell 'cat /proc/modules | grep kernelsu'          # kernelsu ... Live
```

Root comes from the KernelSU userspace (manager/`ksud` su at
`/data/adb/ksu/bin/ksu`); the exploit no longer ships its own su client or
daemon.

Without `INJECT_KO` a plain run only drops `selinux_state` into permissive
mode; it does not leave a root shell behind (see
[PERMISSIVE.md](PERMISSIVE.md)).  Spray size and KGSL pressure are chosen
from `/proc/meminfo` (8192 children and ~60% of MemAvailable on an 8 GB
device).  The race runs the `kgsl_map_user_mem` thread on a second CPU,
waits for it to enter the driver, then sweeps the overlap `mmap` delay over
0..the measured ioctl duration (a fixed `KGSL_RACE_DELAY_US` pins it).
`KGSL_PRESSURE_HOLD=1` optionally keeps the pressure mapping resident across
the fork spray.  The memory scan batches up to 2048 pages per GPU submission
(1 MiB dump buffer, 16 MiB IB) and falls back to a full scan if the fast
scan finds nothing.

## Optional settings

| env | default | effect |
| --- | --- | --- |
| `SEC_PERMISSIVE` | `1` | clear `selinux_state.enforcing` through the forged `thread.cpu_context`; `0` skips the hijack |
| `SEC_PERM_TRIGGER` | `1` | `0` performs the dry run: leak KASLR, print the derived addresses, leave the context untouched |
| `INJECT_KO` | off | path to a KernelSU LKM to late-load from the root child |
| `INJECT_KO_PARAMS` | `allow_shell=1` | module parameters passed to `init_module` |
| `SEC_SID=n` | off | forge `task_security_struct` with SID `n` (`1` = `u:r:kernel:s0`); see [SEC_SID.md](SEC_SID.md) |
| `KGSL_CHILDREN` | auto (8192 on >= 7 GB) | spray children (512..16384) |
| `KGSL_PRESSURE_MB` | auto (~60% MemAvailable) | memory pressure to drain the KGSL pool (0..5120) |
| `KGSL_PRESSURE_HOLD` | `0` | keep the pressure resident across the fork spray; `0` releases it before spraying |
| `KGSL_RACERS` | `1` | concurrent `kgsl_map_user_mem` racers (1..4) |
| `KGSL_RACE_CPU` | auto (a second CPU) | CPU for the racer threads; set it to the park CPU to use the old single-CPU race |
| `KGSL_RACE_DELAY_US` | auto | sweep the delay after the racer enters the ioctl over 0..the measured ioctl duration; set a value to pin it (0..100000) |
| `KGSL_RACE_RETRY_MS` | `200` | settle time between race attempts (0..5000); give the KGSL pool time to release the last 256 MiB object |
| `KGSL_SCAN_FULL` | off | force the full task scan (`1`); otherwise the fast scan falls back to it when it finds nothing |
| `KGSL_ROUNDS` | `8` | exploit rounds (1..16) |

```sh
# permissive + KernelSU late-load
adb shell 'INJECT_KO=/data/local/tmp/kernelsu.ko INJECT_KO_PARAMS=allow_shell=1 /data/local/tmp/kgsl_root_su'

# permissive only
adb shell '/data/local/tmp/kgsl_root_su'

# no kernel write
adb shell 'SEC_PERMISSIVE=0 /data/local/tmp/kgsl_root_su'

# dry run: derive and print, change nothing
adb shell 'SEC_PERM_TRIGGER=0 /data/local/tmp/kgsl_root_su'
```

## KernelSU late-load

The LKM is built from the [backslashxx KernelSU
fork](https://github.com/backslashxx/KernelSU) (`KernelSU/kernel`) against
the stock Sony 4.19 tree:

- `CONFIG_KSU=m`, `CONFIG_KSU_HACK_ARM64_BRANCH_LINK=y`, and
  `CONFIG_KALLSYMS_ALL=y` (the device config already has it).
- `CONFIG_MODVERSIONS=y` with a full `Module.symvers` generated from the
  device `vmlinux`, so `module_layout` and every exported CRC match.  The
  changelog's `CONFIG_MODVERSIONS=n` is optional; with matching CRCs it is
  not needed.
- Build with (run inside the stock kernel tree, with the fork's `kernel/`
  copied to `KernelSU/kernel` and its Kconfig sourced):

  ```sh
  make ARCH=arm64 LLVM_IAS=1 CROSS_COMPILE=aarch64-linux-android30- \
    CC="$NDK/aarch64-linux-android30-clang" LD=ld.lld AR=llvm-ar NM=llvm-nm \
    OBJCOPY=llvm-objcopy OBJDUMP=llvm-objdump STRIP=llvm-strip HOSTCC=gcc \
    KBUILD_MODPOST_WARN=1 \
    KCFLAGS="-march=armv8-a+lse -DCONFIG_AS_LSE=1 -mbranch-protection=none" \
    M="$PWD/KernelSU/kernel" modules
  ```

  `-mbranch-protection=none` avoids the PAuth relocations clang 17 emits for
  function-pointer tables.  The 4.19 arm64 module loader also lacks the GOT
  relocations a weak `path_umount` produces; the staging `kernel_umount.c`
  wraps the weak `path_umount` in `#ifndef MODULE`, so the module takes the
  `ksyscall(umount)` path and emits no GOT relocations.
- `src/ko_loader.c` binds the module's undefined symbols from
  `/proc/kallsyms` (temporarily setting `kptr_restrict=1`), patches them to
  `SHN_ABS`, and calls `init_module` from the full-capability root child.
  `INJECT_KO_PARAMS` is passed as the module argument (`allow_shell=1` by
  default).
- The `scripts/Makefile.modpost` `-w` tweak and the `KALLSYMS_ALL` Kconfig
  change are from
  [`backslashxx/kernel_xiaomi_sm6225@dd352cb`](https://github.com/backslashxx/kernel_xiaomi_sm6225/commit/dd352cb).
- The KernelSU userspace (manager/`ksud`) must be installed separately to
  get the `su` binary; this exploit only late-loads the kernel module.

### Building the LKM

`tools/build_kernelsu_lkm.sh` automates the whole flow:

```sh
tools/build_kernelsu_lkm.sh                             # origin/staging (default)
KSU_REF=master tools/build_kernelsu_lkm.sh              # a branch
KSU_COMMIT=e2f2e397 tools/build_kernelsu_lkm.sh         # an exact commit
VMLINUX=/path/vmlinux.elf tools/build_kernelsu_lkm.sh   # regenerate the full symvers
```

It clones/fetches `backslashxx/KernelSU` into `KernelSU/`, copies `kernel/`
into `stockkernel_sony_sm8250-main/KernelSU/kernel`, wires the Kconfig and
`CONFIG_KSU=m`, generates `compile.h`/`flask.h`, ensures the full device
`Module.symvers` (via `gen_symvers.py`, using `VMLINUX` when supplied),
re-applies the `path_umount` runtime lookup, builds with the LSE/PA flags,
verifies that no GOT/PAuth relocations remain, and leaves the result at
`build/<project>/kernelsu.ko`.

## Credits

- **Risuntsy** — author of this exploit, including the SELinux permissive
  `thread.cpu_context` switch-in primitive from commit `cdb4832`
  ("feat: root + SELinux permissive by default (forged thread.cpu_context)").
- **Keto (`keto0422`)** — original CVE-2023-33107 KGSL UAF exploit and
  write-up that this port builds on.
- **backslashxx** — [KernelSU fork](https://github.com/backslashxx/KernelSU)
  used for the late-load LKM (`KernelSU/kernel`), including the LKM support
  restoration (`c96e9272`, changelog `65a906e`) and the staging
  `kallsyms_common.h` scan tweak (`2c515d1e`).


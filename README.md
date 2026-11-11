# CVE-2023-33107 Xperia root

> **Warning**
>
> I am not responsible for any damage to your device.

KGSL UAF temporary-root exploit for the Sony Xperia 1 II / 5 II family
(SO-51A, SO-52A, SOG01, SOG02).  It
patches the process credentials, flips SELinux permissive through the
forged `thread.cpu_context` switch-in, and can late-load a KernelSU LKM
plus its userspace.

| Project | Device | Firmware | Kernel |
| --- | --- | --- | --- |
| `sog02-58.2.C.3.127` | Sony Xperia 5 II (SOG02, KDDI) | `58.2.C.3.127` | `4.19.157-perf+` |
| `so-51a-58.2.B.0.520` | Sony Xperia 1 II (SO-51A) | `58.2.B.0.520` | `4.19.157-perf+` |
| `so-52a-58.2.B.0.520` | Sony Xperia 5 II (SO-52A) | `58.2.B.0.520` | `4.19.157-perf+` |
| `sog01-58.2.C.5.10` | Sony Xperia 1 II (SOG01, KDDI) | `58.2.C.5.10` | `4.19.157-perf+` |

## Documentation

- [docs/exploit.md](docs/exploit.md) — how the exploit works, end to end.
- [docs/troubleshooting.md](docs/troubleshooting.md) — failure modes and tuning.
- [docs/primitive.md](docs/primitive.md) — primitive and SELinux notes.
- [docs/porting.md](docs/porting.md) — profiles and deriving new offsets.
- [docs/kernelsu-late-load.md](docs/kernelsu-late-load.md) — the LKM and late-load.

## Dependencies (Arch Linux)

Official repositories:

```sh
sudo pacman -S --needed base-devel git curl unzip bc bison flex pahole \
  android-tools python
```

`vmlinux-to-elf` is not in the official repositories; install it from the AUR:

```sh
paru -S vmlinux-to-elf
```

The NDK (`android-ndk-r26d`) and the kernel tree are fetched by
`./build.sh --setup`; no manual download is needed.

### Building the Fracture app

The app build needs a JDK, Gradle, and the Android SDK (platform 35 and
build-tools); the NDK comes from `./build.sh --setup`.

```sh
sudo pacman -S --needed jdk-openjdk gradle
paru -S android-sdk          # AUR; or use Google's cmdline-tools
export ANDROID_HOME=/opt/android-sdk
sdkmanager "platforms;android-35" "build-tools;36.0.0"
```

Then build the unified loader and the app together:

```sh
./build.sh -p unified --app --push
```

## Usage

1. Build and push the exploit + LKM for your profile:

   ```sh
   ./build.sh -p <project> --push
   ```

2. Install the [backslashxx/KernelSU](https://github.com/backslashxx/KernelSU/)
   manager. It is the only supported manager; the LKM is built from this
   fork.

3. Run the exploit:

   ```sh
   adb shell /data/local/tmp/kgsl_root_su
   ```

## Custom paths

By default the helper uses `./kernel_sony_sm8250` and `./android-ndk-r26d`.
If your kernel source or NDK live elsewhere, point it at them:

```sh
./build.sh -p sog02-58.2.C.3.127 \
  --kernel-dir /home/exer/kernelsrc \
  --ndk /ndklocation
```

These flags override the defaults for the build; `--setup` still populates
the default `./kernel_sony_sm8250` and `./android-ndk-r26d`.

## Build and run

The simplest path:

```sh
./build.sh                                 # list the available targets
./build.sh -p sog02-58.2.C.3.127           # build exploit + LKM (no push)
./build.sh -p sog02-58.2.C.3.127 --push    # build + push
./build.sh --detect --push --run           # connected device: push + run
./build.sh --setup                         # fetch the NDK and kernel if missing
```

Profiles are SOG02, SO-51A, SO-52A and SOG01. Pushing is opt-in with
`--push`; the pushed files are verified by md5. `--setup` downloads
`android-ndk-r26d` and clones `kernel_sony_sm8250` when they are missing;
`--force --setup` deletes and re-fetches both.

Manual equivalent:

```sh
make PROJECT=sog02-58.2.C.3.127 NDK_ROOT="$NDK"
tools/build_kernelsu_lkm.sh

adb push build/sog02-58.2.C.3.127/kgsl_root_su /data/local/tmp/kgsl_root_su
adb push build/sog02-58.2.C.3.127/kernelsu.ko /data/local/tmp/kernelsu.ko

adb shell 'chmod 755 /data/local/tmp/kgsl_root_su; \
  /data/local/tmp/kgsl_root_su'
adb shell 'getenforce'                                 # permissive at startup; KSU may enforce
adb shell 'cat /proc/modules | grep kernelsu'          # kernelsu ... Live
```

A plain run loads `/data/local/tmp/kernelsu.ko` and runs
`/data/adb/ksud late-load` from the root child.  `INJECT_KO=0` and/or
`LATE_LOAD=0` disable either half.  `POLICY_FIX=1` forces the exploit's
own SELinux policy reload while the late-load is enabled (normally skipped;
see the crash note below).

Root comes from the KernelSU userspace (manager / `ksud` su); the exploit
does not ship its own su client or daemon.

## How it works

- **KGSL race.** `kgsl_map_user_mem` runs on a second CPU and races the
  overlap `mmap`.  The exploit measures the ioctl duration, sweeps the
  `mmap` delay over `0..that duration`, and time-bounds the retry loop.
  The freed object's pages are reclaimed by spraying children
  (`/proc/meminfo`-derived sizes).
- **Credentials.** A child `task_struct`/`cred` is located through the
  reclaimed GPU mapping and patched to uid/gid 0 with full capability
  sets; the root child verifies via `/proc/<pid>/status`.
- **Permissive.** The raw `thread.cpu_context` switch-in leaks KASLR
  (`__switch_to` continuation), stores `0x01000000` into `selinux_state`
  (enforcing=0), and replays the `__switch_to` epilogue.  The root child
  then writes `/sys/fs/selinux/enforce` so `init` and the property service
  refresh their cached AVC state.
- **KernelSU.** `src/ko_loader.c` resolves the module's undefined symbols
  from `/proc/kallsyms`, patches the symtab entries to `SHN_ABS`, and calls
  `init_module` from the full-capability root child.  The root child then
  runs `ksud late-load`, which installs the userspace and initializes the
  manager side.

The manager's driver-fd handshake and detection belong to the KernelSU
userspace; the exploit does not restart or relaunch it.

## SELinux / permissive failures

Permissive is only needed for the exploit startup.  The forged-context
store writes `selinux_state.enforcing = 0`, and the root child writes
`/sys/fs/selinux/enforce` so `init` picks it up; the module load
(`init_module`) would be denied by the shell domain while enforcing, so
this happens before `INJECT_KO`.

KernelSU's LKM init then re-enables enforcing by design
(`ksu.c`: `if (!!getenforce()) return; pr_info("Permissive SELinux,
enforcing"); setenforce(true);`).  The exploit leaves that decision to
KernelSU, so `getenforce` may report `Enforcing` after a late-load run —
that is expected, not a failure.  A second selinuxfs write would be denied
by the `security:security setenforce` check for the shell domain, so it is
not attempted.

The startup permissive fails only when the forged-context hijack did not
arm (`permissive hijack not armed`, implausible KASLR/context, or a GPU
write failure).  The raw store never happens then, and the selinuxfs write
is denied; the exploit prints the reason.

## Known failure modes

- **KGSL `ENOMEM` on every try** — the driver pool is exhausted from
  repeated 256 MiB objects.  The exploit stops after a full round of
  `ENOMEM`; reboot the device.  `KGSL_RACE_RETRY_MS` (default 200) is the
  settle time between attempts.
- **Watchdog panic / freeze.**  `console-ramoops-0` shows every CPU
  spinning on the SELinux policy read lock (`security_context_to_sid_core`,
  `security_compute_sid`, `avc_compute_av`) right after `KernelSU: shell is
  allowed at init! / transive domain failed.`  Two `security_load_policy()`
  calls (KernelSU's own sepolicy load and the exploit's `policy_fix.sh`)
  hold the policy write lock long enough for the watchdog to bark.  The
  exploit now skips `policy_fix.sh` whenever the KernelSU late-load is
  enabled; do not combine `POLICY_FIX=1` with `LATE_LOAD`.  Reboot after a
  watchdog panic.
- Changing `sys.usb.config` re-enumerates USB and can drop adb.

## Optional settings

| env | default | effect |
| --- | --- | --- |
| `SEC_PERMISSIVE` | `1` | clear `selinux_state.enforcing` through the forged `thread.cpu_context`; `0` skips the hijack |
| `SEC_PERM_TRIGGER` | `1` | `0` performs the dry run: leak KASLR, print the derived addresses, leave the context untouched |
| `INJECT_KO` | `/data/local/tmp/kernelsu.ko` | LKM loaded from the root child; `0` disables |
| `INJECT_KO_PARAMS` | `allow_shell=0` | module parameters passed to `init_module` |
| `LATE_LOAD` | `/data/adb/ksud` | userspace binary for `late-load`; `0` disables |
| `KSU_PACKAGE` | `me.weishu.kernelsu` | manager package passed to `late-load` |
| `POLICY_FIX` | `0` | force `policy_fix.sh` even when the late-load is enabled (not recommended) |
| `SEC_SID=n` | off | forge `task_security_struct` with SID `n` (`1` = `u:r:kernel:s0`); see [SEC_SID.md](SEC_SID.md) |
| `KGSL_CHILDREN` | auto (8192 on >= 7 GB) | spray children (512..16384) |
| `KGSL_PRESSURE_MB` | auto (~60% MemAvailable) | memory pressure to drain the KGSL pool (0..5120) |
| `KGSL_PRESSURE_HOLD` | `0` | keep the pressure resident across the fork spray |
| `KGSL_RACERS` | `1` | concurrent `kgsl_map_user_mem` racers (1..4) |
| `KGSL_RACE_CPU` | auto (a second CPU) | CPU for the racer threads; a value equal to the park CPU is auto-corrected |
| `KGSL_CPU` | auto | CPU the parent parks on for the spray/scan |
| `KGSL_RACE_DELAY_US` | auto | sweep the overlap `mmap` delay over `0..the measured ioctl duration`; set a value to pin it (0..100000) |
| `KGSL_RACE_RETRY_MS` | `200` | settle time between race attempts (0..5000) |
| `KGSL_SCAN_FULL` | off | setting it skips the full-scan fallback; unset lets a miss retry the full scan |
| `KGSL_ROUNDS` | `8` | exploit rounds (1..16) |
| `KGSL_RETRY` | `0` | internal; the exploit restarts itself when the permissive store misses (max 3 attempts) |

```sh
# default: permissive + LKM + ksud late-load
adb shell '/data/local/tmp/kgsl_root_su'

# exploit only, no module/userspace
adb shell 'INJECT_KO=0 LATE_LOAD=0 /data/local/tmp/kgsl_root_su'

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
  `CONFIG_KALLSYMS_ALL=y` (already in the device config).
- `CONFIG_MODVERSIONS=y` with a full `Module.symvers` generated from the
  device `vmlinux`, so `module_layout` and every exported CRC match.
- Build with `-march=armv8-a+lse -DCONFIG_AS_LSE=1
  -mbranch-protection=none`; the LSE flag is needed for the inline atomics
  and `-mbranch-protection=none` avoids PAuth relocations the 4.19 module
  loader cannot handle.
- The 4.19 loader also has no GOT relocations.  The staging
  `kernel_umount.c` wraps the weak `path_umount` in `#ifndef MODULE` and
  uses `ksyscall(umount)`, so the module never emits a GOT reference; the
  build script does not patch it.
- No preinit workaround is needed: the staging source takes the
  `KSU_NO_PREINIT` path on this kernel and upstream fixed the late-load
  kthread call.
- `src/ko_loader.c` binds undefined symbols from `/proc/kallsyms`
  (temporarily setting `kptr_restrict=1`), patches them to `SHN_ABS`, and
  calls `init_module` from the root child.
- The KernelSU userspace (`ksud` / manager) must be installed to get `su`;
  this repository only builds and late-loads the kernel module.
- If `/data/adb/ksud` is not installed on a fresh boot, the root child
  falls back to `/data/adb/ksu/bin/ksud` and then the manager APK's
  `lib/arm64/libksud.so`, and reports the `execv` error if none of them
  run.

`tools/build_kernelsu_lkm.sh` automates the whole flow:

```sh
tools/build_kernelsu_lkm.sh                    # build the existing KernelSU checkout
tools/build_kernelsu_lkm.sh --pull             # fetch, then build origin/staging
tools/build_kernelsu_lkm.sh --pull --ref master        # fetch then build a branch
tools/build_kernelsu_lkm.sh --commit <sha>     # an exact commit
tools/build_kernelsu_lkm.sh --vmlinux /path/vmlinux.elf  # regenerate full symvers
```

It clones the fork once (when `KernelSU/` is missing) and otherwise leaves
the checkout alone unless `--pull` is given. It copies `kernel/` into the
stock tree, wires Kconfig and `CONFIG_KSU=m`, generates `compile.h` /
`flask.h` / `av_permissions.h`, ensures the device `Module.symvers` (via
`gen_symvers.py`), builds the module, verifies there are no GOT/PAuth
relocations, and stages `build/<project>/kernelsu.ko`.

## Credits

- **Risuntsy** — author of this exploit, including the SELinux permissive
  `thread.cpu_context` switch-in primitive from commit `cdb4832`
  ("feat: root + SELinux permissive by default (forged thread.cpu_context)").
- **Keto (`keto0422`)** — original CVE-2023-33107 KGSL UAF exploit and
  write-up that this port builds on.
- **backslashxx** — [KernelSU fork](https://github.com/backslashxx/KernelSU)
  used for the late-load LKM, and the `dd352cb` modpost/KALLSYMS_ALL tweak.

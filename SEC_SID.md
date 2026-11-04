# `SEC_SID=1` — SELinux bypass through a forged `task_security_struct`

Temporary-root follow-up for `sog02-58.2.C.3.127`. The KGSL UAF gives uid 0,
but the process stays in `u:r:shell:s0` with SELinux enforcing, which blocks
`/dev/qseecom`, every `block_device`, `/dev/socket/tad`, the MiscTA HAL and
`/sys/fs/selinux/*`.

The exploit already forges kernel objects inside the reclaimed KGSL pages
(it edits a `struct cred` image and points `task->cred`/`task->real_cred` at
it). `SEC_SID=1` does the same for the SELinux security struct:

1. `task->group_leader` (offset `0x670`, single-threaded child so it points
   at the task itself) is read through the GPU mapping. That gives the
   **kernel virtual address** of the child's `task_struct`; the reclaimed
   object is only addressable as a GPU VA, and `task->security` must hold a
   kernel VA.
2. `{u32 osid = 1, u32 sid = 1}` is written at `task_struct + 0xae0` (the
   `frozen` / `android_kabi_reserved1` union, the only spare 8 bytes in a
   packed `0xec0`-byte task_struct).
3. `task->security` (`0xad8`) and the forged cred's `security` pointer
   (`cred + 0x78`) are set to that kernel VA.
4. The child verifies itself and then **never exits**: `selinux_task_free()`
   and `selinux_cred_free()` would `kfree()` an interior pointer and take the
   kernel down. A panic with
   `ro.boot.bootreason=kernel_panic,fatal_exception` was observed when the
   patched task was allowed to die, and also when the first version wrote the
   GPU VA instead of the kernel VA.

SID 1 is `SECINITSID_KERNEL` (`u:r:kernel:s0`). Verified live on
`QV72130554`:

```
$ cat /proc/<patched-pid>/attr/current
u:r:kernel:s0
```

## Usage

```sh
# root + forged SID, child stays alive in u:r:kernel:s0
adb shell 'SEC_SID=1 KGSL_CHILDREN=4000 KGSL_PRESSURE_MB=2560 /data/local/tmp/kgsl_sid'

# root + forged SID + Keymaster device-state read (0x202)
adb shell 'SEC_SID=1 KM_UNLOCK_MODE=read KGSL_CHILDREN=4000 KGSL_PRESSURE_MB=2560 /data/local/tmp/kgsl_sid'
```

With `KM_UNLOCK_MODE` set, the child skips the (broken, PAN-blocked)
`selinux_handoff` and calls the QSEECom client directly from the SID-1
process.

## Target offsets (SOG02 `58.2.C.3.127`, from `layout.log`)

| field | offset |
|---|---|
| `task_struct.addr_limit` | `0x40` |
| `task_struct.real_cred` / `cred` / `comm` | `0x7d8` / `0x7e0` / `0x7e8` |
| `task_struct.group_leader` | `0x670` |
| `task_struct.security` | `0xad8` |
| spare union (`frozen`) for the fake struct | `0xae0` |
| `cred.security` | `0x78` |

## Hazards

- The patched task must not exit or be killed while the patch is live. Do not
  `pkill` the exploit binary after a successful `SEC_SID` run; reboot to clear.
- `frozen` is overwritten by `osid = 1`; the task's freezer state is bogus for
  the rest of the boot.
- The forged cred and security structs are not real slab objects.

# Primitive and SELinux notes

## KGSL UAF → arbitrary R/W

The bug is the CVE-2023-33107 KGSL UAF on the Adreno 650 / vendor KGSL
driver. The exploit races `kgsl_map_user_mem` against the overlap
`mmap` and reclaims the freed page, then uses the GPU submission path
(`gpu_write_words` / `gpu_read_words`) as a kernel read/write primitive.

Grooming knobs (all heuristics, tune per device):

| env | default |
| --- | --- |
| `KGSL_CHILDREN` | auto from `/proc/meminfo` (8192 on >= 7 GB) |
| `KGSL_PRESSURE_MB` | auto (~60% MemAvailable) |
| `KGSL_RACERS` | 1 |
| `KGSL_RACE_CPU` | auto (second CPU) |
| `KGSL_RACE_DELAY_US` | 30 |
| `KGSL_ROUNDS` | 8 |

The race window is scheduler/driver/build dependent; the children and
pressure are memory-derived, not firmware constants.

## Credential patch

The child's `task_struct`/`cred` are found by scanning the credential
aliases and matching a selected child; the `cred` uids/caps are patched
to 0/full. This is the usual temporary-root step and is target-offset
dependent.

## SELinux permissive

### Why the obvious routes do not work here

- The `addr_limit = KERNEL_DS` + `read(/dev/zero)` trick is dead on this
  SoC: `CONFIG_ARM64_PAN=y` and the Kryo 585 reports
  `ID_AA64MMFR2_EL1.UAO == 0`, so arm64 uaccess (`LDTR/STTR`) cannot
  touch TTBR1 kernel pages even with a forged addr_limit.
- `setenforce` from a shell is not usable because there is no permissive
  domain in the sepolicy; the selinuxfs write is checked by policy.

### The working mechanism: forged `thread.cpu_context`

The `__switch_to` path is hijacked through the child's saved
`thread.cpu_context`:

- `cpu_context.pc = _text + 0x89fc` gives a self-validating KASLR leak
  (the continuation is only right for the real base).
- Forge `x19 = selinux_state`, `x20 = 0x01000000`, `sp = task + 0xb70`,
  `pc = _text + 0x427410`; the gadget at `0x427410` executes
  `str w20, [x19]`.
- Two words in the fpsimd vregs, `[saved cpu_context.sp, _text + 0x117228]`,
  replay `__switch_to`'s epilogue, clear `prev->on_cpu`, and resume the
  child in `futex_wait`.
- The stored word `0x01000000` yields
  `{disabled=0, enforcing=0, checkreqprot=0, initialized=1}`.

`selinux_state` layout on this vendor kernel: `disabled@0, enforcing@1,
checkreqprot@2, initialized@3` (confirmed from `sel_read_enforce`:
`ldrb w3, [x8, #0x1]`).

So the kernel is permissive, and `getenforce` reports `Permissive`.

## The userspace AVC problem

Kernel permissive is not enough for the property service. The raw
`selinux_state` store does not update the status page or broadcast the
AVC netlink, so `init`/`property_service` keep their cached
`enforcing = 1`. Direct `setprop` / `stop` / `start` from the
`u:r:shell:s0` su then fail with `permissive=0` in the audit log, even
though `getenforce` says Permissive.

Three workarounds, in the order tried:

1. **Proper `setenforce` from the root child** — write
   `/sys/fs/selinux/enforce` = `0` from the root child (the ghostlock-oneplus
   `root.c` approach). This goes through `security_setenforce()`, which
   updates the status page and broadcasts the netlink, so `init`'s AVC
   flips too. The root child needs to do this before the userspace
   check matters.
2. **Policy patch** — `policy_fix.sh` copies `/sys/fs/selinux/policy`,
   ORs `0xC0000000` into the config word (netlink policy flags), and
   reloads with `load_policy` or `cat > /sys/fs/selinux/load`.
   Alternatively the KernelSU `ksud`/module `sepolicy.rule` with:
   ```
   allow shell ctl_stop_prop:property_service set;
   allow shell ctl_start_prop:property_service set;
   allow shell usb_control_prop:property_service set;
   allow shell usb_prop:property_service set;
   ```
3. **`runcon` wrappers** (`tools/su_env`) — `setprop` / `stop` / `start`
   through `runcon u:r:init:s0`, and `persist.usb.eng*` through
   `runcon u:r:usbeng:s0`. The init domain is allowed to touch the
   property types, so this works even with the stale AVC.

Property types observed on the SOG02:
`sys.usb.config` -> `u:object_r:usb_control_prop:s0`,
`sys.usb.config.*` -> `u:object_r:usb_prop:s0`.

### `system()` and capabilities

`system()` spawns `sh` with no effective/permitted caps (they are not
ambient/inheritable), so uid 0 alone cannot write into the shell-owned
`/data/local/tmp` (mode `0771`). The root child therefore does
`chmod 0777 /data/local/tmp` before backgrounding the policy fix, and
the script falls back to stderr if the log redirect still fails.

## Removed pieces

- The Keymaster/KM unlock path (`keymaster_device_state`, `KM_UNLOCK_MODE`,
  the QSEE SID handoff) was dropped; it did not work on this device and
  is not needed.
- The custom su client/daemon was removed. Root now comes from the
  KernelSU userspace; `tools/su_env` is only a property/service wrapper
  helper.

## Known limitations

- The KGSL race can lose or fail with `ENOMEM` after previous runs
  (leaked VMAs/GPU memory); a reboot cleanly resets it.
- Changing `sys.usb.config` re-enumerates USB and can drop adb.
- `ro.*` properties stay immutable by design.

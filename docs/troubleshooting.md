# Troubleshooting and tuning

Symptom → cause → what to do. The normal output walkthrough is in
[exploit.md](exploit.md).

## Quick checks

```sh
adb shell getenforce                      # Permissive after the hijack
adb shell 'cat /proc/modules | grep kernelsu'   # kernelsu ... Live
adb shell 'dmesg | grep -iE "oom|lowmemory|kernelsu"'
adb shell 'cat /proc/<pid>/status | grep -E "^(Uid|Gid|Cap)"'
```

Always start a new attempt from a **reboot**. The KGSL pool and the
driver's leaked VMAs are not fully released by a failed run, and a second
run commonly fails with `ENOMEM` or a worse race.

## `[exit] 137` (SIGKILL)

The process was killed — usually the OOM killer/`lmkd` during the full
page scan, not an exploit error. It is more likely when the process runs
at `oom_score_adj=0` (an app) than at `-1000` (a shell).

- The fast scan found nothing, the full 65 540-page scan ran, and the
  memory pressure/spray was still large. Reduce `KGSL_PRESSURE_MB`
  (e.g. 1024–1536 on 8 GB) and/or `KGSL_CHILDREN`.
- To avoid the long scan entirely in a constrained context, set
  `KGSL_SCAN_FULL=1`: in the current code the condition is
  `!getenv("KGSL_SCAN_FULL")`, so **setting it skips the full-scan
  fallback** and the round retries instead (the round then fails fast).
  Unset (default) means the fallback runs.
- `dmesg | grep oom_reaper` confirms which processes were reaped.
- If you are testing through the Android front end (`app` branch), the
  exploit child lives in the app cgroup; the same pressure/spray can be
  fine in a shell and fatal in the app.

## `KGSL returned ENOMEM on every try`

The driver pool is exhausted (leaked VMAs/GPU memory from previous runs).
Reboot. Do not loop more race attempts against an exhausted pool.

## `race not won`

The race window moved or the CPU choice is wrong.

- Try `KGSL_RACE_DELAY_US=<us>` around the measured duration, or more
  `KGSL_RACERS`.
- `KGSL_RACE_CPU` / `KGSL_CPU` must be a CPU that exists on the device;
  the big core is usually CPU 7 on SM8250. The exploit corrects a racer
  pinned to the park CPU.
- Reboot and retry; a device under memory pressure behaves differently.

## Fast scan finds nothing / `task_struct not found`

- The spray did not reclaim the page: raise `KGSL_CHILDREN` (up to the
  pids/`RLIMIT_NPROC` budget) and/or the pressure.
- The app cgroup is usually the limitation (pids/memory), not the kernel.
  Check `RLIMIT_NPROC` (`grep "Max processes" /proc/<pid>/limits`) and
  the cgroup, and prefer a shell context while debugging.
- Confirm the profile matches the booted kernel (see §Profiles in
  [exploit.md](exploit.md)); a wrong `selinux_state`/gadget offset makes
  later stages fail even if the scan succeeds.

## `no accessible child task_struct yielded root IDs`

The credential aliases were found but none verified.

- Enable `KGSL_SCAN_DIAGNOSTICS=1`: the child prints
  `cannot read /proc/<pid>/status: ...` or
  `incomplete /proc/<pid>/status fields mask=...`.
  - `cannot read` from an app (`untrusted_app`) can be a SELinux/proc
    restriction; a shell/`ksu` domain sees its children normally.
  - `incomplete fields` means the status parse did not see
    Uid/Gid/CapPrm/CapEff/CapBnd; check the kernel's `/proc` behaviour.
- The alias scan found false candidates: the selected child's cred page
  offset did not match a real cred. Retry a round, or reboot; the
  race/reclaim determines which aliases appear.
- Verify the profile offsets (cred `0x30`/`0x04`, `task.cred` `0x7e0`,
  `task_stride` `0xec0`) against the image.

## `selinuxfs setenforce: Permission denied`

The proper `setenforce` write was denied; the forged `thread.cpu_context`
hijack is the fallback.

The exploit now waits for the selected child to be parked (`/proc` state
`S`) before arming and auto-restarts up to 3 times if `enforce` is still
`1`; the log shows `[*] child ... not parked` or
`[*] permissive missed; restarting (attempt N)`.  If it never lands,
re-check the profile's `selinux_state`/store gadget and the child state.

- If the hijack also reports `enforce=1`, the store did not land:
  wrong `selinux_state_off`/store gadget for the booted kernel, or the
  KernelSU module is already Live and its `selinux_hide` interferes.
  Reboot, or run with `INJECT_KO=0` to test the permissive path alone.
- `SEC_PERM_TRIGGER=0` is the dry run: it leaks KASLR and prints the
  derived addresses without touching the context. Use it to validate the
  profile.

## `init_module: Operation not permitted` / `EEXIST`

- `EEXIST`/the module already listed in `/proc/modules`: reboot before
  loading again; a second `init_module` of the same module is not useful
  and produces misleading EACCES.
- `EPERM` while the module is not loaded: the domain is still enforcing
  (the permissive step failed) or the module's CRC/vermagic does not match
  (wrong `Module.symvers`/kernel config).
- `INJECT_KO=0` isolates the exploit from the module path.

## `late-load` fails (`execv ... Permission denied`, non-zero exit)

- The module parameter `allow_shell` may be `0`, which blocks the shell's
  `ksud`; `--allow-shell` is passed by the exploit, but the module's
  parameter still applies. Check `INJECT_KO_PARAMS`.
- The userspace may not be installed: the exploit tries
  `/data/adb/ksud`, `/data/adb/ksu/bin/ksud`, then the manager APK's
  `lib/arm64/libksud.so`. Install/launch the manager once.
- `LATE_LOAD=0` disables this step.

## Module builds but does not load

- `kernelsu.ko` must match the device's `module_layout` and exported
  CRCs: build with the device-derived `Module.symvers`
  (`gen_symvers.py` from the split image).
- Vermagic must match: `4.19.157-perf+ SMP preempt mod_unload modversions
  aarch64` for these kernels.
- The build script rejects GOT/PAuth relocations; if it fails, check the
  clang flags (`-march=armv8-a+lse -DCONFIG_AS_LSE=1
  -mbranch-protection=none`) and `CONFIG_KALLSYMS_ALL`.
- The late-load module needs the `kallsyms`-based loader; a plain
  `insmod` of the unrelocated `.ko` fails on the 4.19 loader.

## Manager does not see KernelSU

- The manager and module versions must be compatible (the source is the
  `backslashxx/KernelSU` staging checkout; use a matching manager).
- A late-loaded module has no init-started `ksud`; the exploit runs
  `ksud late-load` so the manager gets a driver fd. If that step was
  skipped (`LATE_LOAD=0`), the manager may show nothing.
- Check `/proc/modules` first, then the manager.

## Watchdog panic after loading

Do not combine the KernelSU late-load with `POLICY_FIX=1`. Two
`security_load_policy()` calls hold the policy write lock long enough to
trip the watchdog. Reboot after a panic; `console-ramoops-0` has the
trace.

## adb drops during a run

Changing `sys.usb.config` (or the policy fix's property work)
re-enumerates USB. Reconnect; the exploit itself does not need adb once
running.

## Profile sanity

- `make list-projects` should list `sog02-58.2.C.3.127`,
  `so-51a-58.2.B.0.520`, `so-52a-58.2.B.0.520`,
  `sog01-58.2.C.5.10`.
- A wrong kernel build/offset shows up as an implausible KASLR slide,
  `cpu_context.pc` mismatch, or a permissive store that does not land.
  Re-derive from the device's own `-kernel` image (see
  [porting.md](porting.md)); do not copy another model's gadget offsets.
- The SO-51A image's layout matches SOG01 (`0x31ae000`/`0x424350`) even
  though it shares source with SO-52A; use the values for the kernel
  actually booted.

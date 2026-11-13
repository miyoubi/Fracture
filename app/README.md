# Fracture

Material 3 loader for the [`CVE-2023-33107`](../README.md) exploit. It runs
`libfracture.so` as an **LD_PRELOAD** library into `/system/bin/sh`
through Shizuku (not as the app uid), so the exploit gets the same shell
context as a CLI run, and streams every line back into the output card.

## Requirements

- Shizuku running and authorized
  ([moe.shizuku.privileged.api](https://github.com/RikkaApps/Shizuku)).
- [backslashxx/KernelSU](https://github.com/backslashxx/KernelSU/) manager if
  the KernelSU toggle is on. Only that manager is supported.
- A bundled payload for the device profile (see below).

## Device / payload

The card shows the model, build, Android version, kernel, and a
**Supported / Unsupported** chip. A device is supported when its
`ro.product.model` + `ro.build.display.id` match a profile and the matching
`kgsl_root_su` asset is bundled:

| profile | model | build |
| --- | --- | --- |
| `sog02-58.2.C.3.127` | SOG02 | 58.2.C.3.127 |
| `so-51a-58.2.B.0.520` | SO-51A | 58.2.B.0.520 |
| `so-52a-58.2.B.0.520` | SO-52A | 58.2.B.0.520 |
| `sog01-58.2.C.5.10` | SOG01 | 58.2.C.5.10 |

The exploit is **unified**: one `libfracture.so` contains all four
profiles and picks the entry from `ro.product.model` + `ro.build.display.id`
at runtime. The Gradle `stageAssets` task copies
`build/unified/libfracture.so` and `kernelsu.ko` into the APK.

```sh
make PROJECT=unified bin   # build/unified/kgsl_root_su (CLI binary)
make PROJECT=unified lib   # build/unified/libfracture.so (preload)
make PROJECT=unified       # both
```

## Controls

- **Run exploit** — stages `libfracture.so` to `/data/local/tmp` and
  preloads it into `/system/bin/sh` via Shizuku.
- **Soft reboot after root** — after a successful run, executes
  `su -c '/data/adb/ksud soft-reboot'` (KernelSU's own soft reboot; needs
  the KernelSU toggle; the exploit is started with `allow_shell=1` so the
  shell's `su` works).
- **KernelSU modules** — load `kernelsu.ko` and run the userspace
  late-load; off = exploit-only temporary root (`INJECT_KO=0`,
  `LATE_LOAD=0`).

## Build

Requires JDK 17+, Gradle, and the Android SDK (platform 35 + build-tools);
see the root README's "Dependencies (Arch Linux)".  The NDK comes from
`../build.sh --setup`.

```sh
gradle --no-daemon assembleDebug
adb install -r app/build/outputs/apk/debug/app-debug.apk
```

Or from the repository root (unified loader + app):

```sh
./build.sh -p unified --app --push
```

# CVE-2023-33107 Xperia root

KGSL UAF temporary-root exploit with a persistent `su` daemon.

| Project | Device | Firmware | Kernel |
| --- | --- | --- | --- |
| `sog02-58.2.C.3.127` | Sony Xperia 5 II (SOG02, KDDI) | `58.2.C.3.127` | `4.19.157-perf+` |

## Manual build / run

```sh
make PROJECT=sog02-58.2.C.3.127 NDK_ROOT="$NDK"
adb push build/sog02-58.2.C.3.127/kgsl_root_su /data/local/tmp/kgsl_root_su
adb shell 'chmod 755 /data/local/tmp/kgsl_root_su; /data/local/tmp/kgsl_root_su'
adb shell '/data/local/tmp/su -c id'
```


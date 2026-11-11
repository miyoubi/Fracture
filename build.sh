#!/usr/bin/env bash
# Build the exploit and the KernelSU LKM for a Sony Xperia profile.
# Pushing to the device is opt-in with --push.
#
#   ./build.sh                        # list the available targets
#   ./build.sh -p sog02-58.2.C.3.127  # build only
#   ./build.sh -p sog02-58.2.C.3.127 --push
#   ./build.sh --detect --push --run  # connected device; push + run
#   ./build.sh -s <serial> --pull     # multiple devices; update KernelSU
#
set -euo pipefail

ROOT=$(cd "$(dirname "$0")" && pwd)
PROJECT=""
SERIAL="${ANDROID_SERIAL:-}"
PUSH=0
RUN=0
PULL=0
CONFIG=""
SYMVERS=""
VMLINUX=""
KERNEL_DIR="$ROOT/kernel_sony_sm8250"
NDK="$ROOT/android-ndk-r26d"
JOBS=""
LIST_ONLY=0
DETECT=0
SETUP=0
FORCE=0

log() { printf '[build] %s\n' "$*"; }
die() { printf '[build] error: %s\n' "$*" >&2; exit 1; }

usage() {
    sed -n '/^# Build the exploit/,/^#   .\/build.sh -s/p' "$0" \
        | sed 's/^# \{0,1\}//'
    cat <<'EOF'

Options:
  -p, --project NAME   profile from `make list-projects` (else use --detect)
  -d, --detect         use the connected device's model/build
  -s, --serial SERIAL  adb serial (or ANDROID_SERIAL)
  -P, --push           push both binaries to /data/local/tmp (off by default)
  -r, --run            push and run the exploit (implies --push)
      --setup          download the NDK and clone the kernel if missing
      --force          with --setup, delete and re-fetch both
      --pull           fetch KernelSU before building
      --config PATH    kernel .config (default: tree copy, else device)
      --symvers PATH   Module.symvers (default: tree copy)
      --vmlinux PATH   regenerate Module.symvers from this vmlinux
      --kernel-dir DIR kernel source (default: kernel_sony_sm8250)
      --ndk DIR        NDK root (default: android-ndk-r26d)
  -j, --jobs N         make jobs for the LKM
  -h, --help           this help

Examples:
  ./build.sh                                    # list targets
  ./build.sh -p sog02-58.2.C.3.127              # build only
  ./build.sh -p unified                         # one loader, all profiles
  ./build.sh -p sog02-58.2.C.3.127 --push       # build + push
  ./build.sh --detect --push --run              # connected device; push + run
  ./build.sh -s QV7246YW54 -p sog02-58.2.C.3.127 --push
  ./build.sh --setup                            # fetch the NDK and kernel
EOF
}

ARG_COUNT=$#
[ "$ARG_COUNT" -eq 0 ] && LIST_ONLY=1

while [ $# -gt 0 ]; do
    case "$1" in
        -p|--project)  [ $# -ge 2 ] || die "$1 needs a value"; PROJECT=$2; shift ;;
        -d|--detect)   DETECT=1 ;;
        -s|--serial)   [ $# -ge 2 ] || die "$1 needs a value"; SERIAL=$2; shift ;;
        -n|--no-push)  PUSH=0 ;;
        -P|--push)     PUSH=1 ;;
        -r|--run)      RUN=1 ;;
        --setup)       SETUP=1 ;;
        --force)       FORCE=1; SETUP=1 ;;
        --pull)        PULL=1 ;;
        --config)      [ $# -ge 2 ] || die "$1 needs a value"; CONFIG=$2; shift ;;
        --symvers)     [ $# -ge 2 ] || die "$1 needs a value"; SYMVERS=$2; shift ;;
        --vmlinux)     [ $# -ge 2 ] || die "$1 needs a value"; VMLINUX=$2; shift ;;
        --kernel-dir)  [ $# -ge 2 ] || die "$1 needs a value"; KERNEL_DIR=$2; shift ;;
        --ndk)         [ $# -ge 2 ] || die "$1 needs a value"; NDK=$2; shift ;;
        -j|--jobs)     [ $# -ge 2 ] || die "$1 needs a value"; JOBS=$2; shift ;;
        -h|--help)     usage; exit 0 ;;
        *) die "unknown option: $1 (try --help)" ;;
    esac
    shift
done

if [ "$RUN" = 1 ]; then
    PUSH=1
fi

adb_cmd() {
    if [ -n "$SERIAL" ]; then adb -s "$SERIAL" "$@"; else adb "$@"; fi
}

device_prop() {
    adb_cmd shell getprop "$1" 2>/dev/null | tr -d '\r'
}

list_targets() {
    local p model kernel devs d m b
    printf 'Available build targets:\n\n'
    printf '  %-26s %-10s %s\n' "project" "model" "kernel"
    while IFS= read -r p; do
        [ -n "$p" ] || continue
        if [ "$p" = unified ]; then
            printf '  %-26s %-10s %s\n' "$p" "ALL" "4.19.157-perf+"
            continue
        fi
        model=$(printf '%s' "${p%%-58*}" | tr '[:lower:]' '[:upper:]')
        kernel=$(grep -m1 'TARGET_KERNEL_RELEASE' \
                "$ROOT/src/targets/$p/target.h" 2>/dev/null | cut -d'"' -f2)
        printf '  %-26s %-10s %s\n' "$p" "${model:-?}" "${kernel:-?}"
    done < <(make -s -C "$ROOT" list-projects)

    if command -v adb >/dev/null 2>&1; then
        devs=$(adb devices 2>/dev/null | awk 'NR > 1 && $2 == "device" { print $1 }')
        if [ -n "$devs" ]; then
            printf '\nConnected devices (not auto-selected; use -p or --detect):\n'
            while IFS= read -r d; do
                [ -n "$d" ] || continue
                m=$(adb -s "$d" shell getprop ro.product.model 2>/dev/null | tr -d '\r')
                b=$(adb -s "$d" shell getprop ro.build.display.id 2>/dev/null | tr -d '\r')
                printf '  %-22s %-10s %s\n' "$d" "${m:-?}" "${b:-?}"
            done <<< "$devs"
        fi
    fi
    printf 'Example: ./build.sh -p sog02-58.2.C.3.127 [--push]\n'
    printf '\nComponents:\n'
    if [ -d "$NDK" ]; then
        printf '  NDK:    present (%s)\n' "$NDK"
    else
        printf '  NDK:    missing (%s) - run ./build.sh --setup\n' "$NDK"
    fi
    if [ -d "$KERNEL_DIR" ]; then
        printf '  kernel: present (%s)\n' "$KERNEL_DIR"
    else
        printf '  kernel: missing (%s) - run ./build.sh --setup\n' "$KERNEL_DIR"
    fi
}

setup_components() {
    local ndk="$ROOT/android-ndk-r26d"
    local kdir="$ROOT/kernel_sony_sm8250"
    local ndk_url="https://dl.google.com/android/repository/android-ndk-r26d-linux.zip"
    local kernel_url="https://github.com/miyoubi/stock-kernel_sony_sm8250"

    if [ -e "$ndk" ] && [ "$FORCE" = 0 ]; then
        log "NDK already present: $ndk"
    else
        if [ "$FORCE" = 1 ] && [ -e "$ndk" ]; then
            log "removing $ndk (--force)"
            rm -rf "$ndk"
        fi
        command -v unzip >/dev/null 2>&1 || die "unzip is required for --setup"
        command -v curl >/dev/null 2>&1 || command -v wget >/dev/null 2>&1             || die "curl or wget is required for --setup"
        local zip="$ROOT/.android-ndk-r26d-linux.zip"
        log "downloading android-ndk-r26d-linux.zip"
        if command -v curl >/dev/null 2>&1; then
            curl -L --fail -o "$zip" "$ndk_url" || die "NDK download failed"
        else
            wget -O "$zip" "$ndk_url" || die "NDK download failed"
        fi
        log "extracting the NDK"
        unzip -q -o "$zip" -d "$ROOT" || die "NDK extraction failed"
        rm -f "$zip"
        [ -d "$ndk" ] || die "NDK archive did not produce $ndk"
    fi

    if [ -e "$kdir" ] && [ "$FORCE" = 0 ]; then
        log "kernel tree already present: $kdir"
    else
        if [ "$FORCE" = 1 ] && [ -e "$kdir" ]; then
            log "removing $kdir (--force)"
            rm -rf "$kdir"
        fi
        command -v git >/dev/null 2>&1 || die "git is required for --setup"
        log "cloning the kernel from GitHub"
        git clone --depth=1 "$kernel_url" "$kdir" || die "kernel clone failed"
        git -C "$kdir" rev-parse --verify HEAD >/dev/null 2>&1             || die "kernel clone is empty; push the repository first"
    fi
}

detect_project() {
    command -v adb >/dev/null || die "adb not found; pass --project"
    local model build list prefix matches exact
    model=$(device_prop ro.product.model)
    build=$(device_prop ro.build.display.id)
    [ -n "$model" ] || die "no device found; pass --project (make list-projects)"
    case "$model|$build" in
        "SOG02|58.2.C.3.127"|"SO-51A|58.2.B.0.520"|"SO-52A|58.2.B.0.520"|"SOG01|58.2.C.5.10")
            printf 'unified'
            return ;;
    esac
    list=$(make -s -C "$ROOT" list-projects)
    prefix=$(printf '%s' "$model" | tr '[:upper:]' '[:lower:]')
    matches=$(printf '%s\n' "$list" | grep -i "^${prefix}-" || true)
    exact=$(printf '%s\n' "$matches" | grep -F -- "-${build}" || true)
    if [ -n "$exact" ] && [ "$(printf '%s\n' "$exact" | sed '/^$/d' | wc -l)" = 1 ]; then
        printf '%s' "$exact"
        return
    fi
    if [ "$(printf '%s\n' "$matches" | sed '/^$/d' | wc -l)" = 1 ]; then
        printf '[build] warning: device build %s does not match; using %s\n' \
            "${build:-?}" "$matches" >&2
        printf '%s' "$matches"
        return
    fi
    die "no profile for $model/${build:-?}; use --project (make list-projects)"
}

if [ "$LIST_ONLY" = 1 ]; then
    list_targets
    exit 0
fi

if [ "$SETUP" = 1 ]; then
    setup_components
fi

[ -d "$ROOT/src" ] || die "run this from the repository root"
if [ -z "$PROJECT" ]; then
    if [ "$DETECT" = 1 ]; then
        PROJECT=$(detect_project)
    elif [ "$SETUP" = 1 ]; then
        log "setup complete"
        list_targets
        exit 0
    else
        die "pass -p <project> (run ./build.sh with no arguments to list targets)"
    fi
fi
if [ "$PROJECT" != unified ] && [ ! -d "$ROOT/src/targets/$PROJECT" ]; then
    die "unknown project $PROJECT (make list-projects)"
fi
[ -d "$KERNEL_DIR" ] \
    || die "missing kernel tree: $KERNEL_DIR; run ./build.sh --setup"
[ -d "$NDK" ] || die "missing NDK: $NDK; run ./build.sh --setup"

log "project: $PROJECT"
[ -n "$SERIAL" ] && log "device:  $SERIAL"

# 1. exploit
make_args=(PROJECT="$PROJECT")
[ -d "$NDK" ] && make_args+=(NDK_ROOT="$NDK")
log "building exploit"
make -C "$ROOT" "${make_args[@]}"
EXPLOIT="$ROOT/build/$PROJECT/kgsl_root_su"
LIB="$ROOT/build/$PROJECT/libfracture.so"
[ -f "$EXPLOIT" ] || die "exploit build produced no $EXPLOIT"

# 2. LKM
if [ -z "$CONFIG" ] && [ ! -f "$KERNEL_DIR/.config" ] && command -v adb >/dev/null; then
    if [ -n "$(device_prop ro.product.model)" ]; then
        log "pulling the device kernel config"
        adb_cmd exec-out sh -c 'zcat /proc/config.gz' \
            > "$KERNEL_DIR/.config" 2>/dev/null || true
        [ -s "$KERNEL_DIR/.config" ] || rm -f "$KERNEL_DIR/.config"
    fi
fi
[ -f "$KERNEL_DIR/.config" ] || die \
    "no $KERNEL_DIR/.config; pass --config or extract it with scripts/extract-ikconfig"
if [ -z "$SYMVERS" ] && [ ! -s "$KERNEL_DIR/Module.symvers" ] && [ -z "$VMLINUX" ]; then
    die "no $KERNEL_DIR/Module.symvers; pass --symvers or generate it with --vmlinux"
fi

lkm_args=()
[ "$PULL" = 1 ] && lkm_args+=(--pull)
[ -n "$CONFIG" ] && lkm_args+=(--config "$CONFIG")
[ -n "$SYMVERS" ] && lkm_args+=(--symvers "$SYMVERS")
[ -n "$VMLINUX" ] && lkm_args+=(--vmlinux "$VMLINUX")
[ -n "$JOBS" ] && lkm_args+=(--jobs "$JOBS")

log "building KernelSU LKM"
PROJECT="$PROJECT" KERNEL_DIR="$KERNEL_DIR" NDK_ROOT="$NDK" \
    OUT="$ROOT/build/$PROJECT" \
    "$ROOT/tools/build_kernelsu_lkm.sh" "${lkm_args[@]}"
KO="$ROOT/build/$PROJECT/kernelsu.ko"
[ -f "$KO" ] || die "LKM build produced no $KO"

# 3. push
if [ "$PUSH" = 0 ]; then
    log "build only: $EXPLOIT"
    [ -f "$LIB" ] && log "build only: $LIB"
    log "build only: $KO"
    log "add --push to install them on the device"
    exit 0
fi

command -v adb >/dev/null || die "adb not found; cannot --push"
log "pushing to /data/local/tmp"
adb_cmd push "$EXPLOIT" /data/local/tmp/kgsl_root_su
adb_cmd push "$KO" /data/local/tmp/kernelsu.ko
[ -f "$LIB" ] && adb_cmd push "$LIB" /data/local/tmp/libfracture.so
adb_cmd shell 'chmod 755 /data/local/tmp/kgsl_root_su /data/local/tmp/kernelsu.ko'
[ -f "$LIB" ] && adb_cmd shell 'chmod 755 /data/local/tmp/libfracture.so'

files=("kgsl_root_su:$EXPLOIT" "kernelsu.ko:$KO")
[ -f "$LIB" ] && files+=("libfracture.so:$LIB")
for pair in "${files[@]}"; do
    name=${pair%%:*}
    path=${pair#*:}
    host_md5=$(md5sum "$path" | cut -d' ' -f1)
    dev_md5=$(adb_cmd shell md5sum "/data/local/tmp/$name" | tr -d '\r' | cut -d' ' -f1)
    [ "$host_md5" = "$dev_md5" ] || die "md5 mismatch for $name"
done
log "pushed and verified: /data/local/tmp/kgsl_root_su, /data/local/tmp/kernelsu.ko"

if [ "$RUN" = 1 ]; then
    log "running the exploit"
    adb_cmd shell '/data/local/tmp/kgsl_root_su'
else
    log "run it with: adb shell /data/local/tmp/kgsl_root_su"
fi

#!/usr/bin/env bash
# Build the exploit and the KernelSU LKM for the connected Sony Xperia,
# then push both to /data/local/tmp.
#
#   ./build.sh                        # auto-detect the device, build, push
#   ./build.sh --run                  # ...and start the exploit
#   ./build.sh -p so-52a-58.2.B.0.520 # cross-build for a specific profile
#   ./build.sh --no-push              # build only
#   ./build.sh -s <serial> --pull     # multiple devices; update KernelSU
#
set -euo pipefail

ROOT=$(cd "$(dirname "$0")" && pwd)
PROJECT=""
SERIAL="${ANDROID_SERIAL:-}"
PUSH=1
RUN=0
PULL=0
CONFIG=""
SYMVERS=""
VMLINUX=""
KERNEL_DIR="$ROOT/kernel_sony_sm8250"
NDK="$ROOT/android-ndk-r26d"
JOBS=""

log() { printf '[build] %s\n' "$*"; }
die() { printf '[build] error: %s\n' "$*" >&2; exit 1; }

usage() {
    sed -n '/^# Build the exploit/,/^#   .\/build.sh -s/p' "$0" \
        | sed 's/^# \{0,1\}//'
    cat <<'EOF'

Options:
  -p, --project NAME   profile from `make list-projects`
  -s, --serial SERIAL  adb serial (or ANDROID_SERIAL)
  -n, --no-push        build only
  -r, --run            run the exploit after pushing
      --pull           fetch KernelSU before building
      --config PATH    kernel .config (default: tree copy, else device)
      --symvers PATH   Module.symvers (default: tree copy)
      --vmlinux PATH   regenerate Module.symvers from this vmlinux
      --kernel-dir DIR kernel source (default: kernel_sony_sm8250)
      --ndk DIR        NDK root (default: android-ndk-r26d)
  -j, --jobs N         make jobs for the LKM
  -h, --help           this help

Examples:
  ./build.sh
  ./build.sh -p so-51a-58.2.B.0.520 --no-push
  ./build.sh -s QV7246YW54 --run
EOF
}

while [ $# -gt 0 ]; do
    case "$1" in
        -p|--project)  [ $# -ge 2 ] || die "$1 needs a value"; PROJECT=$2; shift ;;
        -s|--serial)   [ $# -ge 2 ] || die "$1 needs a value"; SERIAL=$2; shift ;;
        -n|--no-push)  PUSH=0 ;;
        -r|--run)      RUN=1 ;;
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

adb_cmd() {
    if [ -n "$SERIAL" ]; then adb -s "$SERIAL" "$@"; else adb "$@"; fi
}

device_prop() {
    adb_cmd shell getprop "$1" 2>/dev/null | tr -d '\r'
}

detect_project() {
    command -v adb >/dev/null || die "adb not found; pass --project"
    local model build list prefix matches exact
    model=$(device_prop ro.product.model)
    build=$(device_prop ro.build.display.id)
    [ -n "$model" ] || die "no device found; pass --project (make list-projects)"
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

[ -d "$ROOT/src" ] || die "run this from the repository root"
[ -n "$PROJECT" ] || PROJECT=$(detect_project)
[ -d "$ROOT/src/targets/$PROJECT" ] \
    || die "unknown project $PROJECT (make list-projects)"
[ -d "$KERNEL_DIR" ] || die "kernel tree not found: $KERNEL_DIR"

log "project: $PROJECT"
[ -n "$SERIAL" ] && log "device:  $SERIAL"

# 1. exploit
make_args=(PROJECT="$PROJECT")
[ -d "$NDK" ] && make_args+=(NDK_ROOT="$NDK")
log "building exploit"
make -C "$ROOT" "${make_args[@]}"
EXPLOIT="$ROOT/build/$PROJECT/kgsl_root_su"
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
    log "build only: $KO"
    exit 0
fi

command -v adb >/dev/null || die "adb not found (use --no-push to build only)"
log "pushing to /data/local/tmp"
adb_cmd push "$EXPLOIT" /data/local/tmp/kgsl_root_su
adb_cmd push "$KO" /data/local/tmp/kernelsu.ko
adb_cmd shell 'chmod 755 /data/local/tmp/kgsl_root_su /data/local/tmp/kernelsu.ko'

for pair in "kgsl_root_su:$EXPLOIT" "kernelsu.ko:$KO"; do
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

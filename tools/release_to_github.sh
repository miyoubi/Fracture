#!/usr/bin/env bash
# Build and publish a Fracture release to GitHub Releases.
#
# Builds the unified loader/LKM and the release APK (unless --no-build),
# then creates or updates a GitHub release and uploads the artifacts.
#
# Usage:
#   tools/release_to_github.sh v2.0.1
#   tools/release_to_github.sh v2.0.1 --notes-file RELEASE_NOTES.md
#   tools/release_to_github.sh v2.0.1 --title "Fracture v2.0.1" --draft
#   tools/release_to_github.sh v2.0.1 --no-build --prerelease
#
# Auth: set GH_TOKEN or GITHUB_TOKEN with a token that can create releases
#       for this repository (contents: write). Uses curl + the GitHub API.
#
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
REPO_SLUG="${GITHUB_REPOSITORY:-miyoubi/CVE-2023-33107}"
TAG=""
TITLE=""
NOTES_FILE=""
NOTES=""
DRAFT=false
PRERELEASE=false
DO_BUILD=1
TARGET_COMMITISH=""

log() { printf '[release] %s\n' "$*"; }
die() { printf '[release] error: %s\n' "$*" >&2; exit 1; }

usage() {
    sed -n '2,18p' "$0" | sed 's/^# \{0,1\}//'
    cat <<'EOF'

Options:
  <tag>                 Release tag (e.g. v2.0.1); required
  -t, --title TEXT      Release title (default: "Fracture <tag>")
  -n, --notes TEXT      Release notes text
  -F, --notes-file PATH Read release notes from file
      --draft           Create as a draft release
      --prerelease      Mark as a prerelease
      --no-build        Do not build; upload existing artifacts
      --target REF      Target commit/branch for a new tag (default: HEAD)
      --repo OWNER/REPO Override repository (default: miyoubi/CVE-2023-33107)
      --fracture        Shortcut for --repo miyoubi/Fracture
  -h, --help            Show this help

Artifacts uploaded (when present): app/app/build/outputs/apk/release/app-release.apk
EOF
}

while [ $# -gt 0 ]; do
    case "$1" in
        -t|--title)      [ $# -ge 2 ] || die "$1 needs a value"; TITLE=$2; shift ;;
        -n|--notes)      [ $# -ge 2 ] || die "$1 needs a value"; NOTES=$2; shift ;;
        -F|--notes-file) [ $# -ge 2 ] || die "$1 needs a value"; NOTES_FILE=$2; shift ;;
        --draft)         DRAFT=true ;;
        --prerelease)    PRERELEASE=true ;;
        --no-build)      DO_BUILD=0 ;;
        --target)        [ $# -ge 2 ] || die "$1 needs a value"; TARGET_COMMITISH=$2; shift ;;
        --repo)          [ $# -ge 2 ] || die "$1 needs a value"; REPO_SLUG=$2; shift ;;
        --fracture)      REPO_SLUG="miyoubi/Fracture" ;;
        -h|--help)       usage; exit 0 ;;
        -*)              die "unknown option: $1 (try --help)" ;;
        *)               if [ -z "$TAG" ]; then TAG=$1; else die "unexpected argument: $1"; fi ;;
    esac
    shift
done

[ -n "$TAG" ] || { usage >&2; die "release tag is required"; }
[ -z "$TITLE" ] && TITLE="Fracture $TAG"

TOKEN="${GH_TOKEN:-${GITHUB_TOKEN:-}}"
[ -n "$TOKEN" ] || die "set GH_TOKEN or GITHUB_TOKEN (needs repo contents:write) to create releases"

command -v curl >/dev/null 2>&1 || die "curl is required"
command -v python3 >/dev/null 2>&1 || die "python3 is required (for JSON/API handling)"

if [ -n "$NOTES_FILE" ]; then
    [ -f "$NOTES_FILE" ] || die "notes file not found: $NOTES_FILE"
    NOTES=$(cat "$NOTES_FILE")
fi

API="https://api.github.com"
UPLOAD_API="https://uploads.github.com"
AUTH=(-H "Authorization: Bearer $TOKEN" -H "Accept: application/vnd.github+json" -H "X-GitHub-Api-Version: 2022-11-28")

if [ "$DO_BUILD" = 1 ]; then
    log "building unified loader/LKM and release APK"
    (cd "$ROOT" && ./build.sh -p unified --app)
else
    log "skipping build (--no-build)"
fi

ARTIFACTS=(
    "$ROOT/app/app/build/outputs/apk/release/app-release.apk"
)

have_any=0
for f in "${ARTIFACTS[@]}"; do
    [ -f "$f" ] && have_any=1
done
[ "$have_any" = 1 ] || die "no release artifacts found; run a build first or omit --no-build"

http=$(curl -sS -o /tmp/fracture_release.json -w '%{http_code}' \
    "${AUTH[@]}" "$API/repos/$REPO_SLUG/releases/tags/$TAG" || true)

if [ "$http" = "200" ]; then
    log "updating existing release for $TAG"
else
    log "creating release $TAG ($TITLE)"
    payload=$(TAG="$TAG" TITLE="$TITLE" NOTES="$NOTES" DRAFT="$DRAFT" PRERELEASE="$PRERELEASE" TARGET="$TARGET_COMMITISH" python3 - <<'PY'
import json, os
p = {
  "tag_name": os.environ["TAG"],
  "name": os.environ["TITLE"],
  "body": os.environ.get("NOTES",""),
  "draft": os.environ.get("DRAFT","false") == "true",
  "prerelease": os.environ.get("PRERELEASE","false") == "true",
}
t = os.environ.get("TARGET","")
if t:
  p["target_commitish"] = t
print(json.dumps(p))
PY
)
    http=$(curl -sS -o /tmp/fracture_release.json -w '%{http_code}' \
        -X POST "${AUTH[@]}" -H "Content-Type: application/json" \
        -d "$payload" "$API/repos/$REPO_SLUG/releases")
    if [ "$http" != "201" ]; then
        printf '[release] API response (%s):\n' "$http" >&2
        cat /tmp/fracture_release.json >&2
        die "failed to create release (HTTP $http)"
    fi
fi

release_id=$(python3 -c 'import json; print(json.load(open("/tmp/fracture_release.json"))["id"])')

# refresh assets list (for replacement on re-run)
curl -sS "${AUTH[@]}" "$API/repos/$REPO_SLUG/releases/$release_id" -o /tmp/fracture_release.json >/dev/null || true
assets=$(python3 -c 'import json; r=json.load(open("/tmp/fracture_release.json"));
for a in r.get("assets",[]): print(a["id"], a["name"])' 2>/dev/null || true)

for f in "${ARTIFACTS[@]}"; do
    [ -f "$f" ] || { log "skipping missing artifact: $f"; continue; }
    name=$(basename "$f")
    id=$(printf '%s\n' "$assets" | awk -v n="$name" '$2==n{print $1; exit}')
    if [ -n "${id:-}" ]; then
        log "removing existing asset $name (id $id)"
        curl -sS -X DELETE "${AUTH[@]}" "$API/repos/$REPO_SLUG/releases/assets/$id" >/dev/null || true
    fi
    log "uploading $name"
    httpc=$(curl -sS -o /tmp/fracture_asset.json -w '%{http_code}' \
        -X POST "${AUTH[@]}" \
        -H "Content-Type: application/octet-stream" \
        --data-binary @"$f" \
        "$UPLOAD_API/repos/$REPO_SLUG/releases/$release_id/assets?name=$name")
    if [ "$httpc" != "201" ]; then
        printf '[release] upload response (%s) for %s:\n' "$httpc" "$name" >&2
        cat /tmp/fracture_asset.json >&2
        die "failed to upload $name (HTTP $httpc)"
    fi
done

url=$(python3 -c 'import json; print(json.load(open("/tmp/fracture_release.json")).get("html_url",""))' 2>/dev/null || true)
log "release ready: ${url:-$API/repos/$REPO_SLUG/releases/tags/$TAG}"

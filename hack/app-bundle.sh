#!/bin/bash
# Copyright The k3sm Authors.
# SPDX-License-Identifier: Apache-2.0
#
# Publish a signed macOS app from the cluster registry.
set -euo pipefail
umask 077
export LC_ALL=C

manifest_type=application/vnd.oci.image.manifest.v1+json
artifact_type=application/vnd.k3sm.app.bundle.v1
layer_type=application/vnd.k3sm.app.bundle.v1+zip
empty_type=application/vnd.oci.empty.v1+json
empty_digest=sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a
max_zip_bytes=8589934592

die() { echo "app-bundle: $*" >&2; exit 1; }
usage() {
    cat >&2 <<'USAGE'
Usage: app-bundle.sh push App.app apps/name:tag
USAGE
    exit 2
}

parse_ref() {
    local ref=$1 component='[a-z0-9]+([._-][a-z0-9]+)*'
    if [[ $ref == *@* ]]; then
        repo=${ref%@*}
        reference=${ref##*@}
        [[ $reference =~ ^sha256:[0-9a-f]{64}$ ]] || die "invalid manifest digest"
    else
        [[ $ref == *:* ]] || die "include an explicit tag or digest"
        repo=${ref%:*}
        reference=${ref##*:}
        [[ $reference =~ ^[a-zA-Z0-9_][a-zA-Z0-9_.-]{0,127}$ ]] || die "invalid tag"
    fi
    [[ $repo =~ ^apps/$component(/$component)*$ && ${#repo} -le 255 ]] || die "expected an apps/ repository"
}

sha() { /usr/bin/shasum -a 256 < "$1" | awk '{print "sha256:" $1}'; }
size() { /usr/bin/stat -f %z "$1"; }
# Keep lock names and staged archives inside a caller-controlled directory.
trusted_dir() {
    local owner mode
    read -r owner mode < <(/usr/bin/stat -f '%u %Lp' "$1")
    [[ $owner == "$EUID" ]] && (( (8#$mode & 022) == 0 )) ||
        die "use a directory you own with no group or other write permission: $1"
}

stage() {
    trusted_dir "$1"
    tmp=$(mktemp -d "$1/.k3sm-app.XXXXXXXX")
    trap 'rm -rf -- "$tmp"' EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM
}

publish() {
    local app=$1 blobs zip manifest layer_digest manifest_digest
    [[ $app == /* ]] || app="$PWD/$app"
    app=${app%/}
    [[ $app == *.app && -d $app && ! -L $app && -f $app/Contents/Info.plist ]] || die "expected a .app bundle"
    # A build can replace files while publishing. Sign-check the private copy
    # that ditto will archive so a later build cannot invalidate this check.
    local temp_root
    temp_root=$(cd -P -- "${TMPDIR:-$(/usr/bin/getconf DARWIN_USER_TEMP_DIR)}" && /bin/pwd -P)
    stage "$temp_root"
    mkdir "$tmp/source"
    local copy="$tmp/source/${app##*/}"
    /usr/bin/ditto "$app" "$copy"
    /usr/bin/codesign --verify --strict --deep "$copy"
    blobs="$tmp/layout/blobs/sha256"
    mkdir -p "$blobs"
    zip="$tmp/bundle.zip"
    /usr/bin/ditto -c -k --sequesterRsrc --keepParent "$copy" "$zip"
    local bytes
    bytes=$(size "$zip")
    (( bytes > 0 && bytes <= max_zip_bytes )) || die "bundle archive exceeds 8 GiB"
    layer_digest=$(sha "$zip")
    mv "$zip" "$blobs/${layer_digest#sha256:}"
    printf '{}' > "$blobs/${empty_digest#sha256:}"
    manifest="$tmp/manifest.json"
    /usr/bin/jq -cn --arg mt "$manifest_type" --arg at "$artifact_type" \
        --arg ct "$empty_type" --arg cd "$empty_digest" --arg lt "$layer_type" \
        --arg ld "$layer_digest" --argjson size "$bytes" \
        '{schemaVersion:2,mediaType:$mt,artifactType:$at,config:{mediaType:$ct,digest:$cd,size:2},
          layers:[{mediaType:$lt,digest:$ld,size:$size,annotations:{"org.opencontainers.image.title":"bundle.zip"}}]}' > "$manifest"
    manifest_digest=$(sha "$manifest")
    /usr/bin/jq -cn --arg mt "$manifest_type" --arg digest "$manifest_digest" --argjson size "$(size "$manifest")" \
        '{schemaVersion:2,manifests:[{mediaType:$mt,digest:$digest,size:$size}]}' > "$tmp/layout/index.json"
    mv "$manifest" "$blobs/${manifest_digest#sha256:}"
    printf '{"imageLayoutVersion":"1.0.0"}\n' > "$tmp/layout/oci-layout"
    k3sm image push "$tmp/layout" "registry-k3sm:6450/$repo:$reference"
}

main() {
    local verb=${1:-}
    case "$verb" in
        push)
            [[ $# == 3 ]] || usage
            parse_ref "$3"
            [[ $reference != sha256:* ]] || die "push requires a tag"
            publish "$2"
            ;;
        *) usage ;;
    esac
}

if [[ ${BASH_SOURCE[0]} == "$0" ]]; then main "$@"; fi

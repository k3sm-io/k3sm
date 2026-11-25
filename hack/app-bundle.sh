#!/bin/bash
# Copyright The k3sm Authors.
# SPDX-License-Identifier: Apache-2.0
#
# Publish a signed macOS app or fetch its opaque archive from the cluster registry.
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
       app-bundle.sh pull apps/name:tag|apps/name@sha256:... destination.zip
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
# Native pod volume aliases are rebased for the shell. System utilities can
# drop that shim at exec, so pass their already-resolved working directory.
physical_file() { (cd -P -- "$(dirname "$1")" && printf '%s/%s\n' "$(/bin/pwd -P)" "$(basename "$1")"); }
# Keep lock names and staged archives inside a caller-controlled directory.
trusted_dir() {
    local owner mode
    read -r owner mode < <(/usr/bin/stat -f '%u %Lp' "$1")
    [[ $owner == "$EUID" ]] && (( (8#$mode & 022) == 0 )) ||
        die "use a directory you own with no group or other write permission: $1"
}

check_output() {
    [[ $1 == *.zip && ! -L $1 && ( ! -e $1 || -f $1 ) ]] ||
        die "destination must be a regular zip file in an existing directory"
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

# Pods can use service DNS and their mounted CA. Macs discover the serving
# endpoint from Kubernetes, retaining registry-k3sm as the certified TLS name.
connect_registry() {
    local sa=/var/run/secrets/kubernetes.io/serviceaccount port address host=registry-k3sm
    tls=(--noproxy '*' --proto '=https')
    if [[ -n ${KUBERNETES_SERVICE_HOST:-} ]]; then
        if [[ ! -r $sa/ca.crt && -n ${K3SM_ROOTFS:-} ]]; then sa="$K3SM_ROOTFS$sa"; fi
        [[ -r $sa/ca.crt ]] || die "pod has no readable projected cluster CA"
        host="registry-k3sm.k3sm-registry.svc.${K3SM_DNS_DOMAIN:-cluster.local}"
        [[ $host =~ ^[a-z0-9.-]+$ ]] || die "invalid cluster DNS domain"
        port=${REGISTRY_K3SM_SERVICE_PORT:-6450}
        ca=$(physical_file "$sa/ca.crt")
    else
        ca="$tmp/registry-ca.pem"
        k3sm kubectl config view --raw --flatten --minify \
            -o 'jsonpath={.clusters[0].cluster.certificate-authority-data}' | /usr/bin/base64 -D > "$ca"
        [[ -s $ca ]] || die "the kubeconfig must carry the cluster CA"
        local slice="$tmp/endpoint.json"
        k3sm kubectl -n k3sm-registry get endpointslice registry-k3sm -o json > "$slice"
        port=$(/usr/bin/jq -er 'first(.ports[] | select(.name == "registry").port)' "$slice")
        address=$(/usr/bin/jq -er 'first(.endpoints[] | select(.conditions.ready != false) | .addresses[])' "$slice")
        [[ $address =~ ^[0-9A-Fa-f:.]+$ ]] || die "invalid registry endpoint address"
        if [[ $address == *:* ]]; then address="[$address]"; fi
        tls+=(--resolve "registry-k3sm:$port:$address")
    fi
    [[ $port =~ ^[1-9][0-9]{0,4}$ && $port -le 65535 ]] || die "invalid registry port"
    tls+=(--cacert "$ca")
    base="https://$host:$port/v2/$repo"
}

fetch() {
    /usr/bin/curl --disable --silent --show-error --fail "${tls[@]}" --connect-timeout 15 \
        --speed-time 120 --speed-limit 1 --max-filesize "$2" \
        --header "Accept: $manifest_type" --output "$3" "$base/$1"
}

download() {
    local output=$1 manifest actual layer bytes
    stage "$(dirname "$output")"
    connect_registry
    manifest="$tmp/manifest.json"
    fetch "manifests/$reference" 1048576 "$manifest"
    actual=$(sha "$manifest")
    if [[ $reference == sha256:* && $actual != "$reference" ]]; then die "manifest digest mismatch"; fi
    local descriptor
    descriptor=$(/usr/bin/jq -ers --arg mt "$manifest_type" --arg at "$artifact_type" \
        --arg ct "$empty_type" --arg cd "$empty_digest" --arg lt "$layer_type" --argjson limit "$max_zip_bytes" '
        select(length == 1) | .[0] |
        select(.schemaVersion == 2 and .mediaType == $mt and .artifactType == $at and
               .config == {mediaType:$ct,digest:$cd,size:2} and (.layers|type) == "array" and (.layers|length) == 1) |
        .layers[0] | select(.mediaType == $lt and (.digest|type) == "string" and
               (.digest|test("^sha256:[0-9a-f]{64}\\z")) and (.size|type) == "number" and
               .size == (.size|floor) and .size > 0 and .size <= $limit) |
        [.digest, .size] | @tsv' "$manifest") || die "invalid app bundle manifest"
    IFS=$'\t' read -r layer bytes <<< "$descriptor"
    if [[ -f $output && $(size "$output") == "$bytes" && $(sha "$output") == "$layer" ]]; then
        echo "current $repo@$actual"
        return
    fi
    fetch "blobs/$layer" "$bytes" "$tmp/archive.zip"
    [[ $(size "$tmp/archive.zip") == "$bytes" && $(sha "$tmp/archive.zip") == "$layer" ]] || die "archive size or digest mismatch"
    check_output "$output"
    mv -fh "$tmp/archive.zip" "$output"
    echo "downloaded $repo@$actual to $output"
}

main() {
    local verb=${1:-} output
    case "$verb" in
        push)
            [[ $# == 3 ]] || usage
            parse_ref "$3"
            [[ $reference != sha256:* ]] || die "push requires a tag"
            publish "$2"
            ;;
        pull|_pull)
            [[ $# == 3 ]] || usage
            parse_ref "$2"
            output=$3
            output=$(physical_file "$output")
            trusted_dir "$(dirname "$output")"
            check_output "$output"
            [[ ! -L $output.lock && ( ! -e $output.lock || -f $output.lock ) ]] || die "unsafe destination lock file"
            if [[ $verb == _pull ]]; then download "$output"; return; fi
            local script
            script=$(physical_file "$0")
            /usr/bin/lockf -k "$output.lock" /bin/bash "$script" _pull "$2" "$output"
            ;;
        *) usage ;;
    esac
}

if [[ ${BASH_SOURCE[0]} == "$0" ]]; then main "$@"; fi

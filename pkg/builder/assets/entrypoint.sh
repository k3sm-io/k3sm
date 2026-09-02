#!/bin/sh
#
# entrypoint.sh — the whole in-pod payload of the k3sm buildkitd engine.
#
# It runs as guest root inside a k3sm `vm` pod, from the stock upstream
# moby/buildkit image, and brings a buildkitd worker up as a long-lived server
# that `k3sm build` (the full path) drives remotely over a Service:
#
#   self-mount kernel FSes -> ext4-on-loop state -> verified buildx -> config
#   -> buildkitd (unix socket + tcp listener) -> exec (stay foreground)
#
# It is POSIX sh on purpose. The buildkit image is alpine/busybox and carries
# NO bash; a `#!/bin/bash` here fails with "not found" before the first line
# runs, which reads as a broken image rather than a broken script.
#
# Contract with the host driver (pkg/builder):
#   in : the env block the Pod spec carries (asserted below), the cache PVC at
#        $K3SM_BUILDER_CACHE (default /cache), and the buildx pin as env
#        (BUILDX_VERSION / BUILDX_ASSET / BUILDX_SHA256 / BUILDX_URL) rendered
#        from the pkg/builder Go constants so the pin lives in one place.
#   out: a buildkitd whose worker registers on the unix socket (the host polls
#        `buildctl debug workers` through an exec) and whose tcp listener the
#        ClusterIP Service fronts. Readiness is a REGISTERED WORKER, never the
#        socket: buildkitd binds the listener before the OCI worker finishes
#        initialising, so a socket-ready check hands a build a daemon that never
#        answers.
#
# ---------------------------------------------------------------------------
# The platform facts this script exists to satisfy. Each was measured on the
# k3sm vm path, and each produces a misleading error when violated:
#
#  1. NO /proc AND NO /sys/fs/cgroup in the container chroot by default. The
#     kernel filesystems are guest-root-only and are not pre-mounted into the
#     pod's rootfs. buildkitd's OCI worker and runc both need them. We are guest
#     root, so we mount them ourselves — TOLERANT of a runtimed that already
#     provides them (the per-container prereq change landing in parallel).
#  2. The writable rootfs upper is RAM-BACKED and HARD-CAPPED. A layer store
#     blows through it in minutes, so buildkit's --root, $TMPDIR and the buildx
#     state dir all live on the cache PVC — but NOT as bare virtiofs paths:
#     virtiofs cannot host an overlayfs upperdir and pins file ownership to one
#     host identity. The fix is a sparse ext4 IMAGE on the PVC, loop-mounted
#     guest-side — a real Linux filesystem whose backing bytes persist on the
#     claim across pods.
#  3. NO securityContext anywhere in the pod. k3sm admission rejects a foreign
#     runAsUser, and the image's own default root IS guest root with full caps.
#     The VM is the isolation boundary, so buildkitd runs privileged-root and
#     `noProcessSandbox` stays FALSE (it is legal only for a ROOTLESS daemon and
#     makes the daemon refuse to start otherwise).
#  4. Readiness is a REGISTERED WORKER, not a socket (see the contract above).
# ---------------------------------------------------------------------------

set -eu
# busybox ash has had `pipefail` for years, but a hard `set -o pipefail` on a
# shell without it aborts the script at line one, so probe first.
# shellcheck disable=SC3040
(set -o pipefail) 2>/dev/null && set -o pipefail || true

fatal() { echo "BUILDER: FATAL: $*" >&2; exit 1; }
say()   { echo "BUILDER: $*"; }

# ---- 0. the env contract ---------------------------------------------------
#
# Refused rather than defaulted, and refused HERE rather than at buildkitd
# start: an unset pin would fetch an unverified binary, and an unset tcp port
# would bind nothing for the Service to front.
: "${BUILDX_VERSION:?required — the pinned buildx release tag, from pkg/builder}"
: "${BUILDX_ASSET:?required — the pinned buildx asset name, from pkg/builder}"
: "${BUILDX_SHA256:?required — the pinned buildx sha256, from pkg/builder}"
: "${BUILDX_URL:?required — the pinned buildx download URL, from pkg/builder}"
: "${K3SM_BUILDER_TCP_PORT:?required — the tcp port the ClusterIP Service fronts}"

CACHE_DIR="${K3SM_BUILDER_CACHE:-/cache}"
EXT4_SIZE="${K3SM_BUILDER_EXT4_SIZE:-40G}"
GUEST_STATE="${K3SM_BUILDER_STATE:-/var/lib/k3sm-builder}"
SOCK_ADDR="unix:///run/buildkit/buildkitd.sock"
TCP_ADDR="tcp://0.0.0.0:${K3SM_BUILDER_TCP_PORT}"

say "=== k3sm buildkitd engine: buildx ${BUILDX_VERSION}, tcp :${K3SM_BUILDER_TCP_PORT} ==="

# ---- 1. kernel filesystems (fact 1) ----------------------------------------
#
# Tolerant of already-mounted throughout: a retry pod, or a runtimed that
# pre-mounts these per container, must not fail here. /proc goes first because
# every subsequent mountpoint test reads /proc/mounts.
mkdir -p /proc /sys /run/buildkit
mount -t proc proc /proc 2>/dev/null || true
[ -r /proc/mounts ] || fatal "/proc is not mounted and could not be mounted — buildkitd's OCI worker cannot run without it"

is_mounted() { grep -q "[[:space:]]$1[[:space:]]" /proc/mounts 2>/dev/null; }

if ! is_mounted /sys; then
    mount -t sysfs sysfs /sys 2>/dev/null || say "note: sysfs not mounted at /sys (continuing — cgroup2 below is what runc needs)"
fi
if ! is_mounted /sys/fs/cgroup; then
    mkdir -p /sys/fs/cgroup
    mount -t cgroup2 none /sys/fs/cgroup 2>/dev/null \
        || fatal "could not mount cgroup2 at /sys/fs/cgroup — runc cannot create a build container without it"
fi
say "kernel filesystems: /proc $(is_mounted /proc && echo ok || echo MISSING), /sys/fs/cgroup $(is_mounted /sys/fs/cgroup && echo ok || echo MISSING)"

# ---- 2. buildkit state on ext4-over-loop (fact 2) --------------------------
EXT4_IMG="$CACHE_DIR/buildkit.ext4"
[ -d "$CACHE_DIR" ] || fatal "no cache at $CACHE_DIR — the builder-cache claim is not mounted"

if ! command -v mkfs.ext4 >/dev/null 2>&1; then
    say "installing e2fsprogs for the loopback image"
    apk add --no-cache e2fsprogs >/dev/null 2>&1 || fatal "mkfs.ext4 unavailable and apk add e2fsprogs failed — no fetcher or no egress"
fi
if [ ! -f "$EXT4_IMG" ]; then
    say "creating sparse ext4 image $EXT4_IMG ($EXT4_SIZE)"
    truncate -s "$EXT4_SIZE" "$EXT4_IMG" || fatal "could not create the sparse image on the cache claim"
    mkfs.ext4 -F -q "$EXT4_IMG" || fatal "mkfs.ext4 failed on the loopback image"
fi
mkdir -p "$GUEST_STATE"
if ! is_mounted "$GUEST_STATE"; then
    # The container's /dev is a deliberate minimal allowlist with no loop
    # devices, so `mount -o loop` cannot set one up. We are guest root in our
    # own micro-VM, so we mount a fresh devtmpfs to reach the kernel's loop
    # devices directly — tolerant of one already provided by runtimed.
    DEVHOST=/run-builder-dev
    mkdir -p "$DEVHOST"
    is_mounted "$DEVHOST" || mount -t devtmpfs dev "$DEVHOST" 2>/dev/null || true
    [ -e "$DEVHOST/loop-control" ] || [ -e /dev/loop-control ] || fatal "kernel exposes no loop-control (BLK_DEV_LOOP?)"
    [ -e "$DEVHOST/loop-control" ] || DEVHOST=/dev
    LOOPDEV=""
    for n in 0 1 2 3 4 5 6 7; do
        if losetup "$DEVHOST/loop$n" "$EXT4_IMG" 2>/dev/null; then
            LOOPDEV="$DEVHOST/loop$n"; break
        fi
        if losetup "$DEVHOST/loop$n" 2>/dev/null | grep -q "buildkit.ext4"; then
            LOOPDEV="$DEVHOST/loop$n"; break
        fi
    done
    [ -n "$LOOPDEV" ] || fatal "no free loop device for the buildkit image"
    mount -t ext4 "$LOOPDEV" "$GUEST_STATE" || fatal "ext4 mount of $LOOPDEV ($EXT4_IMG) at $GUEST_STATE failed"
fi
say "buildkit state on ext4-over-loop at $GUEST_STATE (backing file on the cache claim)"

BUILDKIT_ROOT="$GUEST_STATE/buildkit"
export TMPDIR="$GUEST_STATE/tmp"
export BUILDX_CONFIG="$CACHE_DIR/buildx"
BIN_DIR="$CACHE_DIR/bin"
WORK_DIR="$CACHE_DIR/work"
mkdir -p "$BUILDKIT_ROOT" "$TMPDIR" "$BUILDX_CONFIG" "$BIN_DIR" "$WORK_DIR"

# ---- 3. buildx: fetch once, verify EVERY time (the pin lives in Go) ---------
#
# The buildkit image carries buildkitd and buildctl and NOTHING ELSE — buildx
# is a separate release. `k3sm build` (full path) drives it against this
# daemon; staging a verified copy here keeps one proven copy in the cluster
# until the release-time source-built buildx leg lands (see pkg/builder).
#
# buildx itself must match the GUEST arch, which is a DIFFERENT axis from the
# --platform an image targets: a foreign-arch buildx would not execute.
case "$(uname -m)" in
    aarch64|arm64) : ;;
    *) fatal "guest arch is $(uname -m) but the pinned buildx asset is $BUILDX_ASSET — pin the matching asset AND its sha256 together in pkg/builder" ;;
esac

BUILDX_BIN="$BIN_DIR/buildx"
buildx_verified() {
    [ -x "$BUILDX_BIN" ] || return 1
    echo "$BUILDX_SHA256  $BUILDX_BIN" | sha256sum -c - >/dev/null 2>&1
}
fetch_to() {
    if command -v curl >/dev/null 2>&1; then curl -fsSL --retry 3 -o "$2" "$1" && return 0; fi
    if command -v wget >/dev/null 2>&1; then wget -q -O "$2" "$1" && return 0; fi
    if command -v apk >/dev/null 2>&1; then
        apk add --no-cache curl >/dev/null 2>&1 || true
        command -v curl >/dev/null 2>&1 && curl -fsSL --retry 3 -o "$2" "$1" && return 0
    fi
    return 1
}
if buildx_verified; then
    say "buildx $BUILDX_VERSION already cached and verified: $BUILDX_BIN"
else
    say "fetching buildx $BUILDX_VERSION -> $BUILDX_BIN"
    rm -f "$BUILDX_BIN.tmp"
    fetch_to "$BUILDX_URL" "$BUILDX_BIN.tmp" \
        || fatal "could not download $BUILDX_URL (no working curl/wget in the image, or no egress from the guest)"
    echo "$BUILDX_SHA256  $BUILDX_BIN.tmp" | sha256sum -c - >/dev/null 2>&1 \
        || { rm -f "$BUILDX_BIN.tmp"; fatal "sha256 mismatch on $BUILDX_ASSET — refusing to stage an unverified builder binary"; }
    chmod 0755 "$BUILDX_BIN.tmp"
    mv "$BUILDX_BIN.tmp" "$BUILDX_BIN"
    buildx_verified || fatal "buildx failed verification immediately after install"
    say "buildx installed and verified"
fi

# ---- 4. the buildkitd config -----------------------------------------------
#
# Written here (not mounted) so the pod object set stays PVC+Pod+Service. The
# native/overlay choice, gc policy and noProcessSandbox=false are the measured
# facts from the vm path — see the header.
BUILDKITD_TOML="$WORK_DIR/buildkitd.toml"
cat > "$BUILDKITD_TOML" <<EOF
[worker.oci]
  enabled = true
  # overlayfs works because the state root is a loop-mounted ext4 image (fact 2)
  # rather than bare virtiofs.
  snapshotter = "overlayfs"
  gc = true
  # noProcessSandbox stays FALSE: it is legal ONLY for a rootless daemon, and
  # this daemon runs as guest root inside the vm (the VM is the boundary).
  noProcessSandbox = false
  [[worker.oci.gcpolicy]]
    all = true
    keepBytes = ${K3SM_BUILDER_GC_KEEP_BYTES:-20000000000}
EOF
say "wrote $BUILDKITD_TOML"

# ---- 5. buildkitd (foreground) ---------------------------------------------
#
# TWO listeners: the unix socket the host polls for readiness through an exec,
# and the tcp listener the ClusterIP Service fronts so buildx on the Mac can
# reach it with `--driver remote tcp://<clusterIP>:<port>`. --root on the ext4
# state is load-bearing: the default store on a container overlay cannot nest a
# snapshotter, and the worker then never initialises.
#
# exec so buildkitd is PID-visible as the container's main process: a long-lived
# server, restarted by the pod lifecycle, never a background job the shell
# outlives.
say "=== buildkitd (root=$BUILDKIT_ROOT, addrs=$SOCK_ADDR + $TCP_ADDR) ==="
exec buildkitd \
    --root "$BUILDKIT_ROOT" \
    --config "$BUILDKITD_TOML" \
    --addr "$SOCK_ADDR" \
    --addr "$TCP_ADDR"

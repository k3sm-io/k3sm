#!/usr/bin/env bash
# M11.0-d4 / S4 — the guest kernel artifact. Feeds B111; publishes nothing itself.
#
# S4 answers "what config does the shipping kernel need, how big is it, and can
# it be built reproducibly" — it does NOT produce the artifact. B111 is the
# human-gated producer, because the digest a human pins IS the guest TCB trust
# root, and a spike must not be able to mint one.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
. "$HERE/lib.sh"

note "S4 — the required config, as a checklist the build must satisfy"
cat <<'EOF'
  Against a >=6.12 LTS tree. EVERYTHING BUILT IN, not modules: the initramfs
  carries no module tree, so a =m here is a boot failure that looks like a
  missing device.

    CONFIG_VIRTIO_FS=y            the share transport
    CONFIG_FUSE_FS=y              virtiofs rides FUSE
    CONFIG_OVERLAY_FS=y           per-container writable layer
      + metacopy support          (the ownership-sidecar path depends on it)
    CONFIG_VSOCKETS=y             \
    CONFIG_VIRTIO_VSOCKETS=y      / the GuestAgent transport
    CONFIG_VIRTIO_NET=y           NAT networking
    CONFIG_VIRTIO_CONSOLE=y       the console k3sm caps into console.log
    CONFIG_HW_RANDOM_VIRTIO=y     entropy; without it early userspace can stall
    CONFIG_BINFMT_MISC=y          the Rosetta registration point (v0.2.x, but
                                  omitting it now would force a kernel rebuild
                                  to add amd64 later)
    CONFIG_TMPFS_XATTR=y          \
    CONFIG_TMPFS_POSIX_ACL=y      / the tmpfs upper must carry xattrs
    CONFIG_MEMCG=y, CONFIG_CGROUPS=y   per-container accounting
    idmapped-mount support        the S3(2) gate's kernel half
    CONFIG_EXT4_FS=y              only if S3(1) un-parks virtio-blk; record the
                                  decision rather than defaulting it in

  FORMAT: an UNCOMPRESSED arm64 `Image`. VZLinuxBootLoader rejects a gzipped
  kernel — S1 criterion 2b records that rejection, so this is a fact, not a
  guess. A build that emits `Image.gz` has not produced a usable artifact.

  RECORD: the size figure. It is the decision input for B111's
  bundle-vs-install-ensure question (R23) — a kernel small enough to bundle
  changes the install story, and that decision is a human's.

  BUILD: a containerized, reproducible dry-run. Record the toolchain, the config
  hash, and whether two runs produce identical bytes. Non-reproducible here means
  the pinned digest B111 publishes cannot be independently re-derived, which
  defeats the point of pinning it.
EOF

note "S4 — record in findings-s4.md. B111 consumes this; S4 publishes nothing."

#!/usr/bin/env bash
# M11.0-d3 / S3 — virtiofs semantics and performance. ONE HARD GATE, four recordings.
#
# S3(2) is a GATE, the rest are measurements. That split matters: only (2) can
# stop work, and conflating them would let a slow pgbench number read as a
# blocker when it is a documented ceiling.
#
#   2 does Apple's virtiofs advertise FUSE IDMAPPED-MOUNT support?   — HARD GATE
#     kernel >=6.12 is necessary but NOT sufficient; the host-side server opt-in
#     is the unknown. It is a named B112 merge-precondition and it governs the
#     m11-core fsGroup leg. NO => the fsGroup design is re-planned under human
#     review; the chmod fallback is deliberately NOT pre-encoded, because a
#     silent chmod would change ownership semantics the guest cannot undo.
#     Pre-decided consequence (the M11 plan's R28 / the plan's risk 2): on NO, the CORE
#     storage leg substitutes a root-in-guest image and PVC-PGDATA-with-fsGroup
#     moves to the follow-on. Nothing is improvised in the sitting.
#
#   1 guest fsync -> host fsync(2) or F_FULLFSYNC on APFS, and pgbench on a
#     virtiofs-backed PGDATA against the 0.25x-native bar. BELOW the bar the
#     parked virtio-blk escape hatch un-parks as an OPT-IN k3sm-block
#     StorageClass (R24c) — never as a replacement for the host-visible default,
#     because PV host-visibility is a product requirement (R24a), not an
#     implementation accident. ABOVE the bar the hatch is DELETED.
#   3 ownership-sidecar apply cost on a real image (thousands of non-root-owned
#     files -> N metadata copy-ups into the tmpfs upper): latency and RAM.
#   4 emptyDir sequential/random IO over the RW share.
#   5 APFS case-collision through virtiofs vs the extractor's own detection.
#   6 confined-vs-unconfined vmhost throughput (Resolution 7's data).
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
. "$HERE/lib.sh"

note "S3 — preflight: S1 must have reported GO"
grep -qiE '^\*\*Verdict:\*\* *_?\(?GO' "$HERE/findings-s1.md" 2>/dev/null || {
  echo "  findings-s1.md records no GO — S3 extends S1's harness and is moot without it."; exit 1; }

note "S3(2) — the idmapped-mount gate"
cat <<'EOF'
  In the guest, against a virtiofs share:

    mount_setattr(AT_FDCWD, "/mnt/share", 0,
                  &(struct mount_attr){ .attr_set = MOUNT_ATTR_IDMAP,
                                        .userns_fd = <fd> }, sizeof ...)

  Record: the kernel version, whether the syscall SUCCEEDS on a virtiofs mount,
  and the exact errno if not. A generic "unsupported" is not a finding — EINVAL
  and EOPNOTSUPP point at different causes (the mount vs the filesystem type),
  and the re-plan depends on which.

  YES => B112 unblocks (merge still gated on the R21 triple and the
         security-engineer-authored CEL).
  NO  => human-reviewed fsGroup re-plan. Do NOT adopt a chmod fallback here;
         it is banned as a dual path, and adopting one in a lab session is
         exactly the silent divergence the M11 plan's Resolution 1 forbids.
EOF

note "S3(1) — the pgbench bar, stated before it is measured"
cat <<'EOF'
  Measure pgbench TPS on a virtiofs-backed PGDATA, and the SAME workload on the
  native path's APFS. The bar is a RATIO, fixed in advance so the result cannot
  be rationalised after the fact:

    virtiofs TPS < 0.25 x native  => un-park virtio-blk as an OPT-IN
                                     k3sm-block StorageClass (R24c)
    virtiofs TPS >= 0.25 x native => DELETE the escape hatch; virtiofs-PGDATA
                                     becomes a documented ceiling

  Also record whether guest fsync maps to host fsync(2) or F_FULLFSYNC: on APFS
  those differ by roughly an order of magnitude, and a PGDATA whose fsync is not
  durable is a correctness claim, not a performance one.
EOF

note "S3 — record all six in findings-s3.md; only (2) can stop work"

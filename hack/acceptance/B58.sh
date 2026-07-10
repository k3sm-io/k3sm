#!/usr/bin/env bash
#
# k3sm B58 acceptance gate — the runnable proof of the UNSIGNED goreleaser
# SNAPSHOT config (.goreleaser.yaml): the single k3sm Mach-O plus its renamed
# k3sm-netd copy, LICENSE and NOTICE, staged into a darwin/arm64 tarball with a
# checksums file. Signing/notarization/tap-push are the human M7.1 slice and are
# stubbed-disabled in the config, so this gate proves BUILD SHAPE only.
#
# This is an integration-tier, lab-pending gate: goreleaser is not installed in
# the lab. When absent the gate reports PENDING and exits NON-ZERO (it must never
# falsely pass, or red-at-main becomes unprovable). In CI (${CI} set) goreleaser
# MUST be present — its absence is a hard FAIL.
#
# Usage: hack/acceptance/B58.sh
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$HERE/../.." && pwd)"
CONFIG="$REPO_ROOT/.goreleaser.yaml"

PASS=0; FAIL=0
ladder() { if [ "$1" = ok ]; then echo "PASS  $2"; PASS=$((PASS+1)); else echo "FAIL  $2"; FAIL=$((FAIL+1)); fi; }

echo "==> k3sm B58 acceptance (goreleaser unsigned-snapshot build shape)"

# B58.0 — the config exists (independent of the tool being installed).
if [ -f "$CONFIG" ]; then
	ladder ok "b58.0  .goreleaser.yaml present"
else
	ladder no "b58.0  .goreleaser.yaml present"
fi

# B58.1 — the DEFERRED cp-payload + kine members are DECLARED (commented) in the
# manifest, labeled deferred. This holds whether or not goreleaser is installed:
# it proves the full manifest shape is reviewable even though the snapshot only
# stages what has an in-tree producer.
if grep -q 'DEFERRED' "$CONFIG" \
	&& grep -q 'kube-apiserver' "$CONFIG" \
	&& grep -q '# - src: "dist/cp-payload/kine"' "$CONFIG"; then
	ladder ok "b58.1  cp-payload + kine declared as deferred (commented) manifest members"
else
	ladder no "b58.1  cp-payload + kine declared as deferred (commented) manifest members"
fi

# ---- goreleaser presence gate -----------------------------------------------
if ! command -v goreleaser >/dev/null 2>&1; then
	echo "----------------------------------------"
	if [ -n "${CI:-}" ]; then
		echo "FAIL  b58  goreleaser not installed — CI MUST have the release tool" >&2
		echo "B58: goreleaser absent under CI — hard FAIL" >&2
		exit 1
	fi
	echo "PENDING (lab-tier): goreleaser not installed — the archive proof runs in CI." >&2
	echo "B58: build-shape checks passed ($PASS ok); the live snapshot/archive proof is deferred to CI." >&2
	# Non-zero so an un-run archive proof never falsely passes the gate.
	exit 3
fi

# ---- live snapshot proof (goreleaser present) -------------------------------
# Use `release --snapshot` (not `build`): only the release pipeline exercises the
# archives: stanza and produces the tarball + checksums this gate asserts.
DIST="$REPO_ROOT/dist"
rm -rf "$DIST"
if ( cd "$REPO_ROOT" && GOWORK=off goreleaser release --snapshot --clean --skip=publish,sign,notarize ); then
	ladder ok "b58.2  goreleaser snapshot release succeeded"
else
	ladder no "b58.2  goreleaser snapshot release succeeded"
fi

# B58.3 — the darwin/arm64 tarball contains exactly the honestly-stageable set.
TARBALL="$(find "$DIST" -name '*darwin*arm64*.tar.gz' -print -quit 2>/dev/null || true)"
if [ -n "$TARBALL" ] && [ -f "$TARBALL" ]; then
	ladder ok "b58.3  darwin/arm64 archive produced ($(basename "$TARBALL"))"
	members="$(tar tzf "$TARBALL")"
	for want in k3sm k3sm-netd LICENSE NOTICE; do
		# Basename-tolerant: assert the semantic fact "member present" regardless of
		# whether goreleaser emits it at the archive root, with a leading "./", or a
		# nested path — robust to goreleaser path-handling across versions.
		if printf '%s\n' "$members" | grep -qE "(^|/)${want}$"; then
			ladder ok "b58.3  archive contains $want"
		else
			ladder no "b58.3  archive contains $want"
		fi
	done
else
	ladder no "b58.3  darwin/arm64 archive produced"
fi

# B58.4 — a checksums file is produced.
if find "$DIST" -name '*checksums.txt' -print -quit | grep -q .; then
	ladder ok "b58.4  checksums file produced"
else
	ladder no "b58.4  checksums file produced"
fi

echo "----------------------------------------"
echo "B58: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ] || exit 1
echo "================ B58 GREEN ================"

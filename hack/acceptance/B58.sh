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

# B58.1 — the supporting artifacts are LIVE manifest members (they were commented
# "DEFERRED" while no in-tree producer existed; hack/release/stage.sh is that
# producer now). The payload members must carry BOTH dst: cp-payload and
# strip_parent — with either missing, the members land at the wrong path and
# `k3sm install` fail-fasts on a user's Mac while every build check stays green.
#
# The archive's member set as a whole is asserted against
# `k3sm install --print-required-artifacts` by the release gate; this row only
# pins the two encodings that are easy to mis-fix.
if grep -q 'build/stage/k3sm-execshim' "$CONFIG" \
	&& grep -q 'build/stage/cp-payload/\*' "$CONFIG" \
	&& grep -q 'dst: cp-payload' "$CONFIG"; then
	ladder ok "b58.1  supporting artifacts + cp-payload are live manifest members (dst + strip_parent)"
else
	ladder no "b58.1  supporting artifacts + cp-payload are live manifest members (dst + strip_parent)"
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

# The archive now references the supporting artifacts hack/release/stage.sh
# produces. This gate proves the manifest SHAPE, not the artifacts' contents, so
# it stages STUBS: nothing here needs a real Mach-O or a ~250 MB control-plane
# download, and keeping the network out is what lets this run anywhere. The
# release pipeline stages the real thing and verifies digests.
STAGE="$REPO_ROOT/build/stage"
rm -rf "$REPO_ROOT/build"
mkdir -p "$STAGE/cp-payload"
printf 'stub\n' >"$STAGE/k3sm-execshim"
printf 'stub\n' >"$STAGE/libk3sm_pathrebase_shim.dylib"
printf 'stub\n' >"$STAGE/libk3sm_getaddrinfo_shim.dylib"
# Derived, not re-typed: the payload set comes from the binary's own contract.
for b in $(cd "$REPO_ROOT" && GOWORK=off go run ./cmd/k3sm install --print-required-artifacts 2>/dev/null | sed -n 's|^cp-payload/||p'); do
	printf 'stub\n' >"$STAGE/cp-payload/$b"
done
trap 'rm -rf "$REPO_ROOT/build"' EXIT

if ( cd "$REPO_ROOT" && GOWORK=off goreleaser release --snapshot --clean --skip=publish,sign,notarize ); then
	ladder ok "b58.2  goreleaser snapshot release succeeded"
else
	ladder no "b58.2  goreleaser snapshot release succeeded"
fi

# B58.3 — the archive carries every artifact `k3sm install` resolves beside the
# binary, at the path it resolves it. The expected set is DERIVED from
# pkg/install.RequiredSiblings via the binary's own flag, so adding an artifact
# there reddens this gate until a manifest member appears for it.
TARBALL="$(find "$DIST" -name '*darwin*arm64*.tar.gz' -print -quit 2>/dev/null || true)"
if [ -n "$TARBALL" ] && [ -f "$TARBALL" ]; then
	ladder ok "b58.3  darwin/arm64 archive produced ($(basename "$TARBALL"))"
	members="$(tar tzf "$TARBALL")"
	required="$(cd "$REPO_ROOT" && GOWORK=off go run ./cmd/k3sm install --print-required-artifacts 2>/dev/null)"
	if [ -z "$required" ]; then
		ladder no "b58.3  could not derive the required-artifact set (k3sm install --print-required-artifacts)"
	fi
	# k3sm/k3sm-netd/LICENSE/NOTICE are the manifest's own members; the rest are
	# derived. cp-payload members are asserted with their DIRECTORY prefix, since
	# landing them at the archive root is the exact mis-encoding that breaks install.
	for want in k3sm k3sm-netd LICENSE NOTICE; do
		if printf '%s\n' "$members" | grep -qE "(^|/)${want}$"; then
			ladder ok "b58.3  archive contains $want"
		else
			ladder no "b58.3  archive contains $want"
		fi
	done
	for want in $required; do
		case "$want" in
		cp-payload/*) pat="(^|/)$(printf '%s' "$want" | sed 's|/|/|g')$" ;;
		*) pat="(^|/)${want}$" ;;
		esac
		if printf '%s\n' "$members" | grep -qE "$pat"; then
			ladder ok "b58.3  archive contains $want"
		else
			ladder no "b58.3  archive contains $want (required by pkg/install.RequiredSiblings)"
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

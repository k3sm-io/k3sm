#!/usr/bin/env bash
#
# k3sm B391 acceptance gate — the buildx re-pin procedure checks the darwin
# signer MECHANICALLY, not as reviewer prose.
#
# hack/verify-buildx-signer.sh downloads the pinned darwin buildx asset, asserts
# its sha256 equals builder.HostBuildxSHA256, and asserts codesign reports a
# strictly valid signature whose TeamIdentifier equals builder.HostBuildxTeamID.
# This gate proves the signer half without the network:
#
#   b391.1  the decision-core table tests pass (recorded codesign output shapes:
#           pinned Developer ID passes; unsigned, ad-hoc, missing TeamIdentifier
#           line, the retired signer and any other team each fail distinctly).
#
#   b391.2  LIVE fixture: a Mach-O this gate compiles, with its signature
#           removed, is rejected by the real CLI with the "unsigned" exit (3).
#
#   b391.3  LIVE fixture: the same Mach-O after `codesign -s -` is rejected with
#           the "ad-hoc" exit (5).
#
# Verdicts are asserted by EXIT CODE, never by output text. The download path is
# not exercised here (no network); the CLI's --file mode reaches the same
# codesign-inspection stage and decision core the download path feeds.
#
# RED BEFORE: on main there is no hack/buildx/verifysigner and no
# hack/verify-buildx-signer.sh, so b391.0 fails.
#
# Usage:  hack/acceptance/B391.sh
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
K3SM_ROOT="$(cd "$HERE/../.." && pwd)"
SELF="$HERE/B391.sh"
WRAPPER="$K3SM_ROOT/hack/verify-buildx-signer.sh"
PKG="./hack/buildx/verifysigner"

PASS=0; FAIL=0
ladder() { if [ "$1" = ok ]; then echo "PASS  $2"; PASS=$((PASS+1)); else echo "FAIL  $2"; FAIL=$((FAIL+1)); fi; }
GOENV=(env GOARCH=arm64 CGO_ENABLED=1)

echo "==> k3sm B391 acceptance (re-pin-time buildx signer check)"

# ---- b391.0 — the gate parses and its pieces exist --------------------------
b0=ok
bash -n "$SELF" || b0=no
[ -x "$WRAPPER" ] && bash -n "$WRAPPER" || b0=no
[ -f "$K3SM_ROOT/hack/buildx/verifysigner/signer.go" ] || b0=no
[ -f "$K3SM_ROOT/hack/buildx/verifysigner/main.go" ] || b0=no
command -v codesign >/dev/null 2>&1 || b0=no
ladder "$b0" "b391.0  gate + wrapper parse; checker package and codesign present"
if [ "$b0" != ok ]; then
	echo "B391: $PASS passed, $FAIL failed" >&2
	exit 1
fi

WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT

# ---- b391.1 — decision-core table tests ------------------------------------
b1=ok
out="$(cd "$K3SM_ROOT" && "${GOENV[@]}" go test -count=1 -v -run '^(TestDecide|TestExitCodesDistinct|TestPinnedTeamIDShape)$' "$PKG" 2>&1)" || b1=no
if [ "$b1" = ok ] && printf '%s\n' "$out" | grep -qE 'no tests to run|no test files'; then b1=no; fi
ran="$(printf '%s\n' "$out" | grep -cE '^--- PASS: Test' || true)"
[ "$ran" -eq 3 ] || b1=no
[ "$b1" = ok ] || printf '%s\n' "$out" | tail -40
ladder "$b1" "b391.1  decision-core tests pass ($ran/3 top-level tests)"

# ---- fixture: a trivial Mach-O built here, never fetched --------------------
FIX="$WORKDIR/fixture"
mkdir -p "$FIX/src"
printf 'module fixture\n\ngo 1.26\n' > "$FIX/src/go.mod"
printf 'package main\n\nfunc main() {}\n' > "$FIX/src/main.go"
fix_ok=ok
(cd "$FIX/src" && env GOWORK=off GOTOOLCHAIN=local GOOS=darwin GOARCH=arm64 CGO_ENABLED=0 go build -o "$FIX/macho" .) || fix_ok=no

# run_cli <file> prints the wrapper's exit status (never its text).
run_cli() {
	local rc=0
	(cd "$K3SM_ROOT" && "${GOENV[@]}" "$WRAPPER" --file "$1") >"$WORKDIR/cli.log" 2>&1 || rc=$?
	echo "$rc"
}

# ---- b391.2 — unsigned fixture → exit 3 -------------------------------------
b2=ok
if [ "$fix_ok" = ok ]; then
	cp "$FIX/macho" "$FIX/unsigned"
	codesign --remove-signature "$FIX/unsigned" || b2=no
	# Non-vacuity: the fixture must really be unsigned for this rung to mean anything.
	if codesign --verify --strict "$FIX/unsigned" 2>/dev/null; then b2=no; fi
	rc="$(run_cli "$FIX/unsigned")"
	[ "$rc" = 3 ] || { b2=no; echo "  unsigned fixture: exit $rc, want 3"; cat "$WORKDIR/cli.log"; }
else
	b2=no; echo "  could not build the fixture Mach-O"
fi
ladder "$b2" "b391.2  unsigned fixture Mach-O rejected with exit 3 (unsigned)"

# ---- b391.3 — ad-hoc-signed fixture → exit 5 --------------------------------
b3=ok
if [ "$fix_ok" = ok ]; then
	cp "$FIX/unsigned" "$FIX/adhoc"
	codesign -s - "$FIX/adhoc" || b3=no
	# Non-vacuity: the ad-hoc signature must itself be valid, so the rejection is
	# about WHO signed, not about a broken signature.
	codesign --verify --strict "$FIX/adhoc" || b3=no
	rc="$(run_cli "$FIX/adhoc")"
	[ "$rc" = 5 ] || { b3=no; echo "  ad-hoc fixture: exit $rc, want 5"; cat "$WORKDIR/cli.log"; }
else
	b3=no; echo "  could not build the fixture Mach-O"
fi
ladder "$b3" "b391.3  ad-hoc-signed fixture Mach-O rejected with exit 5 (ad-hoc)"

echo "----------------------------------------"
echo "B391: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ] || exit 1
echo "================ B391 GREEN ================"

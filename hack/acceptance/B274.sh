#!/usr/bin/env bash
#
# k3sm B274 acceptance gate — the runnable proof that `sudo k3sm uninstall`
# clears the mesh's MSS-clamp pf anchor (darwin-net's mesh.PFAnchor,
# "io.k3sm.mesh"), rather than leaving it loaded against a utun interface
# number that no longer exists.
#
# The defect: netd's shutdown path flushes NOTHING — `k3sm netd` cancels its
# context and netd.Server.Serve just closes its listener. The pf anchor is
# only ever flushed by mesh.WGDevice.Down, and the only caller of Down is the
# RemoveMesh RPC; no signal path reaches it. So a booted-out netd (which is
# exactly what `k3sm uninstall` does) leaves "scrub out on utunN proto tcp all
# max-mss 1340 fragment reassemble" loaded in the anchor, scoped to a utun
# number that is now gone. macOS recycles utun numbers across interface
# creations, so the NEXT tunnel — k3sm's on a reinstall, or an unrelated
# VPN/wireguard client — that gets that same number silently inherits the
# stale clamp.
#
# A daemon-shutdown-path fix was considered and rejected: a live daemon
# RESTART already self-heals, because netd's mesh bring-up (Up) reloads the
# anchor for whichever utun the current run created — so the residue is
# user-visible only across an uninstall, which is why this gate is scoped to
# the installer's own backstop (pkg/install), not to darwin-net.
#
# TWO TIERS, split by what a single Mac can prove without a live install:
#
#   CI TIER (always runs, GOARCH=arm64 CGO_ENABLED=1 pinned) — the unit-provable
#   half: Uninstall calls the new System.FlushMeshPFAnchor() exactly once, in
#   the same ordered call list TestUninstallIdempotent already pins for every
#   other artifact. RED BEFORE: on the unmodified tree FlushMeshPFAnchor does
#   not exist on the System interface, so pkg/install fails to build.
#
#   LAB TIER (K3SM_LAB=1, a Mac with k3sm actually installed, root) — the live
#   proof: `sudo k3sm uninstall`, then `sudo pfctl -a io.k3sm.mesh -sr` prints
#   no rules (the anchor may also be entirely absent — pfctl treats flushing a
#   never-loaded anchor as a no-op). THIS TIER IS DESTRUCTIVE TO THE HOST'S
#   k3sm INSTALL: it uninstalls whatever is currently on the machine and does
#   not reinstall it. Do not run it against a Mac you need running k3sm.
#   Without K3SM_LAB the lab rung is announced LAB-PENDING and never silently
#   passed.
#
# Usage:  hack/acceptance/B274.sh            # CI tier only
#         K3SM_LAB=1 hack/acceptance/B274.sh # + the destructive live-uninstall lab rung
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
K3SM_ROOT="$(cd "$HERE/../.." && pwd)"
SELF="$HERE/B274.sh"
INSTALL_GO="$K3SM_ROOT/pkg/install/install.go"
INSTALL_DARWIN_GO="$K3SM_ROOT/pkg/install/install_darwin.go"

PASS=0; FAIL=0
ladder() { if [ "$1" = ok ]; then echo "PASS  $2"; PASS=$((PASS+1)); else echo "FAIL  $2"; FAIL=$((FAIL+1)); fi; }
lab_pending() { echo "LAB-PENDING  $1"; }

echo "==> k3sm B274 acceptance (uninstall flushes the mesh pf anchor)"

# ---- b274.0 — the gate parses and its sources exist -------------------------
b0=ok
[ -f "$SELF" ] && bash -n "$SELF" || b0=no
[ -f "$INSTALL_GO" ] || b0=no
[ -f "$INSTALL_DARWIN_GO" ] || b0=no
ladder "$b0" "b274.0  gate parses (bash -n) + pkg/install/install.go + install_darwin.go present"
if [ "$b0" != ok ]; then
	echo "----------------------------------------"
	echo "B274: the gate or its wiring source is missing/unparseable — nothing else can run" >&2
	echo "B274: $PASS passed, $FAIL failed" >&2
	exit 1
fi

# ---- b274.1 — the WIRING, read straight out of the source -------------------
w=ok
grep -qE 'FlushMeshPFAnchor\(\) error' "$INSTALL_GO" || w=no
grep -qE 'note\(sys\.FlushMeshPFAnchor\(\)\)' "$INSTALL_GO" || w=no
grep -qE 'func \(darwinSystem\) FlushMeshPFAnchor\(\) error' "$INSTALL_DARWIN_GO" || w=no
grep -qE 'pfctl", "-a", mesh\.PFAnchor, "-F", "all"' "$INSTALL_DARWIN_GO" || w=no
ladder "$w" "b274.1  System.FlushMeshPFAnchor exists, Uninstall calls it, and darwinSystem runs pfctl -a mesh.PFAnchor -F all"

# ---- Go leg runner ------------------------------------------------------------
# GOARCH is pinned to arm64: a Mac whose Go toolchain is itself x86_64-under-
# Rosetta would otherwise build the wrong arch for a darwin/arm64-only product.
run_test() {
	local id="$1" min="$2" name="$3" pkg="$4" dir="$5" cgo="$6" out rc=0 ran
	out="$(cd "$dir" && env GOARCH=arm64 CGO_ENABLED="$cgo" go test -count=1 -v -run "^${name}\$" "$pkg" 2>&1)" || rc=$?
	if [ "$rc" -ne 0 ]; then
		printf '%s\n' "$out" | tail -30
		ladder no "$id  $name ($pkg) passed"
		return
	fi
	if printf '%s\n' "$out" | grep -qE 'no tests to run|no test files'; then
		ladder no "$id  $name ($pkg) actually RAN — go test reported no tests to run (renamed test?)"
		return
	fi
	if ! printf '%s\n' "$out" | grep -qE "^[[:space:]]*--- PASS: ${name}( |\$)"; then
		ladder no "$id  $name ($pkg) actually RAN — no top-level --- PASS line"
		return
	fi
	ran="$(printf '%s\n' "$out" | grep -cE "^[[:space:]]*--- PASS: ${name}/" || true)"
	if [ "$ran" -ge "$min" ]; then
		ladder ok "$id  $name ($pkg): $ran subtests passed (min $min)"
	else
		ladder no "$id  $name ($pkg): only $ran subtests passed, want >= $min"
	fi
}

# ---- b274.2 — Uninstall's ordered call list includes the new backstop -------
run_test "b274.2" 0 TestUninstallIdempotent ./pkg/install/ "$K3SM_ROOT" 1
run_test "b274.2" 0 TestUninstallFlushesTheMeshPFAnchor ./pkg/install/ "$K3SM_ROOT" 1

# ---- b274.3 — the package is formatted and vet-clean -------------------------
f=ok
unformatted="$(cd "$K3SM_ROOT" && gofmt -l pkg/install 2>&1 || true)"
[ -z "$unformatted" ] || { printf '%s\n' "$unformatted"; f=no; }
ladder "$f" "b274.3  gofmt -l is empty over pkg/install"

v=ok
vetout="$(cd "$K3SM_ROOT" && env GOARCH=arm64 CGO_ENABLED=1 go vet ./pkg/install/... 2>&1)" || v=no
[ "$v" = ok ] || printf '%s\n' "$vetout" | tail -20
ladder "$v" "b274.3  go vet is clean over pkg/install (CGO_ENABLED=1)"

# ============================================================================
# LAB TIER — a Mac with k3sm actually installed, root. DESTRUCTIVE.
# ============================================================================
if [ "${K3SM_LAB:-}" != 1 ]; then
	echo "----------------------------------------"
	echo "B274 LAB tier (a Mac with k3sm installed, root; set K3SM_LAB=1 to run):"
	lab_pending "b274.L0  after \`sudo k3sm uninstall\`, \`sudo pfctl -a io.k3sm.mesh -sr\` prints no rules (anchor absent is also a pass)"
	echo
	echo "  DESTRUCTIVE: this rung runs \`sudo k3sm uninstall\` on the host it is invoked"
	echo "  on and does NOT reinstall afterward. Only run it against a Mac you do not"
	echo "  need running k3sm right now."
else
	echo "----------------------------------------"
	echo "B274 LAB tier: running \`sudo k3sm uninstall\` on this host (root; DESTRUCTIVE — no reinstall follows)"

	l0=ok
	if ! command -v k3sm >/dev/null 2>&1 && [ ! -x /usr/local/bin/k3sm ]; then
		echo "    k3sm is not on PATH and /usr/local/bin/k3sm is not present — nothing installed to uninstall"
		l0=no
	fi
	if [ "$l0" = ok ]; then
		sudo k3sm uninstall || { echo "    sudo k3sm uninstall failed"; l0=no; }
	fi
	if [ "$l0" = ok ]; then
		rules="$(sudo pfctl -a io.k3sm.mesh -sr 2>/dev/null || true)"
		if [ -n "$rules" ]; then
			echo "    io.k3sm.mesh still carries rules after uninstall:"
			printf '%s\n' "$rules" | sed 's/^/    | /'
			l0=no
		fi
	fi
	ladder "$l0" "b274.L0  after \`sudo k3sm uninstall\`, \`sudo pfctl -a io.k3sm.mesh -sr\` prints no rules"
fi

echo "----------------------------------------"
echo "B274: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ] || exit 1
if [ "${K3SM_LAB:-}" = 1 ]; then
	echo "================ B274 GREEN (CI + lab tiers) ================"
else
	echo "================ B274 GREEN (CI tier; the lab tier needs K3SM_LAB=1, root, and a real install) ================"
fi

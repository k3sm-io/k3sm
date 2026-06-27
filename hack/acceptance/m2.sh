#!/usr/bin/env bash
# k3sm M2 acceptance gate — the runnable proof of isolation, resources & pod-spec
# fidelity (DESIGN §9 M2) under the USER-SPACE (netd-helper) posture: the single
# root step is `sudo k3sm install`, which lays down the io.k3sm.netd (root
# privileged-network helper) and io.k3sm.server (control plane, running as the
# unprivileged _k3sm user) LaunchDaemons; EVERYTHING ELSE then runs user-space.
# The fidelity checks (pod-to-pod over real pod IPs, ClusterIP VIP, Seatbelt
# /Users-denied, OOMKilled, kubectl top) plus the helper-protocol checks
# (peer-auth rejection, out-of-policy-request rejection) are the typed TestM2
# e2e suite; this script adds the install/uninstall lifecycle + structural checks
# around it.
#
# Tier: integration (requires a dev Mac + root for the one-time install). It runs
# in the lab tier and is NOT exercised in unit CI. Exit 0 iff every check passes.
#
# Usage: sudo hack/acceptance/m2.sh
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$HERE/../.." && pwd)"

PASS=0; FAIL=0
ladder() { if [ "$1" = ok ]; then echo "PASS  $2"; PASS=$((PASS+1)); else echo "FAIL  $2"; FAIL=$((FAIL+1)); fi; }

NETD_SOCK="/var/lib/k3sm/run/netd.sock"
INSTALL_DIR="/Library/k3sm"
BIN="$REPO_ROOT/k3sm-m2"
INVOKING_USER="${SUDO_USER:-$(id -un)}"
KUBECONFIG_PATH="$(eval echo "~$INVOKING_USER")/.kube/config"

cleanup() {
	# Always attempt uninstall so a failed run leaves no daemons/aliases behind.
	"$BIN" uninstall >/dev/null 2>&1 || true
	rm -f "$BIN" >/dev/null 2>&1 || true
}
trap cleanup EXIT

if [ "$(id -u)" -ne 0 ]; then
	echo "M2 gate requires root for the one-time install — run: sudo $0" >&2
	exit 1
fi

echo "==> k3sm M2 acceptance (user-space: sudo k3sm install once, then fidelity checks)"

# Build the single binary CGO_ENABLED=1 (kine sqlite), runtime pinned to runtimed.
( cd "$REPO_ROOT" && CGO_ENABLED=1 go build -o "$BIN" ./cmd/k3sm )
codesign -s - -f "$BIN" >/dev/null 2>&1 || true

# ── The ONE root step: install both LaunchDaemons. ───────────────────────────
if "$BIN" install --user "$INVOKING_USER" >/dev/null 2>&1; then
	ladder ok "m2.0  sudo k3sm install (io.k3sm.netd + io.k3sm.server LaunchDaemons)"
else
	ladder no "m2.0  sudo k3sm install"
	echo "M2: install failed — aborting"; exit 1
fi

# m2.1 — the root helper is up: socket present, 0660, root-owned (peer-auth posture:
# the SCM_CREDS uid verifier admits ONLY the _k3sm uid on top of these perms).
sock_ok=no
if [ -S "$NETD_SOCK" ]; then
	mode="$(stat -f '%Lp' "$NETD_SOCK" 2>/dev/null || echo '')"
	owner="$(stat -f '%Su' "$NETD_SOCK" 2>/dev/null || echo '')"
	[ "$mode" = "660" ] && [ "$owner" = "root" ] && sock_ok=yes
fi
ladder "$([ "$sock_ok" = yes ] && echo ok || echo no)" "m2.1  netd socket present, 0660, root-owned"

# m2.2 — both daemons loaded into the system launchd domain.
if launchctl print system/io.k3sm.netd >/dev/null 2>&1; then
	ladder ok "m2.2  io.k3sm.netd LaunchDaemon loaded (root)"
else
	ladder no "m2.2  io.k3sm.netd LaunchDaemon loaded (root)"
fi
if launchctl print system/io.k3sm.server >/dev/null 2>&1; then
	ladder ok "m2.2  io.k3sm.server LaunchDaemon loaded (UserName=_k3sm)"
else
	ladder no "m2.2  io.k3sm.server LaunchDaemon loaded (UserName=_k3sm)"
fi

# m2.3 — the control plane (running as _k3sm via the helper) is serving, and the
# admin kubeconfig was written to the HUMAN's home (owned by them, not root).
export KUBECONFIG="$KUBECONFIG_PATH"
healthy=no
for _ in $(seq 1 180); do
	[ "$("$INSTALL_DIR/k3sm" kubectl get --raw /healthz 2>/dev/null)" = "ok" ] && { healthy=yes; break; }
	sleep 1
done
ladder "$([ "$healthy" = yes ] && echo ok || echo no)" "m2.3  control plane healthy via _k3sm (kubeconfig: $KUBECONFIG_PATH)"
kube_owner="$(stat -f '%Su' "$KUBECONFIG_PATH" 2>/dev/null || echo '')"
ladder "$([ "$kube_owner" = "$INVOKING_USER" ] && echo ok || echo no)" "m2.3  admin kubeconfig owned by $INVOKING_USER (NOT root)"

# m2.A — the typed M2 fidelity + helper-protocol suite (pod-to-pod over real pod
# IPs, ClusterIP VIP, Seatbelt /Users-denied, OOMKilled, kubectl top, peer-auth
# rejection, out-of-policy-request rejection). Run user-space against the running
# cluster. GUARD the vacuous green: an absent/empty TestM2 (no tests matched)
# must FAIL the gate, never false-green.
e2e_out="$(cd "$REPO_ROOT" && CGO_ENABLED=1 go test -tags e2e -run TestM2 -timeout 600s -v ./e2e/... 2>&1)" && e2e_rc=0 || e2e_rc=1
echo "$e2e_out" | sed 's/^/    /'
if echo "$e2e_out" | grep -qE 'no tests to run|warning: no tests to run'; then
	ladder no "m2.A  TestM2 fidelity suite ran (VACUOUS: -run TestM2 matched no tests — author e2e/m2_test.go)"
elif [ "$e2e_rc" -eq 0 ] && echo "$e2e_out" | grep -qE '^(ok|PASS|--- PASS: TestM2)'; then
	ladder ok "m2.A  TestM2 fidelity + helper-protocol suite (pod-to-pod, ClusterIP, Seatbelt, OOMKilled, top, peer-auth, out-of-policy)"
else
	ladder no "m2.A  TestM2 fidelity + helper-protocol suite"
fi

# m2.4 — uninstall cleanliness: both daemons booted out, install dir removed,
# socket gone, and the helper flushed its lo0 pod/Service aliases on SIGTERM.
"$BIN" uninstall >/dev/null 2>&1 || true
clean=yes
launchctl print system/io.k3sm.server >/dev/null 2>&1 && clean=no
launchctl print system/io.k3sm.netd   >/dev/null 2>&1 && clean=no
[ -e "$INSTALL_DIR" ] && clean=no
[ -S "$NETD_SOCK" ] && clean=no
# No 100.64.* (pod) or service-VIP aliases should remain on lo0 after teardown.
ifconfig lo0 2>/dev/null | grep -qE 'inet (100\.64\.|10\.43\.)' && clean=no
ladder "$([ "$clean" = yes ] && echo ok || echo no)" "m2.4  uninstall clean (daemons out, $INSTALL_DIR gone, socket gone, lo0 aliases flushed)"

echo "----------------------------------------"
echo "M2: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ] || exit 1
echo "================ M2 GREEN ================"

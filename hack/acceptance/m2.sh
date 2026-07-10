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
. "$HERE/../lib/conformance.sh"

PASS=0; FAIL=0
ladder() { if [ "$1" = ok ]; then echo "PASS  $2"; PASS=$((PASS+1)); else echo "FAIL  $2"; FAIL=$((FAIL+1)); fi; }

NETD_SOCK="/var/lib/k3sm/run/netd.sock"
INSTALL_DIR="/Library/k3sm"
BIN="$REPO_ROOT/k3sm-m2"
EXECSHIM="$REPO_ROOT/k3sm-execshim"
PATHSHIM="$REPO_ROOT/libk3sm_pathrebase_shim.dylib"
DNSSHIM="$REPO_ROOT/libk3sm_getaddrinfo_shim.dylib"
PAYLOAD_DIR="$REPO_ROOT/cp-payload"
INVOKING_USER="${SUDO_USER:-$(id -un)}"
KUBECONFIG_PATH="$(eval echo "~$INVOKING_USER")/.kube/config"

cleanup() {
	# Always attempt uninstall so a failed run leaves no daemons/aliases behind.
	"$BIN" uninstall >/dev/null 2>&1 || true
	# Belt-and-suspenders: reap any control-plane children that outlived the daemon
	# and flush the DNS VIP, so a mid-run failure can't poison a re-run (uninstall
	# now does the reap too, but a build/install-failed run never reaches it).
	pkill -9 -f '/var/lib/k3sm/server/bin/' >/dev/null 2>&1 || true
	ifconfig lo0 -alias 10.43.0.10 >/dev/null 2>&1 || true
	rm -f "$BIN" "$EXECSHIM" "$PATHSHIM" "$DNSSHIM" >/dev/null 2>&1 || true
	rm -rf "$PAYLOAD_DIR" >/dev/null 2>&1 || true
}
trap cleanup EXIT

if [ "$(id -u)" -ne 0 ]; then
	echo "M2 gate requires root for the one-time install — run: sudo $0" >&2
	exit 1
fi

echo "==> k3sm M2 acceptance (user-space: sudo k3sm install once, then fidelity checks)"
# RUN-STAMP: a unique wall-clock time + the two repos' git SHAs, so a reader can tell
# a FRESH run from stale/re-pasted output and see exactly which code version ran (a
# recurring source of confusion on this live gate). Dirty tree → "+dirty".
_sha() { local d="$1" s; s="$(git -C "$d" rev-parse --short HEAD 2>/dev/null || echo '?')"; git -C "$d" diff --quiet 2>/dev/null || s="$s+dirty"; printf '%s' "$s"; }
echo "==> RUN $(date '+%Y-%m-%dT%H:%M:%S%z')  code: k3sm@$(_sha "$REPO_ROOT") runtimed@$(_sha "$REPO_ROOT/../runtimed")"

# Build the single binary CGO_ENABLED=1 (kine sqlite), runtime pinned to runtimed.
( cd "$REPO_ROOT" && CGO_ENABLED=1 go build -o "$BIN" ./cmd/k3sm )
codesign -s - -f "$BIN" >/dev/null 2>&1 || true
# Build the k3sm-execshim Seatbelt helper BESIDE it — `k3sm install` stages the
# BinarySource's k3sm-execshim sibling next to the installed binary, where the
# runtimed backend resolves it; without it the server dies at boot. Built from
# the workspace root (go.work spans the runtimed module).
( cd "$REPO_ROOT/.." && CGO_ENABLED=1 go build -o "$EXECSHIM" k3sm.io/runtimed/cmd/k3sm-execshim )
codesign -s - -f "$EXECSHIM" >/dev/null 2>&1 || true
# Build the path-rebase DYLD shim BESIDE it — `k3sm install` stages the
# BinarySource's libk3sm_pathrebase_shim.dylib sibling next to the installed binary,
# where runtimed resolves it and injects it into a mounting pod so an absolute
# volume mount resolves under the pod data volume (no chroot). Plain clang C dylib.
"$REPO_ROOT/../runtimed/hack/build-pathshim.sh" "$REPO_ROOT" >/dev/null
codesign -s - -f "$PATHSHIM" >/dev/null 2>&1 || true
# Build the getaddrinfo DNS shim BESIDE it — `k3sm install` stages it next to the
# binary, where the provider resolves it and injects it into each pod so in-pod
# cluster DNS reaches the per-node resolver on the DNS VIP. Plain clang C dylib.
"$REPO_ROOT/../darwin-net/hack/build-shim.sh" "$REPO_ROOT" >/dev/null
codesign -s - -f "$DNSSHIM" >/dev/null 2>&1 || true

# Stage the control-plane payload BESIDE it (cp-payload/: kube-apiserver etc. +
# kine) — `k3sm install` copies it to /Library/k3sm/bin, from which the _k3sm
# daemon's boot seeds its workdir. The daemon has neither gh nor go; staging runs
# HERE, as the invoking human (whose shell has both — PATH passed through — and
# whose Go caches stay theirs via -H). Reuses the executor's pinned versions.
sudo -H -u "$INVOKING_USER" env PATH="$PATH" "$BIN" payload "$PAYLOAD_DIR"

# ── The ONE root step: install both LaunchDaemons. ───────────────────────────
if "$BIN" install --user "$INVOKING_USER" >/dev/null 2>&1; then
	ladder ok "m2.0  sudo k3sm install (io.k3sm.netd + io.k3sm.server LaunchDaemons)"
else
	ladder no "m2.0  sudo k3sm install"
	echo "M2: install failed — aborting"; exit 1
fi

# m2.1 — the root helper is up: socket present, 0660, root-owned (peer-auth posture:
# the SCM_CREDS uid verifier admits ONLY the _k3sm uid on top of these perms).
# Bounded retry: launchd spawns the daemon asynchronously after bootstrap, so the
# socket appears moments after install returns — checking once would race it.
sock_ok=no
for _ in $(seq 1 30); do
	if [ -S "$NETD_SOCK" ]; then
		mode="$(stat -f '%Lp' "$NETD_SOCK" 2>/dev/null || echo '')"
		owner="$(stat -f '%Su' "$NETD_SOCK" 2>/dev/null || echo '')"
		[ "$mode" = "660" ] && [ "$owner" = "root" ] && sock_ok=yes && break
	fi
	sleep 1
done
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

# [diagnostic] The cluster Service set the netd port-authorizer confirms <1024
# infra-VIP binds against (cmd/k3sm/netd.go): default/kubernetes must declare 443
# (the API VIP 10.43.0.1) and kube-dns must declare 53 (the DNS VIP 10.43.0.10), or
# netd denies those binds. Informational only (never gates); it pinpoints an empty /
# missing Service set behind a DNS/API-VIP bind denial in server.log/netd.log.
echo "==> [diagnostic] cluster Services (the netd authorizer's Service set):"
"$INSTALL_DIR/k3sm" kubectl get svc -A -o wide 2>&1 | head -20 || true

# [diagnostic] In-pod DNS path, reproduced from the shell so a red InPodDNS/InPodKubectl
# pinpoints the broken LAYER without reading server.log. Three independent probes:
#   (1) STAGING   — is the getaddrinfo shim dylib actually on disk beside the binary?
#   (2) RESOLVER  — does a raw UDP query to the DNS VIP get answered? (shim-independent)
#   (3) SHIM E2E  — does a getaddrinfo call with the shim injected + K3SM_DNS_* set
#                   resolve an unqualified cluster name, exactly as a pod does?
# If (3) works but the pods don't → injection (env/annotation not reaching the pod);
# if (2) fails → the resolver; if (1) is missing → staging. Informational, never gates.
echo "==> [diagnostic] in-pod DNS path (staging / resolver / shim):"
echo "--- (1) staged pod-support dylibs in $INSTALL_DIR:"
ls -la "$INSTALL_DIR"/*.dylib 2>&1 || echo "    (no .dylib staged — DNS/path shims absent)"
DNS_VIP="${K3SM_DNS_VIP:-10.43.0.10}"
DNS_PROBE_DIR="$(mktemp -d)"
cat > "$DNS_PROBE_DIR/probe.go" <<'PROBE'
package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"time"
)

// probe direct <vip> <fqdn>  — raw UDP DNS query straight at the VIP (no shim).
// probe shim <name>          — plain getaddrinfo path (the injected shim, if any, resolves it).
func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	switch os.Args[1] {
	case "direct":
		vip, fqdn := os.Args[2], os.Args[3]
		r := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "udp", net.JoinHostPort(vip, "53"))
		}}
		ips, err := r.LookupHost(ctx, fqdn)
		if err != nil {
			fmt.Printf("    RESOLVER FAIL: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("    RESOLVER OK: %s -> %v\n", fqdn, ips)
	case "shim":
		ips, err := net.DefaultResolver.LookupHost(ctx, os.Args[2])
		if err != nil {
			fmt.Printf("    SHIM FAIL: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("    SHIM OK: %s -> %v\n", os.Args[2], ips)
	}
}
PROBE
if ( cd "$DNS_PROBE_DIR" && go build -o probe probe.go ) 2>/dev/null; then
	codesign -s - -f "$DNS_PROBE_DIR/probe" >/dev/null 2>&1 || true
	echo "--- (2) resolver: raw UDP query to $DNS_VIP:53 for kubernetes.default.svc.cluster.local:"
	"$DNS_PROBE_DIR/probe" direct "$DNS_VIP" kubernetes.default.svc.cluster.local 2>&1 || true
	echo "--- (3) shim e2e: getaddrinfo('kubernetes.default.svc') with the staged shim injected:"
	DNS_SHIM="$INSTALL_DIR/libk3sm_getaddrinfo_shim.dylib"
	if [ -f "$DNS_SHIM" ]; then
		DYLD_INSERT_LIBRARIES="$DNS_SHIM" \
			K3SM_DNS_SERVER="$DNS_VIP" K3SM_DNS_PORT=53 K3SM_DNS_DOMAIN=cluster.local \
			K3SM_DNS_SEARCH="default.svc.cluster.local svc.cluster.local cluster.local" K3SM_DNS_NDOTS=5 \
			"$DNS_PROBE_DIR/probe" shim kubernetes.default.svc 2>&1 || true
	else
		echo "    (shim not staged at $DNS_SHIM — cannot probe the injected path)"
	fi
else
	echo "    (probe build failed — skipping resolver/shim probes)"
fi
rm -rf "$DNS_PROBE_DIR"

# m2.A — the per-criterion M2 conformance suite (e2e/m2_test.go), each criterion
# named per its reference-workload feature class. The NON-VACUOUS guard
# (hack/lib/conformance.sh) enumerates the REQUIRED criterion set below and turns
# the gate RED on any criterion that is missing, failed, OR skipped — closing the
# old guard's PARTIAL-coverage and ALL-SKIP false-greens. Deferred criteria
# (TestM2_ImagePullSecrets / _DaemonSet) are t.Skip'd TODOs absent from this list,
# so their skip is allowed and visible. The full TestM2 set is run (so deferred
# skips print) but only the required list gates.
#
# The conformance helper binaries (e2e/testdata/cmd) are built+ad-hoc-signed by the
# suite's TestMain into $K3SM_CONFORMANCE_BIN; that dir must be world-readable and
# on a path the default-deny Seatbelt profile admits for exec by the _k3sm pods.
# OPEN INTEGRATION ITEM: the exact profile-admitted path is validated on a dev Mac;
# /tmp here is the conventional world-accessible default. ($KUBECONFIG was exported
# to the human's ~/.kube/config in the m2.3 step above.)
export K3SM_CONFORMANCE_BIN="/tmp/k3sm-conformance-bin"
# Clean any stale helper binaries so TestMain rebuilds them from the CURRENT source
# (a prior run left them here; a stale conftool lacking a new subcommand would fail
# the criteria that use it). Recreated world-readable for the _k3sm pods' exec.
rm -rf "$K3SM_CONFORMANCE_BIN"
mkdir -p "$K3SM_CONFORMANCE_BIN"; chmod 755 "$K3SM_CONFORMANCE_BIN"
M2_CRITERIA=(
	M2_ConfigMapMount M2_SecretMount M2_EmptyDir M2_DownwardAPIEnv M2_EnvFrom
	M2_Probes M2_FsGroup M2_GracefulStop M2_ResourceLimitsOOMKilled M2_KubectlTop
	M2_InPodKubectl M2_InPodDNS M2_DenyUsers
)
if run_conformance_slice "$REPO_ROOT" "TestM2" 600s "${M2_CRITERIA[@]}"; then
	ladder ok "m2.A  M2 conformance suite (all ${#M2_CRITERIA[@]} required criteria PASS, none skipped)"
else
	ladder no "m2.A  M2 conformance suite (a required criterion missing, failed, or skipped)"
fi

# m2.4 — uninstall cleanliness: both daemons booted out, install dir removed,
# socket gone, and the helper flushed its lo0 pod/Service aliases on SIGTERM.
# Bounded retry: bootout delivers SIGTERM and returns; the daemons' shutdown
# handlers (socket unlink, lo0 flush) complete asynchronously — a single
# immediate check races a still-exiting netd.
"$BIN" uninstall >/dev/null 2>&1 || true
clean=no
for _ in $(seq 1 15); do
	ok=yes
	launchctl print system/io.k3sm.server >/dev/null 2>&1 && ok=no
	launchctl print system/io.k3sm.netd   >/dev/null 2>&1 && ok=no
	[ -e "$INSTALL_DIR" ] && ok=no
	[ -S "$NETD_SOCK" ] && ok=no
	# No 100.64.* (pod) or service-VIP aliases should remain on lo0 after teardown.
	ifconfig lo0 2>/dev/null | grep -qE 'inet (100\.64\.|10\.43\.)' && ok=no
	[ "$ok" = yes ] && clean=yes && break
	sleep 1
done
ladder "$([ "$clean" = yes ] && echo ok || echo no)" "m2.4  uninstall clean (daemons out, $INSTALL_DIR gone, socket gone, lo0 aliases flushed)"

echo "----------------------------------------"
echo "M2: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ] || exit 1
echo "================ M2 GREEN ================"

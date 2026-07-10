#!/usr/bin/env bash
# k3sm M6 lab gate — the runnable proof of HA: kine→Postgres multi-writer datastore +
# leader election (M6.0) AND server-join + the identical-CA bootstrap bundle (M6.1)
# (DESIGN §9 M6; docs/PHASES.md M6.0/M6.1). Unlike the single-host m0/m1/m2 gates this
# needs TWO control-plane servers sharing ONE Postgres, so it is manual: true / requires
# two-macs + postgres in hack/acceptance/phases.json and runs ONLY under K3SM_LAB=1. The
# orchestrator reports it "pending lab" (never auto-green) when K3SM_LAB is unset.
#
# It asserts the M6 acceptance (two servers, one Postgres):
#   (a) M6_WriteOnAReadOnB          — a write committed on server A is read on B
#                                      (they share one Postgres — the single source
#                                      of truth, no etcd quorum).
#   (b) M6_LeaderElectionSingleActive — scheduler + KCM hold their kube-system Leases
#                                      (leader-elect is ON in HA), and A and B resolve
#                                      the SAME leader (one active scheduler/KCM).
#   (c) M6_WatchStalenessSoak       — the PRODUCTION-TRUST gate (kine#577 failure
#                                      mode): under churn, a consistent LIST on B
#                                      immediately after A's committed write reflects
#                                      it. The gate runs a representative smoke-soak
#                                      (K3SM_M6_SOAK_DURATION, default 20s); the real
#                                      production-trust decision sets it long (e.g.
#                                      K3SM_M6_SOAK_DURATION=24h) for a production-trust run.
#   (e) M6_SecondServerJoinsReconstructsCAs — the M6.1 acceptance: server B reconstructed
#                                      the IDENTICAL cluster CA from server A's
#                                      AES-256-GCM bootstrap bundle (both admin
#                                      kubeconfigs embed the same cluster CA data).
#   (d) failover                    — kill server A → the cluster keeps serving via B.
#                                      Automated when $K3SM_SERVER_A_STOP names a stop
#                                      command (e.g. "ssh mac-a sudo launchctl kickstart
#                                      -k system/io.k3sm.server" — actually a stop, not a
#                                      restart); else printed as a manual step.
#
# Prerequisites (manual two-Mac + Postgres setup, NOT done here):
#   - Postgres reachable from both Macs, an empty database + role for k3sm.
#   - server A:  sudo K3SM_DATASTORE_ENDPOINT='postgres://k3sm@pg:5432/k3sm?sslmode=require' \
#                  k3sm server --mesh-ip <a-mesh-ip>
#   - on server A, mint the SERVER-class join token (reconstructs the cluster CAs;
#     give it ONLY to a trusted control-plane Mac):  k3sm token create --server
#   - server B:  sudo K3SM_DATASTORE_ENDPOINT='postgres://k3sm@pg:5432/k3sm?sslmode=require' \
#                  k3sm server --server-join --mesh-ip <b-mesh-ip> \
#                  --server <a-mesh-ip> --token <server-token>   (M6.1: fetches A's
#                  AES-256-GCM bundle, reconstructs the IDENTICAL cluster + signing CAs)
#   - this host has each server's HA admin kubeconfig (the signing-CA client-cert one
#     <work-dir>/admin.kubeconfig — CA-bearing, NOT the loopback token kubeconfig) as
#     $KUBECONFIG (server A) and $K3SM_KUBECONFIG_B (server B).
#
# Tier: lab (two-macs + postgres). Exit 0 iff every check passes (or skipped pending lab).
#
# Usage: K3SM_LAB=1 KUBECONFIG=<A> K3SM_KUBECONFIG_B=<B> [K3SM_M6_SOAK_DURATION=20s] \
#          [K3SM_SERVER_A_STOP='<cmd>'] hack/lab/m6.sh
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$HERE/../.." && pwd)"
. "$HERE/../lib/conformance.sh"

# ── Lab guard: only run under K3SM_LAB=1 (a real two-Mac + Postgres rig). ──────
if [ "${K3SM_LAB:-}" != "1" ]; then
	echo "M6 lab gate: PENDING (two-macs + postgres). Set K3SM_LAB=1 with two servers on one Postgres to run; this is NOT a pass."
	exit 0
fi

PASS=0; FAIL=0
ladder() { if [ "$1" = ok ]; then echo "PASS  $2"; PASS=$((PASS+1)); else echo "FAIL  $2"; FAIL=$((FAIL+1)); fi; }

KUBECONFIG_PATH="${KUBECONFIG:-$HOME/.kube/config}"
export KUBECONFIG="$KUBECONFIG_PATH"

if ! command -v kubectl >/dev/null 2>&1; then
	echo "M6 lab gate requires kubectl on PATH (the admin client for the running cluster)" >&2
	exit 1
fi
if [ -z "${K3SM_KUBECONFIG_B:-}" ]; then
	ladder no "m6.0  \$K3SM_KUBECONFIG_B unset — the second HA server's kubeconfig is required"
	echo "M6: $PASS passed, $FAIL failed"; exit 1
fi

echo "==> k3sm M6.0 lab gate (two servers + one Postgres; A=$KUBECONFIG_PATH B=$K3SM_KUBECONFIG_B)"

# m6.0 — both control-plane servers are serving (A and B share the Postgres datastore).
a_ok="$(kubectl --kubeconfig "$KUBECONFIG_PATH" get --raw /healthz 2>/dev/null || true)"
b_ok="$(kubectl --kubeconfig "$K3SM_KUBECONFIG_B" get --raw /healthz 2>/dev/null || true)"
if [ "$a_ok" = "ok" ] && [ "$b_ok" = "ok" ]; then
	ladder ok "m6.0  both HA servers healthy (/healthz ok on A and B)"
else
	ladder no "m6.0  both HA servers healthy (A=$a_ok B=$b_ok)"
	echo "M6: $PASS passed, $FAIL failed"; exit 1
fi

# m6.A — the M6 conformance suite. REQUIRED criteria (the non-vacuous guard turns a
# missing/failed/skipped one RED):
#   M6_WriteOnAReadOnB                  (a) write on A read on B (shared datastore)
#   M6_LeaderElectionSingleActive       (b) leader-elect ON; A and B see one leader
#   M6_WatchStalenessSoak               (c) consistent LIST on B reflects A's write under churn
#   M6_SecondServerJoinsReconstructsCAs (e) B reconstructed A's identical cluster CA (M6.1)
M6_CRITERIA=(M6_WriteOnAReadOnB M6_LeaderElectionSingleActive M6_WatchStalenessSoak M6_SecondServerJoinsReconstructsCAs)
if run_conformance_slice "$REPO_ROOT" "TestM6" 1800s "${M6_CRITERIA[@]}"; then
	ladder ok "m6.A  M6 conformance suite (multi-writer read, single active leader, watch-staleness soak, identical-CA server-join)"
else
	ladder no "m6.A  M6 conformance suite (a required criterion missing, failed, or skipped)"
fi

# m6.B — failover: stop server A, the cluster must keep serving via server B. This is
# the half the Go suite cannot drive (it must kill a daemon). Automated when
# $K3SM_SERVER_A_STOP is a command that stops server A's daemon; else a manual step.
if [ -n "${K3SM_SERVER_A_STOP:-}" ]; then
	echo "==> stopping server A: $K3SM_SERVER_A_STOP"
	if ! eval "$K3SM_SERVER_A_STOP"; then
		ladder no "m6.B  stop server A ($K3SM_SERVER_A_STOP failed)"
	else
		served=no
		for _ in $(seq 1 30); do
			if [ "$(kubectl --kubeconfig "$K3SM_KUBECONFIG_B" get --raw /healthz 2>/dev/null || true)" = "ok" ]; then served=yes; break; fi
			sleep 2
		done
		if [ "$served" = yes ]; then
			ladder ok "m6.B  failover: server A down, cluster still serving via B (/healthz ok)"
		else
			ladder no "m6.B  failover: server B did not keep serving after A stopped"
		fi
	fi
else
	echo "m6.B  failover is a MANUAL step (set K3SM_SERVER_A_STOP to automate):"
	echo "      1) stop server A's daemon (e.g. ssh mac-a sudo launchctl bootout system/io.k3sm.server)"
	echo "      2) kubectl --kubeconfig \$K3SM_KUBECONFIG_B get --raw /healthz   # must stay 'ok'"
	echo "      3) kubectl --kubeconfig \$K3SM_KUBECONFIG_B get nodes            # cluster still served by B"
fi

echo "----------------------------------------"
echo "M6: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ] || exit 1
echo "================ M6 GREEN ================"

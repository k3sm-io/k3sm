#!/usr/bin/env bash
# hack/sit/run.sh — the k3sm System Integration Test: ONE runnable script that
# boots the WHOLE stack (apis + runtimed + darwin-net + k3sm) on a single node via
# the `k3sm dev` disposable-cluster verb and runs the cross-component conformance
# surface as TWO privilege tiers plus a flagged-boot leg, then tears down and
# reports a bucketed summary. Single-node only (see README.md for the scope +
# fidelity table).
#
#   T0 rootless (no sudo): `k3sm dev up`          — runtimed + network=none
#   T1 root     (sudo):    `k3sm dev up --datapath` — runtimed + network=direct
#   T2 psa-enforce (no sudo): a DEDICATED `k3sm server --psa-enforce-baseline`
#
# T2 is the SHORT third leg, and it exists because `k3sm dev up` deliberately
# boots the SHIPPED admission default — TestM10_PSADefaultWarn / _AuditLogLevel
# assert exactly that posture, so dev must not carry the cutover flag. A criterion
# whose own skip-spec demands the flagged boot therefore has no home in T0/T1: it
# needs a SECOND control plane, booted with the flag, for the length of one test.
# So T2 boots one on its own allocated ports, runs only the criteria classified
# `tier=psa-enforce`, and tears it down. It is admission-level — the assertion is
# a 403 from the apiserver — so it needs neither a datapath nor root, and runs in
# both invocations below.
#
# Each tier runs EXACTLY the criteria criteria.env classes to that tier, via an
# explicit `-run` alternation derived from criteria.env — NEVER a bare TestM<n>
# (root criteria have no self-skip → a bare selector runs them under `none`, they
# hard-fail, and conformance.sh's exit-code trap reddens the slice). The permanent
# t.Skip stubs (unbuilt) are EXCLUDED from every required-set.
#
# This is a DIAGNOSTIC, not a milestone gate: it has no phases.json row and does
# not match the m[0-9]*.sh orphan glob, so phases_test.go stays green untouched.
#
# Usage:  hack/sit/run.sh          # T0 + T2 (rootless)
#         sudo hack/sit/run.sh     # T0 (as the SUDO_USER human) + T1 (root) + T2
#         hack/sit/run.sh --plan   # print the leg ladder + bucket accounting and
#                                  # exit — boots NOTHING, builds nothing
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$HERE/../.." && pwd)"
. "$HERE/../lib/clusterup.sh"
. "$HERE/../lib/conformance.sh"

CRITERIA_ENV="$HERE/criteria.env"
SIT_TIMEOUT="${SIT_TIMEOUT:-900s}"
DEV_NAME="${SIT_DEV_NAME:-sit}"

# The T2 leg's own state root. A FIXED path for the same reason
# hack/lib/clusterup.sh pins $K3SM_WORKDIR: bin/ under it is a control-plane
# download cache worth keeping ACROSS runs, while everything else is state that
# must not survive one — reset_dir (sourced from clusterup.sh) keeps the former
# and removes the latter at both ends of the leg. Override it to run two SITs
# side by side; the leg's PORTS are already allocated per run (see psa_port).
SIT_PSA_WORKDIR="${SIT_PSA_WORKDIR:-/tmp/k3sm-sit-psa}"
SIT_PSA_PID=""

# --plan is the dry path: it walks the SAME leg ladder and the SAME bucket
# accounting, printing each leg's boot argv and its exact `-run` selector, then
# exits — without building the binary, booting a cluster, or running a test. It
# exists so the wiring (which leg runs which criteria, and that every criterion
# in the manifest lands in a bucket) is checkable without a live macOS host.
SIT_PLAN=0
case "${1:-}" in
"") ;;
--plan) SIT_PLAN=1 ;;
*)
	echo "usage: $0 [--plan]" >&2
	exit 2
	;;
esac

# The single k3sm binary the SIT drives (built once, CGO for kine).
BIN="$REPO_ROOT/k3sm-sit"

# A THROWAWAY kubeconfig for the `k3sm dev up` context merge, so the SIT never
# touches an operator's real ~/.kube/config. The e2e run itself targets the
# instance's own internal kubeconfig (set per-tier below), not this file.
SIT_KUBECONFIG="${SIT_KUBECONFIG:-$(mktemp -t k3sm-sit-kube.XXXXXX)}"

# ── criteria.env parsing ────────────────────────────────────────────────────
# crit_field <criterion> <field>  → the value of tier=/root_reason=/fidelity= .
crit_field() { awk -v c="$1" -v f="$2" '$1==c { for(i=2;i<=NF;i++){ split($i,kv,"="); if(kv[1]==f){print kv[2]} } }' "$CRITERIA_ENV"; }

# crits_for_tier <tier>  → the criterion names classified to a tier.
crits_for_tier() { awk -v t="tier=$1" '/^[^#]/ && $2==t {print $1}' "$CRITERIA_ENV"; }

# run_regex <crit...>  → an EXACT anchored alternation (Test<c>$|Test<c2>$…) so a
# bare TestM<n> can never pull an out-of-tier root criterion into the selection.
run_regex() {
	local first=1 out=""
	for c in "$@"; do
		if [ $first -eq 1 ]; then out="Test${c}\$"; first=0; else out="${out}|Test${c}\$"; fi
	done
	printf '%s' "$out"
}

# all_crits  → every criterion named in the manifest, in file order. The bucket
# accounting below partitions THIS list; a criterion missing from every bucket is
# a harness wiring hole, not a pass.
all_crits() { awk '/^[^#]/ && NF>0 {print $1}' "$CRITERIA_ENV"; }

# in_list <needle> <haystack...>  → 0 iff needle is one of the haystack words.
in_list() {
	local needle="$1" x
	shift
	for x in "$@"; do
		if [ "$x" = "$needle" ]; then return 0; fi
	done
	return 1
}

# ── T2 port allocation (the per-instance-ports discipline) ──────────────────
# Every singleton TCP listener a control plane owns is allocated by probe, never
# left on its default: a second control plane on the fixed ports does not fail
# cleanly, it takes the first one's datastore over and comes up REPORTING
# HEALTHY, and one bring-up later its node dies on the kubelet bind. The five
# windows mirror pkg/dev/alloc.go's (the allocator `k3sm dev` applies to its own
# instances) so the two schemes cannot disagree about which port belongs to which
# role; the probe walks past whatever is already bound, so the leg boots beside a
# live dev instance or a parallel SIT.
PSA_PORT_SPAN=512
psa_port_offset() { echo $(( $$ % PSA_PORT_SPAN )); }

# psa_port <base>  → the first port in [base, base+span) with no loopback
# listener. `nc -z` sees a wildcard bind too, so a foreign holder on 0.0.0.0 is
# skipped exactly like one on 127.0.0.1.
psa_port() {
	local base="$1" off i p
	off="$(psa_port_offset)"
	for ((i = 0; i < PSA_PORT_SPAN; i++)); do
		p=$(( base + (off + i) % PSA_PORT_SPAN ))
		if ! nc -z 127.0.0.1 "$p" >/dev/null 2>&1; then
			printf '%s' "$p"
			return 0
		fi
	done
	echo "psa_port: no free port in [$base,$((base + PSA_PORT_SPAN)))" >&2
	return 1
}

# ── reclaim-state reporting ─────────────────────────────────────────────────
reclaim_state() {
	echo "  reclaim state:"
	echo "    k3sm procs: $(pgrep -f 'k3sm' 2>/dev/null | tr '\n' ' ' || echo none)"
	echo "    lo0 cluster aliases: $(ifconfig lo0 2>/dev/null | awk '/inet /{print $2}' | grep -E '^(10\.43\.|100\.64\.)' | tr '\n' ' ' || echo none)"
	echo "    dev api listeners: $(lsof -nP -iTCP -sTCP:LISTEN 2>/dev/null | awk '/1644[0-9]|164[0-9][0-9]/{print $9}' | tr '\n' ' ' || echo none)"
}

# ── teardown trap ───────────────────────────────────────────────────────────
# psa_leg_down terminates the T2 control plane and removes its state. It is
# idempotent (SIT_PSA_PID is cleared once reaped) so the leg's own teardown and
# the EXIT trap can both call it. SIGTERM goes to the PID and never to a process
# GROUP: the server was not put in one of its own, so `kill -- -$pid` would name
# this script's group and take the SIT down with it.
psa_leg_down() {
	if [ -n "$SIT_PSA_PID" ]; then
		kill -TERM "$SIT_PSA_PID" 2>/dev/null || true
		local n=0
		while kill -0 "$SIT_PSA_PID" 2>/dev/null; do
			sleep 0.3
			n=$((n + 1))
			if [ "$n" -gt 100 ]; then
				kill -KILL "$SIT_PSA_PID" 2>/dev/null || true
				break
			fi
		done
		wait "$SIT_PSA_PID" 2>/dev/null || true
		SIT_PSA_PID=""
	fi
	# Keep bin/ (the download cache), remove the datastore/certs/kubeconfig: a
	# datastore surviving into the next run is exactly the cross-run
	# contamination cluster_reset exists to prevent.
	if [ -d "$SIT_PSA_WORKDIR/server" ]; then
		reset_dir "$SIT_PSA_WORKDIR/server" bin >/dev/null 2>&1 || true
	fi
	rm -rf "$SIT_PSA_WORKDIR/pods" >/dev/null 2>&1 || true
}

cleanup() {
	if [ "$SIT_PLAN" -eq 1 ]; then
		rm -f "$SIT_KUBECONFIG" >/dev/null 2>&1 || true
		return 0
	fi
	psa_leg_down
	"$BIN" dev down --all >/dev/null 2>&1 || true
	# Belt-and-braces lo0 flush (the dev tool already flushes per-instance; this
	# catches any orphan) — root only.
	[ "$(id -u)" -eq 0 ] && lo0_flush 10.43.0.0/16 100.64.0.0/10 >/dev/null 2>&1 || true
	rm -f "$BIN" "$SIT_KUBECONFIG" >/dev/null 2>&1 || true
}
trap cleanup EXIT

# ── bucket accounting ───────────────────────────────────────────────────────
# TIER_RED holds the criteria of a leg that RAN and went red — they are neither
# proven nor deferred, and without a bucket of their own they would land in the
# unaccounted residue below and mask the wiring hole that residue exists to
# report. PLANNED is the --plan analog of PROVEN (what a leg WOULD have run).
PROVEN=(); ROOT_DEFERRED=(); MULTINODE_DEFERRED=(); UNBUILT_DEFERRED=(); TIER_RED=(); PLANNED=()

echo "==> k3sm SIT — single-node system integration test (driving \`k3sm dev\`)"
echo "    manifest: $CRITERIA_ENV"

# Build the binary once (CGO for runtimed's capability probes; kine is a child process).
# --plan boots nothing, so it needs neither the binary nor the staged helpers.
if [ "$SIT_PLAN" -eq 0 ]; then
	( cd "$REPO_ROOT" && CGO_ENABLED=1 go build -o "$BIN" ./cmd/k3sm )
	codesign -s - -f "$BIN" >/dev/null 2>&1 || true

	# The conformance helper binaries must be world-readable + on a Seatbelt-admitted
	# path for exec by the _k3sm pods (mirrors m2.sh/m3.sh).
	export K3SM_CONFORMANCE_BIN="${K3SM_CONFORMANCE_BIN:-/tmp/k3sm-conformance-bin}"
	mkdir -p "$K3SM_CONFORMANCE_BIN"; chmod 755 "$K3SM_CONFORMANCE_BIN"
fi

# Collect the tier buckets that DON'T run here so they are reported, not silent.
MULTINODE_DEFERRED=(); while IFS= read -r __l; do [ -n "$__l" ] && MULTINODE_DEFERRED+=("$__l"); done < <(crits_for_tier multinode)
UNBUILT_DEFERRED=(); while IFS= read -r __l; do [ -n "$__l" ] && UNBUILT_DEFERRED+=("$__l"); done < <(crits_for_tier unbuilt)

# run_tier <label> <up-flags> <required-crit...>
#   Boots `k3sm dev up`, points $KUBECONFIG + $K3SM_WORK_DIR at the instance, runs
#   the tier's exact required-set via the non-vacuous guard, tears the instance
#   down, and records the outcome.
run_tier() {
	local label="$1"; shift
	local up_flags="$1"; shift
	local crits=("$@")
	echo ""
	echo "── $label ─────────────────────────────────────────────────────────"

	local regex; regex="$(run_regex "${crits[@]}")"
	if [ "$SIT_PLAN" -eq 1 ]; then
		echo "  PLAN boot: k3sm dev up --name $DEV_NAME ${up_flags:-<no flags>}"
		echo "  PLAN -run '$regex'"
		PLANNED+=("${crits[@]}")
		return 0
	fi

	# --kubeconfig points the context merge at a throwaway file (never ~/.kube/config).
	# shellcheck disable=SC2086
	"$BIN" dev up --name "$DEV_NAME" --kubeconfig "$SIT_KUBECONFIG" $up_flags
	# The instance's kubeconfig + workdir live under the durable registry root
	# (~/.k3sm/dev/<name>/server — the path pkg/dev's Manager.workDir encodes).
	local work_dir="${HOME}/.k3sm/dev/$DEV_NAME/server"
	export K3SM_WORK_DIR="$work_dir"
	export KUBECONFIG="$work_dir/k3sm.kubeconfig"

	echo "  -run '$regex'"
	if run_conformance_slice "$REPO_ROOT" "$regex" "$SIT_TIMEOUT" "${crits[@]}"; then
		echo "  TIER $label: GREEN"
		PROVEN+=("${crits[@]}")
	else
		echo "  TIER $label: RED (a required criterion missing/failed/skipped)"
		TIER_RED+=("${crits[@]}")
		"$BIN" dev down --name "$DEV_NAME" >/dev/null 2>&1 || true
		reclaim_state
		return 1
	fi

	"$BIN" dev down --name "$DEV_NAME" >/dev/null 2>&1 || true
	reclaim_state
}

# run_psa_enforce_leg <crit...>
#   The T2 flagged-boot leg. It boots a DEDICATED `k3sm server` with
#   --psa-enforce-baseline on freshly allocated ports, exports the two things the
#   criteria's own skip-spec names ($KUBECONFIG + K3SM_PSA_ENFORCE=1), runs
#   exactly the criteria classified to it, and tears the server down again.
#
#   WHY IT IS NOT A `k3sm dev up`: the flag is an apiserver-config choice made at
#   boot, and dev boots the SHIPPED default on purpose (see the note above
#   spawnServer in pkg/dev) because the T0/T1 PSA/audit criteria assert that
#   default. The two postures cannot be the same control plane, so the leg brings
#   up a second one rather than re-flagging the tiers' instance.
#
#   WHY hostprocess + network=none: the criteria are ADMISSION-level — the whole
#   assertion is which HTTP status the apiserver returns to a create — so no pod
#   has to run, no traffic has to route, and no root is involved. runtimed would
#   additionally demand the staged execshim + dylib siblings the dev tiers
#   provision, for a leg in which nothing is ever exec'd.
run_psa_enforce_leg() {
	local crits=("$@")
	if [ "${#crits[@]}" -eq 0 ]; then return 0; fi
	echo ""
	echo "── T2 psa-enforce (k3sm server --psa-enforce-baseline · dedicated instance) ──"

	local work_dir="$SIT_PSA_WORKDIR/server" log="$SIT_PSA_WORKDIR/server.log"
	local api kine kubelet sched cm
	api="$(psa_port 16440)" || return 1
	kine="$(psa_port 12379)" || return 1
	kubelet="$(psa_port 10450)" || return 1
	sched="$(psa_port 11450)" || return 1
	cm="$(psa_port 13450)" || return 1

	local argv=(
		server --psa-enforce-baseline
		--work-dir "$work_dir"
		--node-name "k3sm-sit-psa" --node-ip 127.0.0.1
		--runtime hostprocess --network none
		--api-port "$api" --kine-port "$kine" --kubelet-port "$kubelet"
		--scheduler-port "$sched" --controller-manager-port "$cm"
		--ingress-http-port 0 --ingress-https-port 0
	)
	local regex; regex="$(run_regex "${crits[@]}")"
	if [ "$SIT_PLAN" -eq 1 ]; then
		echo "  PLAN boot: k3sm ${argv[*]}"
		echo "  PLAN -run '$regex'"
		PLANNED+=("${crits[@]}")
		return 0
	fi

	# Start from clean state, keeping only the bin/ download cache.
	mkdir -p "$work_dir"
	reset_dir "$work_dir" bin || return 1
	# Seed that cache from the dev instance the earlier legs already provisioned
	# when it is there: the SAME pinned control-plane binaries, so this is a copy
	# of a cache and not a second acquisition path. Absent it (a first run), the
	# executor's own acquisition runs as usual.
	local dev_bin="${HOME:-}/.k3sm/dev/$DEV_NAME/server/bin"
	if [ ! -d "$work_dir/bin" ] && [ -d "$dev_bin" ]; then
		cp -R "$dev_bin" "$work_dir/bin" >/dev/null 2>&1 || true
	fi
	echo "  ports: api=$api kine=$kine kubelet=$kubelet scheduler=$sched controller-manager=$cm"
	echo "  boot:  k3sm ${argv[*]}"

	# K3SM_WORK_DIR is exported into the server for the same reason `k3sm dev`
	# exports it: the M10 audit/PSA e2e read the audit log out of that workdir.
	nohup env CGO_ENABLED=1 K3SM_WORK_DIR="$work_dir" "$BIN" "${argv[@]}" > "$log" 2>&1 &
	SIT_PSA_PID=$!

	local kubeconfig="$work_dir/k3sm.kubeconfig" kubectl="$work_dir/bin/kubectl"
	# Bounded waits, each polling the server pid: the flagged server can die long
	# after the control plane is healthy (node bring-up runs last), and a wait that
	# spins its full timeout against a corpse blames the wrong component.
	psa_died() { [ -n "$SIT_PSA_PID" ] && ! kill -0 "$SIT_PSA_PID" 2>/dev/null; }
	psa_red() {
		echo "  RED  the flagged server $1 — its last log lines:"
		tail -20 "$log" 2>/dev/null | sed 's/^/      /'
		psa_leg_down
		reclaim_state
		return 1
	}
	local n=0
	until [ -f "$kubeconfig" ] && [ -x "$kubectl" ]; do
		if psa_died; then psa_red "exited during provisioning"; return 1; fi
		sleep 1; n=$((n + 1))
		# Generous: a COLD run acquires the pinned control-plane release + builds
		# kine before it can serve anything. Later runs hit the bin/ cache.
		if [ $n -gt 600 ]; then psa_red "did not provision within 600s"; return 1; fi
	done
	n=0
	until [ "$(KUBECONFIG="$kubeconfig" "$kubectl" get --raw /healthz 2>/dev/null)" = "ok" ]; do
		if psa_died; then psa_red "exited during control-plane bring-up"; return 1; fi
		sleep 1; n=$((n + 1))
		if [ $n -gt 180 ]; then psa_red "apiserver healthz not ok within 180s"; return 1; fi
	done
	# The criteria CREATE a pod (the admitted reference control), and the
	# apiserver's ServiceAccount admission refuses every pod until default/default
	# exists — an object the controller-manager writes asynchronously.
	n=0
	until KUBECONFIG="$kubeconfig" "$kubectl" get serviceaccount default -n default >/dev/null 2>&1; do
		if psa_died; then psa_red "exited before the default ServiceAccount appeared"; return 1; fi
		sleep 1; n=$((n + 1))
		if [ $n -gt 60 ]; then psa_red "default/default ServiceAccount not created within 60s"; return 1; fi
	done

	export K3SM_WORK_DIR="$work_dir"
	export KUBECONFIG="$kubeconfig"
	# The criteria's own skip-spec signal: it says the AMBIENT server was booted
	# with the flag. Scoped to this leg and unset again below, so it can never
	# tell a later leg's default-posture cluster that it is the flagged one.
	export K3SM_PSA_ENFORCE=1
	echo "  -run '$regex'"
	local rc=0
	run_conformance_slice "$REPO_ROOT" "$regex" "$SIT_TIMEOUT" "${crits[@]}" || rc=1
	unset K3SM_PSA_ENFORCE

	if [ "$rc" -eq 0 ]; then
		echo "  TIER T2 psa-enforce: GREEN"
		PROVEN+=("${crits[@]}")
	else
		echo "  TIER T2 psa-enforce: RED (a required criterion missing/failed/skipped)"
		TIER_RED+=("${crits[@]}")
	fi
	psa_leg_down
	reclaim_state
	return "$rc"
}

# TIER_FAILED records a red tier WITHOUT aborting the run. Under `set -e` a bare
# run_tier call killed the script the moment T0 went red, so the T1 datapath tier
# never executed — even under sudo, which is the ONLY reason to invoke it — and
# the bucketed summary below (the honesty contract) never printed either, on
# exactly the runs where it matters most. The tiers are INDEPENDENT bring-ups, so
# a red T0 says nothing about T1. Red is still red: the summary reports it and the
# script exits non-zero.
TIER_FAILED=0

# ── T0 rootless ─────────────────────────────────────────────────────────────
T0_CRITS=(); while IFS= read -r __l; do [ -n "$__l" ] && T0_CRITS+=("$__l"); done < <(crits_for_tier rootless)
run_tier "T0 rootless (k3sm dev up · runtimed none)" "" "${T0_CRITS[@]}" || TIER_FAILED=1

# The root-tier criteria are deferred at T0; recorded so they're never silent.
ROOT_DEFERRED=(); while IFS= read -r __l; do [ -n "$__l" ] && ROOT_DEFERRED+=("$__l"); done < <(crits_for_tier root)

# ── T1 root (only under sudo) ───────────────────────────────────────────────
if [ "$(id -u)" -eq 0 ]; then
	T1_CRITS=(); while IFS= read -r __l; do [ -n "$__l" ] && T1_CRITS+=("$__l"); done < <(crits_for_tier root)
	run_tier "T1 root (sudo k3sm dev up --datapath · runtimed direct)" "--datapath" "${T1_CRITS[@]}" || TIER_FAILED=1
	# Under sudo the root tier RAN, so it is no longer deferred — the criteria are
	# reported by their own tier verdict (PROVEN only on green), never as deferred.
	ROOT_DEFERRED=()
else
	echo ""
	echo "── T1 root: SKIPPED (not root) — re-run 'sudo $0' to prove the datapath tier"
fi

# ── T2 psa-enforce (always — rootless, its own control plane) ────────────────
PSA_CRITS=(); while IFS= read -r __l; do [ -n "$__l" ] && PSA_CRITS+=("$__l"); done < <(crits_for_tier psa-enforce)
run_psa_enforce_leg ${PSA_CRITS[@]+"${PSA_CRITS[@]}"} || TIER_FAILED=1

# ── bucket accounting ───────────────────────────────────────────────────────
# The buckets are an HONESTY CONTRACT, and it is only honest if it is TOTAL. A
# criterion classified to a tier whose leg is never invoked falls out of every
# bucket, and the summary would still print GREEN — silently dropping the
# criterion the tier was added to prove, which is the failure a first-class tier
# is supposed to end. So the residue is computed and it is RED.
ACCOUNTED=(
	${PROVEN[@]+"${PROVEN[@]}"}
	${PLANNED[@]+"${PLANNED[@]}"}
	${TIER_RED[@]+"${TIER_RED[@]}"}
	${ROOT_DEFERRED[@]+"${ROOT_DEFERRED[@]}"}
	${MULTINODE_DEFERRED[@]+"${MULTINODE_DEFERRED[@]}"}
	${UNBUILT_DEFERRED[@]+"${UNBUILT_DEFERRED[@]}"}
)
UNACCOUNTED=()
while IFS= read -r __c; do
	if [ -z "$__c" ]; then continue; fi
	if in_list "$__c" ${ACCOUNTED[@]+"${ACCOUNTED[@]}"}; then continue; fi
	UNACCOUNTED+=("$__c")
done < <(all_crits)

# ── bucketed summary ────────────────────────────────────────────────────────
echo ""
echo "======================== SIT SUMMARY ========================"
if [ "$SIT_PLAN" -eq 1 ]; then
	echo "MODE: --plan (nothing booted; leg wiring + bucket accounting only)"
	echo "planned-to-run (${#PLANNED[@]}):            ${PLANNED[*]:-none}"
fi
echo "proven (${#PROVEN[@]}):                    ${PROVEN[*]:-none}"
echo "tier-red (${#TIER_RED[@]}):                  ${TIER_RED[*]:-none}"
echo "root-deferred (${#ROOT_DEFERRED[@]}):             ${ROOT_DEFERRED[*]:-none}"
echo "multi-node-deferred (${#MULTINODE_DEFERRED[@]}):       ${MULTINODE_DEFERRED[*]:-none}"
echo "feature-unbuilt-deferred (${#UNBUILT_DEFERRED[@]}):  ${UNBUILT_DEFERRED[*]:-none}"
echo "unaccounted (${#UNACCOUNTED[@]}):               ${UNACCOUNTED[*]:-none}"
echo "============================================================="
if [ "${#UNACCOUNTED[@]}" -ne 0 ]; then
	echo "SIT RED (criteria in NO bucket — a manifest tier whose harness leg never ran: ${UNACCOUNTED[*]})"
	exit 1
fi
if [ "$TIER_FAILED" -ne 0 ]; then
	echo "SIT RED (at least one RUN tier had a missing/failed/skipped required criterion)"
	exit 1
fi
if [ "$SIT_PLAN" -eq 1 ]; then
	echo "SIT PLAN OK (every criterion in the manifest is claimed by a leg or a deferral bucket)"
	exit 0
fi
echo "SIT GREEN (every required criterion in each RUN tier passed)"

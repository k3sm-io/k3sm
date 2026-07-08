#!/usr/bin/env bash
# hack/sit/run.sh — the k3sm System Integration Test: ONE runnable script that
# boots the WHOLE stack (apis + runtimed + darwin-net + k3sm) on a single node via
# the `k3sm dev` disposable-cluster verb and runs the cross-component conformance
# surface as TWO privilege tiers, then tears down and reports a four-bucket
# summary. Single-node only (see README.md for the scope + fidelity table).
#
#   T0 rootless (no sudo): `k3sm dev up`          — runtimed + network=none
#   T1 root     (sudo):    `k3sm dev up --datapath` — runtimed + network=direct
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
# Usage:  hack/sit/run.sh          # T0 only (rootless)
#         sudo hack/sit/run.sh     # T0 (as the SUDO_USER human) + T1 (root)
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$HERE/../.." && pwd)"
. "$HERE/../lib/clusterup.sh"
. "$HERE/../lib/conformance.sh"

CRITERIA_ENV="$HERE/criteria.env"
SIT_TIMEOUT="${SIT_TIMEOUT:-900s}"
DEV_NAME="${SIT_DEV_NAME:-sit}"

# The single k3sm binary the SIT drives (built once, CGO for kine).
BIN="$REPO_ROOT/k3sm-sit"

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

# ── reclaim-state reporting ─────────────────────────────────────────────────
reclaim_state() {
	echo "  reclaim state:"
	echo "    k3sm procs: $(pgrep -f 'k3sm' 2>/dev/null | tr '\n' ' ' || echo none)"
	echo "    lo0 cluster aliases: $(ifconfig lo0 2>/dev/null | awk '/inet /{print $2}' | grep -E '^(10\.43\.|100\.64\.)' | tr '\n' ' ' || echo none)"
	echo "    dev api listeners: $(lsof -nP -iTCP -sTCP:LISTEN 2>/dev/null | awk '/1644[0-9]|164[0-9][0-9]/{print $9}' | tr '\n' ' ' || echo none)"
}

# ── teardown trap ───────────────────────────────────────────────────────────
cleanup() {
	"$BIN" dev down --all >/dev/null 2>&1 || true
	# Belt-and-braces lo0 flush (the dev tool already flushes per-instance; this
	# catches any orphan) — root only.
	[ "$(id -u)" -eq 0 ] && lo0_flush 10.43.0.0/16 100.64.0.0/10 >/dev/null 2>&1 || true
	rm -f "$BIN" >/dev/null 2>&1 || true
}
trap cleanup EXIT

# ── bucket accounting ───────────────────────────────────────────────────────
PROVEN=(); ROOT_DEFERRED=(); MULTINODE_DEFERRED=(); UNBUILT_DEFERRED=()

echo "==> k3sm SIT — single-node system integration test (driving \`k3sm dev\`)"
echo "    manifest: $CRITERIA_ENV"

# Build the binary once (CGO for the embedded kine sqlite).
( cd "$REPO_ROOT" && CGO_ENABLED=1 go build -o "$BIN" ./cmd/k3sm )
codesign -s - -f "$BIN" >/dev/null 2>&1 || true

# The conformance helper binaries must be world-readable + on a Seatbelt-admitted
# path for exec by the _k3sm pods (mirrors m2.sh/m3.sh).
export K3SM_CONFORMANCE_BIN="${K3SM_CONFORMANCE_BIN:-/tmp/k3sm-conformance-bin}"
mkdir -p "$K3SM_CONFORMANCE_BIN"; chmod 755 "$K3SM_CONFORMANCE_BIN"

# Collect the tier buckets that DON'T run here so they are reported, not silent.
mapfile -t MULTINODE_DEFERRED < <(crits_for_tier multinode)
mapfile -t UNBUILT_DEFERRED   < <(crits_for_tier unbuilt)

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

	# shellcheck disable=SC2086
	"$BIN" dev up --name "$DEV_NAME" $up_flags
	# The instance's kubeconfig + workdir live under the durable registry root
	# (~/.k3sm/dev/<name>/server — the path pkg/dev's Manager.workDir encodes).
	local work_dir="${HOME}/.k3sm/dev/$DEV_NAME/server"
	export K3SM_WORK_DIR="$work_dir"
	export KUBECONFIG="$work_dir/k3sm.kubeconfig"

	local regex; regex="$(run_regex "${crits[@]}")"
	echo "  -run '$regex'"
	if run_conformance_slice "$REPO_ROOT" "$regex" "$SIT_TIMEOUT" "${crits[@]}"; then
		echo "  TIER $label: GREEN"
		PROVEN+=("${crits[@]}")
	else
		echo "  TIER $label: RED (a required criterion missing/failed/skipped)"
		"$BIN" dev down --name "$DEV_NAME" >/dev/null 2>&1 || true
		reclaim_state
		return 1
	fi

	"$BIN" dev down --name "$DEV_NAME" >/dev/null 2>&1 || true
	reclaim_state
}

# ── T0 rootless ─────────────────────────────────────────────────────────────
mapfile -t T0_CRITS < <(crits_for_tier rootless)
run_tier "T0 rootless (k3sm dev up · runtimed none)" "" "${T0_CRITS[@]}"

# The root-tier criteria are deferred at T0; recorded so they're never silent.
mapfile -t ROOT_DEFERRED < <(crits_for_tier root)

# ── T1 root (only under sudo) ───────────────────────────────────────────────
if [ "$(id -u)" -eq 0 ]; then
	mapfile -t T1_CRITS < <(crits_for_tier root)
	run_tier "T1 root (sudo k3sm dev up --datapath · runtimed direct)" "--datapath" "${T1_CRITS[@]}"
	# Under sudo the root tier is PROVEN, so it is no longer deferred.
	ROOT_DEFERRED=()
else
	echo ""
	echo "── T1 root: SKIPPED (not root) — re-run 'sudo $0' to prove the datapath tier"
fi

# ── four-bucket summary ─────────────────────────────────────────────────────
echo ""
echo "======================== SIT SUMMARY ========================"
echo "proven (${#PROVEN[@]}):                    ${PROVEN[*]:-none}"
echo "root-deferred (${#ROOT_DEFERRED[@]}):             ${ROOT_DEFERRED[*]:-none}"
echo "multi-node-deferred (${#MULTINODE_DEFERRED[@]}):       ${MULTINODE_DEFERRED[*]:-none}"
echo "feature-unbuilt-deferred (${#UNBUILT_DEFERRED[@]}):  ${UNBUILT_DEFERRED[*]:-none}"
echo "============================================================="
echo "SIT GREEN (every required criterion in each RUN tier passed)"

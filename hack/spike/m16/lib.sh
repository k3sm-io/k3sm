#!/usr/bin/env bash
# Shared plumbing for the M16.0 spikes (s0.sh … s4.sh) and for run.sh, which chains
# them. The M16 plan's §M16.0 is what each rung answers; docs/PHASES.md M16.0-d1…d5
# is the ledger row each one discharges.
#
# The spikes run on the M16 RIG, not on the workstation: the rig is a laptop Mac
# running its OWN single-node `k3sm server`, so the fleet shares a node with its
# apiserver (cross-node vm traffic is out of scope) and the workstation's cluster is
# never touched. Each s<N>.sh is a DRIVER — it ships a rig-side payload over ssh and
# runs it under the guardrails recorded in docs/PHASES.md M16.0:
#
#   * every write confined to $PREFIX (default ~/k3sm-spike-m16) or /tmp scratch;
#   * never /Library/Sandbox/Profiles, the TCC/Privacy DB, Gatekeeper/SIP state,
#     or any LaunchDaemon;
#   * no sudo and no root — nothing in M16.0 needs privilege;
#   * every Kubernetes object created in the spike namespace and deleted at the end
#     of the rung that made it; the M8 MLXModel and its PVC are never touched;
#   * any halt lands the plan's PRE-DECIDED substitution in the findings file, and
#     no rung improvises a new one.
#
# Usage (from a k3sm checkout):
#   K3SM_M16_HOST=<rig> hack/spike/m16/run.sh          # the whole ladder, S0 → S4
#   K3SM_M16_HOST=<rig> hack/spike/m16/s0.sh           # one rung
#   hack/spike/m16/s0.sh --plan                        # the question, no host needed
#
# K3SM_M16_HOST is REQUIRED on the real path and has no default: the ssh target is
# an operator's own machine, so naming one here would put a private host in a public
# repo.
#
# ---------------------------------------------------------------------------------
# THE EXIT CONTRACT (defined here, ONCE — every s<N>.sh and run.sh obey it)
#
#   0  PASS      every required criterion of the rung reached a verdict, and passed.
#   1  FAIL      at least one required criterion failed. The plan's halt for that
#                criterion applies, and its substitution is pre-decided.
#   2  RECORDED  nothing failed, but the rung produced only measurements and no
#                verdict. This is NOT a green M16.0: a measurement without a verdict
#                cannot discharge a ledger row, and the acceptance asks for exit 0.
#
# A rung that both passes a criterion and records figures exits 0 — recording is
# additive evidence, never a downgrade. Only a rung with no verdict at all exits 2.
# ---------------------------------------------------------------------------------
#
# SOURCING THIS FILE REQUIRES NOTHING. K3SM_M16_HOST is demanded by spike_host(),
# which runs on the real path only, so `s<N>.sh --plan` works on a machine with no
# rig, no GPU and no cluster — which is every machine that reviews the PR adding it.
#
# Findings live beside these scripts as findings-s<N>.md. Re-running overwrites rig
# state under $PREFIX; it does not rewrite a findings file.

PREFIX="${K3SM_M16_PREFIX:-\$HOME/k3sm-spike-m16}"   # expanded rig-side, deliberately
NS="${K3SM_M16_NAMESPACE:-k3sm-m16-spike}"
RIG_KUBECONFIG="${K3SM_M16_KUBECONFIG:-\$HOME/.kube/config}"   # expanded rig-side

# The engine and model pins. The model class is R16's budget decision: on 8 GiB this
# is the only class that fits TWO engines beside the control plane. The revision is
# the same one hack/acceptance/m8.sh pins, so S0(2) and the M8 baseline it is
# compared against are the same weights.
ENGINE_VERSION="${K3SM_M16_ENGINE_VERSION:-0.4.1}"
MODEL_REPO="${K3SM_M16_MODEL:-mlx-community/Qwen3-0.6B-4bit}"
MODEL_REV="${K3SM_M16_MODEL_REV:-73e3e38d981303bc594367cd910ea6eb48349da8}"

# The upstream serving framework (Apache-2.0), named here as a compatibility fact.
# S1 resolves UPSTREAM_REF to a commit and RECORDS it — that resolved sha is the pin
# the plan's R2 promotes, so nothing here hard-codes one it has not verified.
UPSTREAM_REPO="${K3SM_M16_UPSTREAM_REPO:-https://github.com/ai-dynamo/dynamo.git}"
UPSTREAM_REF="${K3SM_M16_UPSTREAM_REF:-main}"
RUST_TOOLCHAIN="${K3SM_M16_RUST_TOOLCHAIN:-1.90.0}"
MATURIN_MIN="${K3SM_M16_MATURIN_MIN:-1.7.0}"

# vm-hosted helper image for the webhook backends. A Linux image under
# runtimeClassName: vm is the point: a native backend would pass S0(1) without ever
# exercising the guest leg the fleet's control plane actually uses.
WEBHOOK_IMAGE="${K3SM_M16_WEBHOOK_IMAGE:-python:3.12-alpine}"

PASSES=0; FAILS=0; RECORDS=0

note()   { printf '\n==> %s\n' "$*"; }
pass()   { echo "PASS      $*"; PASSES=$((PASSES + 1)); }
fail()   { echo "FAIL      $*"; FAILS=$((FAILS + 1)); }
record() { echo "RECORDED  $*"; RECORDS=$((RECORDS + 1)); }

# spike_verdict <rung> — print the scoreboard and exit per the contract above.
spike_verdict() {
	echo
	echo "==== $1: $PASSES passed, $FAILS failed, $RECORDS recorded ===="
	if [ "$FAILS" -gt 0 ]; then
		echo "$1: FAIL — the plan's halt for the failed criterion applies; land its pre-decided substitution in findings-$(echo "$1" | tr 'A-Z' 'a-z').md"
		exit 1
	fi
	if [ "$PASSES" -eq 0 ]; then
		echo "$1: RECORDED ONLY — measurements without a verdict do not discharge a ledger row"
		exit 2
	fi
	echo "$1: PASS"
	exit 0
}

# spike_plan <rung> <question> <method> <halt> — the --plan handler. It prints the
# rung's question, method and halt and exits 0 WITHOUT reading K3SM_M16_HOST, so the
# shape of the ladder is reviewable with no rig attached.
spike_plan() {
	echo "==> k3sm M16.0 spike $1 — PLAN ONLY (nothing is contacted, nothing is written)"
	echo
	echo "question"
	printf '  %s\n' "$2"
	echo
	echo "method"
	printf '  %s\n' "$3"
	echo
	echo "halt"
	printf '  %s\n' "$4"
	echo
	echo "findings   hack/spike/m16/findings-$(echo "$1" | tr 'A-Z' 'a-z').md"
	echo "exit       0 PASS · 1 FAIL · 2 RECORDED (hack/spike/m16/lib.sh)"
	echo "rig        K3SM_M16_HOST (required on the real path; no default)"
	exit 0
}

# spike_host — demand the ssh target. Called on the real path only.
spike_host() {
	HOST="${K3SM_M16_HOST:?set K3SM_M16_HOST to the M16 rig (a Mac running its own single-node k3sm server)}"
}

# spike_require_pin <VAR> <what> — refuse to run a rung whose pin the operator has
# not supplied, with the reason. A spike that invents a digest proves nothing about
# the artifact that ships.
spike_require_pin() {
	local var="$1" what="$2" val
	eval "val=\${$var:-}"
	if [ -z "$val" ]; then
		echo "FAIL      $var is unset — $what" >&2
		echo "          Set it from the mirror (the plan's R12) or, until the mirror push lands, from the upstream registry BY DIGEST. Never a tag." >&2
		exit 1
	fi
}

# RIG-SIDE PREAMBLE, injected ahead of every payload: a non-interactive ssh gets
# neither a login PATH nor GNU coreutils, and both bit the M11 harness before it
# reached a rig. macOS ships no timeout(1); run_timeout is the portable stand-in.
read -r -d '' LAB_PREAMBLE <<'PREEOF' || true
export PATH="/opt/homebrew/bin:/usr/local/bin:$HOME/.cargo/bin:$HOME/.local/bin:$PATH"

run_timeout() {
  local secs="$1"; shift
  "$@" & local pid=$!
  ( sleep "$secs"; kill -TERM "$pid" 2>/dev/null; sleep 2; kill -KILL "$pid" 2>/dev/null ) 2>/dev/null &
  local watcher=$!
  local rc=0; wait "$pid" 2>/dev/null || rc=$?
  kill -TERM "$watcher" 2>/dev/null || true
  return "$rc"
}

# verdict PASS|FAIL <text> / recorded <text> — the ONLY way a payload reports. The
# driver scans for these tokens, so a rung's verdict is data the rig produced, never
# the driver's reading of a log.
verdict()  { echo "VERDICT $1 $2"; }
recorded() { echo "RECORD $*"; }

kc() { kubectl --kubeconfig "$KUBECONFIG_RIG" --request-timeout=30s "$@"; }

spike_preflight() {
  local missing=0
  command -v kubectl >/dev/null || { echo "SPIKE PREFLIGHT FAIL: kubectl not found"; missing=1; }
  command -v curl    >/dev/null || { echo "SPIKE PREFLIGHT FAIL: curl not found"; missing=1; }
  command -v python3 >/dev/null || { echo "SPIKE PREFLIGHT FAIL: python3 not found"; missing=1; }
  [ -r "$KUBECONFIG_RIG" ] || { echo "SPIKE PREFLIGHT FAIL: no kubeconfig at $KUBECONFIG_RIG"; missing=1; }
  [ "$missing" -eq 0 ] || exit 1
  kc get --raw /healthz >/dev/null || { echo "SPIKE PREFLIGHT FAIL: the rig's apiserver does not answer /healthz"; exit 1; }
  echo "preflight ok: $(kubectl version --client -o yaml 2>/dev/null | head -2 | tr '\n' ' ')"
}
PREEOF

# lab <<'EOF' — run a heredoc payload on the rig, with the preamble in scope. Its
# output is teed so the transcript keeps the audit trail, and scanned so the
# payload's own VERDICT/RECORD lines drive the scoreboard.
lab() {
	local out rc=0
	out="$(mktemp -t k3sm-m16-lab)"
	{ printf '%s\n' "$LAB_PREAMBLE"; cat; } | ssh "$HOST" \
		"PREFIX=$PREFIX NS=$NS KUBECONFIG_RIG=$RIG_KUBECONFIG \
		 ENGINE_VERSION=$ENGINE_VERSION MODEL_REPO=$MODEL_REPO MODEL_REV=$MODEL_REV \
		 UPSTREAM_REPO=$UPSTREAM_REPO UPSTREAM_REF=$UPSTREAM_REF \
		 RUST_TOOLCHAIN=$RUST_TOOLCHAIN MATURIN_MIN=$MATURIN_MIN \
		 WEBHOOK_IMAGE=$WEBHOOK_IMAGE \
		 CHART_REF=${K3SM_M16_CHART:-} OPERATOR_IMAGE=${K3SM_M16_OPERATOR_IMAGE:-} \
		 FRONTEND_IMAGE=${K3SM_M16_FRONTEND_IMAGE:-} MOCKER_IMAGE=${K3SM_M16_MOCKER_IMAGE:-} \
		 WORKER_IMAGE=${K3SM_M16_WORKER_IMAGE:-} \
		 bash -s" 2>&1 | tee "$out" || rc=$?
	if [ "$rc" != 0 ]; then
		fail "the rig-side payload exited non-zero (ssh/bash rc=$rc) — read the transcript above before reading the scoreboard"
	fi
	spike_scan "$out"
	rm -f "$out"
}

# spike_scan <file> — turn the payload's VERDICT/RECORD lines into the scoreboard.
spike_scan() {
	local line
	while IFS= read -r line; do
		case "$line" in
		"VERDICT PASS "*) pass "${line#VERDICT PASS }" ;;
		"VERDICT FAIL "*) fail "${line#VERDICT FAIL }" ;;
		"RECORD "*)       record "${line#RECORD }" ;;
		esac
	done < "$1"
}

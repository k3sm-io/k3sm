#!/usr/bin/env bash
# Shared plumbing for the M11.0 spikes (s1.sh, and later s3.sh / s4.sh / s5.sh).
#
# The spikes run on the LAB Mac, not on the workstation: they need
# Virtualization.framework, an ad-hoc signature carrying
# com.apple.security.virtualization, and the freedom to boot throwaway guests.
# Each s<N>.sh is a DRIVER — it ships a lab-side payload over ssh and runs it
# under the guardrails recorded in k3sm/docs/PHASES.md M11.0:
#
#   * every write confined to $PREFIX (default ~/k3sm-spike-m11) or /tmp scratch;
#   * never /Library/Sandbox/Profiles, the TCC/Privacy DB, Gatekeeper/SIP state,
#     or any LaunchDaemon;
#   * no sudo and no root EXCEPT where privilege IS the question under test, and
#     there the script asserts the UNPRIVILEGED failure first and records what
#     root buys;
#   * any allow-set widening beyond a spike's stated exit criteria is FLAGGED in
#     the findings file, never silently adopted.
#
# Usage (from a k3sm checkout):
#   K3SM_SPIKE_HOST=<lab-mac> hack/spike/m11/s1.sh
#
# K3SM_SPIKE_HOST is REQUIRED and has no default: the ssh target is an operator's
# own machine, so naming one here would put a private host in a public repo.
#
# Findings live beside these scripts as findings-s<N>.md. Re-running overwrites
# lab state under $PREFIX; it does not rewrite a findings file.
set -euo pipefail

HOST="${K3SM_SPIKE_HOST:?set K3SM_SPIKE_HOST to the lab host}"   # ssh target; no default
PREFIX="${K3SM_SPIKE_PREFIX:-\$HOME/k3sm-spike-m11}"       # expanded lab-side, deliberately

# The throwaway kernel. S1 deliberately does NOT use a pinned artifact: the
# pinned kernel is B111's job, and making a design-invalidating spike wait on a
# human-gated producer would invert the dependency. Any bootable uncompressed
# arm64 Image answers S1's questions.
KERNEL_URL="${K3SM_SPIKE_KERNEL_URL:-https://cloud-images.ubuntu.com/releases/24.04/release/unpacked/ubuntu-24.04-server-cloudimg-arm64-vmlinuz-generic}"

# LAB-SIDE PREAMBLE. Injected ahead of every heredoc, because a non-interactive
# ssh gets neither a login PATH nor GNU coreutils, and both bit this harness
# before it ever reached the rig:
#
#   * go lives at /opt/homebrew/bin/go on the lab Mac and is on NEITHER the
#     non-interactive nor the login-shell PATH, so a bare `go build` fails with
#     "command not found" — the guest init and the vzboot harness both need it;
#   * macOS ships NO timeout(1) and no gtimeout, so every `timeout N ./vzboot`
#     would have failed the same way. run_timeout below is the portable stand-in.
#
# Both are asserted rather than assumed: preflight exits non-zero with a named
# cause, so a missing tool is a one-line failure at the start of a sitting rather
# than a confusing one twenty minutes in.
read -r -d '' LAB_PREAMBLE <<'PREEOF' || true
export PATH="/opt/homebrew/bin:/usr/local/go/bin:$HOME/go/bin:$PATH"

# run_timeout SECONDS CMD... — macOS has no timeout(1). TERM, then KILL.
run_timeout() {
  local secs="$1"; shift
  "$@" & local pid=$!
  ( sleep "$secs"; kill -TERM "$pid" 2>/dev/null; sleep 2; kill -KILL "$pid" 2>/dev/null ) 2>/dev/null &
  local watcher=$!
  local rc=0; wait "$pid" 2>/dev/null || rc=$?
  kill -TERM "$watcher" 2>/dev/null || true
  return "$rc"
}

spike_preflight() {
  local missing=0
  command -v go   >/dev/null || { echo "SPIKE PREFLIGHT FAIL: go not found (expected /opt/homebrew/bin/go)"; missing=1; }
  command -v cpio >/dev/null || { echo "SPIKE PREFLIGHT FAIL: cpio not found"; missing=1; }
  command -v curl >/dev/null || { echo "SPIKE PREFLIGHT FAIL: curl not found"; missing=1; }
  [ "$missing" -eq 0 ] || exit 1
  echo "preflight ok: $(go version)"
}
PREEOF

# lab <<'EOF' — run a heredoc script on the lab Mac, with the preamble in scope.
lab() { { printf '%s\n' "$LAB_PREAMBLE"; cat; } | ssh "$HOST" "PREFIX=$PREFIX KERNEL_URL=$KERNEL_URL bash -s"; }
note() { printf '\n==> %s\n' "$*"; }

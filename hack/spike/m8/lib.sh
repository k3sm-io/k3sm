#!/usr/bin/env bash
# Shared plumbing for the M8.0 spikes (s1.sh / s2.sh / s3.sh).
#
# The spikes run on the LAB Mac, not on the workstation: they need a real Apple
# GPU, and they install a Python/MLX toolchain that must not land on a dev
# machine. Each s<N>.sh is therefore a DRIVER — it ships a lab-side payload over
# ssh and runs it under the guardrails recorded in k3sm/docs/PHASES.md M8.0:
#
#   * every write confined to $PREFIX (default ~/k3sm-spike-m8) or /tmp scratch;
#   * never /Library/Sandbox/Profiles, the TCC/Privacy DB, Gatekeeper/SIP state,
#     or any LaunchDaemon;
#   * no codesign-check disabling, no sudo, no root;
#   * any allow-set widening beyond a spike's exit criteria is FLAGGED in the
#     findings file, never silently adopted.
#
# Usage (from a k3sm checkout):
#   hack/spike/m8/s1.sh [--setup]      # --setup installs uv/python/mlx/model first
#   K3SM_SPIKE_HOST=other-mac hack/spike/m8/s2.sh
#
# The recorded results of the 2026-08-29 run live beside these scripts in
# findings-s1.md / findings-s2.md / findings-s3.md. Re-running overwrites the lab
# state under $PREFIX; it does not rewrite the findings.
set -euo pipefail

HOST="${K3SM_SPIKE_HOST:-miko-studio.blackmesalab.com}"   # the bare name does NOT resolve
PREFIX="${K3SM_SPIKE_PREFIX:-\$HOME/k3sm-spike-m8}"        # expanded lab-side, deliberately
MODEL_S1="${K3SM_SPIKE_MODEL:-mlx-community/Qwen2.5-0.5B-Instruct-4bit}"   # ~276 MB
MODEL_S3="${K3SM_SPIKE_MODEL_BIG:-mlx-community/Llama-3.2-3B-Instruct-4bit}" # ~1.7 GB (cap: 2 GB)

# lab <<'EOF' — run a heredoc script on the lab Mac. stdin is the script body.
lab() { ssh "$HOST" "PREFIX=$PREFIX MODEL_S1=$MODEL_S1 MODEL_S3=$MODEL_S3 bash -s"; }

# note — a banner that keeps the audit trail readable in the transcript.
note() { printf '\n==> %s\n' "$*"; }

#!/usr/bin/env bash
#
# k3sm B330 acceptance gate — the runnable proof that the M16 spike venvs are
# pinned to an arm64 interpreter, so a Mac carrying both an Apple-Silicon and an
# x86_64 Homebrew never silently builds the venv `hack/spike/m16/s0.sh` drives
# vllm-mlx from out of the wrong one.
#
# The defect (observed on the studio rig, S0 run 13): `uv venv --python 3.12
# <dir>` resolves to whichever python 3.12 matches first on PATH. On a Mac with
# a stray x86_64 Homebrew ahead of the Apple-Silicon one, that is the x86_64
# interpreter — so `vllm-mlx==0.4.1` (macosx_*_arm64 wheels only) has nothing to
# resolve against, and s0.sh reported only "vllm-mlx did not install", which
# read as a tooling flake rather than the wrong venv it actually was.
#
# The fix is two shared rig-side helpers in hack/spike/m16/lib.sh's
# LAB_PREAMBLE (so they exist inside the `lab <<'EOF'` payloads that actually
# run this code over ssh, never as ordinary driver-side functions the remote
# bash never sees):
#   spike_venv <dir> <label>   names the EXACT interpreter build
#                              (cpython-3.12-macos-aarch64-none), then asserts
#                              platform.machine() == arm64, FAILing the rung by
#                              name if not.
#   spike_pip  <venv-python> <spec...>
#                              captures `uv pip install` to
#                              $PREFIX/logs/pip-<venv>-<pkg>.log and, on
#                              failure, prints the log's last 8 lines so a
#                              install failure is never a silent >/dev/null.
#
# CI TIER ONLY (no rig, no ssh, no `uv`) — this whole gate is process/bash proof:
# it sources lib.sh, evaluates its LAB_PREAMBLE text (exactly what `lab()` prepends
# to every remote payload) into the CURRENT shell so the helpers are called exactly
# as shipped, and shadows `uv`/`python` with recording fakes on PATH. Nothing here
# contacts a rig, installs a real package, or needs K3SM_M16_HOST.
#
# RED BEFORE: on the unmodified tree spike_venv/spike_pip do not exist in
# lib.sh's LAB_PREAMBLE and s0.sh/s1.sh/s3.sh call `uv venv`/`uv pip install`
# directly, so b330.1's wiring rungs and every b330.2+ behavioural rung fail.
#
# Usage:  hack/acceptance/B330.sh
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
K3SM_ROOT="$(cd "$HERE/../.." && pwd)"
SELF="$HERE/B330.sh"
LIB="$K3SM_ROOT/hack/spike/m16/lib.sh"
S0="$K3SM_ROOT/hack/spike/m16/s0.sh"
S1="$K3SM_ROOT/hack/spike/m16/s1.sh"
S3="$K3SM_ROOT/hack/spike/m16/s3.sh"

PASS=0; FAIL=0
ladder() { if [ "$1" = ok ]; then echo "PASS  $2"; PASS=$((PASS+1)); else echo "FAIL  $2"; FAIL=$((FAIL+1)); fi; }

echo "==> k3sm B330 acceptance (the M16 spike venvs are pinned to an arm64 interpreter)"

# ---- b330.0 — the gate parses and its sources exist -------------------------
b0=ok
[ -f "$SELF" ] && bash -n "$SELF" || b0=no
for f in "$LIB" "$S0" "$S1" "$S3"; do
	[ -f "$f" ] && bash -n "$f" || b0=no
done
grep -q 'spike_venv()' "$LIB" || b0=no
grep -q 'spike_pip()' "$LIB" || b0=no
ladder "$b0" "b330.0  gate parses (bash -n) + lib.sh/s0.sh/s1.sh/s3.sh present + spike_venv/spike_pip defined"
if [ "$b0" != ok ]; then
	echo "----------------------------------------"
	echo "B330: the gate or its wiring source is missing/unparseable — nothing else can run" >&2
	echo "B330: $PASS passed, $FAIL failed" >&2
	exit 1
fi

# ---- b330.1 — the helpers live INSIDE LAB_PREAMBLE, not driver-side --------
# lib.sh's lab() prepends ONLY $LAB_PREAMBLE ahead of a payload before shipping it
# over ssh (see lib.sh's `lab()`); a helper defined outside that heredoc is a
# function the rig's bash never sees, and every s<N>.sh call site would fail
# "command not found" on the real path despite this gate's CI tier reading green.
p=ok
awk '/^read -r -d .. LAB_PREAMBLE <<.PREEOF./,/^PREEOF$/' "$LIB" | grep -q 'spike_venv()' || p=no
awk '/^read -r -d .. LAB_PREAMBLE <<.PREEOF./,/^PREEOF$/' "$LIB" | grep -q 'spike_pip()' || p=no
ladder "$p" "b330.1  spike_venv/spike_pip are defined inside LAB_PREAMBLE (the text lab() actually ships to the rig)"

# ---- b330.2 — the WIRING: s0/s1/s3 call the helpers, never a raw uv call ---
w=ok
for f in "$S0" "$S1" "$S3"; do
	grep -qE '(^|[^a-zA-Z_])uv venv ' "$f" && w=no
done
grep -q 'spike_venv "\$PREFIX/venv" ' "$S0" || w=no
grep -q 'spike_venv "\$PREFIX/venv-s1" ' "$S1" || w=no
grep -q 'spike_venv "\$PREFIX/venv-metal" ' "$S3" || w=no
grep -q 'spike_pip "\$V" "vllm-mlx==\$ENGINE_VERSION"' "$S0" || w=no
grep -q 'spike_pip "\$V" "maturin>=\$MATURIN_MIN"' "$S1" || w=no
grep -q 'spike_pip "\$V" "\$WHEEL"' "$S1" || w=no
grep -q 'spike_pip "\$V" ai-dynamo' "$S1" || w=no
grep -q 'spike_pip "\$VM" vllm-metal' "$S3" || w=no
ladder "$w" "b330.2  s0.sh/s1.sh/s3.sh create every venv and install every wheel through spike_venv/spike_pip (no raw uv venv/pip install left)"

# s3.5's alternative-engine control is RECORDED, never gating — it must still be
# routed through the helpers (an arch mismatch is a tooling bug worth naming), but
# a plain install failure must still fall through to the "recorded, not gating"
# branch rather than becoming a false criterion.
c=ok
grep -qF 'if ! spike_pip "$VM" vllm-metal; then' "$S3" || c=no
grep -qF 'recorded "s3.5 control  the alternative engine did not install' "$S3" || c=no
ladder "$c" "b330.2  s3.5's alternative-engine install stays RECORDED-not-gating through spike_pip's non-zero return"

# s0.sh's install-failure verdict must quote the pip log's own last line, not a
# generic "did not install" — the whole point of naming the failure.
q=ok
grep -qF 'vllm-mlx==$ENGINE_VERSION did not install: $(tail -1 "$PREFIX/logs/pip-venv-vllm-mlx.log"' "$S0" || q=no
ladder "$q" "b330.2  s0.sh's FAIL verdict quotes the pip log's own last line (pip-venv-vllm-mlx.log)"

# ---- fixtures ---------------------------------------------------------------
# Every behavioural rung below runs the helpers EXACTLY as the rig will: source
# lib.sh (defines $LAB_PREAMBLE and never touches a network), then eval that
# text in a throwaway bash -c so spike_venv/spike_pip become real functions in a
# process whose PATH is shadowed with fakes — never the real `uv`.
SCRATCH="$(mktemp -d "${TMPDIR:-/tmp}/k3sm-b330.XXXXXX")"
trap 'rm -rf "$SCRATCH"' EXIT
FAKEBIN="$SCRATCH/fakebin"
mkdir -p "$FAKEBIN"

# A fake `uv` that: records every invocation's argv to $UV_ARGV_LOG; for
# `python install <id>` and `pip install ...` no-ops success unless
# FAKE_PIP_FAIL=1; for `venv --python <id> <dir>` fabricates <dir>/bin/python as
# a script that reports whatever machine string $FAKE_PY_MACH names — the ONE
# knob the acceptance rows below flip between the arm64 and x86_64 fixtures.
cat > "$FAKEBIN/uv" <<'FAKEUV'
#!/usr/bin/env bash
echo "$@" >> "$UV_ARGV_LOG"
case "$1" in
python)
	exit 0
	;;
venv)
	dir="$4"
	mkdir -p "$dir/bin"
	cat > "$dir/bin/python" <<PY
#!/usr/bin/env bash
echo "${FAKE_PY_MACH:-arm64}"
PY
	chmod +x "$dir/bin/python"
	exit 0
	;;
pip)
	if [ "${FAKE_PIP_FAIL:-0}" = 1 ]; then
		echo "Resolved 3 packages in 210ms"
		echo "error: mlx>=0.29.0 has no wheels with a matching platform tag (macosx_26_0_x86_64)"
		exit 1
	fi
	exit 0
	;;
esac
FAKEUV
chmod +x "$FAKEBIN/uv"

# run_helper <extra-env...> -- <helper call> — evaluate LAB_PREAMBLE plus one
# helper call in a fresh bash -c, PATH-shadowed to the fakes only, and capture
# both the output and whether execution continued past the call (a `spike_venv`
# FAIL calls `exit 0`, so anything printed AFTER the call proves it did NOT).
run_helper() {
	# env_assigns always carries this harmless first element: bash 3.2 (macOS's
	# shipped /bin/bash, and whatever a bare `bash` resolves to in CI) treats
	# "${arr[@]}" on a truly EMPTY array as an unbound-variable error under
	# `set -u`, even though the array was declared — so a call with no extra
	# env vars must never leave the array with zero elements.
	local env_assigns=(K3SM_B330_NOOP=1) rest=() seen_dashdash=no arg
	for arg in "$@"; do
		if [ "$seen_dashdash" = no ] && [ "$arg" = "--" ]; then seen_dashdash=yes; continue; fi
		if [ "$seen_dashdash" = no ]; then env_assigns+=("$arg"); else rest+=("$arg"); fi
	done
	# LAB_PREAMBLE's own first line rewrites PATH ("/opt/homebrew/bin:...:$PATH",
	# for real rig ssh sessions that start with no login PATH) — on a Mac that
	# genuinely has a real `uv` under /opt/homebrew/bin that PREPEND would shadow
	# our fake right back, so PATH is re-pinned to the fakebin AFTER the eval,
	# not just before it.
	env "${env_assigns[@]}" PATH="$FAKEBIN:$PATH" K3SM_M16_PREFIX="$SCRATCH/prefix" bash -c '
		set -uo pipefail
		. "'"$LIB"'"
		eval "$LAB_PREAMBLE"
		export PATH="'"$FAKEBIN"':$PATH"
		'"${rest[*]}"'
		echo "REACHED-AFTER"
	' 2>&1
}

# ---- b330.3 — spike_venv asks uv for the EXACT aarch64 cpython spec --------
rm -rf "$SCRATCH/prefix"; mkdir -p "$SCRATCH/prefix"
ARGV_LOG="$SCRATCH/uv-argv-1.log"; : > "$ARGV_LOG"
OUT="$(run_helper UV_ARGV_LOG="$ARGV_LOG" FAKE_PY_MACH=arm64 -- 'spike_venv "$PREFIX/newvenv" "test-label"')"
v1=ok
grep -qF 'python install cpython-3.12-macos-aarch64-none' "$ARGV_LOG" || v1=no
grep -qF 'venv --python cpython-3.12-macos-aarch64-none' "$ARGV_LOG" || v1=no
[ -x "$SCRATCH/prefix/newvenv/bin/python" ] || v1=no
printf '%s\n' "$OUT" | grep -q '^REACHED-AFTER$' || v1=no
ladder "$v1" "b330.3  spike_venv asks uv for the exact cpython-3.12-macos-aarch64-none spec, never a bare 3.12 version match"

# ---- b330.4 — an x86_64-reporting interpreter FAILs, naming the machine ----
rm -rf "$SCRATCH/prefix"; mkdir -p "$SCRATCH/prefix/badvenv/bin"
cat > "$SCRATCH/prefix/badvenv/bin/python" <<'PY'
#!/usr/bin/env bash
echo "x86_64"
PY
chmod +x "$SCRATCH/prefix/badvenv/bin/python"
OUT="$(run_helper FAKE_PY_MACH=x86_64 -- 'spike_venv "$PREFIX/badvenv" "b330.4-label"')"
v2=ok
printf '%s\n' "$OUT" | grep -q 'VERDICT FAIL' || v2=no
printf '%s\n' "$OUT" | grep -qF 'b330.4-label' || v2=no
printf '%s\n' "$OUT" | grep -qF 'x86_64' || v2=no
printf '%s\n' "$OUT" | grep -qF "$SCRATCH/prefix/badvenv/bin/python" || v2=no
printf '%s\n' "$OUT" | grep -q '^REACHED-AFTER$' && v2=no   # must NOT reach past the FAIL
ladder "$v2" "b330.4  an x86_64-reporting interpreter FAILs the rung by name, naming the label, the interpreter path and the machine"

# ---- b330.5 — an arm64-reporting interpreter PASSes silently ---------------
rm -rf "$SCRATCH/prefix"; mkdir -p "$SCRATCH/prefix/goodvenv/bin"
cat > "$SCRATCH/prefix/goodvenv/bin/python" <<'PY'
#!/usr/bin/env bash
echo "arm64"
PY
chmod +x "$SCRATCH/prefix/goodvenv/bin/python"
OUT="$(run_helper FAKE_PY_MACH=arm64 -- 'spike_venv "$PREFIX/goodvenv" "b330.5-label"')"
v3=ok
printf '%s\n' "$OUT" | grep -q 'VERDICT FAIL' && v3=no
printf '%s\n' "$OUT" | grep -q '^REACHED-AFTER$' || v3=no
ladder "$v3" "b330.5  an arm64-reporting interpreter passes with no FAIL verdict and execution continues past the call"

# ---- b330.6 — a failing uv pip install surfaces the log's last line -------
rm -rf "$SCRATCH/prefix"; mkdir -p "$SCRATCH/prefix/venv/bin"
cat > "$SCRATCH/prefix/venv/bin/python" <<'PY'
#!/usr/bin/env bash
echo "arm64"
PY
chmod +x "$SCRATCH/prefix/venv/bin/python"
OUT="$(run_helper FAKE_PIP_FAIL=1 -- 'spike_pip "$PREFIX/venv/bin/python" "vllm-mlx==0.4.1" || echo HELPER-RC=$?; echo "LASTLINE=$(tail -1 "$PREFIX/logs/pip-venv-vllm-mlx.log")"')"
v4=ok
printf '%s\n' "$OUT" | grep -qF 'HELPER-RC=1' || v4=no
printf '%s\n' "$OUT" | grep -qF 'macosx_26_0_x86_64' || v4=no
printf '%s\n' "$OUT" | grep -qF 'LASTLINE=error: mlx>=0.29.0 has no wheels with a matching platform tag (macosx_26_0_x86_64)' || v4=no
[ -f "$SCRATCH/prefix/logs/pip-venv-vllm-mlx.log" ] || v4=no
ladder "$v4" "b330.6  a failing uv pip install prints the log's last 8 lines and leaves pip-<venv>-<pkg>.log for the caller to quote"

# ---- b330.7 — the derived log name carries BOTH the venv and the package --
rm -rf "$SCRATCH/prefix"; mkdir -p "$SCRATCH/prefix/venv-s1/bin"
cat > "$SCRATCH/prefix/venv-s1/bin/python" <<'PY'
#!/usr/bin/env bash
echo "arm64"
PY
chmod +x "$SCRATCH/prefix/venv-s1/bin/python"
OUT="$(run_helper -- 'spike_pip "$PREFIX/venv-s1/bin/python" "maturin>=1.7.0"')"
v5=ok
[ -f "$SCRATCH/prefix/logs/pip-venv-s1-maturin.log" ] || v5=no
ladder "$v5" "b330.7  the pip log name derives from BOTH the venv dir (venv-s1) and the package (maturin), never the package alone"

echo "----------------------------------------"
echo "B330: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]

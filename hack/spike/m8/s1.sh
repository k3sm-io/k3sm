#!/usr/bin/env bash
# M8.0-d1 / S1 — Metal under Seatbelt: a FULL MLX inference round-trip under a
# k3sm default-deny profile, plus the egress half of exit criterion 2.
#
# S1 is the M8 GO/NO-GO (the M8 plan §M8.0). Its two exit criteria:
#   (1) tokens generated under the profile                       — REQUIRED
#   (2) an HF weight download through the PRODUCTION datapath    — see findings
#       (DNS shim -> Service-proxy dialer -> egress) under a generated
#       allow_internet_egress profile
#
# What this script does, in order:
#   setup   install uv + CPython + mlx/mlx-lm + a <=1 GB 4-bit model into $PREFIX
#   probe0  run generation under a default-deny profile with NO GPU rules and
#           harvest the raw sandbox denial log (the evidence the allow-set is
#           derived from, not guessed)
#   matrix  test each candidate iokit rule spelling — this is R22's primary job:
#           VALIDATE the (iokit-registry-entry-class-prefix "AGXAcceleratorG")
#           candidate, and record whether it under- or over-scopes
#   minimal emit the converged MINIMAL profile and re-run BOTH a full generation
#           and a cold JIT Metal-kernel compile under it
#   ablate  drop each candidate rule in turn — a rule that is not load-bearing is
#           OVER-SCOPE and must not ship (Res. 11 / the profile's core invariant)
#   cache   probe whether the confined pod can reach the shared shader cache
#           (DARWIN_USER_CACHE_DIR/com.apple.metal*) — the cross-pod channel
#           Res. 11 requires be RECORDED, never silently widened
#   egress  re-download the model under the R21 allow_internet_egress stanza
#
# Recorded verdict: findings-s1.md.
set -euo pipefail
cd "$(dirname "$0")"; . ./lib.sh

DO_SETUP=0; [ "${1:-}" = "--setup" ] && DO_SETUP=1

if [ "$DO_SETUP" = 1 ]; then
  note "S1 setup — uv + CPython 3.12 + mlx/mlx-lm + $MODEL_S1 into \$PREFIX"
  lab <<'EOF'
set -euo pipefail
mkdir -p "$PREFIX"/{bin,cache,pyinstall,hf,sbpl,logs,work/pod/tmp}
export UV_CACHE_DIR=$PREFIX/cache UV_PYTHON_INSTALL_DIR=$PREFIX/pyinstall
[ -x "$PREFIX/bin/uv" ] || curl -LsSf https://astral.sh/uv/install.sh | env UV_INSTALL_DIR="$PREFIX/bin" sh
"$PREFIX/bin/uv" python install 3.12
[ -x "$PREFIX/venv/bin/python" ] || "$PREFIX/bin/uv" venv --python 3.12 "$PREFIX/venv"
"$PREFIX/bin/uv" pip install --python "$PREFIX/venv/bin/python" mlx mlx-lm
"$PREFIX/bin/uv" pip freeze --python "$PREFIX/venv/bin/python" > "$PREFIX/logs/pip-freeze.txt"
HF_HOME=$PREFIX/hf "$PREFIX/venv/bin/python" - <<PY
from huggingface_hub import snapshot_download
print("MODEL", snapshot_download("$MODEL_S1"))
PY
"$PREFIX/venv/bin/python" -c 'import importlib.metadata as m; print("mlx",m.version("mlx"),"mlx-lm",m.version("mlx-lm"))'
EOF
fi

note "S1 — payload + profiles + denial-log convergence"
lab <<'EOF'
set -uo pipefail
W=$PREFIX/work; POD=$W/pod; V=$PREFIX/venv/bin/python
mkdir -p "$POD/tmp" "$PREFIX/sbpl" "$PREFIX/logs"
MP=$(ls -d "$PREFIX"/hf/hub/models--*Qwen2.5-0.5B*/snapshots/* | head -1)

# --- payloads -------------------------------------------------------------
cat > "$W/gen.py" <<'PY'
import os, time
from mlx_lm import load, generate
t0=time.time(); model, tok = load(os.environ["MODEL_PATH"]); t1=time.time()
p = tok.apply_chat_template([{"role":"user","content":"Name three primary colors."}], add_generation_prompt=True)
out = generate(model, tok, prompt=p, max_tokens=int(os.environ.get("MAXTOK","48")), verbose=True)
print("LOAD_S=%.2f GEN_S=%.2f" % (t1-t0, time.time()-t1))
print("TOKENS_OK" if out and out.strip() else "TOKENS_EMPTY")
PY
# a UNIQUE kernel name every run => a genuinely COLD JIT Metal compile, not a
# cache hit. Without this the "no shader-cache write is needed" finding would be
# an artifact of a warm cache.
cat > "$W/jit.py" <<'PY'
import mlx.core as mx, uuid
n = "k3sm_s1_" + uuid.uuid4().hex[:12]
k = mx.fast.metal_kernel(name=n, input_names=["inp"], output_names=["out"],
      source="  uint i = thread_position_in_grid.x;\n  out[i] = inp[i] * 3.0f + 1.0f;\n")
a = mx.arange(64, dtype=mx.float32)
o = k(inputs=[a], grid=(64,1,1), threadgroup=(64,1,1), output_shapes=[a.shape], output_dtypes=[mx.float32])[0]
mx.eval(o); print("JIT_OK", n, float(o[7]))
PY
cat > "$W/cacheprobe.py" <<'PY'
import os
c = os.popen("getconf DARWIN_USER_CACHE_DIR").read().strip()
for d in ["com.apple.metalfe", "com.apple.metal"]:
    p = os.path.join(c, d)
    try: print("LIST_OK", d, len(os.listdir(p)))
    except Exception as e: print("LIST_DENIED", d, type(e).__name__)
    try:
        f = os.path.join(p, "k3sm_s1_probe.txt"); open(f,"w").write("x"); os.remove(f); print("WRITE_OK", d)
    except Exception as e: print("WRITE_DENIED", d, type(e).__name__)
PY
cat > "$W/dl.py" <<'PY'
import os, time
from huggingface_hub import snapshot_download
t0=time.time(); p = snapshot_download(os.environ["HF_MODEL"])
n=sum(os.path.getsize(os.path.join(r,f)) for r,_,fs in os.walk(p) for f in fs)
print("DOWNLOAD_OK %.1fs %.1fMB" % (time.time()-t0, n/1e6))
PY

# --- profile generator ----------------------------------------------------
# Mirrors runtimed/pkg/sandbox/sbpl.go Generate(): (version 1) -> (deny default)
# -> (import "system.sb") -> allows -> [network] -> protected denies -> narrow
# re-allows. $PREFIX lives under /Users, so the pod rootfs/data-volume analogues
# are re-allowed AFTER the (deny ... (subpath "/Users")) exactly as production
# re-allows the pod data volume after the protected denies.
mkp() { cat <<SB
;; k3sm M8.0/S1 spike profile — mirrors runtimed/pkg/sandbox/sbpl.go rule order.
(version 1)
(deny default)
(import "system.sb")
(allow process-exec*)
(allow process-fork)
(allow file-read* (subpath "/System") (subpath "/usr") (subpath "/bin") (subpath "/Library")
  (literal "/dev/null") (literal "/dev/zero") (literal "/dev/random") (literal "/dev/urandom"))
(allow file-write* (subpath "$POD") (literal "/dev/null"))
$1
(deny file-read* file-write* (subpath "/Users"))
(deny file-read* file-write* (subpath "/private/var/db"))
(deny file-write* (subpath "/System/Volumes/Preboot/Cryptexes") (subpath "/System/Cryptexes"))
(allow file-read* (subpath "/private/var/db/dyld"))
(allow file-read* (subpath "$PREFIX/venv") (subpath "$PREFIX/pyinstall") (subpath "$PREFIX/hf") (subpath "$W"))
(allow file-read* file-write* (subpath "$POD"))
SB
}
# denials <since> — the raw sandbox denial log for our interpreter. NOTE: on the
# lab Mac's zsh `log` is a SHELL BUILTIN; /usr/bin/log is mandatory or this
# silently reports "no denials" and the whole convergence is a lie.
denials() {
  sleep 2
  /usr/bin/log show --style compact --start "$1" \
    --predicate 'eventMessage CONTAINS "deny("' 2>/dev/null \
    | grep "Sandbox: python3.12" | sed -E 's/.*deny\(1\) //' | sort -u
}
run() { # run <name> <rules> <script>  -> prints verdict + denials
  local name="$1" rules="$2" script="$3" t0
  mkp "$rules" > "$PREFIX/sbpl/$name.sb"
  t0=$(date +"%Y-%m-%d %H:%M:%S"); sleep 1
  ( cd "$POD" && env -i HOME="$POD" TMPDIR="$POD/tmp" PATH=/usr/bin:/bin \
      MODEL_PATH="$MP" HF_HUB_OFFLINE=1 HF_HOME="$PREFIX/hf" \
      /usr/bin/sandbox-exec -f "$PREFIX/sbpl/$name.sb" "$V" "$script" 2>&1 ) \
    | grep -E "_OK|_EMPTY|Error" | tail -1 | sed "s/^/  $name => /"
  denials "$t0" | sed 's/^/      DENY /'
}

IOK='(allow iokit-open
  (iokit-registry-entry-class "AGXDeviceUserClient")
  (iokit-registry-entry-class "IOSurfaceRootUserClient"))'

echo "### probe0 — default-deny, NO GPU rules (harvest the raw denials)"
run probe0 ";; no GPU rules" "$W/gen.py"

echo "### ioreg — what the AGX registry actually exposes on this rig"
ioreg -l 2>/dev/null | grep -oE 'AGXAccelerator[A-Za-z0-9]*' | sort -u | sed 's/^/  service-class /'
"$V" -c 'import mlx.core as mx; d=mx.device_info(); print("  mlx device_info:", d)'

echo "### matrix — candidate rule spellings (R22 primary job)"
run rule-prefix-R22   '(allow iokit-open (iokit-registry-entry-class-prefix "AGXAcceleratorG"))' "$W/jit.py"
run rule-prefix-uc    '(allow iokit-open (iokit-registry-entry-class-prefix "AGXDeviceUserClient"))' "$W/jit.py"
run rule-exact-pair   "$IOK" "$W/jit.py"
run rule-open-bare    '(allow iokit-open)' "$W/jit.py"

echo "### minimal — the converged allow-set, full generation + COLD JIT compile"
run minimal-gen "$IOK" "$W/gen.py"
run minimal-jit "$IOK" "$W/jit.py"

echo "### ablate — is each extra candidate rule load-bearing? (over-scope check)"
run ablate-plus-mtlcompiler "$IOK
(allow mach-lookup (global-name \"com.apple.MTLCompilerService\"))" "$W/jit.py"
run ablate-plus-getprops "$IOK
(allow iokit-get-properties)" "$W/gen.py"

echo "### cache — can the confined pod reach the SHARED shader cache?"
run cacheprobe "$IOK" "$W/cacheprobe.py"

echo "### egress — exit criterion 2, SBPL half (R21 allow_internet_egress stanza)"
NET=';; network: ALLOWED — unfiltered outbound+bind+inbound under (deny default).
;; macOS 26 Seatbelt accepts only localhost/* hosts in network filters;
;; per-IP scoping (VIP egress, per-pod-IP bind) does NOT compile.
(allow network-outbound)
(allow network-bind)
(allow network-inbound)
;; mach-lookup the DNS resolver path (mDNSResponder) needs.
(allow mach-lookup
  (global-name "com.apple.dnssd.service")
  (global-name "com.apple.mDNSResponder"))'
rm -rf "$POD/hf2"; mkdir -p "$POD/hf2"
mkp "$IOK
$NET" > "$PREFIX/sbpl/egress.sb"
T0=$(date +"%Y-%m-%d %H:%M:%S"); sleep 1
( cd "$POD" && env -i HOME="$POD" TMPDIR="$POD/tmp" PATH=/usr/bin:/bin HF_HOME="$POD/hf2" HF_MODEL="$MODEL_S1" \
    /usr/bin/sandbox-exec -f "$PREFIX/sbpl/egress.sb" "$V" "$W/dl.py" 2>&1 ) | grep -E "DOWNLOAD_OK|Error" | tail -1 | sed 's/^/  egress => /'
denials "$T0" | sed 's/^/      DENY /'

echo "### criterion 2, PRODUCTION-DATAPATH half"
echo "  see findings-s1.md — 'k3sm dev up' rootless is network=none (datapath"
echo "  INERT) and --datapath requires euid 0, which the M8.0 lab guardrails and"
echo "  this dispatch's no-root exclusion forbid. Recorded ATTEMPTED-BLOCKED."
EOF

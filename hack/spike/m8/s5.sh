#!/usr/bin/env bash
# M8.0-d5 / S5 — serving-engine bake-off: vllm-mlx vs oMLX vs mlx-lm.
#
# The M8 plan's working hypothesis for the M8.4 image is vllm-mlx. This spike
# ratifies or replaces it with measurements, on the real rig, of the six axes the
# plan names — plus one it does not, which turns out to decide the question.
#
#   tok/s                generation throughput, same model, same prompt
#   OpenAI-API fidelity  /v1/chat/completions (non-stream + SSE) and /v1/models
#   /health surface      what a k8s readiness probe can actually target
#   license              and whether it is machine-readable from the artifact
#   wheel footprint      the venv delta, against the S4 >2 GB image threshold
#   process model        LOAD-BEARING: S3(5) proved the sampler's leader-PID-only
#                        walk under-counts a forking engine 3.9x, so an engine
#                        that forks costs an M8.2 pgid-enumeration deliverable
#   PACKAGEABILITY       (the extra axis) whether the engine can be installed
#                        from a hash-pinned lockfile at all, which M8.4-d1
#                        REQUIRES (`uv pip install --require-hashes`)
#
# Each engine gets its OWN venv under the prefix so the footprints do not share
# and the process trees cannot be confused. Anything that will not install is
# not skipped — the exact failure IS its verdict, and is recorded as such.
#
# Usage:
#   hack/spike/m8/s5.sh              # install (idempotent) + measure
#   hack/spike/m8/s5.sh --reinstall  # rebuild every engine venv from scratch
#   hack/spike/m8/s5.sh --only <e>   # one of: mlxlm vllmmlx omlx
#
# No sudo, no root, every write confined to $PREFIX. Servers bind 127.0.0.1 on
# ports 8181-8183 and are killed by process group at the end of each engine.
#
# Recorded verdict: findings-s5.md.
set -euo pipefail
cd "$(dirname "$0")"; . ./lib.sh

REINSTALL=0; ONLY=""
while [ $# -gt 0 ]; do
  case "$1" in
    --reinstall) REINSTALL=1; shift ;;
    --only) ONLY="${2:-}"; shift 2 ;;
    *) echo "unknown flag: $1" >&2; exit 2 ;;
  esac
done

lab5() { ssh "$HOST" "PREFIX=$PREFIX MODEL_S1=$MODEL_S1 REINSTALL=$REINSTALL ONLY='$ONLY' bash -s"; }

note "S5 — install each engine into its own venv, then measure the seven axes"
lab5 <<'EOF'
set -uo pipefail
export UV_CACHE_DIR=$PREFIX/cache UV_PYTHON_INSTALL_DIR=$PREFIX/pyinstall
UV=$PREFIX/bin/uv
ENG=$PREFIX/engines
mkdir -p "$ENG"
MP=$(ls -d "$PREFIX"/hf/hub/models--*Qwen2.5-0.5B*/snapshots/* | head -1)
export HF_HOME=$PREFIX/hf HF_HUB_OFFLINE=1

# The pinned oMLX revision. oMLX is NOT on PyPI, so a spike that said "install
# oMLX" would be measuring a moving target; this is the commit measured.
OMLX_REV=e008a66b4703bc77404dab30f8f898a117d49dfe

usedk() { df -k "$PREFIX" | awk 'NR==2{print $3}'; }

# conc.py — the concurrency probe, written out here so the spike is one file to
# copy. It reports EVERY request's outcome, not just an aggregate token count:
# "the engine batched 8 requests" and "7 of the 8 failed" are indistinguishable
# in an aggregate, and on this rig one engine really does the latter.
cat > "$PREFIX/logs/conc.py" <<'CONC'
import json, sys, threading, time, urllib.error, urllib.request

base, model, n = sys.argv[1], sys.argv[2], int(sys.argv[3])
body = json.dumps({
    "model": model,
    "messages": [{"role": "user", "content": "Write one paragraph about the sea."}],
    "max_tokens": 128, "stream": False, "temperature": 0.0,
}).encode()

res = [None] * n

def one(i):
    t0 = time.time()
    req = urllib.request.Request(base + "/v1/chat/completions", data=body,
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=300) as r:
            d = json.loads(r.read())
        res[i] = (r.status, (d.get("usage") or {}).get("completion_tokens"), time.time() - t0, "")
    except urllib.error.HTTPError as e:
        res[i] = (e.code, None, time.time() - t0, e.read()[:160].decode("utf-8", "replace"))
    except Exception as e:
        res[i] = (0, None, time.time() - t0, "%s: %s" % (type(e).__name__, e))

ts = [threading.Thread(target=one, args=(i,)) for i in range(n)]
t0 = time.time()
for t in ts:
    t.start()
for t in ts:
    t.join()
el = time.time() - t0

ok = [r for r in res if r[1]]
tot = sum(r[1] for r in ok)
print("      N=%-2d %6.2fs  %d/%d ok  %5d tokens  %7.1f tok/s aggregate"
      % (n, el, len(ok), n, tot, tot / el if el else 0))
per = {}
for code, ct, dt, err in res:
    k = (code, ct is not None, err.split(":")[0][:60])
    per[k] = per.get(k, 0) + 1
for (code, gotu, err), c in sorted(per.items()):
    print("        x%-2d http=%s usage=%s %s" % (c, code, gotu, err))
if ok:
    lat = sorted(r[2] for r in ok)
    print("        per-request latency: min %.2fs median %.2fs max %.2fs"
          % (lat[0], lat[len(lat) // 2], lat[-1]))
CONC

# ---------------------------------------------------------------- install ----
install_engine() { # install_engine <name> <port> <spec...>
  local e="$1"; shift; shift
  local d=$ENG/$e
  if [ "$REINSTALL" = 1 ]; then rm -rf "$d"; fi
  if [ -x "$d/venv/bin/python" ]; then echo "  $e: already installed"; return 0; fi
  mkdir -p "$d"
  "$UV" venv --python 3.12 "$d/venv" >/dev/null 2>&1
  local u0 t0 t1 u1
  u0=$(usedk); t0=$(date +%s.%N)
  if [ "$e" = omlx ]; then
    # Not on PyPI: `pip install -e .` from a clone is the ONLY route upstream
    # documents besides a .dmg and a brew tap. Pinned to a commit.
    rm -rf "$d/src"
    git clone -q https://github.com/jundot/omlx "$d/src" 2>&1 | tail -2
    git -C "$d/src" checkout -q "$OMLX_REV"
    "$UV" pip install --python "$d/venv/bin/python" "$d/src" 2>&1 | tail -2
  else
    "$UV" pip install --python "$d/venv/bin/python" "$@" 2>&1 | tail -2
  fi
  local rc=$?
  t1=$(date +%s.%N); u1=$(usedk)
  "$UV" pip freeze --python "$d/venv/bin/python" > "$d/freeze.txt" 2>/dev/null
  awk -v a="$t0" -v b="$t1" -v u0="$u0" -v u1="$u1" -v e="$e" -v rc="$rc" \
    'BEGIN{printf "  %s: install rc=%d %.1fs  used-KB %+d\n", e, rc, b-a, u1-u0}'
}

echo "### install"
[ -z "$ONLY" ] || echo "  (restricted to: $ONLY)"
run_engine() { [ -z "$ONLY" ] || [ "$ONLY" = "${1%%-*}" ]; }
run_engine mlxlm   && install_engine mlxlm   8181 "mlx-lm==0.31.3"
run_engine vllmmlx && install_engine vllmmlx 8182 "vllm-mlx==0.4.1"
run_engine omlx    && install_engine omlx    8183

# --------------------------------------------------------- packageability ----
# M8.4-d1 REQUIRES `uv pip install --require-hashes` against a checked-in
# lockfile. An engine whose dependency closure cannot be expressed with hashes
# cannot ship in the image at all, whatever its throughput.
echo
echo "### packageability — can the closure be pinned with --require-hashes?"
hashcheck() { # hashcheck <name> <requirement-source...>
  local e="$1"; shift
  local d=$ENG/$e
  [ -d "$d" ] || return 0
  local out
  out=$("$UV" pip compile --generate-hashes "$@" -o "$d/req-hashed.txt" 2>&1)
  if [ ! -s "$d/req-hashed.txt" ]; then
    printf '  %-8s COMPILE_FAILED: %s\n' "$e" "$(echo "$out" | tail -2 | tr '\n' ' ')"
    return 0
  fi
  printf '  %-8s compiled: %s packages, %s hashes' "$e" \
    "$(grep -cE '^[a-z0-9]' "$d/req-hashed.txt")" "$(grep -c -- '--hash' "$d/req-hashed.txt")"
  local vcs
  vcs=$(grep -c 'git+' "$d/req-hashed.txt")
  printf '  |  git+ direct-URL requirements: %s\n' "$vcs"
  grep 'git+' "$d/req-hashed.txt" | sed 's/^/      /'
  # The decisive test: actually install from it in hash-enforcing mode.
  rm -rf "$d/venv-rh"
  "$UV" venv --python 3.12 "$d/venv-rh" >/dev/null 2>&1
  out=$("$UV" pip install --python "$d/venv-rh/bin/python" --require-hashes -r "$d/req-hashed.txt" --dry-run 2>&1)
  if [ $? -eq 0 ]; then
    printf '  %-8s REQUIRE_HASHES=OK\n' "$e"
  else
    printf '  %-8s REQUIRE_HASHES=FAIL %s\n' "$e" "$(echo "$out" | grep -i error | head -1)"
  fi
  rm -rf "$d/venv-rh"
}
printf 'mlx-lm==0.31.3\n'  > "$ENG/mlxlm.in"
printf 'vllm-mlx==0.4.1\n' > "$ENG/vllmmlx.in"
run_engine mlxlm   && hashcheck mlxlm   "$ENG/mlxlm.in"
run_engine vllmmlx && hashcheck vllmmlx "$ENG/vllmmlx.in"
run_engine omlx    && hashcheck omlx    "$ENG/omlx/src/pyproject.toml"

# ----------------------------------------------------------- footprint -------
echo
echo "### footprint — venv on disk, against the S4 >2 GB unpacked image threshold"
for e in mlxlm vllmmlx omlx; do
  run_engine "$e" || continue
  d=$ENG/$e; [ -d "$d/venv" ] || continue
  app=$(find "$d/venv" -type f -exec stat -f '%z' {} + | awk '{s+=$1} END{printf "%d", s/1024}')
  # Mach-O count: S4 measured 41 for the mlx-lm payload and flagged that the
  # number re-opens with the S5 winner, because AdHocSignTree's cost and the
  # per-pod clonefile both scale with it (S4: ~130 us/entry, ~16 ms/sign).
  # LC_ALL=C: a wheel tree carries binary blobs (JPEG/EXIF test fixtures), and a
  # UTF-8 awk aborts on the first invalid sequence — which SIGPIPEs file(1) and
  # silently truncates the count (observed: 1 Mach-O reported for a 1 GB tree).
  find "$d/venv" -type f -print0 | xargs -0 file | LC_ALL=C awk -F: '/Mach-O/{print $1}' \
    | while IFS= read -r f; do [ -f "$f" ] && printf '%s\n' "$f"; done | sort -u > "$d/machos.txt"
  awk -v e="$e" -v k="$app" -v n="$(wc -l < "$d/freeze.txt" | tr -d ' ')" \
      -v m="$(find "$d/venv" -type f | wc -l | tr -d ' ')" \
      -v o="$(wc -l < "$d/machos.txt" | tr -d ' ')" \
    'BEGIN{printf "  %-8s %9d KB (%.2f GB)  %3d packages  %6d files  %4d Mach-O  ~%.1fs clone, ~%.1fs sign (S4 rates)\n", \
       e, k, k/1048576, n, m, o, m*0.000130, o*0.0164}'
done

# ------------------------------------------------------------- license -------
echo
echo "### license — declared, and machine-readable from the installed artifact?"
for e in mlxlm vllmmlx omlx; do
  run_engine "$e" || continue
  d=$ENG/$e; [ -d "$d/venv" ] || continue
  case "$e" in mlxlm) top=mlx_lm ;; vllmmlx) top=vllm_mlx ;; omlx) top=omlx ;; esac
  "$d/venv/bin/python" -c "
import importlib.metadata as m
for name in ('$top'.replace('_','-'), '$top'):
    try:
        md = m.metadata(name)
    except Exception:
        continue
    print('  %-8s dist=%s ver=%s' % ('$e', name, md['Version']))
    print('           License: %r' % (md.get('License') or md.get('License-Expression'),))
    print('           Classifier: %s' % [c for c in md.get_all('Classifier') or [] if 'License' in c])
    break
else:
    print('  $e   NO DIST METADATA')
" 2>&1
done

# -------------------------------------------------------------- serve --------
echo
echo "### serve — startup, endpoint surface, throughput, process model"
# set -m gives each background job its OWN process group, which is what makes the
# process-model measurement meaningful (and lets us kill the whole tree cleanly).
set -m 2>/dev/null || true

probe() { # probe <port> <path> -> "<code> <body-head>"
  local code body
  body=$(curl -s -m 10 -o "$PREFIX/logs/s5-body.json" -w '%{http_code}' "http://127.0.0.1:$1$2")
  echo "$body $(head -c 220 "$PREFIX/logs/s5-body.json" | tr -d '\n')"
}

serve_engine() { # serve_engine <name> <port> <model-id-for-requests> <argv...>
  local e="$1" port="$2" mid="$3"; shift 3
  # A "<name>-<variant>" engine reuses <name>'s venv: the variant is a serving
  # CONFIGURATION, not a second install, and giving it its own venv would double
  # the footprint number for no reason.
  local d=$ENG/${e%%-*} log=$PREFIX/logs/s5-$e.log
  [ -d "$d/venv" ] || { echo "  $e: NOT INSTALLED — see the install section"; return 0; }
  echo "  --- $e (port $port, model id $mid) ---"
  local stale; stale=$(lsof -ti "tcp:$port" 2>/dev/null | tr '\n' ' ')
  if [ -n "$stale" ]; then
    echo "    (killing stale listener(s) on $port: $stale)"
    kill $stale 2>/dev/null; sleep 2
  fi
  : > "$log"
  # exec, so the background job IS the server: a surviving wrapper shell would
  # be counted as a second process-group member and fake a MULTI_PROCESS verdict.
  ( cd "$d"; exec env HF_HOME="$PREFIX/hf" HF_HUB_OFFLINE=1 "$@" >>"$log" 2>&1 ) &
  local job=$!
  local pgid; pgid=$(ps -o pgid= -p "$job" 2>/dev/null | tr -d ' ')
  if [ -z "$pgid" ]; then echo "    STARTUP=FAILED (server exited immediately)"; tail -8 "$log" | sed 's/^/      /'; return 0; fi
  local t0 up=0 i
  t0=$(date +%s.%N)
  for i in $(seq 1 120); do
    if curl -s -m 2 -o /dev/null "http://127.0.0.1:$port/v1/models"; then up=1; break; fi
    kill -0 "$job" 2>/dev/null || break
    sleep 1
  done
  if [ "$up" != 1 ]; then
    awk -v a="$t0" -v b="$(date +%s.%N)" 'BEGIN{printf "    STARTUP=FAILED after %.0fs\n", b-a}'
    echo "    last log lines:"; tail -8 "$log" | sed 's/^/      /'
    kill -- -"$pgid" 2>/dev/null; wait "$job" 2>/dev/null
    return 0
  fi
  awk -v a="$t0" -v b="$(date +%s.%N)" 'BEGIN{printf "    STARTUP_S=%.1f (to a serving /v1/models)\n", b-a}'

  echo "    endpoints:"
  for p in /health /healthz /v1/models /metrics; do
    printf '      %-12s %s\n' "$p" "$(probe "$port" "$p" | cut -c1-150)"
  done

  # process model — the S3(5) axis. Count members of the server's process group
  # DURING generation, when a forking engine has its workers up.
  local body='{"model":"'"$mid"'","messages":[{"role":"user","content":"Write one paragraph about the sea."}],"max_tokens":128,"stream":false,"temperature":0.0}'
  ( curl -s -m 180 -H 'Content-Type: application/json' -d "$body" \
      "http://127.0.0.1:$port/v1/chat/completions" > "$PREFIX/logs/s5-$e-warm.json" ) &
  local warm=$!
  sleep 6
  echo "    process group $pgid during generation:"
  ps -o pid=,ppid=,pgid=,rss=,comm= -g "$pgid" 2>/dev/null | sed 's/^/      /'
  local nproc; nproc=$(ps -o pid= -g "$pgid" 2>/dev/null | wc -l | tr -d ' ')
  wait "$warm" 2>/dev/null
  echo "    PROCESS_MODEL: $nproc process(es) in the group -> $([ "$nproc" -le 1 ] && echo SINGLE_PROCESS || echo MULTI_PROCESS)"
  echo "    threads in the leader: $(ps -M -p "$job" 2>/dev/null | tail -n +2 | wc -l | tr -d ' ')"

  # throughput — 3 non-streaming runs, best of.
  # Two discarded warm-ups: the first requests of a fresh server pay Metal
  # pipeline setup and the engine's own lazy imports, which is a startup cost
  # already measured above, not a throughput number.
  for i in 1 2; do
    curl -s -m 180 -H 'Content-Type: application/json' -d "$body" \
      "http://127.0.0.1:$port/v1/chat/completions" > /dev/null
  done
  echo "    throughput (3 runs after 2 discarded warm-ups, 128 max_tokens, temp 0):"
  for i in 1 2 3; do
    local ts te
    ts=$(date +%s.%N)
    curl -s -m 180 -H 'Content-Type: application/json' -d "$body" \
      "http://127.0.0.1:$port/v1/chat/completions" > "$PREFIX/logs/s5-$e-gen.json"
    te=$(date +%s.%N)
    "$ENG/mlxlm/venv/bin/python" - "$PREFIX/logs/s5-$e-gen.json" "$ts" "$te" <<'PY'
import json, sys
try:
    d = json.load(open(sys.argv[1]))
except Exception as e:
    print("      run: BAD JSON %s" % e); raise SystemExit
el = float(sys.argv[3]) - float(sys.argv[2])
u = d.get("usage") or {}
ct = u.get("completion_tokens")
print("      run: %.2fs  completion_tokens=%s  %s tok/s  finish=%s"
      % (el, ct, ("%.1f" % (ct / el)) if ct else "n/a",
         (d.get("choices") or [{}])[0].get("finish_reason")))
PY
  done

  # streaming — TTFT and the SSE shape
  echo "    streaming (SSE):"
  local sbody; sbody=$(echo "$body" | sed 's/"stream":false/"stream":true/')
  local ts; ts=$(date +%s.%N)
  curl -s -N -m 120 -H 'Content-Type: application/json' -d "$sbody" \
    "http://127.0.0.1:$port/v1/chat/completions" > "$PREFIX/logs/s5-$e-stream.txt" 2>&1 &
  local sp=$!
  local first=""
  for i in $(seq 1 600); do
    if [ -s "$PREFIX/logs/s5-$e-stream.txt" ]; then first=$(date +%s.%N); break; fi
    sleep 0.05
  done
  wait "$sp" 2>/dev/null
  [ -n "$first" ] && awk -v a="$ts" -v b="$first" 'BEGIN{printf "      TTFB_S=%.2f\n", b-a}'
  echo "      first SSE lines:"; head -c 400 "$PREFIX/logs/s5-$e-stream.txt" | head -3 | sed 's/^/        /'
  echo "      done marker: $(grep -c 'data: \[DONE\]' "$PREFIX/logs/s5-$e-stream.txt" 2>/dev/null)"

  # Concurrency scaling — the axis the working hypothesis actually rests on.
  # "Continuous batching" is a claim about what happens when N requests overlap;
  # a single-stream tok/s number cannot distinguish an engine that batches from
  # one that serializes. Aggregate tok/s that stays FLAT as N rises means the
  # engine is serializing; near-linear means it is batching.
  echo "    concurrency scaling (aggregate tok/s over N overlapping requests):"
  for n in 1 4 8; do
    "$ENG/mlxlm/venv/bin/python" "$PREFIX/logs/conc.py" "http://127.0.0.1:$port" "$mid" "$n"
  done

  # OpenAI-surface fidelity — the four behaviours a drop-in client depends on.
  echo "    OpenAI-surface fidelity:"
  printf '      %-26s %s\n' "POST /v1/completions" \
    "$(curl -s -m 60 -o /dev/null -w '%{http_code}' -H 'Content-Type: application/json' \
        -d '{"model":"'"$mid"'","prompt":"The sea is","max_tokens":8}' \
        "http://127.0.0.1:$port/v1/completions")"
  printf '      %-26s %s\n' "unknown model -> code" \
    "$(curl -s -m 60 -o "$PREFIX/logs/s5-err.json" -w '%{http_code}' -H 'Content-Type: application/json' \
        -d '{"model":"no/such-model","messages":[{"role":"user","content":"hi"}],"max_tokens":4}' \
        "http://127.0.0.1:$port/v1/chat/completions")  body=$(head -c 120 "$PREFIX/logs/s5-err.json" | tr -d '\n')"
  printf '      %-26s %s\n' "non-stream usage keys" \
    "$("$ENG/mlxlm/venv/bin/python" -c "
import json,sys
try: print(sorted((json.load(open(sys.argv[1])).get('usage') or {}).keys()))
except Exception as ex: print('unavailable: %s' % ex)" "$PREFIX/logs/s5-$e-gen.json")"
  curl -s -N -m 120 -H 'Content-Type: application/json' \
    -d '{"model":"'"$mid"'","messages":[{"role":"user","content":"hi"}],"max_tokens":16,"stream":true,"stream_options":{"include_usage":true}}' \
    "http://127.0.0.1:$port/v1/chat/completions" > "$PREFIX/logs/s5-$e-usage.txt" 2>&1
  printf '      %-26s %s\n' "stream_options.include_usage" \
    "$(grep -c '"usage": *{[^n]' "$PREFIX/logs/s5-$e-usage.txt" 2>/dev/null | tr -d ' ') chunk(s) carrying a usage object"

  # /v1/models shape
  echo "    /v1/models shape:"
  curl -s -m 10 "http://127.0.0.1:$port/v1/models" | "$ENG/mlxlm/venv/bin/python" -c "
import json,sys
try: d=json.load(sys.stdin)
except Exception as e: print('      unparseable: %s' % e); raise SystemExit
print('      top keys: %s' % sorted(d.keys()))
it=(d.get('data') or [{}])[0]
print('      entry keys: %s' % sorted(it.keys()))
print('      first id: %r' % it.get('id'))
"

  kill -- -"$pgid" 2>/dev/null
  wait "$job" 2>/dev/null
  sleep 2
}

# oMLX does NOT take a model reference: `omlx serve` discovers models as
# SUBDIRECTORIES of --model-dir, and the subdirectory name becomes the model id.
# That is a real packaging difference, not a CLI detail — see findings-s5.md.
OMLX_MODELS=$ENG/omlx/models
rm -rf "$OMLX_MODELS"; mkdir -p "$OMLX_MODELS"
ln -s "$MP" "$OMLX_MODELS/qwen05b"

run_engine mlxlm   && serve_engine mlxlm   8181 "$MODEL_S1" \
  "$ENG/mlxlm/venv/bin/mlx_lm.server" --model "$MODEL_S1" --port 8181
# vllm-mlx is measured TWICE. Continuous batching — the property the M8 plan's
# working hypothesis names — is OPT-IN there ("--continuous-batching: Enable
# continuous batching for multiple concurrent users (slower for single user)").
# Measuring only the default would understate it; measuring only the flag would
# hide that a default-configured pod 503s under concurrency.
run_engine vllmmlx && serve_engine vllmmlx 8182 "$MODEL_S1" \
  "$ENG/vllmmlx/venv/bin/vllm-mlx" serve "$MODEL_S1" --port 8182
run_engine vllmmlx && serve_engine vllmmlx-cb 8182 "$MODEL_S1" \
  "$ENG/vllmmlx/venv/bin/vllm-mlx" serve "$MODEL_S1" --port 8182 --continuous-batching
run_engine omlx    && serve_engine omlx    8183 "qwen05b" \
  "$ENG/omlx/venv/bin/omlx" serve --model-dir "$OMLX_MODELS" --port 8183

# `run_engine X && serve_engine X` is FALSE for every engine --only excluded, and
# the last such line would otherwise be the payload's exit status. M8.0-a1 wants
# every spike script to exit 0, so say so explicitly rather than by accident.
exit 0
EOF

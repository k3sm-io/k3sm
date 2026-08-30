#!/usr/bin/env bash
# M8.0-d3 / S3 — memory visibility and growth for an MLX serving process.
#
# Feeds runtimed M8.2-d5's contingency and the M8.5 sizing formula. The five
# questions of the M8 plan §M8.0 S3, in order:
#   (1) visibility     does ri_phys_footprint — the OOM watcher's input,
#                      runtimed/pkg/supervisor/sampler.go — see the Metal /
#                      unified-memory working set at all?
#   (2) growth         KV-cache footprint growth over a sustained generation
#   (3) split          the mmap-weights vs MTLBuffer split: footprint vs RSS
#                      under a pure-MTLBuffer allocation with no file backing
#   (4) killer order   what fires past the Metal wired limit — our sampler, the
#                      allocator, or jetsam? BOUNDED probe only: a hard GiB cap
#                      and an abort guard on kern.memorystatus_level. This
#                      deliberately does NOT drive the machine into real
#                      pressure (M8.0 guardrail: never destabilize the lab).
#   (5) group coverage does the sampler's leader-PID-only walk cover a forking
#                      engine, and does proc_listpids(PROC_PGRP_ONLY) fix it?
#                      (Res. 18's pre-authorized contingency.)
#
# The sampler harness (s3mem.go) mirrors runtimed/pkg/supervisor/rusage_darwin.go
# exactly — proc_pid_rusage(RUSAGE_INFO_V2).ri_phys_footprint — so a divergence
# here would be a divergence in production.
#
# Recorded verdict: findings-s3.md.
set -euo pipefail
cd "$(dirname "$0")"; . ./lib.sh

note "S3 — build the rusage sampler, then run the four measurements"
lab <<'EOF'
set -uo pipefail
W=$PREFIX/work; POD=$W/pod; V=$PREFIX/venv/bin/python
GO=${GO:-/opt/homebrew/bin/go}
mkdir -p "$W/s3" "$POD/tmp" "$PREFIX/logs" "$PREFIX/bin"

cat > "$W/s3/main.go" <<'GO'
// s3mem — M8.0/S3 spike sampler. Mirrors runtimed/pkg/supervisor/rusage_darwin.go
// (proc_pid_rusage(RUSAGE_INFO_V2).ri_phys_footprint) and adds the process-GROUP
// walk S3(5) needs: proc_listpids(PROC_PGRP_ONLY, getpgid(pid)).
package main

/*
#include <libproc.h>
#include <sys/resource.h>
#include <unistd.h>
#include <errno.h>
static int k3sm_rusage(int pid, uint64_t *fp, uint64_t *res) {
  struct rusage_info_v2 ri;
  if (proc_pid_rusage(pid, RUSAGE_INFO_V2, (rusage_info_t *)&ri) != 0) return errno ? errno : -1;
  *fp = (uint64_t)ri.ri_phys_footprint;
  *res = (uint64_t)ri.ri_resident_size;
  return 0;
}
static int k3sm_pgrp(int pgid, int *buf, int cap) {
  return proc_listpids(PROC_PGRP_ONLY, (uint32_t)pgid, buf, cap * (int)sizeof(int));
}
static int k3sm_getpgid(int pid) { return (int)getpgid((pid_t)pid); }
*/
import "C"

import (
	"fmt"
	"os"
	"strconv"
	"time"
	"unsafe"
)

func footprint(pid int) (uint64, uint64, error) {
	var fp, res C.uint64_t
	if rc := C.k3sm_rusage(C.int(pid), &fp, &res); rc != 0 {
		return 0, 0, fmt.Errorf("proc_pid_rusage(%d): errno %d", pid, int(rc))
	}
	return uint64(fp), uint64(res), nil
}

func pgrp(pgid int) []int {
	const capacity = 512
	buf := make([]C.int, capacity)
	n := C.k3sm_pgrp(C.int(pgid), (*C.int)(unsafe.Pointer(&buf[0])), C.int(capacity))
	if n <= 0 {
		return nil
	}
	var out []int
	for i := 0; i < int(n)/4; i++ {
		if buf[i] != 0 {
			out = append(out, int(buf[i]))
		}
	}
	return out
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: s3mem <pid> [interval_ms] [count]")
		os.Exit(2)
	}
	pid, _ := strconv.Atoi(os.Args[1])
	iv := 500
	if len(os.Args) > 2 {
		iv, _ = strconv.Atoi(os.Args[2])
	}
	count := 0
	if len(os.Args) > 3 {
		count, _ = strconv.Atoi(os.Args[3])
	}
	fmt.Println("t_ms,pid,phys_footprint,resident_size,pgrp_pids,pgrp_footprint_sum")
	t0 := time.Now()
	for i := 0; count == 0 || i < count; i++ {
		fp, res, err := footprint(pid)
		if err != nil {
			fmt.Fprintln(os.Stderr, "STOP:", err)
			return
		}
		members := pgrp(int(C.k3sm_getpgid(C.int(pid))))
		var sum uint64
		for _, m := range members {
			if f, _, e := footprint(m); e == nil {
				sum += f
			}
		}
		fmt.Printf("%d,%d,%d,%d,%d,%d\n", time.Since(t0).Milliseconds(), pid, fp, res, len(members), sum)
		time.Sleep(time.Duration(iv) * time.Millisecond)
	}
}
GO

echo "### build s3mem (CGO, public libproc — the rusage_darwin.go pattern)"
( cd "$W/s3" && export GOPATH=$W/gopath GOCACHE=$W/gocache GOMODCACHE=$W/gomodcache
  [ -f go.mod ] || "$GO" mod init k3sm.io/spike/s3mem >/dev/null 2>&1
  CGO_ENABLED=1 "$GO" build -o "$PREFIX/bin/s3mem" . ) || { echo "BUILD FAILED"; exit 1; }
echo "  built $($PREFIX/bin/s3mem 2>&1 | head -0; echo ok) $(ls -l "$PREFIX/bin/s3mem" | awk '{print $5" bytes"}')"

mb() { awk -F, 'NR==1{next}{printf "  t=%-6s fp=%8.1fMB rss=%8.1fMB pgrp_n=%s pgrp_sum=%8.1fMB\n",$1,$3/1048576,$4/1048576,$5,$6/1048576}' "$1"; }

# ---------------------------------------------------------------- (1)(2) ---
cat > "$W/s3gen.py" <<'PY'
import os, time
import mlx.core as mx
from mlx_lm import load, stream_generate
mp = os.environ["MODEL_PATH"]; MAX = int(os.environ.get("MAXTOK","1200"))
print("PID", os.getpid(), flush=True)
t0=time.time(); model, tok = load(mp)
print("PHASE loaded t=%.2f mlx_active=%d mlx_peak=%d" % (time.time()-t0, mx.get_active_memory(), mx.get_peak_memory()), flush=True)
time.sleep(2)
p = tok.apply_chat_template([{"role":"user","content":"Write a long, detailed technical essay about distributed systems consensus. Be exhaustive."}], add_generation_prompt=True)
n=0
for _ in stream_generate(model, tok, prompt=p, max_tokens=MAX):
    n += 1
    if n % 200 == 0:
        print("TOK %d t=%.2f mlx_active=%d mlx_peak=%d mlx_cache=%d" % (n, time.time()-t0, mx.get_active_memory(), mx.get_peak_memory(), mx.get_cache_memory()), flush=True)
print("DONE tokens=%d mlx_active=%d mlx_peak=%d" % (n, mx.get_active_memory(), mx.get_peak_memory()), flush=True)
time.sleep(3)
PY
MP3=$(ls -d "$PREFIX"/hf/hub/models--*Llama-3.2-3B*/snapshots/* 2>/dev/null | head -1)
if [ -z "$MP3" ]; then
  echo "### fetching $MODEL_S3 (<=2 GB cap)"
  HF_HOME=$PREFIX/hf "$V" -c "from huggingface_hub import snapshot_download; print(snapshot_download('$MODEL_S3'))"
  MP3=$(ls -d "$PREFIX"/hf/hub/models--*Llama-3.2-3B*/snapshots/* | head -1)
fi
echo "### (1)(2) visibility + sustained-generation growth — $MODEL_S3, 1200 tokens, under the S1 profile"
( cd "$POD" && env -i HOME="$POD" TMPDIR="$POD/tmp" PATH=/usr/bin:/bin MODEL_PATH="$MP3" \
    HF_HUB_OFFLINE=1 HF_HOME="$PREFIX/hf" MAXTOK=1200 \
    /usr/bin/sandbox-exec -f "$PREFIX/sbpl/minimal.sb" "$V" "$W/s3gen.py" > "$PREFIX/logs/s3-gen.log" 2>&1 ) &
BG=$!; sleep 2
PY=$(grep -m1 '^PID ' "$PREFIX/logs/s3-gen.log" | awk '{print $2}')
"$PREFIX/bin/s3mem" "$PY" 500 0 > "$PREFIX/logs/s3-trace.csv" 2>/dev/null
wait $BG
grep -E 'PHASE|TOK|DONE' "$PREFIX/logs/s3-gen.log" | sed 's/^/  /'
mb "$PREFIX/logs/s3-trace.csv"

# ------------------------------------------------------------------ (3)(4) --
cat > "$W/s3probe.py" <<'PY'
# BOUNDED memory probe. HARD CAP $CAP_GB GiB, aborts if kern.memorystatus_level
# (system free-%) drops below 20 -- never induces a real jetsam event.
import mlx.core as mx, os, subprocess, time
CAP = int(os.environ.get("CAP_GB","16")); STEP = 2
WIRED = float(os.environ.get("WIRED_GB","0"))
def lvl(): return int(subprocess.run(["/usr/sbin/sysctl","-n","kern.memorystatus_level"],capture_output=True,text=True).stdout.strip() or 0)
print("PID", os.getpid(), "start_level", lvl(), flush=True)
if WIRED > 0:
    mx.set_wired_limit(int(WIRED*2**30)); print("WIRED_LIMIT_SET %.1fGB" % WIRED, flush=True)
held=[]; g=0
try:
    while g < CAP:
        a = mx.zeros((STEP*2**30//4,), dtype=mx.float32); mx.eval(a); held.append(a); g += STEP
        l = lvl(); print("STEP %dGB mlx_active=%.2fGB level=%d" % (g, mx.get_active_memory()/2**30, l), flush=True)
        if l < 20: print("ABORT low memorystatus_level=%d" % l, flush=True); break
        time.sleep(1)
except Exception as e:
    print("ALLOC_EXC %s: %s at %dGB" % (type(e).__name__, e, g), flush=True)
print("HOLD_DONE held=%dGB level=%d" % (g, lvl()), flush=True)
time.sleep(4)
PY
probe() { # probe <name> <cap_gb> <wired_gb>
  local n="$1" t0
  t0=$(date +"%Y-%m-%d %H:%M:%S")
  ( cd "$POD" && env -i HOME="$POD" TMPDIR="$POD/tmp" PATH=/usr/bin:/usr/sbin:/bin CAP_GB="$2" WIRED_GB="$3" \
      /usr/bin/sandbox-exec -f "$PREFIX/sbpl/minimal.sb" "$V" "$W/s3probe.py" > "$PREFIX/logs/s3-$n.log" 2>&1 ) &
  local bg=$!; sleep 2
  local p; p=$(grep -m1 '^PID ' "$PREFIX/logs/s3-$n.log" | awk '{print $2}')
  "$PREFIX/bin/s3mem" "$p" 1000 14 > "$PREFIX/logs/s3-$n.csv" 2>/dev/null
  wait $bg
  grep -E 'WIRED|STEP|ABORT|EXC|HOLD' "$PREFIX/logs/s3-$n.log" | sed 's/^/  /'
  mb "$PREFIX/logs/s3-$n.csv"
  echo "  jetsam events in window:"
  /usr/bin/log show --style compact --start "$t0" --predicate 'eventMessage CONTAINS "jetsam"' 2>/dev/null \
    | grep -v 'log run noninteractively' | tail -n +2 | head -5 | sed 's/^/    /' || true
}
echo "### (4) killer order — Metal wired limit set to 1 GB, allocate 8 GB past it"
probe probeA 8 1
echo "### (3) footprint vs RSS for a pure MTLBuffer working set — bounded 24 GB ramp"
probe probeB 24 0

# --------------------------------------------------------------------- (5) --
cat > "$W/s3fork.py" <<'PY'
import os, time
print("PID", os.getpid(), "PGID", os.getpgid(0), flush=True)
kids=[]
for _ in range(2):
    if os.fork()==0:
        b=bytearray(300*1024*1024); b[::4096]=b"\x01"*(len(b)//4096); time.sleep(8); os._exit(0)
    kids.append(_)
b=bytearray(200*1024*1024); b[::4096]=b"\x01"*(len(b)//4096); time.sleep(8)
PY
echo "### (5) process-group coverage — leader holds 200 MB, two forked children hold 300 MB each"
( cd "$POD" && "$V" "$W/s3fork.py" > "$PREFIX/logs/s3-fork.log" 2>&1 ) &
BG=$!; sleep 3
FP=$(grep -m1 '^PID' "$PREFIX/logs/s3-fork.log" | awk '{print $2}')
echo "  leader=$FP children=$(pgrep -P "$FP" | tr '\n' ' ')"
"$PREFIX/bin/s3mem" "$FP" 1500 3 > "$PREFIX/logs/s3-fork.csv" 2>/dev/null
mb "$PREFIX/logs/s3-fork.csv"
wait $BG
EOF

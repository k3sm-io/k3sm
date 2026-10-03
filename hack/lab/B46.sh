#!/usr/bin/env bash
# k3sm B46 lab gate: real memory pressure on the control-plane Mac, two legs.
#
#   Leg 1 (eviction acts first): a BestEffort native pod fills incompressible
#   memory at a fixed rate on the server node. Pass iff the provider's eviction
#   manager evicts it BEFORE macOS's own out-of-swap kill acts:
#     l1.trip     a compressor or swap arm crossed its trip value (server log), so
#                 a fill too slow to reach any threshold fails instead of passing;
#     l1.event    one pod Evicted Event and exactly one node EvictionThresholdMet;
#     l1.status   the pod is Failed with reason Evicted;
#     l1.cond     MemoryPressure went True with a Message naming the firing signal;
#     l1.kernel   zero kernel "no paging space" / "swap exhaustion" lines over
#                 [fill start, pod Failed], and the compressor below 98% when the
#                 eviction was observed;
#     l1.release  MemoryPressure returns False and the memory-pressure taint clears.
#
#   Leg 2 (the kernel picks the pod): the same fill in kube-system with
#   priorityClassName system-node-critical, which the manager must skip but the
#   runtime still marks pcontrol-KILL at spawn:
#     l2.mark     the fill's post-exec pid reads (pbsi_flags & 0x600) == 0x600;
#     l2.skip     the manager logged the critical-pod skip and evicted nothing;
#     l2.kernel   a kernel line naming the fill's pid, later than the skip;
#     l2.sigkill  the container terminated on SIGKILL (exit 137).
#
#   After each leg (survival): every recorded control-plane pid unchanged, no
#   node ever NotReady, /readyz ok within 60 s, PRAGMA quick_check ok on the live
#   datastore, and the node / scheduler / controller-manager Leases renewed
#   without a gap.
#
# Exit codes (distinct on purpose; a gate that passes without running is a lie):
#   0  every assertion of the requested legs passed
#   1  an assertion failed, or the watchdog fired (a watchdog kill is never a pass)
#   2  a precondition refused the run (nothing was filled)
#   3  K3SM_LAB is unset: "LAB-PENDING: not a pass"
#
# The run is DRIVEN from another host (the worker) over SSH against the server,
# so the watchdog does not starve with the machine it watches. Nothing about the
# rig is hard-coded; every host fact comes from the environment:
#
#   K3SM_LAB=1                  required to run at all
#   K3SM_B46_SSH                ssh destination of the server (user@host or alias)
#   K3SM_B46_NODE               the server's Kubernetes node name
#   KUBECONFIG                  admin kubeconfig for the cluster (driving host)
#   K3SM_B46_MIN_NODES          nodes that must be Ready (default 2)
#   K3SM_B46_WORK_DIR           server work dir (default /var/lib/k3sm/server)
#   K3SM_B46_SERVER_LOG         server daemon log (default /var/log/k3sm/server.log)
#   K3SM_B46_REMOTE_DIR         server scratch dir for helpers + backups
#                               (default /var/tmp/k3sm-b46; must be traversable by
#                               the pod user, since the fill runs from it)
#   K3SM_B46_EVIDENCE           local evidence dir (default: a new mktemp dir)
#   K3SM_B46_RATE_MIB           fill rate, MiB/s (default 256)
#   K3SM_B46_WALL_SECONDS       per-leg wall clock and pod activeDeadlineSeconds
#                               (default 1200)
#   K3SM_B46_CP_PROCS           control-plane process names to pin by pid
#                               (default "kine kube-apiserver kube-controller-manager
#                               kube-scheduler zot")
#   K3SM_ARTIFACT, K3SM_RC_TAG  the binary under test, for the run-log header
#
# Workload delivery: the fill and the pcontrol reader are tiny C programs
# compiled on the server with cc into K3SM_B46_REMOTE_DIR, ad-hoc signed, and
# run by an `image: native` pod (the pattern the native acceptance gates use for
# host binaries). Nothing is read by the pod from a file it would need a
# ConfigMap for.
#
# Usage:
#   K3SM_LAB=1 K3SM_B46_SSH=... K3SM_B46_NODE=... hack/lab/B46.sh [--leg 1|2]
#   hack/lab/B46.sh --self-test
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
K3SM_ROOT="$(cd "$HERE/../.." && pwd)"
SELF="$HERE/B46.sh"
GATE_NAME="B46"
PENDING_TEXT="LAB-PENDING: not a pass"

LEG="all"
SELF_TEST=no
while [ $# -gt 0 ]; do
	case "$1" in
	--leg)
		[ $# -ge 2 ] || { echo "--leg needs 1 or 2" >&2; exit 2; }
		LEG="$2"; shift 2 ;;
	--leg=*) LEG="${1#--leg=}"; shift ;;
	--self-test) SELF_TEST=yes; shift ;;
	-h|--help) sed -n '2,60p' "$SELF"; exit 0 ;;
	*) echo "unknown argument: $1" >&2; exit 2 ;;
	esac
done
case "$LEG" in all|1|2) ;; *) echo "--leg must be 1 or 2 (got $LEG)" >&2; exit 2 ;; esac

# ── --self-test: the unset-K3SM_LAB contract, pinned ─────────────────────────────
# A copy of an older lab gate's "PENDING, exit 0" shape would turn this gate green
# without running. The self-test runs this script with K3SM_LAB unset and asserts
# the exact text AND exit 3, for every leg selector.
if [ "$SELF_TEST" = yes ]; then
	bad=0
	bash -n "$SELF" || { echo "self-test: $SELF does not parse" >&2; bad=1; }
	for args in "" "--leg 1" "--leg 2"; do
		rc=0
		# shellcheck disable=SC2086
		out="$(env -u K3SM_LAB bash "$SELF" $args 2>&1)" || rc=$?
		if [ "$rc" -ne 3 ]; then
			echo "self-test: '$args' with K3SM_LAB unset exited $rc, want 3" >&2; bad=1
		fi
		case "$out" in
		*"$PENDING_TEXT"*) ;;
		*) echo "self-test: '$args' with K3SM_LAB unset did not print '$PENDING_TEXT'" >&2; bad=1 ;;
		esac
	done
	if [ "$bad" -ne 0 ]; then
		echo "B46 self-test: FAIL"; exit 1
	fi
	echo "B46 self-test: PASS (unset K3SM_LAB -> exit 3 + '$PENDING_TEXT')"
	exit 0
fi

# ── Lab guard ─────────────────────────────────────────────────────────────────────
if [ "${K3SM_LAB:-}" != "1" ]; then
	echo "B46 lab gate: $PENDING_TEXT. Set K3SM_LAB=1 and point K3SM_B46_SSH / K3SM_B46_NODE at the server to run it."
	exit 3
fi

# ── Knobs ─────────────────────────────────────────────────────────────────────────
SSH_DEST="${K3SM_B46_SSH:-}"
NODE="${K3SM_B46_NODE:-}"
MIN_NODES="${K3SM_B46_MIN_NODES:-2}"
WORK_DIR="${K3SM_B46_WORK_DIR:-/var/lib/k3sm/server}"
STATE_DB="$WORK_DIR/db/state.db"
SERVER_LOG="${K3SM_B46_SERVER_LOG:-/var/log/k3sm/server.log}"
RDIR="${K3SM_B46_REMOTE_DIR:-/var/tmp/k3sm-b46}"
EV="${K3SM_B46_EVIDENCE:-}"
RATE_MIB="${K3SM_B46_RATE_MIB:-256}"
WALL="${K3SM_B46_WALL_SECONDS:-1200}"
CP_PROCS="${K3SM_B46_CP_PROCS:-kine kube-apiserver kube-controller-manager kube-scheduler zot}"
NS1="${K3SM_B46_NAMESPACE:-default}"
NS2="kube-system"
RUN_TOKEN="b46-$(date -u +%Y%m%dT%H%M%SZ)-$$"
GIB=$((1 << 30))

[ -n "$EV" ] || EV="$(mktemp -d "${TMPDIR:-/tmp}/k3sm-b46-evidence.XXXXXX")"
mkdir -p "$EV"

PASS=0; FAIL=0
ladder() { if [ "$1" = ok ]; then echo "PASS  $2"; PASS=$((PASS+1)); else echo "FAIL  $2"; FAIL=$((FAIL+1)); fi; }
refuse() { echo "REFUSED  $*" >&2; FINAL_RC=2; exit 2; }
note() { echo "      $*"; }

# ── Run-log header (hack/lab/runs/README.md) ─────────────────────────────────────
artifact_sha256() {
	local a="${K3SM_ARTIFACT:-}" sum
	if [ -n "$a" ] && [ -f "$a" ]; then
		sum="$(shasum -a 256 "$a" | cut -d' ' -f1)"
		if [ -n "${K3SM_RC_TAG:-}" ]; then echo "$sum"; else echo "local:$sum"; fi
		return
	fi
	echo "unknown"
}
repo_git_sha() {
	local dir="$K3SM_ROOT/../$1"
	[ "$1" = k3sm ] && dir="$K3SM_ROOT"
	git -C "$dir" rev-parse HEAD 2>/dev/null || echo "unknown"
}
emit_run_log_header() {
	echo "# k3sm lab run log"
	echo "gate: $GATE_NAME"
	echo "mode: leg-$LEG"
	echo "rc_tag: ${K3SM_RC_TAG:-none}"
	echo "artifact_sha256: $(artifact_sha256)"
	local r
	for r in apis runtimed darwin-net k3sm; do echo "git_sha.$r: $(repo_git_sha "$r")"; done
	echo "started_utc: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
	echo "evidence_dir: $EV"
	echo "result: FAIL (provisional; the final result line below is the verdict, and a log that ends here did not finish)"
}
emit_run_log_verdict() {
	echo "gate: $GATE_NAME"
	echo "finished_utc: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
	echo "result: $1"
}
emit_run_log_header

# ── Remote helpers ────────────────────────────────────────────────────────────────
# rsh runs one command on the server in a login shell (the server's toolchain and
# PATH are set up by its profile). rsudo writes a script FILE on the server and
# runs that file under sudo: `ssh host "sudo a && b"` runs only `a` as root.
SSH_OPTS=(-o BatchMode=yes -o ConnectTimeout=10 -o ServerAliveInterval=5 -o ServerAliveCountMax=3)
rsh() { ssh "${SSH_OPTS[@]}" "$SSH_DEST" "zsh -lc $(printf '%q' "$1")"; }
rsudo() {
	local name="$1" body="$2"
	printf '%s\n' "set -eu" "$body" | ssh "${SSH_OPTS[@]}" "$SSH_DEST" "cat > $RDIR/$name.sh" &&
		rsh "sudo /bin/zsh $RDIR/$name.sh"
}
# Every apiserver call is bounded: a starved apiserver must not hang the
# watchdog, which exists to act exactly then.
kc() { kubectl --request-timeout=10s "$@"; }
server_now() { rsh "date '+%Y-%m-%d %H:%M:%S'"; }

FINAL_RC=1
WATCH_PID=""
FILL_PODS=""
SWAP_START=""
cleanup() {
	local rc=$?
	set +e
	[ "$FINAL_RC" = 2 ] && rc=2
	if [ -n "$WATCH_PID" ]; then kill "$WATCH_PID" 2>/dev/null; wait "$WATCH_PID" 2>/dev/null; fi
	for p in $FILL_PODS; do
		kc delete pod -n "${p%%/*}" "${p##*/}" --grace-period=0 --force --wait=false >/dev/null 2>&1
	done
	# An early refusal exits before bash has read the leg helpers below, so only
	# call them once they exist (nothing was armed or filled before that point).
	if [ -n "$SSH_DEST" ] && [ "$rc" != 3 ] && declare -F kill_fill >/dev/null; then
		disarm_deadman 1
		disarm_deadman 2
		kill_fill ""
	fi
	if [ -n "$SWAP_START" ]; then
		local used=""
		for _ in $(seq 1 120); do
			used="$(rsh "sysctl -n vm.swapusage" 2>/dev/null | sed -E 's/.*used = ([0-9.]+)M.*/\1/' | cut -d. -f1)"
			if [ -n "$used" ] && [ "$used" -le "$SWAP_START" ]; then break; fi
			sleep 5
		done
		if [ -z "$used" ] || [ "$used" -gt "$SWAP_START" ]; then
			echo "FAIL  cleanup: swap used ${used:-unknown} MiB did not fall back to its starting ${SWAP_START} MiB within 10 minutes"
			[ "$rc" = 0 ] && rc=1
		fi
	fi
	# Node readiness is checked and reported on EVERY exit path, a refused or
	# failed run included: the rig must be left Ready, and the log says whether
	# it was. Only a run that was otherwise passing turns red on it.
	if command -v kubectl >/dev/null 2>&1; then
		if all_nodes_ready; then
			echo "      cleanup: every node Ready at exit: yes"
		else
			echo "FAIL  cleanup: every node Ready at exit: no"
			[ "$rc" = 0 ] && rc=1
		fi
	else
		echo "      cleanup: every node Ready at exit: unknown (kubectl not on PATH)"
	fi
	echo "----------------------------------------"
	echo "B46: $PASS passed, $FAIL failed (evidence: $EV)"
	case "$rc" in
	0) emit_run_log_verdict PASS ;;
	*) emit_run_log_verdict FAIL ;;
	esac
	exit "$rc"
}
trap cleanup EXIT

all_nodes_ready() {
	local n ready
	n="$(kc get nodes --no-headers 2>/dev/null | wc -l | tr -d ' ')"
	ready="$(kc get nodes -o jsonpath='{range .items[*]}{.status.conditions[?(@.type=="Ready")].status}{"\n"}{end}' 2>/dev/null | grep -c '^True$' || true)"
	[ "${n:-0}" -ge "$MIN_NODES" ] && [ "$ready" = "$n" ]
}

# ── Preconditions (exit 2, never a skip) ──────────────────────────────────────────
[ -n "$SSH_DEST" ] || refuse "K3SM_B46_SSH is unset (the server's ssh destination)"
[ -n "$NODE" ] || refuse "K3SM_B46_NODE is unset (the server's node name)"
command -v kubectl >/dev/null 2>&1 || refuse "kubectl is not on PATH"
rsh true >/dev/null 2>&1 || refuse "ssh to the server failed"
# The run must be driven from ANOTHER host, so the watchdog does not starve with
# the machine it watches.
[ "$(rsh hostname 2>/dev/null | tr -d '[:space:]')" != "$(hostname | tr -d '[:space:]')" ] ||
	refuse "the driving host is the server; drive the run from another node"
all_nodes_ready || refuse "not every node is Ready (or fewer than $MIN_NODES nodes)"
[ "$(kc get --raw /readyz 2>/dev/null)" = "ok" ] || refuse "/readyz is not ok"
rsh "mkdir -p '$RDIR' && chmod 755 '$RDIR'" || refuse "cannot create $RDIR on the server"

# Control-plane pids, recorded by name; each must resolve to exactly one pid.
cp_pids() {
	local name pid
	for name in io.k3sm.server $CP_PROCS; do
		if [ "$name" = io.k3sm.server ]; then
			pid="$(rsudo lpid "launchctl print system/io.k3sm.server | awk '/^[[:space:]]*pid = /{print \$3; exit}'" 2>/dev/null | tr -d '[:space:]')"
		else
			# The oldest process whose argv[0] path ends in /<name>. The bracket keeps
			# the pattern from matching the remote shell that carries it.
			pid="$(rsh "pgrep -o -f '[/]$name( |\$)'" 2>/dev/null | tr -d '[:space:]')"
		fi
		echo "$name=${pid:-missing}"
	done
}
CP_BEFORE="$(cp_pids)"
printf '%s\n' "$CP_BEFORE" >"$EV/cp-pids-before.txt"
if grep -q '=missing$' "$EV/cp-pids-before.txt"; then
	refuse "a control-plane process is not running: $(grep '=missing$' "$EV/cp-pids-before.txt" | tr '\n' ' ')"
fi

# Datastore backup, verified.
rsudo backup "sqlite3 '$STATE_DB' \".backup '$RDIR/state.db.bak'\" && sqlite3 '$RDIR/state.db.bak' 'PRAGMA quick_check;'" \
	>"$EV/backup-quick-check.txt" 2>&1 || refuse "state.db backup failed (see $EV/backup-quick-check.txt)"
[ "$(tr -d '[:space:]' <"$EV/backup-quick-check.txt")" = "ok" ] || refuse "PRAGMA quick_check on the backup is not ok"

# A copy of the installed binary, for rollback.
rsudo binary "cp -p \"\$(command -v k3sm)\" '$RDIR/k3sm.pre-b46'" || refuse "could not copy the installed k3sm binary"

# Host readings, and the free-space floor.
rsh "sysctl hw.memsize hw.pagesize vm.compressor.pages_compressed_limit vm.compressor.segment.limit vm.swapusage; df -k /System/Volumes/Data /System/Volumes/VM" \
	>"$EV/host-readings.txt" 2>&1 || refuse "could not read the host's memory/compressor/swap sysctls"
MEMSIZE="$(rsh "sysctl -n hw.memsize" | tr -d '[:space:]')"
FREE_KIB="$(rsh "df -k /System/Volumes/Data | awk 'NR==2{print \$4}'" | tr -d '[:space:]')"
CEILING_BYTES=$((MEMSIZE + 30 * GIB))
NEED_KIB=$(((CEILING_BYTES + 30 * GIB) / 1024))
[ "${FREE_KIB:-0}" -ge "$NEED_KIB" ] || refuse "data volume has ${FREE_KIB} KiB free, need ${NEED_KIB} KiB (fill ceiling + 30 GiB)"
SWAP_START="$(rsh "sysctl -n vm.swapusage" | sed -E 's/.*used = ([0-9.]+)M.*/\1/' | cut -d. -f1)"
note "ceiling: $CEILING_BYTES bytes (RAM + 30 GiB) or 95% of either compressor limit; rate ${RATE_MIB} MiB/s; wall ${WALL}s"

# ── Helpers compiled on the server ───────────────────────────────────────────────
FILL_C='#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/sysctl.h>
#include <time.h>
#include <unistd.h>
/* b46-fill <rate-mib> <ceiling-bytes> <limit-pct> <deadline-s> <token>
 * Allocates incompressible memory (arc4random_buf on every page) at a fixed
 * rate, re-touches a rolling window so the pages stay in use, and stops
 * allocating at the byte ceiling or at limit-pct of either compressor limit,
 * then holds until the deadline. */
static uint64_t rd(const char *name) {
	uint64_t v = 0; size_t sz = sizeof v;
	if (sysctlbyname(name, &v, &sz, NULL, 0) != 0) return 0;
	if (sz == 4) { uint32_t w; memcpy(&w, &v, 4); return w; }
	return v;
}
int main(int argc, char **argv) {
	if (argc < 6) { fprintf(stderr, "usage: b46-fill rate-mib ceiling-bytes limit-pct deadline-s token\n"); return 2; }
	uint64_t rate = strtoull(argv[1], 0, 10) << 20, ceil = strtoull(argv[2], 0, 10);
	int lim = atoi(argv[3]); long dl = atol(argv[4]);
	size_t pg = (size_t)sysconf(_SC_PAGESIZE), chunk = (size_t)16 << 20;
	size_t cap = (size_t)(ceil / chunk) + 1, n = 0, touch = 0;
	char **chunks = calloc(cap, sizeof *chunks);
	time_t start = time(NULL); int held = 0;
	setvbuf(stdout, NULL, _IOLBF, 0);
	printf("b46-fill pid=%d token=%s start\n", getpid(), argv[5]);
	for (;;) {
		struct timespec t0, t1; clock_gettime(CLOCK_MONOTONIC, &t0);
		if (time(NULL) - start >= dl) { printf("b46-fill deadline\n"); return 0; }
		uint64_t pl = rd("vm.compressor.pages_compressed_limit"), sl = rd("vm.compressor.segment.limit");
		int pp = pl ? (int)(rd("vm.compressor.pages_compressed") * 100 / pl) : 0;
		int sp = sl ? (int)(rd("vm.compressor.segment.total") * 100 / sl) : 0;
		uint64_t have = (uint64_t)n * chunk;
		if (!held && (have >= ceil || pp >= lim || sp >= lim)) {
			held = 1; printf("b46-fill CEILING bytes=%llu pages_pct=%d segments_pct=%d\n", (unsigned long long)have, pp, sp);
		}
		if (!held) {
			size_t per = (size_t)(rate / chunk); if (per < 1) per = 1;
			for (size_t i = 0; i < per && n < cap; i++) {
				char *p = mmap(NULL, chunk, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, -1, 0);
				if (p == MAP_FAILED) { printf("b46-fill mmap failed\n"); held = 1; break; }
				for (size_t o = 0; o < chunk; o += pg) arc4random_buf(p + o, pg);
				chunks[n++] = p;
			}
		}
		for (int k = 0; k < 4 && n > 0; k++) {
			char *p = chunks[touch++ % n];
			for (size_t o = 0; o < chunk; o += pg) arc4random_buf(p + o, 8);
		}
		printf("b46-fill bytes=%llu pages_pct=%d segments_pct=%d\n", (unsigned long long)n * chunk, pp, sp);
		clock_gettime(CLOCK_MONOTONIC, &t1);
		long ns = (t1.tv_sec - t0.tv_sec) * 1000000000L + (t1.tv_nsec - t0.tv_nsec);
		if (ns < 1000000000L) { struct timespec r = {0, 1000000000L - ns}; nanosleep(&r, NULL); }
	}
}'
PCFLAGS_C='#include <libproc.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/proc_info.h>
/* b46-pcflags <pid>: prints the pid'"'"'s pbsi_flags (PROC_PIDT_SHORTBSDINFO) in hex. */
int main(int argc, char **argv) {
	if (argc < 2) return 2;
	struct proc_bsdshortinfo si;
	int n = proc_pidinfo(atoi(argv[1]), PROC_PIDT_SHORTBSDINFO, 0, &si, sizeof si);
	if (n != (int)sizeof si) { perror("proc_pidinfo"); return 1; }
	printf("0x%x\n", si.pbsi_flags);
	return 0;
}'
printf '%s\n' "$FILL_C" | ssh "${SSH_OPTS[@]}" "$SSH_DEST" "cat > $RDIR/b46-fill.c" || refuse "could not stage the fill source"
printf '%s\n' "$PCFLAGS_C" | ssh "${SSH_OPTS[@]}" "$SSH_DEST" "cat > $RDIR/b46-pcflags.c" || refuse "could not stage the pcflags source"
rsh "cd '$RDIR' && cc -O2 -o b46-fill b46-fill.c && cc -O2 -o b46-pcflags b46-pcflags.c && codesign -s - -f b46-fill b46-pcflags >/dev/null 2>&1 && chmod 755 b46-fill b46-pcflags" \
	>"$EV/compile.txt" 2>&1 || refuse "compiling the helpers on the server failed (see $EV/compile.txt)"

# ── The watchdog (driving host) and the deadman (server) ────────────────────────
# The watchdog samples once every 3 s into $EV/watch.tsv and fires (kills the fill
# pod's process group, records why) on: /readyz failing for 15 s, an ssh failure,
# the fill holding at its ceiling for 120 s with neither mechanism acting, or the
# leg's wall clock. A fired watchdog fails the run.
lease_renew() { kc get lease -n "$1" "$2" -o jsonpath='{.spec.renewTime}' 2>/dev/null || true; }
# fill_pattern <pod|""> is the pgrep -f pattern for this run's fill process(es):
# the helper's name and the run token on its argv. The bracket keeps it from
# matching any shell that carries the pattern text.
fill_pattern() { echo "[b]46-fill .*$RUN_TOKEN${1:+-$1}"; }
# kill_fill [pod] SIGKILLs this run's fill (one pod's, or every leg's). It kills
# the process GROUP only when that is provably the fill's own: never an empty,
# 0 or 1 pgid, and never the group of a recorded control-plane process or of the
# server daemon (which hosts the runtime). Otherwise it kills the pid alone, and
# only a pid whose comm is b46-fill.
kill_fill() {
	local protect
	protect="$(printf '%s\n' "$CP_BEFORE" | cut -d= -f2 | grep -E '^[0-9]+$' | tr '\n' ' ')"
	rsudo killfill "for p in \$(pgrep -f '$(fill_pattern "${1:-}")'); do
	c=\$(ps -o comm= -p \$p 2>/dev/null)
	[ \"\${c##*/}\" = b46-fill ] || continue
	g=\$(ps -o pgid= -p \$p 2>/dev/null | tr -d ' ')
	safe=1
	case \"\$g\" in ''|0|1) safe=0 ;; esac
	for cp in $protect; do
		cg=\$(ps -o pgid= -p \$cp 2>/dev/null | tr -d ' ')
		[ -n \"\$cg\" ] && [ \"\$cg\" = \"\$g\" ] && safe=0
	done
	if [ \$safe = 1 ]; then kill -KILL -- -\$g; else kill -KILL \$p; fi
done
true" >/dev/null 2>&1 || true
}
watchdog() {
	local ns="$1" pod="$2" deadline="$3" readyz_fail_since=0 readyz_bad=0 ceiling_at=0 now sys phase mp mpmsg ready
	: >"$EV/watch.tsv"
	while :; do
		# The /readyz failure window is wall-clock time since the first failed
		# probe, not a count of iterations: an iteration slowed by a starved host
		# must not stretch the window.
		if [ "$(kc get --raw /readyz 2>/dev/null)" = ok ]; then
			readyz_fail_since=0
		elif [ "$readyz_fail_since" -eq 0 ]; then
			readyz_fail_since="$(date +%s)"
		fi
		now="$(date +%s)"
		readyz_bad=0
		[ "$readyz_fail_since" -ne 0 ] && readyz_bad=$((now - readyz_fail_since))
		if ! sys="$(rsh "sysctl -n vm.compressor.pages_compressed vm.compressor.pages_compressed_limit vm.compressor.segment.total vm.compressor.segment.limit vm.swapusage | tr '\n' ' '" 2>/dev/null)"; then
			echo "ssh to the server failed" >"$EV/watchdog.fired"; kill_fill "$pod"; return
		fi
		phase="$(kc get pod -n "$ns" "$pod" -o jsonpath='{.status.phase}' 2>/dev/null || true)"
		mp="$(kc get node "$NODE" -o jsonpath='{.status.conditions[?(@.type=="MemoryPressure")].status}' 2>/dev/null || true)"
		mpmsg="$(kc get node "$NODE" -o jsonpath='{.status.conditions[?(@.type=="MemoryPressure")].message}' 2>/dev/null || true)"
		ready="$(kc get nodes -o jsonpath='{range .items[*]}{.status.conditions[?(@.type=="Ready")].status}{" "}{end}' 2>/dev/null || true)"
		printf '%s\treadyz_bad=%s\tsys=%s\tphase=%s\tmp=%s\tmpmsg=%s\tready=%s\tlease_node=%s\tlease_sched=%s\tlease_kcm=%s\n' \
			"$now" "$readyz_bad" "$sys" "$phase" "$mp" "$mpmsg" "$ready" \
			"$(lease_renew kube-node-lease "$NODE")" "$(lease_renew kube-system kube-scheduler)" \
			"$(lease_renew kube-system kube-controller-manager)" >>"$EV/watch.tsv"
		if [ "$readyz_bad" -ge 15 ]; then echo "/readyz failed for ${readyz_bad} s" >"$EV/watchdog.fired"; kill_fill "$pod"; return; fi
		if [ "$now" -ge "$deadline" ]; then echo "leg wall clock reached" >"$EV/watchdog.fired"; kill_fill "$pod"; return; fi
		if [ "$ceiling_at" -eq 0 ] && kc logs -n "$ns" "$pod" 2>/dev/null | grep -q 'b46-fill CEILING'; then ceiling_at="$now"; fi
		if [ "$ceiling_at" -ne 0 ] && [ "$phase" = Running ] && [ $((now - ceiling_at)) -ge 120 ]; then
			echo "fill held at its ceiling for 120 s and neither mechanism acted" >"$EV/watchdog.fired"; kill_fill "$pod"; return
		fi
		sleep 3
	done
}
# arm_deadman <leg> <pod>: a one-shot server-side deadman per leg. If the driver
# loses the server, that leg's fill (named by the run token) still dies at the
# wall clock plus a margin. disarm_deadman <leg> retires it, so leg 1's deadman
# can never fire into leg 2.
arm_deadman() {
	local leg="$1" pod="$2"
	rsudo "deadman-$leg" "cat > '$RDIR/b46-deadman-$leg' <<'EOF'
#!/bin/zsh
sleep \$1
pkill -KILL -f '$(fill_pattern "$pod")'
EOF
chmod 755 '$RDIR/b46-deadman-$leg'
nohup '$RDIR/b46-deadman-$leg' $((WALL + 300)) >/dev/null 2>&1 &" >/dev/null 2>&1 || refuse "could not arm the server-side deadman for leg $leg"
}
disarm_deadman() { rsudo "disarm-$1" "pkill -f '[b]46-deadman-$1' || true" >/dev/null 2>&1 || true; }

# ── The fill pod ──────────────────────────────────────────────────────────────────
make_fill_pod() {
	local ns="$1" name="$2" prio_line="$3"
	kc apply -f - >/dev/null <<EOF
apiVersion: v1
kind: Pod
metadata: {name: $name, namespace: $ns, labels: {k3sm.io/lab: b46}}
spec:
  nodeName: $NODE
  nodeSelector: {kubernetes.io/os: darwin}
  tolerations: [{key: k3sm.io/provider, operator: Exists, effect: NoSchedule}]
  restartPolicy: Never
  activeDeadlineSeconds: $WALL
$prio_line
  containers:
  - name: fill
    image: native
    command: ["$RDIR/b46-fill", "$RATE_MIB", "$CEILING_BYTES", "95", "$WALL", "$RUN_TOKEN-$name"]
EOF
	FILL_PODS="$FILL_PODS $ns/$name"
}
wait_running() {
	local ns="$1" name="$2"
	for _ in $(seq 1 60); do
		[ "$(kc get pod -n "$ns" "$name" -o jsonpath='{.status.phase}' 2>/dev/null)" = Running ] && return 0
		sleep 2
	done
	return 1
}
# fill_pid <pod>: the fill's pid, matched by helper name + run token (the
# bracket keeps the remote shell from matching itself), and accepted only if
# that pid's comm really is b46-fill.
fill_pid() {
	rsh "p=\$(pgrep -f '$(fill_pattern "$1")' | head -1); [ -n \"\$p\" ] || exit 0; c=\$(ps -o comm= -p \$p); [ \"\${c##*/}\" = b46-fill ] && echo \$p" 2>/dev/null | tr -d '[:space:]'
}
kernel_lines() {
	# kernel_lines <start> <end|""> : the kernel's out-of-swap lines over a window.
	local end_arg=""
	[ -n "$2" ] && end_arg="--end '$2'"
	rsudo klog "log show --style syslog --predicate 'sender == \"kernel\"' --start '$1' $end_arg | grep -Ei 'no paging space|swap exhaustion|low swap|killing largest compressed' || true"
}
# The server log is read from a byte offset taken when the leg starts, so only
# this leg's lines are searched whatever the log's timestamp format.
server_log_offset() { rsudo slogsize "stat -f %z '$SERVER_LOG'" 2>/dev/null | tr -d '[:space:]'; }
server_log_since() { rsudo slog "tail -c +$(($1 + 1)) '$SERVER_LOG'"; }

# survive <leg>: the survival assertions after a leg.
survive() {
	local leg="$1" after ok_readyz=no
	after="$(cp_pids)"
	printf '%s\n' "$after" >"$EV/cp-pids-after-leg$leg.txt"
	if [ "$after" = "$CP_BEFORE" ]; then ladder ok "l$leg.survive.pids  every control-plane pid unchanged"; else
		ladder no "l$leg.survive.pids  a control-plane pid changed ($(diff <(echo "$CP_BEFORE") <(echo "$after") | tr '\n' ' '))"; fi
	if awk -F'\t' '{ for (i=1;i<=NF;i++) if ($i ~ /^ready=/ && $i ~ /(False|Unknown)/) bad=1 } END { exit bad }' "$EV/watch.tsv"; then
		ladder ok "l$leg.survive.ready  no node went NotReady during the leg"
	else ladder no "l$leg.survive.ready  a node went NotReady during the leg (see $EV/watch.tsv)"; fi
	for _ in $(seq 1 30); do [ "$(kc get --raw /readyz 2>/dev/null)" = ok ] && { ok_readyz=yes; break; }; sleep 2; done
	if [ "$ok_readyz" = yes ]; then ladder ok "l$leg.survive.readyz  /readyz ok within 60 s"; else ladder no "l$leg.survive.readyz  /readyz not ok within 60 s"; fi
	if [ "$(rsudo qc "sqlite3 '$STATE_DB' 'PRAGMA quick_check;'" 2>/dev/null | tr -d '[:space:]')" = ok ]; then
		ladder ok "l$leg.survive.datastore  PRAGMA quick_check ok on the live state.db"
	else ladder no "l$leg.survive.datastore  PRAGMA quick_check NOT ok on the live state.db"; fi
	lease_gaps "$leg"
}
# lease_gaps <leg>: a Lease's renewTime must change at least every 40 s across the
# leg. The node Lease is mandatory; the scheduler and controller-manager Leases are
# checked when they exist (a single server may run without leader election).
lease_gaps() {
	local leg="$1" col label verdict
	for col in node sched kcm; do
		verdict="$(awk -F'\t' -v c="lease_$col=" '
			{ for (i=1;i<=NF;i++) if (index($i, c) == 1) v = substr($i, length(c) + 1)
			  if (v == "") { empty++; next }
			  if (v != last) { if (lastchange && $1 - lastchange > gap) gap = $1 - lastchange; lastchange = $1; last = v } }
			END { if (lastchange == 0) print "absent"; else print gap + 0 }' "$EV/watch.tsv")"
		label="lease $col"
		if [ "$verdict" = absent ]; then
			if [ "$col" = node ]; then ladder no "l$leg.survive.$label  the node Lease was never observed"; else note "l$leg.survive.$label  not present on this cluster (no leader election); recorded, not asserted"; fi
		elif [ "$verdict" -le 40 ]; then ladder ok "l$leg.survive.$label  renewed continuously (largest gap ${verdict}s)"
		else ladder no "l$leg.survive.$label  renewal gap ${verdict}s > 40s"; fi
	done
}

# ── Leg 1 ─────────────────────────────────────────────────────────────────────────
leg1() {
	local pod="b46-fill-1" uid start_srv start_epoch end_srv phase reason evicted_cnt etm comp_at mpmsg_seen taint log_off
	echo "==> B46 leg 1: eviction acts first ($NS1/$pod, BestEffort)"
	rm -f "$EV/watchdog.fired"
	arm_deadman 1 "$pod"
	log_off="$(server_log_offset)"; [ -n "$log_off" ] || refuse "cannot read the size of $SERVER_LOG"
	start_srv="$(server_now)"; start_epoch="$(date +%s)"
	make_fill_pod "$NS1" "$pod" ""
	wait_running "$NS1" "$pod" || { ladder no "l1.start  the fill pod never reached Running"; return 1; }
	uid="$(kc get pod -n "$NS1" "$pod" -o jsonpath='{.metadata.uid}')"
	watchdog "$NS1" "$pod" $((start_epoch + WALL)) &
	WATCH_PID=$!
	while :; do
		phase="$(kc get pod -n "$NS1" "$pod" -o jsonpath='{.status.phase}' 2>/dev/null || true)"
		[ "$phase" = Failed ] || [ "$phase" = Succeeded ] && break
		[ -f "$EV/watchdog.fired" ] && break
		sleep 2
	done
	end_srv="$(server_now)"
	kill "$WATCH_PID" 2>/dev/null; wait "$WATCH_PID" 2>/dev/null || true; WATCH_PID=""
	if [ -f "$EV/watchdog.fired" ]; then ladder no "l1.watchdog  fired: $(cat "$EV/watchdog.fired")"; return 1; fi
	ladder ok "l1.watchdog  did not fire"

	server_log_since "$log_off" >"$EV/leg1-server.log" 2>&1 || true
	if grep 'node memory pressure raised' "$EV/leg1-server.log" | grep -Eq 'signal=(compressor|swap)'; then
		ladder ok "l1.trip  a compressor or swap arm crossed its trip value"
	else ladder no "l1.trip  no compressor or swap trip recorded (a fill that never reached a threshold is not a pass)"; fi

	evicted_cnt="$(kc get events -n "$NS1" --field-selector "involvedObject.uid=$uid,reason=Evicted" --no-headers 2>/dev/null | wc -l | tr -d ' ')"
	etm="$(kc get events -A --field-selector "involvedObject.kind=Node,involvedObject.name=$NODE,reason=EvictionThresholdMet" \
		-o jsonpath='{range .items[*]}{.count}{" "}{.lastTimestamp}{"\n"}{end}' 2>/dev/null |
		awk -v s="$(date -u -r "$start_epoch" +%Y-%m-%dT%H:%M:%SZ)" '$2 >= s { n += ($1 ? $1 : 1) } END { print n + 0 }')"
	if [ "$evicted_cnt" -ge 1 ] && [ "$etm" = 1 ]; then ladder ok "l1.event  pod Evicted Event present; exactly one EvictionThresholdMet"
	else ladder no "l1.event  pod Evicted Events=$evicted_cnt, EvictionThresholdMet=$etm (want >=1 and exactly 1)"; fi

	reason="$(kc get pod -n "$NS1" "$pod" -o jsonpath='{.status.reason}' 2>/dev/null || true)"
	if [ "$phase" = Failed ] && [ "$reason" = Evicted ]; then ladder ok "l1.status  pod Failed/Evicted"
	else ladder no "l1.status  pod phase/reason = $phase/$reason, want Failed/Evicted"; fi

	mpmsg_seen="$(awk -F'\t' '$0 ~ /\tmp=True\t/ { for (i=1;i<=NF;i++) if ($i ~ /^mpmsg=/) print $i }' "$EV/watch.tsv" | grep -E 'compressor|swap|memory.available' | head -1)"
	if [ -n "$mpmsg_seen" ]; then ladder ok "l1.cond  MemoryPressure True naming its signal (${mpmsg_seen#mpmsg=})"
	else ladder no "l1.cond  MemoryPressure was never observed True with a signal-naming Message"; fi

	kernel_lines "$start_srv" "$end_srv" >"$EV/leg1-kernel.txt" 2>&1 || true
	comp_at="$(tail -1 "$EV/watch.tsv" | awk -F'\t' '{ for (i=1;i<=NF;i++) if ($i ~ /^sys=/) { split(substr($i,5), a, " "); p = a[2] ? int(a[1]*100/a[2]) : 0; s = a[4] ? int(a[3]*100/a[4]) : 0; print (p > s ? p : s) } }')"
	if [ ! -s "$EV/leg1-kernel.txt" ] && [ "${comp_at:-100}" -lt 98 ]; then
		ladder ok "l1.kernel  zero kernel out-of-swap lines over the window; compressor ${comp_at}% at the eviction"
	else ladder no "l1.kernel  kernel lines=$(wc -l <"$EV/leg1-kernel.txt" | tr -d ' ') compressor=${comp_at:-unknown}% (want 0 lines and <98%)"; fi

	for _ in $(seq 1 100); do
		[ "$(kc get node "$NODE" -o jsonpath='{.status.conditions[?(@.type=="MemoryPressure")].status}')" = False ] || { sleep 3; continue; }
		taint="$(kc get node "$NODE" -o jsonpath='{.spec.taints[*].key}')"
		case " $taint " in *" node.kubernetes.io/memory-pressure "*) sleep 3; continue ;; esac
		break
	done
	if [ "$(kc get node "$NODE" -o jsonpath='{.status.conditions[?(@.type=="MemoryPressure")].status}')" = False ] &&
		! kc get node "$NODE" -o jsonpath='{.spec.taints[*].key}' | grep -q 'node.kubernetes.io/memory-pressure'; then
		ladder ok "l1.release  MemoryPressure back to False and the taint cleared"
	else ladder no "l1.release  MemoryPressure or its taint did not clear within 5 minutes"; fi
	cp "$EV/watch.tsv" "$EV/leg1-watch.tsv"
	survive 1
}

# ── Leg 2 ─────────────────────────────────────────────────────────────────────────
leg2() {
	local pod="b46-fill-2" start_srv start_epoch pid flags skip_srv exitc log_off
	echo "==> B46 leg 2: the kernel picks the marked pod ($NS2/$pod, system-node-critical)"
	rm -f "$EV/watchdog.fired"
	disarm_deadman 1
	arm_deadman 2 "$pod"
	log_off="$(server_log_offset)"; [ -n "$log_off" ] || refuse "cannot read the size of $SERVER_LOG"
	start_srv="$(server_now)"; start_epoch="$(date +%s)"
	make_fill_pod "$NS2" "$pod" "  priorityClassName: system-node-critical"
	wait_running "$NS2" "$pod" || { ladder no "l2.start  the fill pod never reached Running"; return 1; }
	pid="$(fill_pid "$pod")"
	echo "fill pid: ${pid:-unknown}" >"$EV/leg2-pid.txt"
	flags="$(rsudo pcflags "'$RDIR/b46-pcflags' '$pid'" 2>/dev/null | tr -d '[:space:]')"
	if [ -n "$pid" ] && [[ "$flags" =~ ^0x[0-9a-fA-F]+$ ]] && [ $((flags & 0x600)) -eq $((0x600)) ]; then
		ladder ok "l2.mark  fill pid $pid reads pbsi_flags=$flags (pcontrol KILL)"
	else ladder no "l2.mark  fill pid ${pid:-unknown} reads pbsi_flags=${flags:-unreadable}, want (flags & 0x600) == 0x600"; fi
	watchdog "$NS2" "$pod" $((start_epoch + WALL)) &
	WATCH_PID=$!
	skip_srv=""
	while :; do
		if [ -z "$skip_srv" ] && server_log_since "$log_off" 2>/dev/null | grep 'cannot evict a critical pod' | grep -q "pod=$NS2/$pod"; then
			skip_srv="$(server_now)"
		fi
		exitc="$(kc get pod -n "$NS2" "$pod" -o jsonpath='{.status.containerStatuses[0].state.terminated.exitCode}' 2>/dev/null || true)"
		[ -n "$exitc" ] && break
		[ -f "$EV/watchdog.fired" ] && break
		sleep 2
	done
	kill "$WATCH_PID" 2>/dev/null; wait "$WATCH_PID" 2>/dev/null || true; WATCH_PID=""
	if [ -f "$EV/watchdog.fired" ]; then ladder no "l2.watchdog  fired: $(cat "$EV/watchdog.fired")"; return 1; fi
	ladder ok "l2.watchdog  did not fire"

	server_log_since "$log_off" >"$EV/leg2-server.log" 2>&1 || true
	if [ -n "$skip_srv" ] && ! grep 'eviction manager: evicting pod' "$EV/leg2-server.log" | grep -q "pod=$NS2/$pod"; then
		ladder ok "l2.skip  the manager logged the critical-pod skip and evicted nothing"
	else ladder no "l2.skip  skip logged=${skip_srv:+yes} / an eviction of the critical pod was logged"; fi

	if [ -n "$skip_srv" ] && [ -n "$pid" ]; then
		kernel_lines "$skip_srv" "" >"$EV/leg2-kernel.txt" 2>&1 || true
		if grep -Eq "pid[ =:]*$pid([^0-9]|$)|\\[$pid\\]|\\($pid\\)| $pid " "$EV/leg2-kernel.txt"; then
			ladder ok "l2.kernel  a kernel line names fill pid $pid, after the skip"
		else ladder no "l2.kernel  no kernel out-of-swap line names pid $pid after the skip (see $EV/leg2-kernel.txt)"; fi
	else ladder no "l2.kernel  cannot check: no skip time or no fill pid"; fi

	if [ "$exitc" = 137 ]; then ladder ok "l2.sigkill  the container terminated on SIGKILL (137)"
	else ladder no "l2.sigkill  container exit code ${exitc:-none}, want 137"; fi
	cp "$EV/watch.tsv" "$EV/leg2-watch.tsv"
	survive 2
}

# ── Run ───────────────────────────────────────────────────────────────────────────
case "$LEG" in
1) leg1 || true ;;
2) leg2 || true ;;
all)
	leg1 || true
	if [ "$FAIL" -ne 0 ]; then
		echo "==> go/no-go: leg 1 failed; leg 2 is NOT run"
	else
		echo "==> go/no-go: leg 1 passed; running leg 2"
		leg2 || true
	fi
	;;
esac

if [ "$FAIL" -eq 0 ] && [ "$PASS" -gt 0 ]; then FINAL_RC=0; else FINAL_RC=1; fi
exit "$FINAL_RC"

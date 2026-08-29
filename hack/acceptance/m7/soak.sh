#!/usr/bin/env bash
#
# k3sm M7.0 sub-gate — B28: the single-node watch-staleness soak.
#
# THE QUESTION
#
# ConsistentListFromCache is GA-locked true in the shipped kube version, so every
# unset-resourceVersion LIST the apiserver serves comes out of its watch cache
# rather than out of the datastore. That is only safe when the datastore can tell
# the cache which revision it is at — etcd does it with a progress notification,
# and kine grew the same thing in kine#577. A kine that does not deliver progress
# leaves the cache free to answer a consistent LIST from a revision OLDER than a
# write the client has already been told is committed. That is watch staleness,
# and on a single node it is invisible until something depends on read-after-write.
#
# THE ANSWER SHAPE
#
# This soak commits a write, takes its returned resourceVersion as a sentinel, and
# then POLLS a consistent LIST until the store has demonstrably caught up to that
# sentinel — or until a bounded timeout expires. The timeout IS the acceptance
# criterion. It is deliberately NOT "sleep, then LIST once and see": that is a race
# whose verdict is decided by scheduling noise, red on a loaded machine and green on
# an idle one, and it cannot distinguish "the cache lagged 3ms" (fine, every store
# does) from "the cache never caught up" (the kine#577 failure). A poll bounded by a
# stated timeout makes both the pass and the fail deterministic in the sense that
# matters: a probe that never observes its own committed write within the timeout is
# a staleness finding, with the resourceVersion delta printed.
#
# The bound covers both shapes the failure can take. ConsistentListFromCache makes the
# apiserver WAIT inside the LIST for the datastore to report its current revision, so
# a kine that never reports one shows up either as a call that blocks and then errors,
# or as an answer served from an older revision; a bound on total observe latency —
# request time plus retries — catches both, and neither is charged to scheduling noise
# the way a fixed sleep would be.
#
# A soak that finds no staleness because it never stressed anything would close this
# question wrongly, so the run is defended against its own vacuity in four ways, each
# of which turns the gate RED on its own:
#
#   - the churn floor        the run must SUSTAIN >= $K3SM_SOAK_CHURN_FLOOR committed
#                            writes/sec, measured, not assumed;
#   - the revision floor     the datastore's own revision must ADVANCE by at least
#                            the number of writes claimed — proof the churn reached
#                            the store and was not absorbed by a client-side error;
#   - the probe floor        the run must complete >= $K3SM_SOAK_MIN_PROBES probes;
#   - the parser self-check  a probe that cannot parse a list revision aborts LOUDLY
#                            instead of degrading into "never observed", which would
#                            otherwise be indistinguishable from real staleness.
#
# The churn deliberately writes CONFIGMAPS, the same resource the probe LISTs: the
# apiserver's watch cache is per-resource, so churning a different kind would leave
# the cache under test idle.
#
# TIERS
#
#   smoke (default)  K3SM_SOAK_DURATION=120s — CI-runnable, bounded minutes, boots a
#                    disposable rootless `k3sm dev` instance and tears it down.
#   long             K3SM_SOAK_DURATION=4h (or whatever the operator sets) — the same
#                    loop, same criterion, operator-run. Nothing else changes; the
#                    smoke tier is not a different, weaker test.
#
# PIN
#
# The soak certifies a PIN, not "kine" in the abstract, so it refuses to run against
# any kine but the one k3sm ships (executor.DefaultKineVersion, floor v0.16 — the
# first line carrying the kine#577 fix). Three independent witnesses must agree, and
# it prints what it found when they do not:
#
#   the built binary   `go version -m <workdir>/bin/kine` module version
#   the staging marker <workdir>/bin/kine.version           ("<pin> nocgo")
#   the datastore stamp <workdir>/db/state.db.kine-pin      ("<pin> nocgo")
#
# plus, on a booted run, a LIVE witness: the process listening on the instance's kine
# port must be that very binary, serving that very state.db. The live witness exists
# because the datastore stamp is absent on a fresh datastore's first boot (the
# executor writes it only when a state.db already exists as kine starts serving), so
# it cannot be the sole tie between the pin and the data — see assert_pin.
#
# Usage:
#   hack/acceptance/m7/soak.sh                          # smoke tier
#   K3SM_SOAK_DURATION=4h hack/acceptance/m7/soak.sh    # long tier
#   hack/acceptance/m7/soak.sh --check-pin <workdir>    # pin witnesses only, no boot
#
# Knobs (all optional; every value used is printed in the run header):
#   K3SM_SOAK_DURATION        soak window                       (default 120s)
#   K3SM_SOAK_PROBE_TIMEOUT   per-probe bound = the criterion   (default 2s)
#   K3SM_SOAK_PROBE_INTERVAL  poll sleep inside a probe         (default 0.02)
#   K3SM_SOAK_WRITERS         churn writers; 0 = calibrate      (default 0)
#   K3SM_SOAK_CHURN_TARGET    writes/sec the pool is sized for  (default 150)
#   K3SM_SOAK_CHURN_FLOOR     min sustained writes/sec          (default 20)
#   K3SM_SOAK_MIN_PROBES      min probes for a valid run        (default 100)
#   K3SM_SOAK_INSTANCE        `k3sm dev` instance name          (default b28-soak)
#
# EXCLUSIVE HOST
#
# `k3sm server` — and therefore `k3sm dev` — always runs its kine on the fixed
# executor.DefaultKinePort. So a second k3sm cluster on the same Mac cannot bring up
# its own datastore: its kine loses the bind, while the apiserver's readiness probe
# (a TCP check on that port) still finds a listener — the incumbent's. Observed
# 2026-08-29: a `dev up` run while another instance held the port reported a Ready
# node and a healthy apiserver, yet left NO state.db in its own work dir at all, so
# the control plane it brought up was not backed by the datastore this run owns. A
# soak in that state measures someone else's kine and can prove nothing about the
# pin it just fingerprinted. The pre-flight below therefore REFUSES to boot while
# that port is held, naming what holds it, before anything is written anywhere.
#
# TIER: lab/integration — it boots a real control plane and needs the host to itself.
# Rootless; no sudo.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$HERE/../../.." && pwd)"
EXEC_PKG="$REPO_ROOT/pkg/executor"

: "${K3SM_SOAK_DURATION:=120s}"
: "${K3SM_SOAK_PROBE_TIMEOUT:=2s}"
: "${K3SM_SOAK_PROBE_INTERVAL:=0.02}"
: "${K3SM_SOAK_WRITERS:=0}"
: "${K3SM_SOAK_CHURN_FLOOR:=20}"
: "${K3SM_SOAK_CHURN_TARGET:=150}"
: "${K3SM_SOAK_MIN_PROBES:=100}"
: "${K3SM_SOAK_INSTANCE:=b28-soak}"

PROBE_NS="k3sm-soak-probe"
CHURN_NS="k3sm-soak-churn"
# The kine pin floor: v0.16 is the first line carrying kine#577 (watch progress).
KINE_MINOR_FLOOR=16

PASS=0; FAIL=0
ladder() { if [ "$1" = ok ]; then echo "PASS  $2"; PASS=$((PASS+1)); else echo "FAIL  $2"; FAIL=$((FAIL+1)); fi; }

# ── duration/time helpers ────────────────────────────────────────────────────
# parse_secs accepts 90, 90s, 5m, 4h and prints whole seconds.
parse_secs() {
	local v="$1" n
	case "$v" in
	*h) n="${v%h}"; echo $(( n * 3600 )) ;;
	*m) n="${v%m}"; echo $(( n * 60 )) ;;
	*s) n="${v%s}"; echo $(( n )) ;;
	*)  echo $(( v )) ;;
	esac
}

# parse_ms accepts 2s, 1500ms, 0.25s, 250 (bare = ms) and prints whole milliseconds.
# It is pure bash (no bc/awk) so it stays usable inside the probe loop.
parse_ms() {
	local v="$1" whole frac
	case "$v" in
	*ms) echo $(( ${v%ms} )); return ;;
	*s)  v="${v%s}" ;;
	*)   echo $(( v )); return ;;
	esac
	case "$v" in
	*.*) whole="${v%%.*}"; frac="${v#*.}" ;;
	*)   whole="$v"; frac="" ;;
	esac
	[ -n "$whole" ] || whole=0
	frac="${frac}000"; frac="${frac:0:3}"
	echo $(( 10#$whole * 1000 + 10#$frac ))
}

# now_ms is the run's only high-resolution clock. bash 3.2 (the /bin/bash macOS
# ships) has neither EPOCHREALTIME nor printf %(%s)T, and BSD date has no %N, so
# perl's Time::HiRes is the portable millisecond source on this platform.
now_ms() { perl -MTime::HiRes=time -e 'printf "%d\n", time*1000'; }

# ── the pin witnesses ────────────────────────────────────────────────────────
# source_pin prints executor.DefaultKineVersion, the pin k3sm ships.
source_pin() {
	sed -nE 's/^[[:space:]]*DefaultKineVersion[[:space:]]*=[[:space:]]*"([^"]+)".*/\1/p' \
		"$EXEC_PKG/executor.go" | head -1
}

# marker_pin <file> prints the "<version> <variant>" a marker/stamp records, or "".
marker_pin() { [ -f "$1" ] && head -1 "$1" | tr -d '\r' || true; }

# assert_pin <workdir> [kine-port] — REFUSES to certify a soak against anything but
# the shipped pin. Prints every witness it read, in every outcome, so a refusal names
# the pin it actually found rather than only the one it wanted.
#
# Three static witnesses (the built binary, the staging marker, the datastore stamp)
# plus, when a kine port is given, a LIVE one: the process actually listening on that
# port must BE $workdir/bin/kine — the binary whose module version was just read —
# and must have this instance's state.db as its endpoint.
#
# The live witness is not belt-and-braces. The datastore stamp is written by the
# executor only when a state.db already exists at the moment kine starts serving, so
# a FRESH datastore's first boot carries no stamp at all (observed: a first `dev up`
# leaves db/state.db.kine-pin absent; a second boot over the same datastore writes
# it). Requiring the stamp unconditionally would therefore refuse every clean-slate
# soak. So: with a live cluster the process witness is required and the stamp is
# checked only if present; offline (--check-pin) there is no process to interrogate
# and the stamp becomes mandatory, because something must tie the pin to THIS
# datastore rather than merely to the bytes staged beside it.
assert_pin() {
	local wd="$1" port="${2:-}" want minor ok=true
	local kine="$wd/bin/kine" marker="$wd/bin/kine.version" stamp="$wd/db/state.db.kine-pin"
	local built m_txt s_txt kpid kcomm kargs

	want="$(source_pin)"
	if [ -z "$want" ]; then
		echo "  could not read DefaultKineVersion out of pkg/executor/executor.go" >&2
		return 1
	fi
	# Floor check on the SHAPE, not a version sort: the superseded v1.14.x line is a
	# higher number but older code, so a naive comparison would accept exactly the pin
	# this soak exists to run against the retirement of.
	case "$want" in
	v0.*)
		minor="$(printf '%s' "$want" | cut -d. -f2)"
		if [ "$minor" -lt "$KINE_MINOR_FLOOR" ]; then
			echo "  shipped kine pin $want is below the v0.$KINE_MINOR_FLOOR floor (kine#577 watch progress)" >&2
			ok=false
		fi
		;;
	*)
		echo "  shipped kine pin $want is not a v0.x release — the orphan v1.14.x line is retired" >&2
		ok=false
		;;
	esac

	built=""
	if [ -x "$kine" ] && command -v go >/dev/null 2>&1; then
		built="$(go version -m "$kine" 2>/dev/null | awk '$1=="mod" && $2=="github.com/k3s-io/kine" {print $3; exit}')"
	fi
	m_txt="$(marker_pin "$marker")"
	s_txt="$(marker_pin "$stamp")"

	echo "  shipped pin (executor.DefaultKineVersion): $want"
	echo "  built binary   ($kine): ${built:-<absent>}"
	echo "  staging marker ($marker): ${m_txt:-<absent>}"
	echo "  datastore stamp ($stamp): ${s_txt:-<absent>}"

	if [ -z "$built" ]; then
		echo "  no kine binary to interrogate at $kine — cannot prove which kine served" >&2
		ok=false
	elif [ "$built" != "$want" ]; then
		echo "  the staged kine binary is $built, NOT the shipped pin $want" >&2
		ok=false
	fi
	if [ "$m_txt" != "$want nocgo" ]; then
		echo "  staging marker says '${m_txt:-<absent>}', want '$want nocgo'" >&2
		ok=false
	fi
	# The stamp speaks about the DATASTORE ("this pin opened this database"), not about
	# the staging — so a present one that disagrees is fatal in either mode.
	if [ -n "$s_txt" ] && [ "$s_txt" != "$want nocgo" ]; then
		echo "  datastore pin stamp says '$s_txt', want '$want nocgo' — a different kine opened this datastore" >&2
		ok=false
	fi

	if [ -n "$port" ]; then
		kpid="$(lsof -nP -iTCP:"$port" -sTCP:LISTEN -t 2>/dev/null | head -1 || true)"
		kcomm=""; kargs=""
		if [ -n "$kpid" ]; then
			kcomm="$(ps -o comm= -p "$kpid" 2>/dev/null || true)"
			kargs="$(ps -o args= -p "$kpid" 2>/dev/null || true)"
		fi
		echo "  live datastore process (:$port): ${kcomm:-<none>}"
		if [ "$kcomm" != "$kine" ]; then
			echo "  the process serving this instance's datastore port is not $kine — the soak cannot say which kine it measured" >&2
			ok=false
		fi
		case "$kargs" in
		*"$wd/db/state.db"*) ;;
		*)
			echo "  the live kine's endpoint does not name $wd/db/state.db — it is serving a different datastore" >&2
			ok=false
			;;
		esac
	elif [ -z "$s_txt" ]; then
		echo "  no datastore pin stamp and no live process to interrogate — nothing ties a kine pin to this datastore" >&2
		ok=false
	fi
	$ok
}

# --check-pin <workdir>: the pin witnesses alone, no boot. Lets an operator (or this
# gate's own red-path proof) exercise the refusal against any work dir.
if [ "${1:-}" = "--check-pin" ]; then
	if [ -z "${2:-}" ]; then echo "usage: $0 --check-pin <workdir>" >&2; exit 2; fi
	echo "==> B28 soak: kine pin witnesses for work dir $2"
	if assert_pin "$2"; then
		echo "PIN OK"
		exit 0
	fi
	echo "PIN REFUSED — the soak would not certify this datastore" >&2
	exit 1
fi

# ── knobs, resolved and printed ──────────────────────────────────────────────
DURATION_S="$(parse_secs "$K3SM_SOAK_DURATION")"
TIMEOUT_MS="$(parse_ms "$K3SM_SOAK_PROBE_TIMEOUT")"
if [ "$DURATION_S" -le 0 ]; then echo "K3SM_SOAK_DURATION must be positive" >&2; exit 2; fi
if [ "$TIMEOUT_MS" -lt 0 ]; then echo "K3SM_SOAK_PROBE_TIMEOUT must be non-negative" >&2; exit 2; fi

for tool in curl perl go lsof; do
	command -v "$tool" >/dev/null 2>&1 || { echo "B28 soak needs $tool on PATH" >&2; exit 2; }
done

WORK="$(mktemp -d /tmp/b28-soak.XXXXXX)"
KUBECONFIG_FILE="$WORK/kubeconfig"
K3SM_BIN="$WORK/k3sm"
RUNFLAG="$WORK/churning"
BOOTED=""

cleanup() {
	rm -f "$RUNFLAG" 2>/dev/null || true
	# Reap the churn writers before the cluster goes, so they cannot spray
	# connection errors over the teardown output.
	if [ -n "${CHURN_PIDS:-}" ]; then
		for p in $CHURN_PIDS; do kill "$p" 2>/dev/null || true; done
		wait 2>/dev/null || true
	fi
	if [ -n "$BOOTED" ]; then
		echo "==> tearing the soak instance down"
		# ONLY this instance, never --all: another dev instance may be live on this
		# Mac and is not ours to reap.
		"$K3SM_BIN" dev down --name "$K3SM_SOAK_INSTANCE" --kubeconfig "$KUBECONFIG_FILE" >/dev/null 2>&1 || true
	fi
	rm -rf "$WORK" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

echo "==> k3sm B28 watch-staleness soak (single node, consistent LIST after a committed write under churn)"

# ── s0 — the shipped pin, before anything boots ──────────────────────────────
WANT_PIN="$(source_pin)"
echo "    shipped kine pin: ${WANT_PIN:-<unreadable>}"

# The server builds the pinned kine on first use with `go install` under a SCRATCH
# GOPATH it deletes afterwards — and an unset GOMODCACHE derives from GOPATH, so every
# boot re-downloads kine's whole dependency tree into a directory that is then thrown
# away. On a cold-ish cache that download outruns `dev up`'s 90s kubeconfig deadline
# and the boot fails for a reason that has nothing to do with the soak. Pinning
# GOMODCACHE to the shared one (which the child inherits through os.Environ) keeps the
# build inside the deadline; hack/acceptance/B69.sh pins it for the same reason.
export GOMODCACHE="${GOMODCACHE:-$(go env GOMODCACHE)}"

echo "==> building k3sm (CGO_ENABLED=1)"
( cd "$REPO_ROOT" && CGO_ENABLED=1 go build -o "$K3SM_BIN" ./cmd/k3sm ) \
	|| { echo "B28 soak: building k3sm failed" >&2; exit 1; }

# Pre-warm the pinned kine build OUTSIDE the boot. The server builds kine from source
# on first use, inside `dev up`'s 90s kubeconfig deadline; on a cold Go build cache
# that compile does not finish in 90s (observed: the boot log ends with
# "build kine v0.17.0 (CGO_ENABLED=0): signal: terminated" mid-compile, on a Go
# toolchain running translated under Rosetta). Running the IDENTICAL `go install` here
# — same pin, same CGO/GOWORK settings, so the same cache entries — makes the
# in-boot build a cache hit and turns a timing lottery into a deterministic boot.
# It writes only to the shared GOCACHE/GOMODCACHE; the scratch GOPATH is discarded.
echo "==> pre-warming the pinned kine build (kine $WANT_PIN, CGO_ENABLED=0) — first run compiles, later runs are a cache hit"
if ! ( CGO_ENABLED=0 GOWORK=off GOBIN='' GOPATH="$WORK/gopath" \
		go install "github.com/k3s-io/kine@$WANT_PIN" >"$WORK/kine-build.log" 2>&1 ); then
	echo "B28 soak: pre-warming the kine build failed — the in-boot build would fail the same way:" >&2
	tail -20 "$WORK/kine-build.log" >&2
	exit 1
fi

# ── pre-flight: the datastore port must be OURS to take ──────────────────────
KINE_PORT="$(sed -nE 's/^[[:space:]]*DefaultKinePort[[:space:]]*=[[:space:]]*([0-9]+).*/\1/p' "$EXEC_PKG/executor.go" | head -1)"
[ -n "$KINE_PORT" ] || { echo "B28 soak: could not read executor.DefaultKinePort" >&2; exit 1; }
holder="$(lsof -nP -iTCP:"$KINE_PORT" -sTCP:LISTEN -t 2>/dev/null | head -1 || true)"
if [ -n "$holder" ]; then
	echo "B28 soak: REFUSING to boot — :$KINE_PORT (the fixed kine port every k3sm server uses) is already held:" >&2
	ps -o pid=,args= -p "$holder" 2>/dev/null | cut -c1-200 >&2 || true
	echo "B28 soak: a soak booted over it would come up against THAT datastore and certify the wrong kine." >&2
	echo "B28 soak: free the port first (e.g. \`k3sm dev down --name <that instance>\`) and re-run." >&2
	exit 1
fi
# The kubelet API port is not load-bearing for a datastore verdict, so a foreign
# holder is reported rather than fatal.
kholder="$(lsof -nP -iTCP:10250 -sTCP:LISTEN -t 2>/dev/null | head -1 || true)"
if [ -n "$kholder" ]; then
	echo "NOTE: :10250 (the kubelet API port) is already held by pid $kholder — this node's logs/exec endpoint will not bind. The soak does not use it."
fi

# ── boot a disposable rootless dev instance ──────────────────────────────────
# --kubeconfig keeps the merged context inside $WORK: the soak must not touch the
# operator's ~/.kube/config.
# BOOT_LOG is where the detached server writes before the instance manifest exists, so
# it is the ONLY account of a boot that never finished. `dev up` reports its own
# timeout without it, which says when the boot failed but not why.
BOOT_LOG="$HOME/.k3sm/dev/$K3SM_SOAK_INSTANCE/server/server.log"
dump_boot_log() {
	if [ -f "$BOOT_LOG" ]; then
		echo "--- $BOOT_LOG (last 15 lines) ------------------------------" >&2
		tail -15 "$BOOT_LOG" >&2
		echo "------------------------------------------------------------" >&2
	else
		echo "B28 soak: no server log at $BOOT_LOG — the server never started" >&2
	fi
}

echo "==> booting a disposable rootless dev instance ($K3SM_SOAK_INSTANCE)"
BOOTED=1   # set BEFORE the attempt: a half-up instance still has to be torn down
if ! "$K3SM_BIN" dev up --name "$K3SM_SOAK_INSTANCE" --kubeconfig "$KUBECONFIG_FILE"; then
	echo "B28 soak: \`k3sm dev up\` failed — no cluster to soak" >&2
	dump_boot_log
	# ONE retry, and only for the one failure that is genuinely transient: a cold Go
	# module cache. The server builds the pinned kine on first use, and downloading its
	# dependency tree can outrun `dev up`'s 90s kubeconfig deadline — after which the
	# modules are cached and the next boot skips the download entirely. Any other
	# failure is a real failure and is NOT retried; there is no loop here on purpose.
	if grep -qE 'go: downloading|build kine .*signal: terminated' "$BOOT_LOG" 2>/dev/null; then
		echo "B28 soak: RETRYING ONCE — the boot log shows the first-use kine build (module" >&2
		echo "B28 soak: download or compile) outrunning the 90s kubeconfig deadline. The Go" >&2
		echo "B28 soak: caches are warmer now; this is the single sanctioned retry." >&2
		"$K3SM_BIN" dev down --name "$K3SM_SOAK_INSTANCE" --kubeconfig "$KUBECONFIG_FILE" >/dev/null 2>&1 || true
		if ! "$K3SM_BIN" dev up --name "$K3SM_SOAK_INSTANCE" --kubeconfig "$KUBECONFIG_FILE"; then
			echo "B28 soak: the retry failed too — this is not a cold-cache problem" >&2
			dump_boot_log
			exit 1
		fi
	else
		exit 1
	fi
fi
# The work dir comes out of the instance manifest `k3sm dev up` just wrote, not out
# of a path this script re-derives — so a future change to the registry layout moves
# the soak with it instead of silently pointing it at nothing.
INSTANCE_JSON="$HOME/.k3sm/dev/$K3SM_SOAK_INSTANCE/instance.json"
WORKDIR="$(sed -nE 's/.*"workDir"[[:space:]]*:[[:space:]]*"([^"]+)".*/\1/p' "$INSTANCE_JSON" 2>/dev/null | head -1 || true)"
if [ -z "$WORKDIR" ] || [ ! -d "$WORKDIR" ]; then
	echo "B28 soak: could not read the instance work dir out of $INSTANCE_JSON" >&2
	exit 1
fi
SERVER_LOG="$WORKDIR/server.log"
echo "    work dir  $WORKDIR"

# ── s1 — the PIN gate. Nothing else runs until it holds. ─────────────────────
echo "==> s1: kine pin witnesses"
# $KINE_PORT, NOT the manifest's "kinePort": `k3sm dev` allocates a per-instance kine
# port into its manifest but never passes it to the server it spawns, so the datastore
# actually listens on the executor default. Interrogating the manifest port would find
# nothing and refuse every run.
if assert_pin "$WORKDIR" "$KINE_PORT"; then
	ladder ok "s1  the soak is running against the shipped kine pin $WANT_PIN (binary + staging marker + datastore stamp agree)"
else
	ladder no "s1  the soak is running against the shipped kine pin (witnesses disagree — see above)"
	echo "----------------------------------------"
	echo "B28: REFUSING to soak — a staleness verdict against an unidentified kine certifies nothing." >&2
	echo "B28: $PASS passed, $FAIL failed" >&2
	exit 1
fi

# ── API access ───────────────────────────────────────────────────────────────
KCFG="$WORKDIR/k3sm.kubeconfig"
[ -f "$KCFG" ] || { echo "B28 soak: no server kubeconfig at $KCFG" >&2; exit 1; }
API_PORT="$(awk -F'127.0.0.1:' '/server:/{split($2,a,"[^0-9]"); print a[1]; exit}' "$KCFG")"
TOKEN="$(awk -F'token: ' '/token: /{print $2; exit}' "$KCFG" | tr -d '\r')"
[ -n "$API_PORT" ] && [ -n "$TOKEN" ] || { echo "B28 soak: could not read the apiserver port/token out of $KCFG" >&2; exit 1; }
API="https://127.0.0.1:$API_PORT"
echo "    apiserver $API"

# api <method> <path> [json-file] — one request; leaves the body in $RESP and the
# status in $REQ_CODE. `curl -k` is the same posture kc() uses in the acceptance
# library: the endpoint is a loopback port this script just booted.
RESP="$WORK/resp.json"
REQ_CODE=""
api() {
	local m="$1" p="$2" d="${3:-}" code
	if [ -n "$d" ]; then
		code="$(curl -sS -k -X "$m" -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
			--data-binary @"$d" -o "$RESP" -w '%{http_code}' "$API$p" 2>>"$WORK/curl.err")" || return 1
	else
		code="$(curl -sS -k -X "$m" -H "Authorization: Bearer $TOKEN" \
			-o "$RESP" -w '%{http_code}' "$API$p" 2>>"$WORK/curl.err")" || return 1
	fi
	REQ_CODE="$code"
	return 0
}

is2xx() { case "$1" in 2*) return 0 ;; *) return 1 ;; esac; }

# RV_RE matches a resourceVersion field TOLERANTLY of whitespace. That is not
# defensive padding: the apiserver pretty-prints JSON for a plain curl (no
# ?pretty=false, no client-go Accept negotiation), so the wire form is
# `"resourceVersion": "400"` with a space — a `"resourceVersion":"…"` pattern matches
# nothing at all. The parser self-check below caught exactly that; the fix is to parse
# what the server actually sends rather than to demand a shape from it.
RV_RE='"resourceVersion"[[:space:]]*:[[:space:]]*"[0-9]+"'

# obj_rv — the metadata.resourceVersion of a single returned object (its FIRST, which
# is the object's own metadata). Both extractors end in `|| true`: under `set -o
# pipefail` a no-match grep, or a head that closes the pipe early, would otherwise
# make the enclosing `x="$(...)"` assignment fail the whole script — turning a body
# this run needs to REPORT into a silent death.
obj_rv() { grep -oE "$RV_RE" "$RESP" 2>/dev/null | head -1 | tr -dc '0-9' || true; }

# list_rv — the LIST's OWN metadata.resourceVersion, i.e. the store revision the read
# was served at. It is taken from the body PREFIX that precedes "items", so an item's
# own resourceVersion can never be mistaken for the collection's.
list_rv() {
	tr -d '\n' <"$RESP" 2>/dev/null | sed -E 's/"items"[[:space:]]*:.*//' \
		| grep -oE "$RV_RE" | tail -1 | tr -dc '0-9' || true
}

# rv_ge <a> <b> — numeric >= over kine's integer revisions.
rv_ge() {
	case "$1$2" in
	*[!0-9]*|"") return 1 ;;
	esac
	[ "$1" -ge "$2" ]
}

ns_create() {
	printf '{"apiVersion":"v1","kind":"Namespace","metadata":{"name":"%s"}}' "$1" >"$WORK/ns.json"
	api POST /api/v1/namespaces "$WORK/ns.json" || return 1
	case "$REQ_CODE" in 2*|409) return 0 ;; esac
	echo "B28 soak: could not create namespace $1 (HTTP $REQ_CODE)" >&2
	head -c 400 "$RESP" >&2; echo >&2
	return 1
}

ns_create "$PROBE_NS"
ns_create "$CHURN_NS"

# ── churn calibration ────────────────────────────────────────────────────────
# The writer count is not a guess: measure this machine's serial create+delete rate
# and pick N so the projected aggregate clears the floor with headroom, capped at 8
# (past that the loopback apiserver is the bottleneck and more writers only add
# scheduling noise). Whatever is chosen is PRINTED, per the gate's own rule that a
# soak states its churn parameters.
echo "==> calibrating churn (2s serial probe of this machine's write rate)"
cal_n=0
cal_start="$(now_ms)"
while :; do
	printf '{"apiVersion":"v1","kind":"ConfigMap","metadata":{"name":"cal-%s"}}' "$cal_n" >"$WORK/cal.json"
	api POST "/api/v1/namespaces/$CHURN_NS/configmaps" "$WORK/cal.json" || break
	is2xx "$REQ_CODE" || break
	api DELETE "/api/v1/namespaces/$CHURN_NS/configmaps/cal-$cal_n" || break
	cal_n=$((cal_n + 1))
	[ $(( $(now_ms) - cal_start )) -ge 2000 ] && break
done
cal_ms=$(( $(now_ms) - cal_start ))
[ "$cal_ms" -gt 0 ] || cal_ms=1
# 2 datastore writes per iteration (a create and a delete; both are revisions).
CAL_RATE=$(( cal_n * 2 * 1000 / cal_ms ))
echo "    serial rate: $cal_n create+delete pairs in ${cal_ms}ms = ${CAL_RATE} committed writes/sec (1 writer)"

# Size the writer pool from the measured serial rate to hit the TARGET rate — which
# is the parameter that decides whether the soak stresses anything, so it is a stated
# knob and not an emergent property of a writer count someone picked. The default
# target is several times what one serial writer achieves on an M-series Mac, and
# comfortably above the vacuity floor, so a green verdict is bought with real load.
WRITERS="$K3SM_SOAK_WRITERS"
if [ "$WRITERS" -le 0 ]; then
	target="$K3SM_SOAK_CHURN_TARGET"
	if [ "$target" -lt $(( K3SM_SOAK_CHURN_FLOOR * 4 )) ]; then target=$(( K3SM_SOAK_CHURN_FLOOR * 4 )); fi
	WRITERS=1
	if [ "$CAL_RATE" -gt 0 ]; then
		WRITERS=$(( (target + CAL_RATE - 1) / CAL_RATE ))
	fi
	[ "$WRITERS" -lt 2 ] && WRITERS=2
	[ "$WRITERS" -gt 8 ] && WRITERS=8
fi

echo "----------------------------------------"
echo "soak parameters (chosen from this machine's measured capability):"
echo "  window                 ${DURATION_S}s   (K3SM_SOAK_DURATION=$K3SM_SOAK_DURATION)"
echo "  churn writers          $WRITERS        (1-writer measured rate ${CAL_RATE}/s; sized for the ${K3SM_SOAK_CHURN_TARGET}/s target -> projected $(( WRITERS * CAL_RATE ))/s)"
echo "  churn resource         ConfigMaps in $CHURN_NS (SAME resource the probe LISTs — the watch cache is per-resource)"
echo "  probe timeout          ${TIMEOUT_MS}ms  (K3SM_SOAK_PROBE_TIMEOUT=$K3SM_SOAK_PROBE_TIMEOUT) <- THE acceptance criterion"
echo "  probe poll interval    ${K3SM_SOAK_PROBE_INTERVAL}s"
echo "  churn floor            ${K3SM_SOAK_CHURN_FLOOR} committed writes/sec sustained (else the run is vacuous -> RED)"
echo "  probe floor            ${K3SM_SOAK_MIN_PROBES} probes (else the run is vacuous -> RED)"
echo "----------------------------------------"

# ── churn writers ────────────────────────────────────────────────────────────
# Each writer creates and immediately deletes a uniquely-named ConfigMap: two
# datastore revisions per iteration, no read-modify-write, no optimistic-concurrency
# conflicts to mask as churn, and a namespace that never grows. Only 2xx responses
# are counted, so a writer that starts failing cannot inflate the measured rate.
churn_writer() {
	local id="$1" n=0 w=0 name c
	local body="$WORK/churn-$id.json"
	while [ -f "$RUNFLAG" ]; do
		name="churn-$id-$n"
		printf '{"apiVersion":"v1","kind":"ConfigMap","metadata":{"name":"%s"},"data":{"i":"%s"}}' "$name" "$n" >"$body"
		c="$(curl -sS -k -X POST -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
			--data-binary @"$body" -o /dev/null -w '%{http_code}' "$API/api/v1/namespaces/$CHURN_NS/configmaps" 2>/dev/null || echo 000)"
		case "$c" in 2*) w=$((w + 1)) ;; esac
		c="$(curl -sS -k -X DELETE -H "Authorization: Bearer $TOKEN" \
			-o /dev/null -w '%{http_code}' "$API/api/v1/namespaces/$CHURN_NS/configmaps/$name" 2>/dev/null || echo 000)"
		case "$c" in 2*) w=$((w + 1)) ;; esac
		n=$((n + 1))
		printf '%s\n' "$w" >"$WORK/churn-count-$id"
	done
}

# The store revision before any churn — half of the revision-floor proof.
api GET "/api/v1/namespaces/$PROBE_NS/configmaps" || { echo "B28 soak: baseline LIST failed" >&2; exit 1; }
is2xx "$REQ_CODE" || { echo "B28 soak: baseline LIST HTTP $REQ_CODE" >&2; exit 1; }
RV_START="$(list_rv)"
case "$RV_START" in
""|*[!0-9]*)
	echo "B28 soak: could not parse a numeric list resourceVersion from the baseline LIST." >&2
	echo "B28 soak: this is a PARSER failure, not a staleness finding — every probe below would" >&2
	echo "B28 soak: report 'never observed' for a reason that has nothing to do with kine. Body prefix:" >&2
	head -c 400 "$RESP" >&2; echo >&2
	exit 1
	;;
esac
echo "    baseline store revision: $RV_START"

: >"$RUNFLAG"
CHURN_PIDS=""
i=0
while [ "$i" -lt "$WRITERS" ]; do
	printf '0\n' >"$WORK/churn-count-$i"
	churn_writer "$i" &
	CHURN_PIDS="$CHURN_PIDS $!"
	i=$((i + 1))
done
echo "==> churn running ($WRITERS writers); soaking for ${DURATION_S}s"

# ── the probe loop ───────────────────────────────────────────────────────────
PROBES=0
STALE=0
STALE_NEVER=0
STALE_LATE=0
MAX_LAG_MS=0
SUM_LAG_MS=0
MAX_POLLS=0
SLOW_PROBES=0          # observed, but only after more than one poll
FIRST_STALE=""

soak_start="$(now_ms)"
soak_deadline=$(( soak_start + DURATION_S * 1000 ))

while [ "$(now_ms)" -lt "$soak_deadline" ]; do
	name="probe-$PROBES"
	printf '{"apiVersion":"v1","kind":"ConfigMap","metadata":{"name":"%s"}}' "$name" >"$WORK/probe.json"
	if ! api POST "/api/v1/namespaces/$PROBE_NS/configmaps" "$WORK/probe.json" || ! is2xx "$REQ_CODE"; then
		echo "B28 soak: probe write $name failed (HTTP ${REQ_CODE:-?}) — the cluster stopped accepting writes mid-soak" >&2
		head -c 400 "$RESP" >&2; echo >&2
		tail -20 "$SERVER_LOG" >&2 2>/dev/null || true
		exit 1
	fi
	RV_W="$(obj_rv)"
	case "$RV_W" in
	""|*[!0-9]*)
		echo "B28 soak: the create response for $name carried no numeric resourceVersion — PARSER failure, not staleness. Body prefix:" >&2
		head -c 400 "$RESP" >&2; echo >&2
		exit 1
		;;
	esac

	# Poll a CONSISTENT LIST (no resourceVersion parameter => most-recent read, which
	# ConsistentListFromCache serves out of the watch cache) until the store has
	# demonstrably reached the sentinel, or the bounded timeout expires.
	t0="$(now_ms)"
	polls=0; seen=no; last_rv=""; last_code=""; present=no
	while :; do
		polls=$((polls + 1))
		if api GET "/api/v1/namespaces/$PROBE_NS/configmaps"; then
			last_code="$REQ_CODE"
			if is2xx "$REQ_CODE"; then
				last_rv="$(list_rv)"
				if grep -qE "\"name\"[[:space:]]*:[[:space:]]*\"$name\"" "$RESP"; then present=yes; else present=no; fi
				# BOTH conjuncts: the object is in the answer AND the answer was
				# served at a revision at least as new as the write. The second
				# catches a cache that returned an older snapshot which happens to
				# contain the object for an unrelated reason.
				if [ "$present" = yes ] && rv_ge "$last_rv" "$RV_W"; then seen=yes; fi
			fi
		else
			last_code="curl-error"
		fi
		[ "$seen" = yes ] && break
		[ $(( $(now_ms) - t0 )) -ge "$TIMEOUT_MS" ] && break
		sleep "$K3SM_SOAK_PROBE_INTERVAL"
	done
	lag=$(( $(now_ms) - t0 ))

	PROBES=$((PROBES + 1))
	SUM_LAG_MS=$((SUM_LAG_MS + lag))
	[ "$lag" -gt "$MAX_LAG_MS" ] && MAX_LAG_MS="$lag"
	[ "$polls" -gt "$MAX_POLLS" ] && MAX_POLLS="$polls"
	[ "$polls" -gt 1 ] && SLOW_PROBES=$((SLOW_PROBES + 1))

	# The bound is on the OBSERVATION, not merely on the retry loop. A single LIST
	# that blocks past the bound and then returns the write is still a read-after-write
	# that took longer than the criterion allows — the apiserver's cacher waits for the
	# datastore's progress notification INSIDE the request, so a lagging kine shows up
	# as one slow call at least as often as it shows up as a stale answer. Counting
	# only the never-observed shape would miss half the failure.
	if [ "$seen" != yes ]; then
		STALE=$((STALE + 1)); STALE_NEVER=$((STALE_NEVER + 1))
		delta="n/a"
		if [ -n "$last_rv" ]; then delta=$(( RV_W - last_rv )); fi
		msg="probe #$PROBES ($name): NEVER OBSERVED — committed at resourceVersion $RV_W; after $polls consistent LIST(s) over ${lag}ms the store was still at ${last_rv:-<unparsed>} (delta $delta), object present=$present, last HTTP ${last_code:-?}"
		echo "STALE  $msg" >&2
		[ -z "$FIRST_STALE" ] && FIRST_STALE="$msg"
	elif [ "$lag" -gt "$TIMEOUT_MS" ]; then
		STALE=$((STALE + 1)); STALE_LATE=$((STALE_LATE + 1))
		msg="probe #$PROBES ($name): LATE — committed at resourceVersion $RV_W, observed only after ${lag}ms over $polls consistent LIST(s), bound ${TIMEOUT_MS}ms (store reached $last_rv)"
		echo "STALE  $msg" >&2
		[ -z "$FIRST_STALE" ] && FIRST_STALE="$msg"
	fi

	curl -sS -k -X DELETE -H "Authorization: Bearer $TOKEN" -o /dev/null \
		"$API/api/v1/namespaces/$PROBE_NS/configmaps/$name" >/dev/null 2>&1 || true
done
soak_ms=$(( $(now_ms) - soak_start ))

# ── stop churn, measure what actually happened ───────────────────────────────
rm -f "$RUNFLAG"
for p in $CHURN_PIDS; do wait "$p" 2>/dev/null || true; done
CHURN_PIDS=""

CHURN_WRITES=0
i=0
while [ "$i" -lt "$WRITERS" ]; do
	c="$(cat "$WORK/churn-count-$i" 2>/dev/null || echo 0)"
	case "$c" in ''|*[!0-9]*) c=0 ;; esac
	CHURN_WRITES=$((CHURN_WRITES + c))
	i=$((i + 1))
done
[ "$soak_ms" -gt 0 ] || soak_ms=1
CHURN_RATE=$(( CHURN_WRITES * 1000 / soak_ms ))

api GET "/api/v1/namespaces/$PROBE_NS/configmaps" || true
RV_END="$(list_rv)"
case "$RV_END" in ''|*[!0-9]*) RV_END=0 ;; esac
RV_DELTA=$(( RV_END - RV_START ))

AVG_LAG_MS=0
[ "$PROBES" -gt 0 ] && AVG_LAG_MS=$(( SUM_LAG_MS / PROBES ))

echo "----------------------------------------"
echo "soak results (window ${soak_ms}ms):"
echo "  probes                 $PROBES  (min $K3SM_SOAK_MIN_PROBES)"
echo "  stale probes           $STALE   <- the verdict"
echo "  probes needing >1 poll $SLOW_PROBES (max polls in one probe: $MAX_POLLS)"
echo "  observe latency        max ${MAX_LAG_MS}ms, mean ${AVG_LAG_MS}ms (bound ${TIMEOUT_MS}ms)"
echo "  churn committed        $CHURN_WRITES writes = ${CHURN_RATE}/s over $WRITERS writers (floor ${K3SM_SOAK_CHURN_FLOOR}/s)"
echo "  store revision         $RV_START -> $RV_END (advanced $RV_DELTA)"
echo "----------------------------------------"

# ── s2 — non-vacuity: the run has to have been a soak at all ─────────────────
vac_ok=true
if [ "$PROBES" -lt "$K3SM_SOAK_MIN_PROBES" ]; then
	echo "  only $PROBES probes ran (floor $K3SM_SOAK_MIN_PROBES) — too few to say anything about staleness" >&2
	vac_ok=false
fi
if [ "$CHURN_RATE" -lt "$K3SM_SOAK_CHURN_FLOOR" ]; then
	echo "  sustained churn was ${CHURN_RATE}/s, below the ${K3SM_SOAK_CHURN_FLOOR}/s floor — the datastore was not stressed" >&2
	vac_ok=false
fi
# The revision floor: writes CLAIMED must show up as revisions the store actually
# took. It is the check that a "green" run cannot be bought with client-side errors.
if [ "$RV_DELTA" -lt "$CHURN_WRITES" ]; then
	echo "  the store revision advanced $RV_DELTA while $CHURN_WRITES writes were reported committed — the churn did not reach the datastore" >&2
	vac_ok=false
fi
if $vac_ok; then
	ladder ok "s2  the run was a real soak ($PROBES probes, ${CHURN_RATE} writes/s sustained, store revision advanced $RV_DELTA)"
else
	ladder no "s2  the run was a real soak (churn/probe/revision floors)"
fi

# ── s3 — the verdict ─────────────────────────────────────────────────────────
if [ "$STALE" -eq 0 ]; then
	ladder ok "s3  every committed write was observable by a consistent LIST within ${TIMEOUT_MS}ms (max observed ${MAX_LAG_MS}ms)"
else
	ladder no "s3  $STALE of $PROBES probes did not observe their own committed write within ${TIMEOUT_MS}ms ($STALE_NEVER never observed, $STALE_LATE observed late)"
	echo "" >&2
	echo "READ-AFTER-WRITE VIOLATION on kine $WANT_PIN, single node. First occurrence:" >&2
	echo "  $FIRST_STALE" >&2
	echo "" >&2
	# The two shapes are NOT the same finding and must not be reported as one.
	if [ "$STALE_NEVER" -gt 0 ]; then
		echo "$STALE_NEVER probe(s) NEVER observed their own committed write. That is the kine#577" >&2
		echo "failure shape: the apiserver's watch cache answered a consistent (unset-" >&2
		echo "resourceVersion) LIST from a revision older than a write the client had already" >&2
		echo "been told was committed, and never caught up inside the bound." >&2
	fi
	if [ "$STALE_LATE" -gt 0 ]; then
		echo "$STALE_LATE probe(s) DID observe the write, but only after the ${TIMEOUT_MS}ms bound" >&2
		echo "(max ${MAX_LAG_MS}ms). Read-after-write still exceeded the criterion — but check the" >&2
		echo "bound before blaming the datastore: a bound set below this machine's ordinary" >&2
		echo "apiserver round-trip makes every probe late by construction." >&2
	fi
	echo "Server log tail:" >&2
	tail -30 "$SERVER_LOG" >&2 2>/dev/null || true
fi

# Namespaces go with the instance teardown, but delete them explicitly so a
# reused-name instance never inherits a previous soak's objects.
curl -sS -k -X DELETE -H "Authorization: Bearer $TOKEN" -o /dev/null "$API/api/v1/namespaces/$PROBE_NS" >/dev/null 2>&1 || true
curl -sS -k -X DELETE -H "Authorization: Bearer $TOKEN" -o /dev/null "$API/api/v1/namespaces/$CHURN_NS" >/dev/null 2>&1 || true

echo "----------------------------------------"
echo "B28 soak: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ] || exit 1
echo "============ B28 SOAK GREEN ============"

#!/usr/bin/env bash
#
# k3sm runtimed control-socket acceptance — the runnable proof that a stock
# `k3sm server` SERVES runtimed's gRPC control socket, so the daemon-side
# `k3sm image` commands (ls, df, prune, load, import) have something to dial.
#
# It exists because of a gap no unit test could see: the shipped node builds its
# runtime IN-PROCESS (provider.NewRuntimed -> runtime.New) and, before this gate's
# feature, never called runtime.Listen/Serve. Every `k3sm image` command is a
# client of runtimed's Images service over that socket, so on a stock install they
# all failed to dial a socket nothing had bound. A green unit suite proves the
# wiring and the retry contract; only the live tier proves an image gets into the
# store the node actually starts pods from.
#
# TWO TIERS, split by what can be proven without a live cluster:
#
#   CI TIER (always runs, GOARCH=arm64 CGO_ENABLED=1 pinned) — the unit-provable
#   half: the socket-path derivation is the one both the listener and the pod
#   deny-set go through, the served path is ALWAYS denied to pods, the serve loop
#   is never fatal and its retry is bounded, the listener closes before teardown
#   returns, the startup reconcile runs exactly once across both callers, and the
#   `k3sm image` client's default --socket is byte-identical to what a
#   default-rooted node binds.
#
#   LIVE TIER (needs $KUBECONFIG) — the socket actually serving: the node bound
#   it at the derived path with the documented 0700-dir/0600-node posture,
#   `k3sm image ls` and `k3sm image df` succeed against it, a `k3sm build
#   --format docker` tarball survives `k3sm image load` and then APPEARS in ls,
#   and a dial from a second uid is refused.
#
# Without $KUBECONFIG the live rungs are announced LIVE-PENDING and never fail —
# and the summary says so in as many words, so an exit 0 from a CI-tier-only run
# cannot be misread as "the socket serves".
#
# The GOARCH=arm64 pin is a CORRECTNESS requirement, not hygiene: a Mac's Go
# toolchain may itself be x86_64-under-Rosetta, and an unpinned build produces an
# x86_64 binary this arm64-only product cannot run.
#
# Usage:
#   hack/acceptance/image-socket.sh                   # CI tier only
#   KUBECONFIG=/path/to/kubeconfig \
#     K3SM_WORK_DIR=/var/lib/k3sm/server \
#     hack/acceptance/image-socket.sh                 # + the live tier
#
# Environment:
#   KUBECONFIG      a running k3sm server (enables the live tier)
#   K3SM_WORK_DIR   the control-plane work dir; the runtime root is its PARENT
#                   (executor.RuntimeRoot), and the socket is <root>/run/runtimed.sock
#   K3SM_SOCKET     override the socket path instead of deriving it
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
K3SM_ROOT="$(cd "$HERE/../.." && pwd)"
SELF="$HERE/image-socket.sh"

PASS=0; FAIL=0; PENDING=0; SKIP=0
ladder() { if [ "$1" = ok ]; then echo "PASS  $2"; PASS=$((PASS+1)); else echo "FAIL  $2"; FAIL=$((FAIL+1)); fi; }
pending() { echo "PEND  $1"; PENDING=$((PENDING+1)); }
skip() { echo "SKIP  $1"; SKIP=$((SKIP+1)); }

echo "==> k3sm runtimed control-socket acceptance"

# ---- image-socket.0 — the gate parses and its sources exist ----------------
b0=ok
[ -f "$SELF" ] && bash -n "$SELF" || b0=no
[ -f "$K3SM_ROOT/cmd/k3sm/runtimedsocket.go" ] || b0=no
[ -f "$K3SM_ROOT/cmd/k3sm/image.go" ] || b0=no
ladder "$b0" "image-socket.0  gate parses (bash -n) + the listener and the client are present"
if [ "$b0" != ok ]; then
	echo "----------------------------------------"
	echo "image-socket: the gate or its sources are missing/unparseable — nothing else can run" >&2
	echo "image-socket: $PASS passed, $FAIL failed" >&2
	exit 1
fi

# ---- Go leg runner (GOARCH=arm64 CGO_ENABLED=1) ----------------------------
GOFLAGS_ENV=(env GOARCH=arm64 CGO_ENABLED=1)

# run_test <id> <min-subtests> <TestName> <pkg>
# Asserts the leg actually RAN its subtests: `go test -run <filter>` EXITS 0 on a
# zero-match filter, so a renamed test would read PASS forever. Each leg fails
# unless "no tests to run" is ABSENT and the count of `--- PASS: <TestName>/`
# subtest lines meets the pinned minimum.
run_test() {
	local id="$1" min="$2" name="$3" pkg="$4" out rc=0 ran
	out="$(cd "$K3SM_ROOT" && "${GOFLAGS_ENV[@]}" go test -count=1 -v -run "^${name}\$" "$pkg" 2>&1)" || rc=$?
	if [ "$rc" -ne 0 ]; then
		printf '%s\n' "$out" | tail -30
		ladder no "$id  $name ($pkg) passed"
		return
	fi
	if printf '%s\n' "$out" | grep -qE 'no tests to run|no test files'; then
		ladder no "$id  $name ($pkg) actually RAN — go test reported no tests to run (renamed test?)"
		return
	fi
	ran="$(printf '%s\n' "$out" | grep -cE "^[[:space:]]*--- PASS: ${name}/" || true)"
	if [ "$ran" -ge "$min" ]; then
		ladder ok "$id  $name ($pkg): $ran subtests passed (min $min)"
	else
		ladder no "$id  $name ($pkg): only $ran subtests passed, want >= $min"
	fi
}

# ---- image-socket.1 — the path derivation and its safety invariant --------
# The served path and the pod Seatbelt deny-set must be the SAME string by
# construction: the socket's 0700-dir/0600-node posture admits the daemon's own
# uid, and a confined pod runs as that uid, so the deny is the only fence.
run_test "image-socket.1a" 4 TestRuntimedSocketPath ./pkg/provider/
run_test "image-socket.1b" 4 TestRuntimedSocketPathIsAlwaysDenied ./pkg/provider/
run_test "image-socket.1c" 3 TestRuntimedSocketDeniedToPods ./pkg/provider/

# ---- image-socket.2 — the serve loop is never fatal, and bounded ----------
run_test "image-socket.2" 3 TestRuntimedControlSocketRunIsNeverFatal ./cmd/k3sm/

# ---- image-socket.3 — the startup reconcile is not re-run by Serve --------
# Serve re-enters PodNetAdapter.ReconcileStartup through runtimed's
# reconcileNetworkStartup, whose own sync.Once the node's direct call never
# trips. A second pass sweeps every LIVE pod alias, because the known set is
# empty by construction — silent, and fatal to pod networking.
b3=ok
"${GOFLAGS_ENV[@]}" bash -c "cd '$K3SM_ROOT' && go test -count=1 -run '^TestPodNetAdapterReconcileStartup(RunsExactlyOnce|ReplaysFailure)\$' ./pkg/provider/" >/dev/null 2>&1 || b3=no
ladder "$b3" "image-socket.3  ReconcileStartup runs exactly once across both callers (and replays a failure)"

# ---- image-socket.4 — the wiring is present in the node bring-up ----------
# A structural rung, and a cheap one: the unit tests above prove the listener
# behaves, but only this proves startNode actually starts it. A refactor that
# dropped the call would leave every test above green.
b4=ok
grep -q 'startRuntimedControlSocket(ctx, prov, opts.podRoot' "$K3SM_ROOT/cmd/k3sm/node.go" || b4=no
grep -q 'stopControlSocket()' "$K3SM_ROOT/cmd/k3sm/node.go" || b4=no
ladder "$b4" "image-socket.4  startNode starts the control socket and defers its teardown"

# ---- image-socket.5 — the client dials what a default-rooted node binds ---
# Byte-identity, checked through the SHIPPED binary's own flag default rather
# than by re-deriving the constant here: a gate that recomputes the answer it is
# checking proves only that it can compute.
K3SM_BIN="$(mktemp -d)/k3sm"
trap 'rm -rf "$(dirname "$K3SM_BIN")"' EXIT
if (cd "$K3SM_ROOT" && "${GOFLAGS_ENV[@]}" go build -o "$K3SM_BIN" ./cmd/k3sm) ; then
	ladder ok "image-socket.5a the k3sm binary builds (GOARCH=arm64 CGO_ENABLED=1)"
else
	ladder no "image-socket.5a the k3sm binary builds (GOARCH=arm64 CGO_ENABLED=1)"
fi
DEFAULT_SOCK="/var/lib/k3sm/run/runtimed.sock"
# `image -h` exits non-zero (flag.ErrHelp), and this script runs under pipefail,
# so the output is captured before it is matched — a pipeline would report the
# binary's exit status and never the grep's.
IMAGE_HELP=""
[ -x "$K3SM_BIN" ] && IMAGE_HELP="$("$K3SM_BIN" image -h 2>&1 || true)"
if printf '%s\n' "$IMAGE_HELP" | grep -q "default \"$DEFAULT_SOCK\""; then
	ladder ok "image-socket.5b \`k3sm image\` defaults --socket to $DEFAULT_SOCK (what a default-rooted node binds)"
else
	ladder no "image-socket.5b \`k3sm image\` defaults --socket to $DEFAULT_SOCK (what a default-rooted node binds)"
fi
# An absent socket must fail as a DIAL against the named path, not as a parse or
# a panic: that error is the operator's only clue when the node is not serving.
ABSENT="$(dirname "$K3SM_BIN")/absent.sock"
LS_OUT="$(dirname "$K3SM_BIN")/ls.err"
if [ -x "$K3SM_BIN" ] && ! "$K3SM_BIN" image ls --socket "$ABSENT" --timeout 5s >"$LS_OUT" 2>&1; then
	if grep -q "$ABSENT" "$LS_OUT"; then
		ladder ok "image-socket.5c \`k3sm image ls\` against an unbound socket fails naming the path it dialled"
	else
		tail -5 "$LS_OUT"
		ladder no "image-socket.5c \`k3sm image ls\` against an unbound socket fails naming the path it dialled"
	fi
else
	ladder no "image-socket.5c \`k3sm image ls\` against an unbound socket must fail (it did not)"
fi

# ---- LIVE TIER ------------------------------------------------------------
if [ -z "${KUBECONFIG:-}" ]; then
	pending "image-socket.6  live: the node bound the socket at the derived path   (set KUBECONFIG)"
	pending "image-socket.7  live: the socket posture is 0700 dir / 0600 node      (set KUBECONFIG)"
	pending "image-socket.8  live: \`k3sm image ls\` succeeds against the node       (set KUBECONFIG)"
	pending "image-socket.9  live: \`k3sm image df\` reports the store's usage       (set KUBECONFIG)"
	pending "image-socket.10 live: \`k3sm image load\` ingests and the ref appears   (set KUBECONFIG)"
	pending "image-socket.11 live: a dial from a second uid is refused             (set KUBECONFIG)"
	echo "----------------------------------------"
	echo "image-socket: $PASS passed, $FAIL failed, $PENDING LIVE-PENDING"
	[ "$FAIL" -eq 0 ] || exit 1
	echo "image-socket: CI TIER GREEN — the LIVE tier did NOT run, so this exit 0 does NOT mean the socket serves."
	echo "              Start a server and re-run with KUBECONFIG (and K3SM_WORK_DIR) set."
	exit 0
fi

kubectl get --raw /healthz >/dev/null || { echo "the cluster at \$KUBECONFIG is not serving" >&2; exit 1; }

# The runtime root is the work dir's PARENT (executor.RuntimeRoot), and the socket
# hangs off it — the same derivation provider.RuntimedSocketPath makes.
SOCK="${K3SM_SOCKET:-}"
if [ -z "$SOCK" ]; then
	WORK_DIR="${K3SM_WORK_DIR:-/var/lib/k3sm/server}"
	SOCK="$(dirname "${WORK_DIR%/}")/run/runtimed.sock"
fi

# ---- image-socket.6 — the node bound it -----------------------------------
if [ -S "$SOCK" ]; then
	ladder ok "image-socket.6  the node bound a unix socket at $SOCK"
else
	ladder no "image-socket.6  the node bound a unix socket at $SOCK (not a socket; is the server running with this work dir?)"
	echo "----------------------------------------"
	echo "image-socket: no socket to talk to — the remaining live rungs cannot run ($PASS passed, $FAIL failed)" >&2
	exit 1
fi

# ---- image-socket.7 — the documented posture ------------------------------
# This is the ONLY thing keeping a non-daemon uid out of the node's control API,
# so it is asserted rather than assumed.
SOCK_MODE="$(stat -f '%Lp' "$SOCK" 2>/dev/null || stat -c '%a' "$SOCK" 2>/dev/null || echo '?')"
DIR_MODE="$(stat -f '%Lp' "$(dirname "$SOCK")" 2>/dev/null || stat -c '%a' "$(dirname "$SOCK")" 2>/dev/null || echo '?')"
[ "$SOCK_MODE" = "600" ] && ladder ok "image-socket.7a the socket node is mode 600 (got $SOCK_MODE)" \
	|| ladder no "image-socket.7a the socket node is mode 600 (got $SOCK_MODE) — any local uid could drive this node's runtime"
[ "$DIR_MODE" = "700" ] && ladder ok "image-socket.7b the socket dir is mode 700 (got $DIR_MODE)" \
	|| ladder no "image-socket.7b the socket dir is mode 700 (got $DIR_MODE)"

# ---- image-socket.8/9 — the metadata commands answer ----------------------
LIVE_OUT="$(dirname "$K3SM_BIN")/live.out"
if "$K3SM_BIN" image ls --socket "$SOCK" >"$LIVE_OUT" 2>&1; then
	ladder ok "image-socket.8  \`k3sm image ls\` succeeded against the running node"
else
	tail -5 "$LIVE_OUT"
	ladder no "image-socket.8  \`k3sm image ls\` succeeded against the running node"
fi
if "$K3SM_BIN" image df --socket "$SOCK" >"$LIVE_OUT" 2>&1; then
	ladder ok "image-socket.9  \`k3sm image df\` reported the image store's usage"
else
	tail -5 "$LIVE_OUT"
	ladder no "image-socket.9  \`k3sm image df\` reported the image store's usage"
fi

# ---- image-socket.10 — load ingests, and the ref becomes visible ----------
# The two halves are one rung on purpose: a load that reports success but leaves
# nothing in ls has written to a store the node does not read, which is exactly
# the failure a second out-of-process runtime would produce.
TMP="$(dirname "$K3SM_BIN")"
CTX="$TMP/ctx"; mkdir -p "$CTX"
REF="k3sm-image-socket-probe:t"
b10=ok
(cd "$K3SM_ROOT" && env GOARCH=arm64 CGO_ENABLED=0 go build -o "$CTX/hello-http" ./e2e/testdata/cmd/hello-http) || b10=no
cat > "$CTX/Dockerfile" <<'DOCKEREOF'
FROM scratch
COPY hello-http /bin/hello-http
ENTRYPOINT ["/bin/hello-http", "--id", "image-socket-probe", "--addr", ":8080"]
DOCKEREOF
TARBALL="$TMP/probe.tar"
if [ "$b10" = ok ]; then
	(cd "$CTX" && "$K3SM_BIN" build --tag "$REF" --format docker --output "$TARBALL" .) >"$LIVE_OUT" 2>&1 || b10=no
fi
if [ "$b10" != ok ]; then
	tail -10 "$LIVE_OUT" || true
	ladder no "image-socket.10a a \`docker load\`-shaped probe tarball was built"
	ladder no "image-socket.10b \`k3sm image load\` ingested it and the ref appears in ls"
else
	ladder ok "image-socket.10a a \`docker load\`-shaped probe tarball was built"
	if "$K3SM_BIN" image load "$TARBALL" --socket "$SOCK" >"$LIVE_OUT" 2>&1 &&
		"$K3SM_BIN" image ls --socket "$SOCK" 2>/dev/null | grep -q "$REF"; then
		ladder ok "image-socket.10b \`k3sm image load\` ingested it and the ref appears in ls"
	else
		tail -10 "$LIVE_OUT" || true
		ladder no "image-socket.10b \`k3sm image load\` ingested it and the ref appears in ls"
	fi
fi

# ---- image-socket.11 — a second uid is refused ----------------------------
# The uid gate is enforced by the filesystem, so proving it needs a second uid.
# Where none can be assumed (no passwordless sudo), the rung SKIPS rather than
# passing on the mode check alone — rung 7 already made that claim, and a rung
# that restates an earlier one is not evidence.
if [ "$(id -u)" = "0" ]; then
	skip "image-socket.11 a second uid is refused (running as root: root bypasses the mode)"
elif sudo -n true 2>/dev/null; then
	if sudo -n -u nobody "$K3SM_BIN" image ls --socket "$SOCK" --timeout 10s >"$LIVE_OUT" 2>&1; then
		ladder no "image-socket.11 a dial from a second uid is refused (uid 'nobody' READ this node's image store)"
	else
		ladder ok "image-socket.11 a dial from a second uid ('nobody') is refused"
	fi
else
	skip "image-socket.11 a second uid is refused (needs passwordless sudo to become another uid)"
fi

echo "----------------------------------------"
echo "image-socket: $PASS passed, $FAIL failed, $SKIP skipped"
[ "$FAIL" -eq 0 ] || exit 1
echo "=========== RUNTIMED CONTROL SOCKET GREEN ==========="

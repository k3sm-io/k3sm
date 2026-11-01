#!/usr/bin/env bash
#
# ociconformance.sh: build and run the OCI distribution-spec conformance suite
# (github.com/opencontainers/distribution-spec/conformance, a Ginkgo test
# binary) against the k3sm registry server (pkg/ociregistry).
#
# The suite is test tooling. It is built from a wrapper module kept as text in
# hack/ociconformance (go.mod.txt, go.sum.txt, wrapper.go.txt), outside this
# repo's go.mod, with -mod=readonly, so every module it links is hash-checked
# against go.sum.txt. hack/verify-deps.sh screens that go.sum's graph through
# hack/deps-ociconformance.lock (its wrapper graph stage). Nothing here is
# shipped: the k3sm binary links neither the suite nor Ginkgo.
#
#   build [<out-dir>]   build conformance.test and the server launcher
#                       (hack/ociconformance/serve) into <out-dir>
#                       (default hack/.ociconformance/bin). Needs the module
#                       proxy or a warm module cache.
#   run <bin-dir> <report-dir>
#                       run all four areas (pull, push, content discovery,
#                       content management) against a fresh server and write
#                       the suite's junit.xml into <report-dir>. No network:
#                       both processes run under a loopback-only sandbox.
#   regen               rewrite go.mod.txt and go.sum.txt from PIN with
#                       `go mod tidy`; then run hack/verify-deps.sh --update.
#
# The run's credential: a 32-byte random secret for the k3sm principal, minted
# from /dev/urandom into a 0600 file in a 0700 run directory. The server reads
# it from that file and keeps only its SHA-256; the suite gets it in its
# environment from a python3 execve (never on a command line). The k3sm-gate
# principal gets a secret the server mints and never writes. Both processes
# start with an empty environment apart from the variables named below. The
# run directory (secret and store) is removed on every exit, and the report is
# refused if it carries the secret.
#
# Exit status: 0 pass; 1 failure; 2 usage.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
K3SM_ROOT="$(cd "$HERE/.." && pwd)"
WRAPPER="$HERE/ociconformance"
OUT_ROOT="$HERE/.ociconformance"

# MODULE and PIN are the suite. The conformance directory is its own module
# and carries no tag of its own, so the pin is the pseudo-version of the
# commit the repository's v1.1.1 release tag names (a139cc4, 2025-01-23).
MODULE=github.com/opencontainers/distribution-spec/conformance
PIN=v0.0.0-20250123160558-a139cc423184

# The run's namespaces.
NAMESPACE=conformance/main
CROSSMOUNT_NAMESPACE=conformance/crossmount

die() {
	echo "FAIL: [ociconformance] $*" >&2
	exit 1
}

usage() {
	echo "usage: hack/ociconformance.sh build [<out-dir>] | run <bin-dir> <report-dir> | regen" >&2
	exit 2
}

# materialize <dir>: the wrapper module, as a buildable directory.
materialize() {
	mkdir -p "$1"
	cp "$WRAPPER/go.mod.txt" "$1/go.mod"
	cp "$WRAPPER/go.sum.txt" "$1/go.sum"
	cp "$WRAPPER/wrapper.go.txt" "$1/wrapper.go"
}

# check_pin: go.mod.txt requires MODULE at PIN, once.
check_pin() {
	local n
	n="$(grep -cE "^(require )?[[:space:]]*${MODULE//./\\.} ${PIN//./\\.}\$" "$WRAPPER/go.mod.txt" || true)"
	[ "$n" = 1 ] || die "hack/ociconformance/go.mod.txt does not require $MODULE $PIN exactly once"
}

build() {
	local out="${1:-$OUT_ROOT/bin}"
	command -v go >/dev/null 2>&1 || die "go is not on PATH"
	check_pin
	mkdir -p "$out" "$OUT_ROOT"
	out="$(cd "$out" && pwd)"
	local work
	work="$(mktemp -d "$OUT_ROOT/build.XXXXXX")"
	# shellcheck disable=SC2064 # expand work now
	trap "rm -rf '$work'" EXIT
	materialize "$work/wrapper"
	(
		cd "$work/wrapper"
		export GOWORK=off
		go mod verify
		go mod tidy -diff >/dev/null || die "hack/ociconformance/go.sum.txt is not tidy; run hack/ociconformance.sh regen"
		go test -c -mod=readonly -trimpath -o "$out/conformance.test" "$MODULE"
	) || die "could not build the conformance suite"
	(cd "$K3SM_ROOT" && go build -trimpath -o "$out/serve" ./hack/ociconformance/serve) ||
		die "could not build the server launcher"
	echo "OK: [ociconformance] built $out/conformance.test ($MODULE $PIN) and $out/serve"
}

regen() {
	command -v go >/dev/null 2>&1 || die "go is not on PATH"
	mkdir -p "$OUT_ROOT"
	local work
	work="$(mktemp -d "$OUT_ROOT/regen.XXXXXX")"
	# shellcheck disable=SC2064 # expand work now
	trap "rm -rf '$work'" EXIT
	local gover
	gover="$(sed -n 's/^go //p' "$WRAPPER/go.mod.txt")"
	printf 'module k3sm.io/ociconformance-child\n\ngo %s\n\nrequire %s %s\n' "$gover" "$MODULE" "$PIN" >"$work/go.mod"
	cp "$WRAPPER/wrapper.go.txt" "$work/wrapper.go"
	(cd "$work" && GOWORK=off go mod tidy) || die "go mod tidy failed"
	cp "$work/go.mod" "$WRAPPER/go.mod.txt"
	cp "$work/go.sum" "$WRAPPER/go.sum.txt"
	check_pin
	echo "OK: [ociconformance] rewrote hack/ociconformance/go.mod.txt and go.sum.txt; now run hack/verify-deps.sh --update"
}

# The sandbox both processes of a run share: everything but the network,
# which is loopback only.
SANDBOX_PROFILE='(version 1)
(allow default)
(deny network*)
(allow network-bind (local ip "localhost:*"))
(allow network-inbound (local ip "localhost:*"))
(allow network-outbound (remote ip "localhost:*"))
(allow network-outbound (remote unix-socket))'

# confine: print the command prefix that keeps a process off the network. A
# process already inside a sandbox cannot apply a second one (macOS refuses a
# nested sandbox-exec); then the enclosing sandbox must deny the network
# itself. Either way a connect to a public address has to fail first.
confine() {
	if sandbox-exec -p '(version 1)(allow default)' /usr/bin/true 2>/dev/null; then
		# The profile itself is proven: a connect to a public address under it
		# has to fail.
		! sandbox-exec -p "$SANDBOX_PROFILE" /usr/bin/nc -z -G 3 -w 3 1.1.1.1 443 >/dev/null 2>&1 ||
			die "the loopback-only sandbox let a connect to a public address through"
		echo sandbox
		return 0
	fi
	! /usr/bin/nc -z -G 3 -w 3 1.1.1.1 443 >/dev/null 2>&1 ||
		die "cannot apply the loopback-only sandbox, and the network is reachable from here"
	echo inherited
}

# launch <mode> <env-json> <secret-env-name|-> <secret-file|-> <cmd...>: exec
# cmd under python3 with exactly the environment in env-json, plus the secret
# read from secret-file into secret-env-name, so the secret never reaches a
# command line. It execs, so it is run in a subshell or in the background,
# where $! is then the launched process itself.
LAUNCH_PY='
import json, os, sys
env = json.loads(sys.argv[1])
if sys.argv[2] != "-":
    with open(sys.argv[3]) as f:
        env[sys.argv[2]] = f.read().strip()
os.execve(sys.argv[4], sys.argv[4:], env)
'
launch() {
	local mode="$1" envjson="$2" sname="$3" sfile="$4"
	shift 4
	if [ "$mode" = sandbox ]; then
		exec sandbox-exec -p "$SANDBOX_PROFILE" /usr/bin/python3 -I -c "$LAUNCH_PY" "$envjson" "$sname" "$sfile" "$@"
	fi
	exec /usr/bin/python3 -I -c "$LAUNCH_PY" "$envjson" "$sname" "$sfile" "$@"
}

run() {
	[ $# -eq 2 ] || usage
	local bin report
	bin="$(cd "$1" && pwd)" || die "no bin dir $1"
	mkdir -p "$2"
	report="$(cd "$2" && pwd)"
	[ -x "$bin/conformance.test" ] && [ -x "$bin/serve" ] || die "$bin lacks conformance.test or serve; run hack/ociconformance.sh build first"
	local mode
	mode="$(confine)"
	echo "==> [ociconformance] network confinement: $mode"
	mkdir -p "$OUT_ROOT"
	local rd
	rd="$(mktemp -d "$OUT_ROOT/run.XXXXXX")"
	chmod 700 "$rd"
	SERVE_PID=""
	# shellcheck disable=SC2064 # expand rd now; SERVE_PID is read at exit
	trap "[ -z \"\$SERVE_PID\" ] || kill \"\$SERVE_PID\" 2>/dev/null || true; wait 2>/dev/null || true; rm -rf '$rd'" EXIT
	(umask 077 && head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n' >"$rd/secret")
	[ "$(wc -c <"$rd/secret" | tr -d ' ')" = 64 ] || die "could not mint the run credential"
	mkdir -p "$rd/work" "$rd/report"
	launch "$mode" '{}' - - "$bin/serve" -work-dir "$rd/work" -secret-file "$rd/secret" -addr-file "$rd/addr" 2>"$rd/serve.log" &
	SERVE_PID=$!
	local i
	for i in $(seq 300); do
		[ ! -s "$rd/addr" ] || break
		kill -0 "$SERVE_PID" 2>/dev/null || { cat "$rd/serve.log" >&2; die "the registry server exited"; }
		sleep 0.1
	done
	[ -s "$rd/addr" ] || die "the registry server did not report its address"
	local addr
	addr="$(cat "$rd/addr")"
	case "$addr" in 127.0.0.1:[0-9]*) ;; *) die "unexpected server address '$addr'" ;; esac
	echo "==> [ociconformance] server on $addr, running $MODULE $PIN"
	local envjson
	envjson="$(/usr/bin/python3 -I -c 'import json, sys; print(json.dumps(dict(a.split("=", 1) for a in sys.argv[1:])))' \
		"OCI_ROOT_URL=http://$addr" \
		"OCI_NAMESPACE=$NAMESPACE" \
		"OCI_CROSSMOUNT_NAMESPACE=$CROSSMOUNT_NAMESPACE" \
		"OCI_USERNAME=k3sm" \
		"OCI_TEST_PULL=1" \
		"OCI_TEST_PUSH=1" \
		"OCI_TEST_CONTENT_DISCOVERY=1" \
		"OCI_TEST_CONTENT_MANAGEMENT=1" \
		"OCI_AUTOMATIC_CROSSMOUNT=0" \
		"OCI_HIDE_SKIPPED_WORKFLOWS=0" \
		"OCI_DEBUG=0" \
		"OCI_REPORT_DIR=$rd/report")"
	local rc=0
	(cd "$rd" && launch "$mode" "$envjson" OCI_PASSWORD "$rd/secret" "$bin/conformance.test" -test.v -ginkgo.no-color) >"$rd/suite.log" 2>&1 || rc=$?
	kill "$SERVE_PID" 2>/dev/null || true
	wait "$SERVE_PID" 2>/dev/null || true
	SERVE_PID=""
	[ -s "$rd/report/junit.xml" ] || { tail -40 "$rd/suite.log" >&2; die "the suite wrote no junit.xml (exit $rc)"; }
	if grep -qF -f "$rd/secret" "$rd/report/junit.xml" "$rd/suite.log" "$rd/serve.log"; then
		die "the run's output carries the run credential; refusing to keep it"
	fi
	cp "$rd/report/junit.xml" "$report/junit.xml"
	cp "$rd/suite.log" "$report/suite.log"
	cp "$rd/serve.log" "$report/serve.log"
	tail -6 "$rd/suite.log"
	echo "==> [ociconformance] suite exit $rc; junit.xml in $report"
	return "$rc"
}

case "${1:-}" in
build) shift; [ $# -le 1 ] || usage; build "$@" ;;
run) shift; run "$@" ;;
regen) shift; [ $# -eq 0 ] || usage; regen ;;
*) usage ;;
esac

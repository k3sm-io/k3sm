#!/usr/bin/env bash
#
# etcd-wrapper.sh — regenerate and verify the embedded etcd wrapper module.
#
# The executor builds two programs from a three-file wrapper module embedded as
# text in pkg/executor/etcdchild (go.mod.txt, go.sum.txt, main.go.txt):
#
#   - the pinned etcd server: the wrapper's main is upstream's own
#     server/main.go. `go install go.etcd.io/etcd/server/v3@<pin>` is impossible
#     because upstream's server/go.mod carries monorepo replace directives;
#   - etcdutl at the SAME pin, the offline tool `k3sm snapshot restore` runs to
#     rebuild a data dir from a snapshot. It is upstream's own etcdutl main
#     package, declared with a `tool` directive so one go.mod (and one go.sum)
#     selects every module both programs link.
#
# Nothing outside this script sees the wrapper's dependency graph (it is not a
# module of this repo), so this is where it is refreshed and checked.
#
#   regen <version>   rewrite the three files: upstream's server/main.go at
#                     <version>, a fresh `go get` of the server and of etcdutl
#                     as a tool (plus the OVERRIDES below) + `go mod tidy`,
#                     keeping the current go/toolchain lines. Bump
#                     DefaultEtcdVersion (pkg/executor/executor.go) in the same
#                     commit; TestDefaultEtcdVersionMatchesWrapper fails until
#                     you do.
#   verify            materialize the wrapper and run `go mod verify`,
#                     `go mod tidy -diff` (the committed go.sum is complete),
#                     the one-pin check (server and etcdutl at one version),
#                     and `govulncheck` over both programs. A missing
#                     govulncheck prints a SKIP line and does not fail; every
#                     real finding or error does. Needs the module proxy (or a
#                     warm module cache) and, for govulncheck, the
#                     vulnerability database.
#
# Exit status: 0 pass; 1 failure; 2 usage.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
K3SM_ROOT="$(cd "$HERE/.." && pwd)"
WRAPPER="$K3SM_ROOT/pkg/executor/etcdchild"
# The work dir is the repo's own gitignored scratch, removed on exit.
WORK_ROOT="$K3SM_ROOT/hack/.etcd-wrapper"

usage() {
	echo "usage: hack/etcd-wrapper.sh regen <version> | verify" >&2
	exit 2
}

mkwork() {
	mkdir -p "$WORK_ROOT"
	WORK="$(mktemp -d "$WORK_ROOT/run.XXXXXX")"
	trap 'rm -rf "$WORK"; rmdir "$WORK_ROOT" 2>/dev/null || true' EXIT
}

# OVERRIDES raises transitive modules above what the etcd server module selects,
# applied with `go get` before the tidy. Each entry is the lowest version that
# clears a govulncheck finding the wrapper actually calls; drop an entry once the
# pinned etcd selects that version (or newer) on its own.
#   go.opentelemetry.io/otel family v1.45.0: GO-2026-6505 (reached through the
#   otlptrace exporter etcd's tracing setup initializes).
#   golang.org/x/net v0.60.0: GO-2026-6611, GO-2026-6612, GO-2026-6617 (the
#   http2 server and client both programs serve and dial through).
OVERRIDES=(
	golang.org/x/net@v0.60.0
	go.opentelemetry.io/otel@v1.45.0
	go.opentelemetry.io/otel/sdk@v1.45.0
	go.opentelemetry.io/otel/trace@v1.45.0
	go.opentelemetry.io/otel/metric@v1.45.0
	go.opentelemetry.io/otel/exporters/otlp/otlptrace@v1.45.0
	go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc@v1.45.0
)

# ETCDUTL is the restore tool's main package, built from the wrapper module.
ETCDUTL=go.etcd.io/etcd/etcdutl/v3

# Every go invocation here builds the wrapper as its own module: never this
# repo's workspace, never a downloaded toolchain.
wgo() { GOWORK=off GOTOOLCHAIN=local CGO_ENABLED=0 go "$@"; }

# onepin fails unless the server module and etcdutl resolve to <want> (or, with
# no argument, to one shared version), in the wrapper at $WORK.
onepin() {
	local want="${1:-}" server util
	server="$(cd "$WORK" && wgo list -m -f '{{.Version}}' go.etcd.io/etcd/server/v3)"
	util="$(cd "$WORK" && wgo list -m -f '{{.Version}}' "$ETCDUTL")"
	[ -n "$want" ] || want="$server"
	if [ "$server" != "$want" ] || [ "$util" != "$want" ]; then
		echo "etcd-wrapper: etcd server is $server and etcdutl is $util (want both at $want)" >&2
		exit 1
	fi
	if ! (cd "$WORK" && grep -qx "tool $ETCDUTL" go.mod); then
		echo "etcd-wrapper: go.mod declares no 'tool $ETCDUTL'" >&2
		exit 1
	fi
}

regen() {
	local version="$1"
	case "$version" in
	v3.*) ;;
	*) echo "regen: version must look like v3.x.y, got '$version'" >&2; exit 2 ;;
	esac
	mkwork
	local goline toolline
	goline="$(grep -E '^go ' "$WRAPPER/go.mod.txt")"
	toolline="$(grep -E '^toolchain ' "$WRAPPER/go.mod.txt" || true)"
	{
		printf 'module k3sm.io/etcd-child\n\n%s\n' "$goline"
		[ -z "$toolline" ] || printf '\n%s\n' "$toolline"
	} >"$WORK/go.mod"
	# A placeholder main so `go get` sees the import; replaced by upstream's below.
	printf 'package main\n\nimport _ "go.etcd.io/etcd/server/v3/etcdmain"\n\nfunc main() {}\n' >"$WORK/main.go"
	(cd "$WORK" && GOFLAGS=-mod=mod wgo get "go.etcd.io/etcd/server/v3@$version")
	local dir
	dir="$(cd "$WORK" && wgo list -m -f '{{.Dir}}' go.etcd.io/etcd/server/v3)"
	[ -f "$dir/main.go" ] || { echo "regen: upstream main.go not found in $dir" >&2; exit 1; }
	cp "$dir/main.go" "$WORK/main.go"
	chmod 0644 "$WORK/main.go"
	(cd "$WORK" && GOFLAGS=-mod=mod wgo get -tool "$ETCDUTL@$version")
	(cd "$WORK" && GOFLAGS=-mod=mod wgo get "${OVERRIDES[@]}")
	(cd "$WORK" && GOFLAGS=-mod=mod wgo mod tidy)
	# Neither the tool nor the overrides may move either program off the pin.
	onepin "$version"
	cp "$WORK/go.mod" "$WRAPPER/go.mod.txt"
	cp "$WORK/go.sum" "$WRAPPER/go.sum.txt"
	cp "$WORK/main.go" "$WRAPPER/main.go.txt"
	echo "regen: wrapper now pins go.etcd.io/etcd/server/v3 and $ETCDUTL at $version; set DefaultEtcdVersion = \"$version\" in pkg/executor/executor.go"
}

verify() {
	mkwork
	cp "$WRAPPER/go.mod.txt" "$WORK/go.mod"
	cp "$WRAPPER/go.sum.txt" "$WORK/go.sum"
	cp "$WRAPPER/main.go.txt" "$WORK/main.go"
	echo "==> [etcd-wrapper] go mod download + verify"
	(cd "$WORK" && GOFLAGS=-mod=readonly wgo mod download && GOFLAGS=-mod=readonly wgo mod verify)
	echo "==> [etcd-wrapper] go mod tidy -diff (the committed lockfile is complete)"
	(cd "$WORK" && GOFLAGS= wgo mod tidy -diff)
	echo "==> [etcd-wrapper] one pin: etcd server and etcdutl at the same version"
	onepin
	local vc=""
	for c in "$(command -v govulncheck || true)" "$(go env GOPATH)/bin/govulncheck"; do
		if [ -n "$c" ] && [ -x "$c" ]; then
			vc="$c"
			break
		fi
	done
	if [ -z "$vc" ]; then
		echo "==> [etcd-wrapper] SKIP govulncheck: not installed (go install golang.org/x/vuln/cmd/govulncheck@latest)"
	else
		echo "==> [etcd-wrapper] govulncheck ./... $ETCDUTL"
		(cd "$WORK" && GOWORK=off GOTOOLCHAIN=local GOFLAGS=-mod=readonly "$vc" ./... "$ETCDUTL")
	fi
	echo "OK: etcd wrapper verified"
}

[ $# -ge 1 ] || usage
case "$1" in
regen) [ $# -eq 2 ] || usage; regen "$2" ;;
verify) [ $# -eq 1 ] || usage; verify ;;
*) usage ;;
esac

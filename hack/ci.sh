#!/usr/bin/env bash
# k3sm local CI — the standard CI / pre-commit gate (docs/GO-STANDARDS.md) in one
# command. Run from anywhere.
set -euo pipefail
cd "$(dirname "$0")/.."   # repo root

CGO=1   # k3sm is CGO_ENABLED=1 — it imports runtimed (cgo syscall shims). kine is a child process, not a dependency.

echo "==> [k3sm] gofmt"
fmt=$(gofmt -l .) || true
[ -z "$fmt" ] || { echo "gofmt -w needed:"; echo "$fmt"; exit 1; }

echo "==> [k3sm] license headers"
hack/verify-boilerplate.sh

# Enumerate the Go packages BEFORE deciding to skip anything. Exit 0 with empty
# output means "no Go packages yet" — the legitimate skip this guard was written
# for. A NON-ZERO exit (broken go.mod, unresolvable dependency, bad GOWORK, absent
# toolchain) is a HARD ERROR: the old `[ -n "$(go list ./... 2>/dev/null)" ]` could
# not tell the two apart, so it silently skipped vet/build/test and still reported
# green — a gate that cannot even enumerate its packages must go RED (B168).
golist_err="$(mktemp)"
trap 'rm -f "$golist_err"' EXIT
if ! go_pkgs="$(CGO_ENABLED=$CGO go list ./... 2>"$golist_err")"; then
	echo "FAIL: [k3sm] go list ./... failed — cannot enumerate packages; refusing to skip vet/build/test:" >&2
	cat "$golist_err" >&2
	exit 1
fi

if [ -n "$go_pkgs" ]; then
	echo "==> [k3sm] go vet";   CGO_ENABLED=$CGO go vet ./...
	echo "==> [k3sm] go build"; CGO_ENABLED=$CGO go build ./...
	echo "==> [k3sm] go test";  CGO_ENABLED=$CGO go test ./...   # e2e/ is //go:build e2e — excluded here
	# The integration tier is NOT run here (it needs darwin + a real socket), but
	# nothing else in this repo COMPILES the `integration` build tag, so the
	# B116 privilege-premise canary would rot invisibly. Vet it.
	echo "==> [k3sm] go vet -tags integration"; CGO_ENABLED=$CGO go vet -tags integration ./...
else
	echo "==> [k3sm] (no Go packages yet — skipping vet/build/test)"
fi

echo "==> [k3sm] go mod tidy (no-diff)"
go mod tidy
if [ -n "$(git status --porcelain -- go.mod go.sum 2>/dev/null)" ]; then
	echo "go.mod/go.sum not tidy after 'go mod tidy':"; git --no-pager diff -- go.mod go.sum; exit 1
fi
# Keep the genproto replace (resolves the monolith-vs-split ambiguous import).
grep -q 'replace google.golang.org/genproto' go.mod || { echo "missing genproto replace in go.mod"; exit 1; }

echo "OK: k3sm ci green"

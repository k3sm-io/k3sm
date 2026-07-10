#!/usr/bin/env bash
# k3sm local CI — the standard CI / pre-commit gate (docs/GO-STANDARDS.md) in one
# command. Run from anywhere.
set -euo pipefail
cd "$(dirname "$0")/.."   # repo root

CGO=1   # M1: k3sm is CGO_ENABLED=1 — it imports runtimed (cgo syscall shims) and kine (mattn/go-sqlite3).

echo "==> [k3sm] gofmt"
fmt=$(gofmt -l .) || true
[ -z "$fmt" ] || { echo "gofmt -w needed:"; echo "$fmt"; exit 1; }

echo "==> [k3sm] license headers"
hack/verify-boilerplate.sh

if [ -n "$(CGO_ENABLED=$CGO go list ./... 2>/dev/null)" ]; then
	echo "==> [k3sm] go vet";   CGO_ENABLED=$CGO go vet ./...
	echo "==> [k3sm] go build"; CGO_ENABLED=$CGO go build ./...
	echo "==> [k3sm] go test";  CGO_ENABLED=$CGO go test ./...   # e2e/ is //go:build e2e — excluded here
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

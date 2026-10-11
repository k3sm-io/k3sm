#!/usr/bin/env bash
# Pinned-tools fixture. A comment is not an invocation: go install example.com/x@latest
TOOL_VERSION="v1.4.0"
DEFAULTED="${DEFAULTED:-v0.3.1}"
go install example.com/tool/cmd/a@v1.2.3
GOBIN="$BIN" go install "example.com/tool/cmd/b@${TOOL_VERSION}"
go run "example.com/tool/cmd/c@$DEFAULTED" --flag
go run -tags x example.com/tool/cmd/d@v0.0.0-20240101000000-abcdefabcdef
env CGO_ENABLED=0 \
	go install github.com/Upper/Case/cmd/e@v2.0.0+incompatible
go run ./hack/local
go run -tags x ./cmd/thing
go install
CMD=(go run "example.com/tool/cmd/f@$TOOL_VERSION")
out="$( (cd sub && go run ./cmd/g) )"
echo "to install by hand: go install example.com/tool/cmd/hint@latest"
go install example.com/fixture/cmd/self # a main-module package
go install k3sm.io/apis/cmd/x
install_tool() { go install "${1}@${2}"; }
go -C sub install example.com/tool/cmd/h@v1.0.0
"${GO:-go}" run example.com/tool/cmd/i@v1.0.0
sh -c "go install example.com/tool/cmd/j@v1.0.0"
bash -euc 'cd sub && go run ./local'

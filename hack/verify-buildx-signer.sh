#!/usr/bin/env bash
#
# verify-buildx-signer.sh — re-pin-time check of the pinned darwin buildx asset.
#
# A thin CLI over hack/buildx/verifysigner, which takes the pin, the URL and the
# expected Team ID from pkg/builder (never a copy here). By default it:
#
#   1. downloads the pinned darwin-arm64 buildx asset ONCE (network),
#   2. asserts its sha256 equals builder.HostBuildxSHA256,
#   3. asserts `codesign --verify --strict` passes and `codesign -dv` reports
#      TeamIdentifier == builder.HostBuildxTeamID on that same file.
#
# Run it after editing the buildx pin constants; any failure exits non-zero and
# prints no success line. Runtime verification stays sha256-only: this is
# re-pin tooling, not enforcement.
#
# Usage:
#   hack/verify-buildx-signer.sh                  # download + sha256 + signer
#   hack/verify-buildx-signer.sh --file <path>    # signer stage only, local file, no network
#
# Exit status: 0 pass; 1 operational error; 2 usage; 3 unsigned; 4 strict verify
# failed; 5 ad-hoc; 6 Team ID not set; 7 no TeamIdentifier line; 8 wrong Team ID.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
K3SM_ROOT="$(cd "$HERE/.." && pwd)"

ARGS=()
while [ $# -gt 0 ]; do
	case "$1" in
	--file) ARGS+=(-file "$(cd "$(dirname "${2:?--file needs a path}")" && pwd)/$(basename "$2")"); shift ;;
	--timeout) ARGS+=(-timeout "${2:?--timeout needs a duration}"); shift ;;
	-h | --help)
		sed -n '2,23p' "$0" | sed 's/^# \{0,1\}//'
		exit 0
		;;
	*)
		echo "verify-buildx-signer.sh: unknown argument: $1" >&2
		exit 2
		;;
	esac
	shift
done

# Built, not `go run`: go run flattens every non-zero exit to 1, and the
# verdict-specific exit status is part of this script's contract.
BIN_DIR="$(mktemp -d)"
trap 'rm -rf "$BIN_DIR"' EXIT
(cd "$K3SM_ROOT" && go build -o "$BIN_DIR/verifysigner" ./hack/buildx/verifysigner)
rc=0
"$BIN_DIR/verifysigner" ${ARGS[@]+"${ARGS[@]}"} || rc=$?
exit "$rc"

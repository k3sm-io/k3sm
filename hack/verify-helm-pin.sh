#!/usr/bin/env bash
#
# verify-helm-pin.sh — re-pin-time check of the pinned helm tarball.
#
# A thin CLI over hack/helm/verifypin, which takes the version, asset, URLs and
# pin from pkg/helmchart (never a copy here). By default it:
#
#   1. fetches helm's published <asset>.sha256sum for the pinned darwin-arm64
#      tarball (network),
#   2. asserts the file names the pinned asset and its digest equals
#      helmchart.HelmSHA256.
#
# With --download it also fetches the tarball once and asserts its sha256.
#
# Run it after editing the helm pin constants; any failure exits non-zero and
# prints no PASS line. Runtime verification is the same sha256, checked on every
# download: this is re-pin tooling, not enforcement.
#
# Usage:
#   hack/verify-helm-pin.sh               # published checksum vs the pin
#   hack/verify-helm-pin.sh --download    # plus the tarball's own digest
#
# Exit status: 0 pass; 1 operational error; 2 usage; 3 mismatch.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
K3SM_ROOT="$(cd "$HERE/.." && pwd)"

ARGS=()
while [ $# -gt 0 ]; do
	case "$1" in
	--download) ARGS+=(-download) ;;
	--timeout) ARGS+=(-timeout "${2:?--timeout needs a duration}"); shift ;;
	-h | --help)
		sed -n '2,23p' "$0" | sed 's/^# \{0,1\}//'
		exit 0
		;;
	*)
		echo "verify-helm-pin.sh: unknown argument: $1" >&2
		exit 2
		;;
	esac
	shift
done

# Built, not `go run`: go run flattens every non-zero exit to 1, and the
# verdict-specific exit status is part of this script's contract.
BIN_DIR="$(mktemp -d)"
trap 'rm -rf "$BIN_DIR"' EXIT
(cd "$K3SM_ROOT" && go build -o "$BIN_DIR/verifypin" ./hack/helm/verifypin)
rc=0
"$BIN_DIR/verifypin" ${ARGS[@]+"${ARGS[@]}"} || rc=$?
exit "$rc"

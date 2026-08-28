#!/usr/bin/env bash
#
# verify-image-pins.sh — verify k3sm's digest-pinned image references.
#
# Two orthogonal checks, both implemented in k3sm.io/k3sm/pkg/images (this script is a
# thin CLI over that package, never a reimplementation of it):
#
#   lockstep  the pin constants in pkg/images match hack/images/mirror.yaml, 1:1 in both
#             directions. Pure comparison of two committed files: no network, no
#             registry. It also rides `go test ./...`, so drift reds every CI run whether
#             or not anyone runs this script.
#
#   --live    each manifest entry actually exists in the registry at its recorded digest,
#             carrying the platforms it claims, fetched ANONYMOUSLY. The anonymous fetch
#             is the point: it is what proves the mirrored package is publicly readable.
#             Never add a credential to this path.
#
# OFF BY DEFAULT: with no arguments this script does the offline lockstep check only and
# makes no network request. --live is the opt-in release gate.
#
# Usage:
#   hack/verify-image-pins.sh                                  # offline lockstep
#   hack/verify-image-pins.sh --live                           # + registry verification
#   hack/verify-image-pins.sh --manifest <path>                # lockstep vs another manifest
#   hack/verify-image-pins.sh --live --manifest <path> --registry <host:port> [--insecure]
#                                                              # loopback-fixture seam
#
# When --registry is given the lockstep half is skipped, because fixture content has
# fixture digests and cannot match the shipped constants. --manifest alone still runs
# lockstep — that is how a mutated manifest is proven to fail.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
K3SM_ROOT="$(cd "$HERE/.." && pwd)"
MANIFEST="$K3SM_ROOT/hack/images/mirror.yaml"

LIVE=""
REGISTRY=""
INSECURE=""
EXTRA=()
while [ $# -gt 0 ]; do
	case "$1" in
	--live) LIVE="-live" ;;
	--manifest) MANIFEST="${2:?--manifest needs a path}"; shift ;;
	--registry) REGISTRY="${2:?--registry needs host:port}"; shift ;;
	--insecure) INSECURE="-insecure" ;;
	--timeout) EXTRA+=("-timeout" "${2:?--timeout needs a duration}"); shift ;;
	-h | --help)
		sed -n '2,32p' "$0" | sed 's/^# \{0,1\}//'
		exit 0
		;;
	*)
		echo "verify-image-pins.sh: unknown argument: $1" >&2
		exit 2
		;;
	esac
	shift
done

ARGS=(-manifest "$MANIFEST")
[ -n "$LIVE" ] && ARGS+=("$LIVE")
[ -n "$REGISTRY" ] && ARGS+=(-registry "$REGISTRY")
[ -n "$INSECURE" ] && ARGS+=("$INSECURE")
[ ${#EXTRA[@]} -gt 0 ] && ARGS+=("${EXTRA[@]}")

cd "$K3SM_ROOT"
exec go run ./hack/images/verifypins "${ARGS[@]}"

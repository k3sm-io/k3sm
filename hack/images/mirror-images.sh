#!/usr/bin/env bash
#
# mirror-images.sh — copy every upstream image the mirror manifests record into the
# k3sm GHCR mirror, for each entry whose mirror digest the registry does not yet serve.
#
# Reads hack/images/mirror.yaml (the entries pkg/images pins, held 1:1 by the lockstep
# test) and hack/images/mirror-staged.yaml (entries recorded ahead of the constant that
# will consume them). For every entry it checks whether
# ghcr.io/k3sm-io/mirror/<name>@<digest> is servable; if not, it prints the copy command,
# and with --run it executes it and then re-resolves the durable tag, which must answer
# with the recorded digest.
#
# The copy is `crane cp` of the FULL index from the upstream ref BY DIGEST, never with
# --platform: a platform subset is a different manifest with a different digest, and the
# whole point of the mirror is that its digest IS upstream's, auditable against upstream
# by anyone. crane is pinned at v0.20.2 and run through `go run`, so nothing is installed
# on the host PATH.
#
# OFF BY DEFAULT: with no arguments this prints what it would copy and writes nothing.
# --run is the one registry-write path, and it is an operator act (a public-registry
# write while CI is dormant). The credential is read from stdin into a throwaway
# DOCKER_CONFIG that is deleted on exit; it never touches ~/.docker and is never an
# argument, so it stays out of the process table and shell history.
#
# Without a credential the presence check is anonymous, so an entry in a package that
# exists but is not yet public reads as absent and is listed. Copying it again is
# harmless: the destination digest is identical.
#
# Usage:
#   hack/images/mirror-images.sh                        # dry run: list what is missing
#   hack/images/mirror-images.sh --user <login> --password-stdin < token
#                                                       # dry run, authenticated check
#   hack/images/mirror-images.sh --run --user <login> --password-stdin < token
#                                                       # copy every missing entry
#   hack/images/mirror-images.sh --manifest <path> ...  # replace the default manifests
#
# Environment:
#   K3SM_CRANE  a crane binary to use instead of `go run ...@v0.20.2`; refused unless
#               `$K3SM_CRANE version` prints exactly v0.20.2.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
CRANE_VERSION="v0.20.2"
MIRROR_PREFIX="ghcr.io/k3sm-io/mirror/"
REGISTRY="ghcr.io"

RUN=""
USER_LOGIN=""
PW_STDIN=""
MANIFESTS=()
while [ $# -gt 0 ]; do
	case "$1" in
	--run) RUN=1 ;;
	--user) USER_LOGIN="${2:?--user needs a login}"; shift ;;
	--password-stdin) PW_STDIN=1 ;;
	--manifest) MANIFESTS+=("${2:?--manifest needs a path}"); shift ;;
	-h | --help)
		sed -n '2,42p' "$0" | sed 's/^# \{0,1\}//'
		exit 0
		;;
	*)
		echo "mirror-images.sh: unknown argument: $1 (try --help)" >&2
		exit 2
		;;
	esac
	shift
done
if [ ${#MANIFESTS[@]} -eq 0 ]; then
	MANIFESTS=("$HERE/mirror.yaml" "$HERE/mirror-staged.yaml")
fi
if [ -n "$PW_STDIN" ] && [ -z "$USER_LOGIN" ]; then
	echo "mirror-images.sh: --password-stdin needs --user" >&2
	exit 2
fi
if [ -n "$USER_LOGIN" ] && [ -z "$PW_STDIN" ]; then
	echo "mirror-images.sh: --user needs --password-stdin (the credential is never an argument)" >&2
	exit 2
fi

if [ -n "${K3SM_CRANE:-}" ]; then
	got="$("$K3SM_CRANE" version 2>/dev/null || true)"
	if [ "$got" != "$CRANE_VERSION" ]; then
		echo "mirror-images.sh: K3SM_CRANE=$K3SM_CRANE reports '${got:-nothing}', want $CRANE_VERSION" >&2
		exit 1
	fi
	CRANE=("$K3SM_CRANE")
else
	CRANE=(go run "github.com/google/go-containerregistry/cmd/crane@$CRANE_VERSION")
fi
CRANE_SHOWN="crane"   # the printed commands name crane; the pin is stated once above

# A throwaway credential store: login writes here, every crane call reads here, and
# the trap removes it however the script exits.
DOCKER_CONFIG="$(mktemp -d -t k3sm-mirror)"
export DOCKER_CONFIG
trap 'rm -rf "$DOCKER_CONFIG"' EXIT
if [ -n "$PW_STDIN" ]; then
	"${CRANE[@]}" auth login "$REGISTRY" -u "$USER_LOGIN" --password-stdin >/dev/null
fi

# entries <manifest> — print "name upstream mirror tag" per entry. The manifests are a
# fixed, flat schema owned by this directory (the Go loader in pkg/images is the strict
# parser for mirror.yaml); this reads only the four scalar keys it needs.
entries() {
	awk '
	function flush() { if (name != "") print name, up, mir, tag; name = up = mir = tag = "" }
	/^  - name:/     { flush(); name = $3; next }
	/^    upstream:/ { up = $2; next }
	/^    mirror:/   { mir = $2; next }
	/^    tag:/      { tag = $2; next }
	END { flush() }
	' "$1"
}

TOTAL=0
MISSING=0
COPIED=0
for mf in "${MANIFESTS[@]}"; do
	[ -r "$mf" ] || { echo "mirror-images.sh: cannot read $mf" >&2; exit 1; }
	while read -r name up mir tag; do
		TOTAL=$((TOTAL + 1))
		for v in "$name" "$up" "$mir" "$tag"; do
			[ -n "$v" ] || { echo "mirror-images.sh: $mf: entry '$name' is missing a key" >&2; exit 1; }
		done
		case "$up" in *@sha256:*) ;; *) echo "mirror-images.sh: $mf: $name upstream is not digest-pinned" >&2; exit 1 ;; esac
		case "$mir" in "$MIRROR_PREFIX"*@sha256:*) ;; *) echo "mirror-images.sh: $mf: $name mirror must be $MIRROR_PREFIX<name>@sha256:..." >&2; exit 1 ;; esac
		digest="${up##*@}"
		if [ "${mir##*@}" != "$digest" ]; then
			echo "mirror-images.sh: $mf: $name upstream and mirror digests differ" >&2
			exit 1
		fi
		# The source is the upstream REPOSITORY at the digest: drop the human-readable
		# tag, which sits after the last path component's colon.
		base="${up%@*}"
		last="${base##*/}"
		src="${base%/*}/${last%%:*}@$digest"
		dst="${mir%@*}:$tag"

		if reason="$("${CRANE[@]}" manifest "$mir" 2>&1 >/dev/null)"; then
			echo "present   $name  $mir"
			continue
		fi
		MISSING=$((MISSING + 1))
		echo "missing   $name  $mir  ($(printf '%s' "$reason" | grep -Eo '(UNAUTHORIZED|DENIED|MANIFEST_UNKNOWN|NAME_UNKNOWN)[^"]*' | head -1 || true))"
		echo "  $CRANE_SHOWN cp $src $dst"
		[ -n "$RUN" ] || continue

		"${CRANE[@]}" cp "$src" "$dst"
		got="$("${CRANE[@]}" digest "$dst")"
		if [ "$got" != "$digest" ]; then
			echo "mirror-images.sh: $name copied but $dst resolves to $got, want $digest" >&2
			exit 1
		fi
		COPIED=$((COPIED + 1))
		echo "copied    $name  $dst = $digest"
	done < <(entries "$mf")
done

echo
echo "$TOTAL entries, $MISSING missing, $COPIED copied"
if [ -z "$RUN" ] && [ "$MISSING" -gt 0 ]; then
	echo "dry run: nothing written. Re-run with --run (and a packages-scoped credential) to copy."
fi

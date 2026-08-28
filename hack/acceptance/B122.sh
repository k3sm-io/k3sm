#!/usr/bin/env bash
#
# k3sm B122 acceptance gate — digest-pinned image constants and the two checks that keep
# them honest.
#
#   pkg/images            the pins, plus Lockstep (constants <-> hack/images/mirror.yaml)
#                         and VerifyLive (manifest <-> registry, anonymous).
#   verify-image-pins.sh  the shipped CLI over that same package. Offline lockstep by
#                         default; --live for a release.
#
# OFFLINE: every leg below is either a pure-Go comparison of committed files or a
# loopback fixture. Nothing here reaches a host off this machine — the --live legs point
# the shipped script at an in-process registry on 127.0.0.1.
#
# NON-VACUOUS BY CONSTRUCTION: the mutation legs run on EVERY invocation. A gate that
# only asserts "the check passes at HEAD" cannot tell a working check from one that
# returns nil unconditionally, so this gate also mutates a temp copy of the manifest and
# requires the shipped script to REJECT it.
#
# Usage: bash hack/acceptance/B122.sh
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
K3SM_ROOT="$(cd "$HERE/../.." && pwd)"
MANIFEST="$K3SM_ROOT/hack/images/mirror.yaml"
SCRIPT="$K3SM_ROOT/hack/verify-image-pins.sh"

PASS=0; FAIL=0
ladder() { if [ "$1" = ok ]; then echo "PASS  $2"; PASS=$((PASS+1)); else echo "FAIL  $2"; FAIL=$((FAIL+1)); fi; }

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

echo "==> k3sm B122 acceptance (image pins: lockstep + live verifier)"

# ---- b122.0 — the artifacts exist -------------------------------------------
for f in "$MANIFEST" "$SCRIPT" "$K3SM_ROOT/pkg/images/pins.go" "$K3SM_ROOT/pkg/images/doc.go"; do
	if [ -f "$f" ]; then
		ladder ok "b122.0  present: ${f#"$K3SM_ROOT"/}"
	else
		ladder no "b122.0  present: ${f#"$K3SM_ROOT"/}"
	fi
done
if [ -x "$SCRIPT" ]; then
	ladder ok "b122.0  hack/verify-image-pins.sh is executable"
else
	ladder no "b122.0  hack/verify-image-pins.sh is executable"
fi
if [ "$FAIL" -ne 0 ]; then
	echo "----------------------------------------"
	echo "B122: $PASS passed, $FAIL failed (artifacts absent — red at main by construction)" >&2
	exit 1
fi

# ---- b122.1 — the package's own test family ---------------------------------
# Pinned as an ASSERTION FAMILY, not a bare `go test`: a `-run` filter that matches
# nothing EXITS 0, so a renamed or deleted test would read as PASS forever. Each name
# below must both exist and pass.
GOENV=(env GOARCH=arm64 CGO_ENABLED=1)
want_test() {
	local id="$1" name="$2" out rc=0
	out="$(cd "$K3SM_ROOT" && "${GOENV[@]}" go test -race -count=1 -v -run "^${name}\$" ./pkg/images/ 2>&1)" || rc=$?
	if [ "$rc" -ne 0 ]; then
		printf '%s\n' "$out" | tail -25
		ladder no "$id  $name passed"
		return
	fi
	if printf '%s\n' "$out" | grep -qE 'no tests to run|no test files'; then
		ladder no "$id  $name actually RAN (go test matched nothing — renamed or deleted?)"
		return
	fi
	if ! printf '%s\n' "$out" | grep -qE "^--- PASS: ${name}\b"; then
		ladder no "$id  $name reported a PASS line"
		return
	fi
	ladder ok "$id  $name"
}
want_test "b122.1a" TestLockstepShippedManifest
want_test "b122.1b" TestShippedManifestValidates
want_test "b122.1c" TestEveryPinnedConstantIsRegistered
want_test "b122.1d" TestLockstep
want_test "b122.1e" TestLoadManifestSchema
want_test "b122.1f" TestVerifyLiveAgainstFixture
want_test "b122.1g" TestVerifyLiveMissingPlatform
want_test "b122.1h" TestVerifyLiveRejectsNonIndex
want_test "b122.1i" TestShippedScriptAgainstFixture

# ---- b122.2 — the shipped script is green offline at HEAD -------------------
if OUT="$(bash "$SCRIPT" 2>&1)"; then
	if printf '%s\n' "$OUT" | grep -q '^ok  lockstep'; then
		ladder ok "b122.2a offline lockstep green at HEAD"
	else
		ladder no "b122.2a offline lockstep green at HEAD (no ok-lockstep line: $OUT)"
	fi
	if printf '%s\n' "$OUT" | grep -q 'live'; then
		ladder no "b122.2b default mode does NOT run the live check (found 'live' in the output)"
	else
		ladder ok "b122.2b default mode does NOT run the live check — --live is opt-in"
	fi
else
	ladder no "b122.2a offline lockstep green at HEAD"
	ladder no "b122.2b default mode does NOT run the live check"
fi

# ---- b122.3 — MUTATION LEGS (the non-vacuity proof) -------------------------
# Each leg copies the shipped manifest, breaks exactly one thing, and requires the
# SHIPPED script to exit non-zero via its --manifest seam. The repo's own manifest is
# never touched.
mutate_leg() {
	local id="$1" desc="$2" needle="$3" file="$4"
	local out rc=0
	out="$(bash "$SCRIPT" --manifest "$file" 2>&1)" || rc=$?
	if [ "$rc" -eq 0 ]; then
		ladder no "$id  $desc rejected (script exited 0 — the check is vacuous)"
		return
	fi
	if [ -n "$needle" ] && ! printf '%s\n' "$out" | grep -q "$needle"; then
		ladder no "$id  $desc rejected for the RIGHT reason (want /$needle/, got: $out)"
		return
	fi
	ladder ok "$id  $desc rejected (exit $rc)"
}

# (a) a flipped index digest in the mirror ref: the constant no longer matches.
sed 's|\(mirror: ghcr.io/k3sm-io/mirror/buildkit@sha256:\)[0-9a-f]\{64\}|\1deadbeef0000000000000000000000000000000000000000000000000000beef|' \
	"$MANIFEST" >"$TMP/flip-mirror.yaml"
if cmp -s "$MANIFEST" "$TMP/flip-mirror.yaml"; then
	ladder no "b122.3a mutation actually changed the manifest (sed matched nothing — the leg would be vacuous)"
else
	# The flip also breaks upstream==mirror, which the schema catches first. That is
	# the correct precedence: a manifest that is not internally consistent is not a
	# record to compare constants against.
	mutate_leg "b122.3a" "flipped mirror digest" "mirror digest" "$TMP/flip-mirror.yaml"
fi

# (b) a flipped digest in BOTH refs: schema-valid, so the LOCKSTEP check must be what
#     rejects it. This is the leg that proves lockstep itself bites.
sed 's|\(sha256:\)28a898719c18a33f4e8000685287fa36fd0dd9560c6440227d3a732d79bb41d8|\1deadbeef0000000000000000000000000000000000000000000000000000beef|g' \
	"$MANIFEST" >"$TMP/flip-both.yaml"
if cmp -s "$MANIFEST" "$TMP/flip-both.yaml"; then
	ladder no "b122.3b mutation actually changed the manifest (sed matched nothing)"
else
	mutate_leg "b122.3b" "flipped index digest (schema-valid, lockstep must catch it)" "disagree" "$TMP/flip-both.yaml"
fi

# (c) the entry removed entirely: the constant is left with nothing to match.
printf 'images:\n  - name: unrelated\n    upstream: docker.io/example/x:v1@sha256:%s\n    mirror: ghcr.io/k3sm-io/mirror/x@sha256:%s\n    tag: v1\n    platforms:\n      - platform: linux/arm64\n        digest: sha256:%s\n' \
	"$(printf 'a%.0s' $(seq 64))" "$(printf 'a%.0s' $(seq 64))" "$(printf 'b%.0s' $(seq 64))" \
	>"$TMP/no-entry.yaml"
mutate_leg "b122.3c" "buildkit entry removed" "has NO manifest entry" "$TMP/no-entry.yaml"

# (d) an orphan entry: present in the record, consumed by no constant.
{
	cat "$MANIFEST"
	printf '  - name: orphan\n    upstream: docker.io/example/x:v1@sha256:%s\n    mirror: ghcr.io/k3sm-io/mirror/orphan@sha256:%s\n    tag: v1\n    platforms:\n      - platform: linux/arm64\n        digest: sha256:%s\n' \
		"$(printf 'a%.0s' $(seq 64))" "$(printf 'a%.0s' $(seq 64))" "$(printf 'b%.0s' $(seq 64))"
} >"$TMP/orphan.yaml"
mutate_leg "b122.3d" "orphan manifest entry" "ORPHAN" "$TMP/orphan.yaml"

# (e) a required platform dropped: schema rejects it before any comparison.
python3 - "$MANIFEST" "$TMP/no-amd64.yaml" <<'PY'
import sys
src, dst = sys.argv[1], sys.argv[2]
lines = open(src).read().splitlines(keepends=True)
out, skip = [], 0
for i, ln in enumerate(lines):
    if "platform: linux/amd64" in ln:
        skip = 2
    if skip:
        skip -= 1
        continue
    out.append(ln)
open(dst, "w").write("".join(out))
PY
if cmp -s "$MANIFEST" "$TMP/no-amd64.yaml"; then
	ladder no "b122.3e mutation actually dropped the amd64 platform"
else
	mutate_leg "b122.3e" "linux/amd64 platform dropped" "required platform linux/amd64 is missing" "$TMP/no-amd64.yaml"
fi

# ---- b122.4 — no real network on the default test path ----------------------
# An absence assertion, so it fails closed: `go list` must succeed AND the positive
# control must be present, or the leg reports that it measured nothing.
LIST_RC=0
LIST="$( (cd "$K3SM_ROOT" && "${GOENV[@]}" go list -deps ./pkg/images/) )" || LIST_RC=$?
if [ "$LIST_RC" -ne 0 ]; then
	ladder no "b122.4  pkg/images dependency closure enumerable — go list exited $LIST_RC (measured nothing)"
elif ! printf '%s\n' "$LIST" | grep -qx 'github.com/google/go-containerregistry/pkg/v1/remote'; then
	ladder no "b122.4  positive control — the closure must list the remote client (an empty listing must not read as clean)"
else
	ladder ok "b122.4  pkg/images non-test closure enumerated ($(printf '%s\n' "$LIST" | grep -c .) packages, remote client present)"
fi

echo "----------------------------------------"
cat <<'UNPROVEN'
KNOWN-UNPROVEN HERE:
  - This gate proves SELF-CONSISTENCY only: that the constants, the manifest and the
    verifier agree. It cannot prove the recorded digest is the upstream image anyone
    intended. That is the reviewer's merge-precondition — independently re-resolve the
    upstream digest and record the match on the bump PR.
  - --live is exercised ONLY against a loopback fixture. That proves the verification
    LOGIC (present / absent / missing platform / not an index / wrong per-arch digest);
    it does not prove the real mirror is populated or publicly readable. That is a
    release-time run of `hack/verify-image-pins.sh --live` with no --registry override.
  - The mirror namespace may legitimately be empty right now: an index copy preserves
    digests, so a pin is commit-safe before the copy runs. Green here therefore says
    nothing about whether the mirror exists yet.
  - Nothing here consumes images.Buildkitd. The first consumer arrives with the builder;
    until then the pin is verified but unused, which the lockstep check cannot detect
    (an unused constant is still a registered constant).
UNPROVEN
echo "----------------------------------------"
echo "B122: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ] || exit 1
echo "================ B122 GREEN ================"

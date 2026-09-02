#!/usr/bin/env bash
#
# k3sm image-primitives CLI acceptance — the runnable proof that the store verbs
# `k3sm image pull | tag | untag | inspect | save` (and push's store-reference
# form) are CLIENTS of runtimed's Images service, and that each one keeps the
# promise its help text makes.
#
# It exists because the daemon-side RPCs and the CLI can be green independently
# and still not meet: the daemon can implement PullImage perfectly while the CLI
# sends an empty Platform instead of none, resolves a tag's target the wrong way
# round, or accepts a truncated export. Those are argv-and-wire faults, and no
# daemon test can see them.
#
# TWO TIERS, split by what can be proven without a live cluster:
#
#   CI TIER (always runs, GOARCH=arm64 CGO_ENABLED=1 pinned) — the unit-provable
#   half: every verb is dispatched, the selector an operator typed reaches the
#   wire unaltered (an unset --platform stays UNSET, a policy is the corev1
#   enum), tag resolves a reference to a DIGEST before it tags, save refuses a
#   truncated archive and leaves nothing on disk, push's store form exports
#   before it uploads, and the shipped binary's own argv grammar refuses what the
#   help says it refuses.
#
#   LIVE TIER (needs $KUBECONFIG) — the verbs against a running node: pull warms
#   the store, tag names the pulled content under this node's own ingest
#   registry, inspect reports both, save writes an archive `docker load` accepts
#   (when docker is present), untag removes the name, and the prune story is
#   unchanged — the pulled root still keeps its content reachable.
#
# Without $KUBECONFIG the live rungs are announced LIVE-PENDING and never fail —
# and the summary says so in as many words, so an exit 0 from a CI-tier-only run
# cannot be misread as "the verbs work against a node".
#
# The GOARCH=arm64 pin is a CORRECTNESS requirement, not hygiene: a Mac's Go
# toolchain may itself be x86_64-under-Rosetta, and an unpinned build produces an
# x86_64 binary this arm64-only product cannot run.
#
# Usage:
#   hack/acceptance/image-primitives-cli.sh                 # CI tier only
#   KUBECONFIG=/path/to/kubeconfig \
#     K3SM_WORK_DIR=/var/lib/k3sm/server \
#     hack/acceptance/image-primitives-cli.sh               # + the live tier
#
# Environment:
#   KUBECONFIG           a running k3sm server (enables the live tier)
#   K3SM_WORK_DIR        the control-plane work dir; the runtime root is its
#                        PARENT, and the socket is <root>/run/runtimed.sock
#   K3SM_SOCKET          override the socket path instead of deriving it
#   K3SM_REGISTRY_PORT   override the node's ingest-registry port instead of
#                        reading it from the KEP-1755 ConfigMap
#   K3SM_PULL_REF        the reference the live pull warms (default alpine:3.20)
#   K3SM_PULL_PLATFORM   the platform it is warmed for (default linux/arm64 — a
#                        WARM is not an execution claim, and the daemon
#                        deliberately does not refuse a platform this host
#                        cannot run natively)
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
K3SM_ROOT="$(cd "$HERE/../.." && pwd)"
SELF="$HERE/image-primitives-cli.sh"

PASS=0; FAIL=0; PENDING=0; SKIP=0
ladder() { if [ "$1" = ok ]; then echo "PASS  $2"; PASS=$((PASS+1)); else echo "FAIL  $2"; FAIL=$((FAIL+1)); fi; }
pending() { echo "PEND  $1"; PENDING=$((PENDING+1)); }
skip() { echo "SKIP  $1"; SKIP=$((SKIP+1)); }

echo "==> k3sm image-primitives CLI acceptance"

# ---- image-cli.0 — the gate parses and its sources exist -------------------
b0=ok
[ -f "$SELF" ] && bash -n "$SELF" || b0=no
for f in image.go imagepull.go imagetag.go imageinspect.go imagesave.go imageplatform.go imagepushstore.go; do
	[ -f "$K3SM_ROOT/cmd/k3sm/$f" ] || b0=no
done
ladder "$b0" "image-cli.0  gate parses (bash -n) + every verb's source is present"
if [ "$b0" != ok ]; then
	echo "----------------------------------------"
	echo "image-cli: the gate or its sources are missing/unparseable — nothing else can run" >&2
	echo "image-cli: $PASS passed, $FAIL failed" >&2
	exit 1
fi

# ---- Go leg runner (GOARCH=arm64 CGO_ENABLED=1) ----------------------------
GOFLAGS_ENV=(env GOARCH=arm64 CGO_ENABLED=1)

# run_test <id> <min-subtests> <TestName> <pkg>
# Asserts the leg actually RAN its subtests: `go test -run <filter>` EXITS 0 on a
# zero-match filter, so a renamed test would read PASS forever. Each leg fails
# unless "no tests to run" is ABSENT and the count of `--- PASS: <TestName>/`
# subtest lines meets the pinned minimum.
run_test() {
	local id="$1" min="$2" name="$3" pkg="$4" out rc=0 ran
	out="$(cd "$K3SM_ROOT" && "${GOFLAGS_ENV[@]}" go test -count=1 -v -run "^${name}\$" "$pkg" 2>&1)" || rc=$?
	if [ "$rc" -ne 0 ]; then
		printf '%s\n' "$out" | tail -30
		ladder no "$id  $name ($pkg) passed"
		return
	fi
	if printf '%s\n' "$out" | grep -qE 'no tests to run|no test files'; then
		ladder no "$id  $name ($pkg) actually RAN — go test reported no tests to run (renamed test?)"
		return
	fi
	ran="$(printf '%s\n' "$out" | grep -cE "^[[:space:]]*--- PASS: ${name}/" || true)"
	if [ "$ran" -ge "$min" ]; then
		ladder ok "$id  $name ($pkg): $ran subtests passed (min $min)"
	else
		ladder no "$id  $name ($pkg): only $ran subtests passed, want >= $min"
	fi
}

# ---- image-cli.1 — the selector an operator typed reaches the wire ---------
run_test "image-cli.1a" 3 TestImageSelectorParsing ./cmd/k3sm/
run_test "image-cli.1b" 10 TestImageVerbArgGrammar ./cmd/k3sm/

# ---- image-cli.2 — each verb is a client, and renders what it was told -----
run_test "image-cli.2a" 4 TestImagePullVerb ./cmd/k3sm/
run_test "image-cli.2b" 4 TestImageTagVerb ./cmd/k3sm/
run_test "image-cli.2c" 3 TestImageUntagVerb ./cmd/k3sm/
run_test "image-cli.2d" 4 TestImageInspectVerb ./cmd/k3sm/

# ---- image-cli.3 — the truncation refusal ---------------------------------
# The load-bearing one. The wire's terminal frame is the ONLY thing that tells a
# complete archive from a short one, so a save that accepted a stream without it
# would hand an operator a tar that opens and is missing a layer.
run_test "image-cli.3a" 6 TestImageSaveVerb ./cmd/k3sm/

# ---- image-cli.4 — push's store form, and its unpacker --------------------
run_test "image-cli.4a" 2 TestImagePushFromStore ./cmd/k3sm/
run_test "image-cli.4b" 8 TestPushSourceDiscrimination ./cmd/k3sm/
run_test "image-cli.4c" 4 TestExtractOCILayout ./cmd/k3sm/

# ---- image-cli.5 — the dispatch is wired ----------------------------------
# A structural rung, and a cheap one: every test above drives imageCommand, so a
# verb that was written and never dispatched would still be caught — but a verb
# dropped from the switch while its file survived would not, and this names that.
b5=ok
for verb in pull tag untag inspect save; do
	grep -q "case \"$verb\":" "$K3SM_ROOT/cmd/k3sm/image.go" || b5=no
done
grep -q 'imagePush(ctx, o, out, dial)' "$K3SM_ROOT/cmd/k3sm/image.go" || b5=no
ladder "$b5" "image-cli.5  imageCommand dispatches every verb, and push takes the dialer"

# ---- image-cli.6 — the shipped binary's own argv grammar ------------------
BIN_DIR="$(mktemp -d)"
trap 'rm -rf "$BIN_DIR"' EXIT
K3SM_BIN="$BIN_DIR/k3sm"
if (cd "$K3SM_ROOT" && "${GOFLAGS_ENV[@]}" go build -o "$K3SM_BIN" ./cmd/k3sm) ; then
	ladder ok "image-cli.6a the k3sm binary builds (GOARCH=arm64 CGO_ENABLED=1)"
else
	ladder no "image-cli.6a the k3sm binary builds (GOARCH=arm64 CGO_ENABLED=1)"
	echo "----------------------------------------"
	echo "image-cli: no binary to exercise — the remaining rungs cannot run ($PASS passed, $FAIL failed)" >&2
	exit 1
fi
# `image -h` exits non-zero (flag.ErrHelp), and this script runs under pipefail,
# so the output is captured before it is matched.
IMAGE_HELP="$("$K3SM_BIN" image -h 2>&1 || true)"
b6b=ok
for verb in pull tag untag inspect save; do
	printf '%s\n' "$IMAGE_HELP" | grep -q "k3sm image $verb " || b6b=no
done
for flag in -platform -policy -digest; do
	printf '%s\n' "$IMAGE_HELP" | grep -q -- "$flag" || b6b=no
done
ladder "$b6b" "image-cli.6b \`k3sm image -h\` advertises every verb and its selectors"

# A verb's refusals are part of its contract, so they are asserted through the
# SHIPPED binary rather than through the parser alone.
refuses() { # refuses <label> <args...>
	local label="$1"; shift
	local out
	if out="$("$K3SM_BIN" image "$@" 2>&1)"; then
		printf '%s\n' "$out" | tail -3
		ladder no "$label"
	else
		ladder ok "$label"
	fi
}
refuses "image-cli.6c save refuses to write an archive to the terminal" save example.test/app:v1
refuses "image-cli.6d inspect refuses a rendering it does not have" inspect example.test/app:v1 -o yaml
refuses "image-cli.6e prune refuses --platform, which it cannot honour" prune --platform darwin/arm64
refuses "image-cli.6f pull refuses an invented policy" pull example.test/app:v1 --policy sometimes

# An absent socket must fail as a DIAL against the named path: that error is the
# operator's only clue when the node is not serving.
ABSENT="$BIN_DIR/absent.sock"
DIAL_OUT="$BIN_DIR/dial.err"
if ! "$K3SM_BIN" image inspect example.test/app:v1 --socket "$ABSENT" --timeout 5s >"$DIAL_OUT" 2>&1; then
	if grep -q "$ABSENT" "$DIAL_OUT"; then
		ladder ok "image-cli.6g a store verb against an unbound socket fails naming the path it dialled"
	else
		tail -5 "$DIAL_OUT"
		ladder no "image-cli.6g a store verb against an unbound socket fails naming the path it dialled"
	fi
else
	ladder no "image-cli.6g a store verb against an unbound socket must fail (it did not)"
fi

# ---- LIVE TIER ------------------------------------------------------------
if [ -z "${KUBECONFIG:-}" ]; then
	pending "image-cli.7  live: \`k3sm image pull\` warms the store                (set KUBECONFIG)"
	pending "image-cli.8  live: \`k3sm image tag\` names it for the node registry  (set KUBECONFIG)"
	pending "image-cli.9  live: \`k3sm image inspect\` reports both names          (set KUBECONFIG)"
	pending "image-cli.10 live: \`k3sm image save\` writes a verified archive      (set KUBECONFIG)"
	pending "image-cli.11 live: \`docker load\` accepts nothing it should not      (set KUBECONFIG + docker)"
	pending "image-cli.12 live: \`k3sm image untag\` removes the name, not bytes   (set KUBECONFIG)"
	echo "----------------------------------------"
	echo "image-cli: $PASS passed, $FAIL failed, $PENDING LIVE-PENDING"
	[ "$FAIL" -eq 0 ] || exit 1
	echo "image-cli: CI TIER GREEN — the LIVE tier did NOT run, so this exit 0 does NOT mean the verbs"
	echo "           work against a node. Start a server and re-run with KUBECONFIG (and K3SM_WORK_DIR) set."
	echo "           OWED: rungs 7-12 above, plus the \`docker load\` interop leg, are human-run."
	exit 0
fi

kubectl get --raw /healthz >/dev/null || { echo "the cluster at \$KUBECONFIG is not serving" >&2; exit 1; }

# The runtime root is the work dir's PARENT, and the socket hangs off it — the
# same derivation provider.RuntimedSocketPath makes.
SOCK="${K3SM_SOCKET:-}"
if [ -z "$SOCK" ]; then
	WORK_DIR="${K3SM_WORK_DIR:-/var/lib/k3sm/server}"
	SOCK="$(dirname "${WORK_DIR%/}")/run/runtimed.sock"
fi
if [ ! -S "$SOCK" ]; then
	echo "----------------------------------------"
	echo "image-cli: no socket at $SOCK — is the server running with this work dir? ($PASS passed, $FAIL failed)" >&2
	exit 1
fi
K3SM_IMAGE=("$K3SM_BIN" image --socket "$SOCK")
LIVE_OUT="$BIN_DIR/live.out"

PULL_REF="${K3SM_PULL_REF:-alpine:3.20}"
PULL_PLATFORM="${K3SM_PULL_PLATFORM:-linux/arm64}"

# ---- image-cli.7 — pull warms the store -----------------------------------
# A named platform is a WARM, not an execution claim: the daemon deliberately
# does not refuse a platform this host cannot run natively, because warming
# linux/arm64 on a Mac is the ordinary vm case.
b7=ok
"${K3SM_IMAGE[@]}" pull "$PULL_REF" --platform "$PULL_PLATFORM" >"$LIVE_OUT" 2>&1 || b7=no
PULLED_DIGEST=""
if [ "$b7" = ok ]; then
	PULLED_DIGEST="$(sed -n 's/^[[:space:]]*digest:[[:space:]]*//p' "$LIVE_OUT" | head -1)"
	[ -n "$PULLED_DIGEST" ] || b7=no
fi
if [ "$b7" != ok ]; then tail -10 "$LIVE_OUT" || true; fi
ladder "$b7" "image-cli.7  \`k3sm image pull $PULL_REF --platform $PULL_PLATFORM\` resolved a digest"
if [ "$b7" != ok ]; then
	echo "----------------------------------------"
	echo "image-cli: nothing was warmed, so the remaining live rungs have no subject ($PASS passed, $FAIL failed)" >&2
	exit 1
fi

# ---- image-cli.8 — tag names it under this node's ingest registry ---------
# The KEP-1755 ConfigMap is how a tool is supposed to find the registry, so the
# gate finds it that way too; K3SM_REGISTRY_PORT is only the escape hatch.
PORT="${K3SM_REGISTRY_PORT:-}"
if [ -z "$PORT" ]; then
	PORT="$(kubectl get configmap local-registry-hosting -n kube-public \
		-o jsonpath='{.data.localRegistryHosting\.v1}' 2>/dev/null |
		sed -n 's/^host:[[:space:]]*"\{0,1\}localhost:\([0-9]\{1,\}\)"\{0,1\}[[:space:]]*$/\1/p' | head -1)"
fi
if [ -z "$PORT" ]; then
	PORT=6450
	echo "      note: the cluster publishes no registry address; the tag uses the suggested port $PORT"
fi
TAG_REF="localhost:$PORT/probe-tag:t"
b8=ok
"${K3SM_IMAGE[@]}" tag "$PULLED_DIGEST" "$TAG_REF" --platform "$PULL_PLATFORM" >"$LIVE_OUT" 2>&1 || b8=no
[ "$b8" = ok ] || tail -10 "$LIVE_OUT" || true
ladder "$b8" "image-cli.8a \`k3sm image tag\` recorded $TAG_REF for the pulled digest"
if "${K3SM_IMAGE[@]}" ls 2>/dev/null | grep -q "probe-tag"; then
	ladder ok "image-cli.8b the new name appears in \`k3sm image ls\`"
else
	ladder no "image-cli.8b the new name appears in \`k3sm image ls\`"
fi

# ---- image-cli.9 — inspect reports both names -----------------------------
b9=ok
for ref in "$PULL_REF" "$TAG_REF"; do
	"${K3SM_IMAGE[@]}" inspect "$ref" --platform "$PULL_PLATFORM" >"$LIVE_OUT" 2>&1 || b9=no
	grep -q "$PULLED_DIGEST" "$LIVE_OUT" || b9=no
done
[ "$b9" = ok ] || tail -10 "$LIVE_OUT" || true
ladder "$b9" "image-cli.9a \`k3sm image inspect\` reports the same digest for both names"
# -o json is the scripting surface, so it must be parseable, not merely printed.
if "${K3SM_IMAGE[@]}" inspect "$PULLED_DIGEST" -o json >"$LIVE_OUT" 2>&1 &&
	python3 -c 'import json,sys; json.load(open(sys.argv[1]))' "$LIVE_OUT"; then
	ladder ok "image-cli.9b \`k3sm image inspect -o json\` emits parseable JSON"
else
	tail -5 "$LIVE_OUT" || true
	ladder no "image-cli.9b \`k3sm image inspect -o json\` emits parseable JSON"
fi

# ---- image-cli.10 — save writes a verified archive ------------------------
ARCHIVE="$BIN_DIR/probe.tar"
b10=ok
"${K3SM_IMAGE[@]}" save "$TAG_REF" -o "$ARCHIVE" --platform "$PULL_PLATFORM" >"$LIVE_OUT" 2>&1 || b10=no
if [ "$b10" = ok ]; then
	[ -s "$ARCHIVE" ] || b10=no
	# An OCI layout, which is what v1 exports — a docker-save tar would be a
	# different archive shape and the daemon answers UNIMPLEMENTED for it.
	tar -tf "$ARCHIVE" 2>/dev/null | grep -q '^\./\{0,1\}index\.json$\|^index\.json$' || b10=no
fi
[ "$b10" = ok ] || tail -10 "$LIVE_OUT" || true
ladder "$b10" "image-cli.10a \`k3sm image save\` wrote a tarred OCI layout with an index.json"
# The refusal half: a save whose target does not exist must leave NO file behind.
GHOST="$BIN_DIR/ghost.tar"
if "${K3SM_IMAGE[@]}" save "no-such-image-probe:absent" -o "$GHOST" >"$LIVE_OUT" 2>&1; then
	ladder no "image-cli.10b a save of an absent image must fail (it did not)"
elif [ -e "$GHOST" ]; then
	ladder no "image-cli.10b a failed save left $GHOST behind"
else
	ladder ok "image-cli.10b a failed save wrote no file at all"
fi

# ---- image-cli.11 — docker interop, when docker is here -------------------
# OPTIONAL AND SKIPPED CLEANLY. `docker load` reads a docker-save tar; v1 exports
# an OCI layout, so the honest interop claim is the one docker itself supports —
# `docker load` of an OCI layout is accepted by recent daemons and refused by
# older ones, and either verdict is information rather than a failure of k3sm.
if ! command -v docker >/dev/null 2>&1; then
	skip "image-cli.11 \`docker load\` interop (docker is not installed)"
elif ! docker info >/dev/null 2>&1; then
	skip "image-cli.11 \`docker load\` interop (docker is installed but its daemon is not running)"
elif [ "$b10" != ok ]; then
	skip "image-cli.11 \`docker load\` interop (there is no archive to load)"
elif docker load -i "$ARCHIVE" >"$LIVE_OUT" 2>&1; then
	ladder ok "image-cli.11 \`docker load\` accepted the exported OCI layout"
else
	tail -5 "$LIVE_OUT" || true
	skip "image-cli.11 \`docker load\` did not accept the OCI layout (this docker reads docker-save tars only)"
fi

# ---- image-cli.12 — untag removes the name, not the bytes -----------------
b12=ok
"${K3SM_IMAGE[@]}" untag "$TAG_REF" --platform "$PULL_PLATFORM" --digest "$PULLED_DIGEST" >"$LIVE_OUT" 2>&1 || b12=no
[ "$b12" = ok ] || tail -10 "$LIVE_OUT" || true
ladder "$b12" "image-cli.12a \`k3sm image untag\` removed $TAG_REF"
if "${K3SM_IMAGE[@]}" ls 2>/dev/null | grep -q "probe-tag"; then
	ladder no "image-cli.12b the untagged name is gone from \`k3sm image ls\`"
else
	ladder ok "image-cli.12b the untagged name is gone from \`k3sm image ls\`"
fi
# THE PRUNE STORY IS UNCHANGED: the pulled reference still holds an operator root
# over that content, so a dry-run prune must not offer to delete the digest the
# pull recorded. This is the invariant that makes `pull` safe to use as a warm.
if "${K3SM_IMAGE[@]}" prune >"$LIVE_OUT" 2>&1; then
	if grep -q "would delete $PULLED_DIGEST" "$LIVE_OUT"; then
		tail -10 "$LIVE_OUT"
		ladder no "image-cli.12c a dry-run prune leaves the pulled digest alone (it offered to delete it)"
	else
		ladder ok "image-cli.12c a dry-run prune leaves the pulled digest alone"
	fi
else
	tail -10 "$LIVE_OUT" || true
	ladder no "image-cli.12c a dry-run prune ran"
fi
# The pulled name itself is left in place: it is the operator's, and this gate
# does not decide when an operator's warm image stops being wanted.
echo "      note: $PULL_REF is still warmed on this node — \`k3sm image untag $PULL_REF --platform $PULL_PLATFORM\` releases it."

echo "----------------------------------------"
echo "image-cli: $PASS passed, $FAIL failed, $SKIP skipped"
[ "$FAIL" -eq 0 ] || exit 1
echo "=========== IMAGE-PRIMITIVES CLI GREEN ==========="

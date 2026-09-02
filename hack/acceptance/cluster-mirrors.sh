#!/usr/bin/env bash
#
# k3sm cluster-image-mirror acceptance — the runnable proof that an image
# pushed into ONE node's ingest registry can be pulled by a Pod scheduled on
# ANOTHER node, and that a Linux-guest Pod can reach its own node's registry.
#
# WHY THE FEATURE EXISTS. Every node runs its own loopback ingest registry, so
# `localhost:<port>/app:v1` names a DIFFERENT registry on every Mac. Push on one,
# schedule on another, and the pull fails against a node that was simply never
# fed. Three pieces close that: each node ADVERTISES its mesh-reachable registry,
# a RELAY makes that registry reachable at addresses peers and vm guests can dial
# (the service itself still binds loopback only), and a MIRROR SOURCE feeds
# runtimed's puller the peers to fall back to.
#
# TWO TIERS, split by what can be proven without a live cluster:
#
#   CI TIER (always runs, GOARCH=arm64 CGO_ENABLED=1 pinned) — the unit-provable
#   half: what a node advertises and what it refuses to advertise, the reader's
#   strictness against a malformed or hostile advertisement, the relay's closed
#   set of bindable addresses (the ONLY off-loopback exposure in the product),
#   the mirror source's self-exclusion and stable order, the seam wiring that
#   carries peers into runtimed's puller, and the RBAC grant that lets a node
#   read the advertisements at all — pinned to its exact verbs, because that
#   grant is the one thing here that widens what every node in the cluster may
#   do, and a widening of it is invisible to every other rung.
#
#   LIVE TIER (two Macs) — the thing itself: push on node A only, schedule a Pod
#   on node B naming `localhost:<port>/<ref>`, and watch it reach Running by way
#   of the mirror. It is OWED, not skipped: the rungs are printed with the exact
#   commands, and this script never claims them.
#
# The GOARCH=arm64 pin is a CORRECTNESS requirement, not hygiene: a Mac's Go
# toolchain may itself be x86_64-under-Rosetta, and an unpinned build produces an
# x86_64 binary this arm64-only product cannot run.
#
# Usage:
#   hack/acceptance/cluster-mirrors.sh        # CI tier; the live tier is printed as owed
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
K3SM_ROOT="$(cd "$HERE/../.." && pwd)"
SELF="$HERE/cluster-mirrors.sh"

PASS=0; FAIL=0; PENDING=0
ladder() { if [ "$1" = ok ]; then echo "PASS  $2"; PASS=$((PASS+1)); else echo "FAIL  $2"; FAIL=$((FAIL+1)); fi; }
pending() { echo "OWED  $1"; PENDING=$((PENDING+1)); }

echo "==> k3sm cluster-image-mirror acceptance"

# ---- mirrors.0 — the gate parses and its sources exist ---------------------
b0=ok
[ -f "$SELF" ] && bash -n "$SELF" || b0=no
for src in \
	pkg/registrysvc/advert.go \
	pkg/registrysvc/relay.go \
	pkg/clustermirror/source.go \
	pkg/rbac/rbac.go \
	cmd/k3sm/registry.go
do
	[ -f "$K3SM_ROOT/$src" ] || b0=no
done
ladder "$b0" "mirrors.0  gate parses (bash -n) + the advertisement, relay, mirror source, RBAC grant and server wiring are present"
if [ "$b0" != ok ]; then
	echo "----------------------------------------"
	echo "cluster-mirrors: the gate or its sources are missing/unparseable — nothing else can run" >&2
	echo "cluster-mirrors: $PASS passed, $FAIL failed" >&2
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

# run_flat_test <id> <TestName> <pkg>
# The same non-vacuity guard for a test that carries no subtests: the top-level
# `--- PASS: <TestName>` line must be present, so a renamed or deleted test is a
# FAIL rather than a silent zero-match exit 0.
run_flat_test() {
	local id="$1" name="$2" pkg="$3" out rc=0
	out="$(cd "$K3SM_ROOT" && "${GOFLAGS_ENV[@]}" go test -count=1 -v -run "^${name}\$" "$pkg" 2>&1)" || rc=$?
	if [ "$rc" -ne 0 ]; then
		printf '%s\n' "$out" | tail -30
		ladder no "$id  $name ($pkg) passed"
		return
	fi
	if printf '%s\n' "$out" | grep -qE "^[[:space:]]*--- PASS: ${name} \("; then
		ladder ok "$id  $name ($pkg) passed"
	else
		ladder no "$id  $name ($pkg) actually RAN — no top-level PASS line (renamed test?)"
	fi
}

# ---- mirrors.1 — what a node advertises, and what it refuses to -----------
# The refusal rows are the load-bearing ones: a node with no mesh address has no
# address a peer could dial, so an advertisement from it would send every peer's
# pull at something unreachable.
run_test "mirrors.1a" 11 TestAdvertisement ./pkg/registrysvc/
run_test "mirrors.1b" 5 TestPublishAdvertisement ./pkg/registrysvc/
run_test "mirrors.1c" 3 TestRemoveAdvertisement ./pkg/registrysvc/

# ---- mirrors.2 — the reader's strictness ----------------------------------
# An advertisement is cluster-supplied data that becomes a registry authority in
# a rewritten image reference. A host carrying a path, a scheme or a name would
# redirect a pull at something the Pod never asked for.
run_test "mirrors.2" 14 TestParseAdvertisement ./pkg/registrysvc/

# ---- mirrors.3 — the relay's bind discipline (the security posture) -------
# The registry binds 127.0.0.1 and refuses anything else, so the relay IS the
# product's only off-loopback exposure of it. The set of addresses it will bind
# must stay closed: two, both derived, never the wildcard.
run_test "mirrors.3a" 11 TestNewRelayBindDiscipline ./pkg/registrysvc/
run_test "mirrors.3b" 4 TestNewRelayPortDiscipline ./pkg/registrysvc/
run_test "mirrors.3c" 4 TestVMNetGateway ./pkg/registrysvc/
run_test "mirrors.3d" 3 TestRelayForwards ./pkg/registrysvc/
run_flat_test "mirrors.3e" TestRelaySkipsAnAbsentAddress ./pkg/registrysvc/
run_flat_test "mirrors.3f" TestRelayStopsOnContextCancel ./pkg/registrysvc/

# ---- mirrors.4 — which peers become candidates ----------------------------
run_test "mirrors.4a" 8 TestMirrors ./pkg/clustermirror/
run_test "mirrors.4b" 4 TestMirrorsDegrades ./pkg/clustermirror/
run_flat_test "mirrors.4c" TestStartWatchesTheCluster ./pkg/clustermirror/

# ---- mirrors.5 — the wiring, which fails SILENTLY when it breaks ----------
# A seam that is never assigned leaves a node that starts, runs every pod it has,
# and simply never falls back to a peer. Nothing else in the suite goes red.
run_test "mirrors.5a" 3 TestClusterMirrorWiring ./cmd/k3sm/
run_test "mirrors.5b" 6 TestStartIngestRegistry ./cmd/k3sm/
run_flat_test "mirrors.5c" TestGuestNATSubnet ./cmd/k3sm/

# ---- mirrors.6 — the grant that lets a node read the advertisements -------
# A node's puller watches the advertisement ConfigMaps, and an informer needs
# list and watch — neither of which RBAC's resourceNames can narrow. So the
# NAMESPACE is the scope, which is why the advertisements have their own and why
# these two rungs assert an exact shape rather than mere presence: three verbs,
# one resource, one namespaced Role bound to system:nodes, and the cluster-scoped
# node-datapath ClusterRole pinned byte-for-byte so a namespaced read cannot have
# quietly become a cluster-wide one. Operator-approved 2026-09-02.
run_flat_test "mirrors.6a" TestRBACRegistryAdvertReaderRole ./pkg/rbac/
run_flat_test "mirrors.6b" TestRBACNodeDatapathUnchangedByTheRegistryGrant ./pkg/rbac/

# ---- mirrors.7 — the consumer end of the seam (cross-module) --------------
# Every test above proves k3sm SUPPLIES peers. This one proves runtimed's puller
# CONSUMES them: it drives Deps.ImageMirrors through the puller the daemon itself
# builds, against two real in-process registries, with a negative control. It
# runs only when the sibling module is resolvable from this checkout.
if (cd "$K3SM_ROOT" && "${GOFLAGS_ENV[@]}" go list k3sm.io/runtimed/pkg/runtime >/dev/null 2>&1); then
	run_test "mirrors.7" 2 TestDefaultPullerConsultsClusterMirrors k3sm.io/runtimed/pkg/runtime
else
	pending "mirrors.7  the runtimed-side fallback test           (k3sm.io/runtimed is not resolvable from this checkout)"
fi

# ---- LIVE TIER (two Macs) — OWED, never claimed ---------------------------
# There is no single-host approximation of this. The whole point is that the
# image exists on ONE node's registry and the Pod runs on the OTHER, so a
# one-Mac run would prove only that a node can pull from itself.
echo "----------------------------------------"
echo "LIVE TIER (two Macs, run by hand on the lab rig):"
pending "mirrors.8  both nodes advertise: kubectl get cm -n k3sm-registry | grep k3sm-node-registry-"
pending "mirrors.9  the grant is in place: kubectl get role,rolebinding -n k3sm-registry k3sm-registry-advert-reader"
pending "mirrors.10 a node identity may read them and nothing else there:"
pending "           kubectl auth can-i list configmaps -n k3sm-registry --as-group=system:nodes --as=system:node:<node>   => yes"
pending "           kubectl auth can-i list secrets    -n k3sm-registry --as-group=system:nodes --as=system:node:<node>   => no"
pending "           kubectl auth can-i list configmaps -n kube-public    --as-group=system:nodes --as=system:node:<node>   => no"
pending "mirrors.11 node A only: k3sm image push <layout> localhost:<port>/probe:t"
pending "mirrors.12 a Pod pinned to node B naming localhost:<port>/probe:t reaches Running"
pending "mirrors.13 node B's log carries \"pulled from a cluster mirror\" naming node A's mesh host"
pending "mirrors.14 a vm-RuntimeClass Pod on either node pushes to <vmnet-gateway>:<port>"

echo "----------------------------------------"
echo "cluster-mirrors: $PASS passed, $FAIL failed, $PENDING OWED"
[ "$FAIL" -eq 0 ] || exit 1
echo "cluster-mirrors: CI TIER GREEN — the LIVE tier did NOT run, so this exit 0 does NOT mean an image"
echo "                 crossed between two Macs. Run the owed rungs on the two-Mac rig."
exit 0

#!/usr/bin/env bash
#
# k3sm B223 acceptance gate — the runnable proof that the kube-controller-manager's
# --root-ca-file names the CA that anchors the serving cert the apiserver ACTUALLY
# presents, in both postures. That flag is what the root-ca-cert-publisher republishes
# into every namespace's kube-root-ca.crt ConfigMap, i.e. every Pod's trust anchor for
# the in-cluster API, so naming the wrong CA breaks in-pod API TLS cluster-wide.
#
# The defect (lab D2): --root-ca-file was PINNED at <workDir>/apiserver-certs/apiserver.crt
# — the apiserver's SELF-SIGNED --cert-dir material. That is right single-node and wrong on
# the mesh path, where cmd/k3sm issues a cluster-CA-signed leaf and passes it as
# --tls-cert-file; an apiserver given a serving cert never self-signs, so on a mesh boot
# that file does not exist at all. Observed directly on a `--mesh-ip 127.0.0.1
# --network none` boot of the unfixed tree:
#
#   E controllermanager.go:637] "Error initializing a controller"
#     err="error parsing root-ca-file at <wd>/apiserver-certs/apiserver.crt: no such file
#     or directory" controller="serviceaccount-token-controller"
#
# — the controller-manager never starts and takes the whole bring-up down. On a work dir
# that had previously booted single-node the same pin comes up "healthy" and publishes a
# stale, unrelated CA, which is the quieter half of the same bug.
#
# The fix derives the flag from the SAME predicate that gates --tls-cert-file
# (Config.meshServingCert), so the pair can never name CAs from two different postures.
#
# TWO TIERS, split by what can be proven without booting a cluster:
#
#   CI TIER (always runs, GOARCH=arm64 CGO_ENABLED=1 pinned) — the argv-provable half:
#   the single-node argv is byte-unchanged, the mesh argv names the cluster CA, the
#   cross-flag invariant holds for every row of the table, the explicit Config.RootCAFile
#   is posture-locked (and Validate rejects it without a serving keypair), and the
#   security-relevant NEIGHBOUR rendered by the same function — the scoped --controllers
#   set — is untouched. Plus structural pins so the gate reddens if the derivation is
#   re-pinned at a literal path or the two flags are split onto different predicates.
#
#   LAB TIER (K3SM_LAB=1, a dev Mac) — the live proof: a real `--mesh-ip 127.0.0.1
#   --network none` boot, then kube-root-ca.crt's bytes in the default namespace must
#   equal <workDir>/tls/cluster-ca.crt, the apiserver's live serving cert must VERIFY
#   against those published bytes, and the self-signed --cert-dir must be empty (which is
#   what makes the old pin's target provably absent, not merely wrong). It needs no root —
#   it boots on non-default ports with the datapath off — but it takes minutes, downloads
#   the control-plane payload unless a warm bin cache is supplied, and mutates host
#   listeners, so it is opt-in. Without K3SM_LAB the lab rungs are announced LAB-PENDING
#   and never silently pass.
#
# The GOARCH=arm64 pin is a CORRECTNESS requirement, not hygiene: this Mac's Go toolchain
# is itself x86_64-under-Rosetta (`go env GOARCH` -> amd64), and the product is
# darwin/arm64-only.
#
# Usage:  hack/acceptance/B223.sh            # CI tier only
#         K3SM_LAB=1 hack/acceptance/B223.sh # + the live mesh boot
#         K3SM_LAB=1 K3SM_B223_BIN_CACHE=/tmp/k3sm-cluster/server/bin hack/acceptance/B223.sh
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
K3SM_ROOT="$(cd "$HERE/../.." && pwd)"
SELF="$HERE/B223.sh"
EXECUTOR="$K3SM_ROOT/pkg/executor/executor.go"
SUPERVISED="$K3SM_ROOT/pkg/executor/supervised.go"
SERVER="$K3SM_ROOT/cmd/k3sm/server.go"

PASS=0; FAIL=0
ladder() { if [ "$1" = ok ]; then echo "PASS  $2"; PASS=$((PASS+1)); else echo "FAIL  $2"; FAIL=$((FAIL+1)); fi; }

echo "==> k3sm B223 acceptance (KCM --root-ca-file follows the apiserver serving posture)"

# ---- b223.0 — the gate parses and every wiring source exists ----------------
b0=ok
[ -f "$SELF" ] && bash -n "$SELF" || b0=no
for f in "$EXECUTOR" "$SUPERVISED" "$SERVER"; do [ -f "$f" ] || b0=no; done
ladder "$b0" "b223.0  gate parses (bash -n) + executor.go, supervised.go, cmd/k3sm/server.go present"
if [ "$b0" != ok ]; then
	echo "----------------------------------------"
	echo "B223: the gate or a wiring source is missing/unparseable — nothing else can run" >&2
	echo "B223: $PASS passed, $FAIL failed" >&2
	exit 1
fi

# ---- b223.1 — ONE posture predicate, consumed by BOTH flags ------------------
# The crux of the item. --tls-cert-file (what the apiserver presents) and --root-ca-file
# (the CA published to every Pod) must be gated on the SAME predicate; two independent
# conditions are exactly how they come to disagree. These pins redden if either flag is
# re-split onto its own condition.
p=ok
grep -qE 'func \(c Config\) meshServingCert\(\) bool' "$EXECUTOR" || p=no
grep -qE 'c\.ServingCertFile != "" && c\.ServingKeyFile != ""' "$EXECUTOR" || p=no
grep -qE 'if cfg\.meshServingCert\(\) \{' "$SUPERVISED" || p=no
ladder "$p" "b223.1  meshServingCert is the ONE posture predicate, and --tls-cert-file is gated on it"

# ---- b223.2 — --root-ca-file is DERIVED, never re-pinned at a literal --------
# The mutant check: the shipped bug was a literal filepath.Join(certDir(wd),
# "apiserver.crt") in the argv. It may appear only inside the derivation (which owns the
# single-node branch), never at the flag site.
d=ok
grep -qE '"--root-ca-file", cfg\.rootCAFile\(\)' "$SUPERVISED" || d=no
if grep -qE '"--root-ca-file", filepath\.Join' "$SUPERVISED"; then d=no; fi
grep -qE 'func \(c Config\) rootCAFile\(\) string' "$EXECUTOR" || d=no
grep -qE 'certs\.ClusterCACertPath\(c\.WorkDir\)' "$EXECUTOR" || d=no
ladder "$d" "b223.2  --root-ca-file renders cfg.rootCAFile() (derived), not a literal cert-dir path"

# ---- b223.3 — the mesh call site names the issuing CA explicitly -------------
# cmd/k3sm sets RootCAFile beside ServingCertFile: one posture, set in one place, so a
# reader of the mesh block sees which CA the cluster publishes.
c=ok
grep -qE 'cfg\.RootCAFile = certs\.ClusterCACertPath\(opts\.workDir\)' "$SERVER" || c=no
grep -qE 'cfg\.ServingCertFile = servingCert' "$SERVER" || c=no
ladder "$c" "b223.3  cmd/k3sm mesh block sets cfg.RootCAFile = certs.ClusterCACertPath beside the serving cert"

# ---- b223.4 — the misconfiguration is LOUD, not silently ignored -------------
v=ok
grep -qE 'ErrRootCAWithoutServingCert' "$EXECUTOR" || v=no
grep -qE 'if c\.RootCAFile != "" && !c\.meshServingCert\(\)' "$EXECUTOR" || v=no
ladder "$v" "b223.4  Validate fails closed on a RootCAFile with no serving keypair"

# ---- Go leg runner (GOARCH=arm64 CGO_ENABLED=1) ----------------------------
GOFLAGS_ENV=(env GOARCH=arm64 CGO_ENABLED=1)

# run_test <id> <min-subtests> <TestName> <pkg>
# Asserts the leg actually RAN its subtests: `go test -run <filter>` EXITS 0 on a
# zero-match filter, so a renamed test would read PASS forever. Each leg fails unless
# "no tests to run" is ABSENT and the count of `--- PASS: <TestName>/` subtest lines
# meets the pinned minimum.
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

# ---- b223.5 — the posture table + the cross-flag invariant -------------------
# 3 single-node rows (byte-unchanged argv) + 2 mesh rows (cluster CA). Every row also
# asserts the invariant against apiServerArgs' own --tls-cert-file, and that the scoped
# --controllers neighbour is intact. RED on the unfixed tree: the two mesh rows fail with
# `--root-ca-file = "/wd/apiserver-certs/apiserver.crt", want "/wd/tls/cluster-ca.crt"`.
run_test "b223.5" 5 TestControllerManagerRootCAFollowsServingPosture ./pkg/executor/

# ---- b223.6 — the explicit field is posture-LOCKED ---------------------------
run_test "b223.6" 4 TestRootCAFileIsPostureLocked ./pkg/executor/

# ---- b223.7 — the fail-closed Validate guard --------------------------------
run_test "b223.7" 4 TestValidateRejectsRootCAWithoutServingCert ./pkg/executor/

# ---- b223.8 — the pre-existing argv guards still hold ------------------------
# The same two renderers this change touched are the ones M4.1/M6.0 pinned. If this
# change perturbed the client-CA wiring or the loopback bind/port posture, these redden.
run_test "b223.8" 2 TestLoopbackComponentsBindLoopbackOnly ./pkg/executor/
out=""; rc=0
out="$(cd "$K3SM_ROOT" && "${GOFLAGS_ENV[@]}" go test -count=1 -run '^TestClientCAFileAlwaysSet$|^TestApiserverFlagsMeshBindAnonOff$|^TestApiserverArgsSingleNodeDefault$' ./pkg/executor/ 2>&1)" || rc=$?
if [ "$rc" -eq 0 ]; then
	ladder ok "b223.8  the apiserver client-CA / mesh-bind / single-node argv guards still pass"
else
	printf '%s\n' "$out" | tail -20
	ladder no "b223.8  the apiserver client-CA / mesh-bind / single-node argv guards still pass"
fi

# ============================================================================
# LAB TIER — the live mesh boot (K3SM_LAB=1, a dev Mac; no root required).
# ============================================================================
lab_pending() { echo "LAB-PENDING  $1"; }

if [ "${K3SM_LAB:-}" != 1 ]; then
	echo "----------------------------------------"
	echo "B223 LAB tier (set K3SM_LAB=1 on a dev Mac to run; no root needed, ~3 min):"
	lab_pending "b223.L1  a --mesh-ip 127.0.0.1 --network none boot reaches healthz (RED before: the KCM dies on 'error parsing root-ca-file ... no such file or directory')"
	lab_pending "b223.L2  default/kube-root-ca.crt bytes == <workDir>/tls/cluster-ca.crt"
	lab_pending "b223.L3  the live apiserver serving cert VERIFIES against the published CA bytes"
	lab_pending "b223.L4  <workDir>/apiserver-certs is empty — the old pin's target does not exist on a mesh boot"
else
	# Self-contained: hack/lib/clusterup.sh's server_up has no --mesh-ip, and mesh is the
	# whole point here, so the boot is spelled out. Non-default ports throughout so it
	# cannot contend with a dev cluster; --network none keeps it rootless.
	LAB_ROOT="${K3SM_B223_LAB_ROOT:-/tmp/k3sm-b223}"
	LAB_WD="$LAB_ROOT/server"
	LAB_BIN="/tmp/k3sm-b223-k3sm"
	LAB_API_PORT=6455; LAB_KINE_PORT=2399; LAB_KUBELET_PORT=10265
	LAB_SCHED_PORT=11259; LAB_KCM_PORT=11257
	LAB_PID=""
	lab_down() {
		if [ -n "$LAB_PID" ] && kill -0 "$LAB_PID" 2>/dev/null; then
			kill -TERM "$LAB_PID" 2>/dev/null || true
			local n=0
			while kill -0 "$LAB_PID" 2>/dev/null; do
				n=$((n+1)); [ "$n" -gt 20 ] && { kill -9 "$LAB_PID" 2>/dev/null || true; break; }
				sleep 1
			done
		fi
	}
	trap lab_down EXIT INT TERM

	echo "----------------------------------------"
	echo "B223 LAB tier: booting a MESH single-node control plane (mutates this Mac's :$LAB_API_PORT/:$LAB_KINE_PORT listeners)"
	# A fresh work dir is load-bearing: on a dir that once booted single-node the stale
	# self-signed apiserver.crt exists, and the unfixed pin would come up "healthy"
	# publishing it — the quiet half of the bug, which b223.L2 catches but b223.L1 would
	# not. Starting clean makes L1 sharp too.
	rm -rf "$LAB_WD"; mkdir -p "$LAB_WD/bin" "$LAB_ROOT/pods"
	if [ -n "${K3SM_B223_BIN_CACHE:-}" ] && [ -d "$K3SM_B223_BIN_CACHE" ]; then
		cp "$K3SM_B223_BIN_CACHE"/* "$LAB_WD/bin/" 2>/dev/null || true
		echo "seeded the control-plane payload from $K3SM_B223_BIN_CACHE"
	fi
	if (cd "$K3SM_ROOT" && env GOARCH=arm64 CGO_ENABLED=1 go build -o "$LAB_BIN" ./cmd/k3sm); then
		ladder ok "b223.L0  built the k3sm binary under test"
	else
		ladder no "b223.L0  built the k3sm binary under test"
	fi

	if [ "$FAIL" -eq 0 ]; then
		nohup env CGO_ENABLED=1 "$LAB_BIN" server \
			--work-dir "$LAB_WD" --node-name b223lab --node-ip 127.0.0.1 --mesh-ip 127.0.0.1 \
			--runtime hostprocess --network none \
			--api-port "$LAB_API_PORT" --kine-port "$LAB_KINE_PORT" --kubelet-port "$LAB_KUBELET_PORT" \
			--scheduler-port "$LAB_SCHED_PORT" --controller-manager-port "$LAB_KCM_PORT" \
			--ingress-http-port 0 --ingress-https-port 0 \
			--pod-root "$LAB_ROOT/pods" > "$LAB_ROOT/server.log" 2>&1 &
		LAB_PID=$!

		KC="$LAB_WD/bin/kubectl"
		export KUBECONFIG="$LAB_WD/k3sm.kubeconfig"
		healthy=no; n=0
		while [ "$n" -lt 120 ]; do
			if ! kill -0 "$LAB_PID" 2>/dev/null; then break; fi
			if [ -x "$KC" ] && [ "$("$KC" get --raw /healthz 2>/dev/null)" = ok ]; then healthy=ok; break; fi
			sleep 3; n=$((n+1))
		done
		if [ "$healthy" = ok ]; then
			ladder ok "b223.L1  mesh boot reached apiserver healthz (the controller-manager started)"
		else
			tail -25 "$LAB_ROOT/server.log" >&2
			ladder no "b223.L1  mesh boot reached apiserver healthz (the controller-manager started)"
		fi

		if [ "$healthy" = ok ]; then
			# The published anchor. Poll: the root-ca-cert-publisher writes it shortly
			# after the KCM's caches sync.
			pub="$LAB_ROOT/published-ca.crt"; n=0; got=no
			while [ "$n" -lt 40 ]; do
				if "$KC" get configmap kube-root-ca.crt -n default -o "jsonpath={.data.ca\\.crt}" > "$pub" 2>/dev/null && [ -s "$pub" ]; then got=ok; break; fi
				sleep 3; n=$((n+1))
			done
			if [ "$got" = ok ] && cmp -s "$pub" "$LAB_WD/tls/cluster-ca.crt"; then
				ladder ok "b223.L2  default/kube-root-ca.crt bytes == $LAB_WD/tls/cluster-ca.crt"
			else
				ladder no "b223.L2  default/kube-root-ca.crt bytes == $LAB_WD/tls/cluster-ca.crt (got $(wc -c < "$pub" 2>/dev/null || echo 0) bytes)"
			fi

			# The end-to-end property the ConfigMap exists FOR: a client holding only the
			# published bytes can verify the live apiserver. Byte-equality alone would
			# still pass if both files were the wrong CA.
			if [ -s "$pub" ] && openssl s_client -connect "127.0.0.1:$LAB_API_PORT" -CAfile "$pub" -servername kubernetes </dev/null 2>/dev/null | grep -q "Verify return code: 0 (ok)"; then
				ladder ok "b223.L3  the live apiserver serving cert VERIFIES against the published CA bytes"
			else
				ladder no "b223.L3  the live apiserver serving cert VERIFIES against the published CA bytes"
			fi

			# The old pin's target. Empty here is why the unfixed tree could not even start
			# the controller-manager on a fresh mesh work dir.
			if [ -z "$(ls -A "$LAB_WD/apiserver-certs" 2>/dev/null)" ]; then
				ladder ok "b223.L4  $LAB_WD/apiserver-certs is EMPTY — a mesh apiserver never self-signs, so the old --root-ca-file target does not exist"
			else
				ladder no "b223.L4  $LAB_WD/apiserver-certs is EMPTY (found: $(ls -A "$LAB_WD/apiserver-certs" | tr '\n' ' '))"
			fi
		fi
		lab_down
	fi
fi

echo "----------------------------------------"
echo "B223: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ] || exit 1
if [ "${K3SM_LAB:-}" = 1 ]; then
	echo "================ B223 GREEN (CI + LAB tiers) ================"
else
	echo "================ B223 GREEN (CI tier) ================"
fi

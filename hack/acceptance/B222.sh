#!/usr/bin/env bash
#
# k3sm B222 acceptance gate — the runnable proof that the apiserver healthz PROBE
# and every in-process CLIENT dial the address the apiserver ACTUALLY BINDS, not a
# hardcoded loopback.
#
# The defect it pins (lab defect D1): pkg/executor/setup.go rendered the apiserver
# URL as https://127.0.0.1:<port> and fed that literal to Supervised.Ready /
# waitHealthz, to the admin kubeconfig, and to the per-component (scheduler /
# controller-manager) client-cert kubeconfigs — while a MESH server binds the
# wireguard mesh IP ONLY (cmd/k3sm/server.go sets Config.BindAddress = --mesh-ip,
# and apiServerArgs renders --bind-address from it, "never 0.0.0.0"). So with a real
# non-loopback --mesh-ip, bring-up WEDGES at the healthz wait and every in-process
# client points at an address nothing is listening on. Loopback-only mesh boots
# (--mesh-ip 127.0.0.1) work by accident, which is why it went unnoticed.
#
# The fix is one named derivation — executor.apiServerHost, the same
# BindAddress -> NodeIP -> loopback chain apiServerArgs already used — threaded
# through apiServerURL, Ready, and both kubeconfig writers. This gate's sharpest
# assertion is that identity: the client host must EQUAL --bind-address, because a
# second independent derivation is precisely how the two came apart.
#
# It also pins the compatibility contract in the other direction: a single-node /
# default Config must render byte-for-byte what it rendered before
# (https://127.0.0.1:6444), and the two co-located components must still bind
# loopback and only loopback.
#
# TWO TIERS, split by what can be proven without root:
#
#   CI TIER (always runs, GOARCH=arm64 CGO_ENABLED=1 pinned) — the unit-provable
#   contract: the derivation chain and its IPv6 bracketing; probe URL, admin
#   kubeconfig and both component kubeconfigs tracking the effective bind across
#   five postures (loopback default, zero Config, mesh, BindAddress-over-NodeIP,
#   the NodeIP fallback rung); an END-TO-END Ready() against a live TLS apiserver
#   bound to [::1] — a NON-loopback-literal address that needs no root, because
#   IPv6 loopback is on lo0 by default; and the byte-unchanged single-node pins.
#   Plus structural mutant checks so deleting the derivation reddens the gate.
#
#   INTEGRATION TIER (root + K3SM_LAB=1) — a real `k3sm server` bound to a
#   non-loopback lo0 alias reaching "control plane healthy", with its written
#   kubeconfig naming that alias. It needs root because creating the lo0 alias does
#   (`ifconfig lo0 alias`). Without root it SKIPS LOUDLY and is counted as a SKIP —
#   never as a pass, so a green CI-tier run can never be read as "the live path was
#   checked".
#
# The GOARCH=arm64 pin is a CORRECTNESS requirement, not hygiene: some dev Macs run
# an x86_64-under-Rosetta Go toolchain (`go env GOARCH` -> amd64), and an unpinned
# build silently decides arch-sensitive behaviour. The product is darwin/arm64-only.
#
# Usage:  hack/acceptance/B222.sh                  # CI tier; integration leg SKIPS
#         sudo K3SM_LAB=1 hack/acceptance/B222.sh  # + the live non-loopback bind
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
K3SM_ROOT="$(cd "$HERE/../.." && pwd)"
SETUP="$K3SM_ROOT/pkg/executor/setup.go"
SUPERVISED="$K3SM_ROOT/pkg/executor/supervised.go"
EMBEDDED="$K3SM_ROOT/pkg/executor/embedded.go"
SELF="$HERE/B222.sh"

PASS=0; FAIL=0; SKIP=0
ladder() { if [ "$1" = ok ]; then echo "PASS  $2"; PASS=$((PASS+1)); else echo "FAIL  $2"; FAIL=$((FAIL+1)); fi; }
skipped() { echo "SKIP  $1"; SKIP=$((SKIP+1)); }

echo "==> k3sm B222 acceptance (apiserver probe + in-process clients follow the effective bind)"

# ---- b222.0 — the gate parses and its sources exist -------------------------
b0=ok
[ -f "$SELF" ] && bash -n "$SELF" || b0=no
for f in "$SETUP" "$SUPERVISED" "$EMBEDDED"; do [ -f "$f" ] || b0=no; done
ladder "$b0" "b222.0  gate parses (bash -n) + pkg/executor sources present"
if [ "$b0" != ok ]; then
	echo "----------------------------------------"
	echo "B222: the gate or its sources are missing/unparseable — nothing else can run" >&2
	echo "B222: $PASS passed, $FAIL failed, $SKIP skipped" >&2
	exit 1
fi

# ---- b222.1 — the derivation exists and is SINGLE-SOURCED -------------------
# Structural pins, so the gate reddens if the helper is deleted or if either side
# grows its own copy of the chain again. The negative pin is the sharp one: the
# exact defect literal must be gone from the URL renderer.
d=ok
grep -qE '^func apiServerHost\(cfg Config\) string \{' "$SETUP" || d=no
grep -qE '^func apiServerURL\(cfg Config\) string \{' "$SETUP" || d=no
grep -qE 'net\.JoinHostPort\(apiServerHost\(cfg\), strconv\.Itoa\(cfg\.APIServerPort\)\)' "$SETUP" || d=no
if grep -qE '"https://127\.0\.0\.1:" \+ strconv\.Itoa' "$SETUP"; then d=no; fi
ladder "$d" "b222.1  apiServerHost/apiServerURL derive the host (and the hardcoded loopback URL literal is gone)"

# ---- b222.2 — apiServerArgs renders --bind-address from the SAME helper -----
# Without this, --bind-address and the client URL are two derivations again, and
# the whole class of defect is one edit away from returning.
a=ok
grep -qE 'bind := apiServerHost\(cfg\)' "$SUPERVISED" || a=no
grep -qE '"--bind-address", bind,' "$SUPERVISED" || a=no
ladder "$a" "b222.2  apiServerArgs renders --bind-address from apiServerHost (ONE derivation)"

# ---- b222.3 — every consumer is threaded --------------------------------------
# The full consumer set: the healthz probe, both RESTConfigToken implementations,
# and the three kubeconfig writes (admin + scheduler + controller-manager).
#
# WHAT IS PINNED, AND WHAT DELIBERATELY IS NOT (re-scoped 2026-09-03): B222's
# subject is the HOST — that every consumer takes it from the ONE derivation
# (apiServerURL/apiServerHost over the config) instead of re-deriving loopback.
# The TOKEN argument travelling beside it is not B222's subject and never was, so
# it is matched loosely. Two rungs here pinned the token expression literally and
# went stale when it changed for unrelated reasons: `s.token` became
# `s.currentToken()` (a mutex-guarded read added with the concurrency fix), and
# the writeKubeconfig call site hoisted the same value into a local so the token
# FILE and the kubeconfig are written from one snapshot. Neither touched a host
# derivation — the behavioural rungs b222.4-b222.9 stayed green throughout — so
# this rung was reporting on token plumbing it does not own. The host halves
# (`apiServerURL(s.cfg)`, `apiServerURL(e.cfg)`, `writeKubeconfig(s.cfg,`,
# `writeComponentKubeconfig(s.cfg,`) stay pinned EXACTLY: those are the literals
# whose loss is the defect B222 exists to prevent.
c=ok
grep -qE 'url := apiServerURL\(s\.cfg\) \+ "/healthz"' "$SUPERVISED" || c=no
grep -qE 'return apiServerURL\(s\.cfg\), ' "$SUPERVISED" || c=no
grep -qE 'return apiServerURL\(e\.cfg\), e\.cfg\.Token' "$EMBEDDED" || c=no
grep -qE '^func writeKubeconfig\(cfg Config, token string\) error \{' "$SETUP" || c=no
grep -qE '^func writeComponentKubeconfig\(cfg Config, path, cn string,' "$SETUP" || c=no
grep -qE 'writeKubeconfig\(s\.cfg, ' "$SUPERVISED" || c=no
[ "$(grep -cE 'writeComponentKubeconfig\(s\.cfg, ' "$SUPERVISED")" -eq 2 ] || c=no
ladder "$c" "b222.3  Ready, both RESTConfigToken, and all three kubeconfig writes consume the derived host"

# ---- Go leg runner (GOARCH=arm64 CGO_ENABLED=1) ----------------------------
GOFLAGS_ENV=(env GOARCH=arm64 CGO_ENABLED=1)

# run_test <id> <min-subtests> <TestName> <pkg>
# Asserts the leg actually RAN: `go test -run <filter>` EXITS 0 on a zero-match
# filter, so a renamed test would read PASS forever. Each leg fails unless "no tests
# to run" is ABSENT and the count of `--- PASS: <TestName>/` subtest lines meets the
# pinned minimum. min=0 means the test has no subtests: assert its own PASS line.
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
	if [ "$min" -eq 0 ]; then
		if printf '%s\n' "$out" | grep -qE "^[[:space:]]*--- PASS: ${name}\b"; then
			ladder ok "$id  $name ($pkg) passed"
		else
			ladder no "$id  $name ($pkg) reported no PASS line of its own"
		fi
		return
	fi
	ran="$(printf '%s\n' "$out" | grep -cE "^[[:space:]]*--- PASS: ${name}/" || true)"
	if [ "$ran" -ge "$min" ]; then
		ladder ok "$id  $name ($pkg): $ran subtests passed (min $min)"
	else
		ladder no "$id  $name ($pkg): only $ran subtests passed, want >= $min"
	fi
}

# ---- b222.4 — the derivation chain, including the IPv6 bracketing -----------
run_test "b222.4" 4 TestAPIServerHostChain ./pkg/executor/

# ---- b222.5 — the probe URL / in-process client host tracks the bind -------
# RED before the fix: the mesh, BindAddress-over-NodeIP and NodeIP-fallback rows all
# report https://127.0.0.1:6444 while --bind-address is the mesh/node address.
run_test "b222.5" 5 TestAPIServerClientsFollowEffectiveBind ./pkg/executor/

# ---- b222.6 — the admin kubeconfig follows the bind (single-node pinned) ----
run_test "b222.6" 5 TestAdminKubeconfigServerFollowsEffectiveBind ./pkg/executor/

# ---- b222.7 — both per-component kubeconfigs follow the bind ---------------
run_test "b222.7" 5 TestComponentKubeconfigServersFollowEffectiveBind ./pkg/executor/

# ---- b222.8 — END-TO-END: Ready() reaches a NON-loopback-literal apiserver --
# A real TLS server on [::1]. No root, no lo0 alias, and the hardcoded-127.0.0.1
# probe cannot reach it — so this leg is genuinely red before the fix.
run_test "b222.8" 0 TestReadyProbesEffectiveBindAddress ./pkg/executor/

# ---- b222.9 — the compatibility contract: the default did not move ----------
# The pre-existing single-node pins must stay green. A "fix" that moved the default
# posture would be a silent break for every single-node install.
run_test "b222.9a" 0 TestSupervisedPathsLayout ./pkg/executor/
run_test "b222.9b" 0 TestApiserverArgsSingleNodeDefault ./pkg/executor/
run_test "b222.9c" 2 TestLoopbackComponentsBindLoopbackOnly ./pkg/executor/

# ============================================================================
# INTEGRATION TIER — a live server bound to a NON-loopback lo0 alias.
# ============================================================================
ALIAS="${B222_ALIAS:-100.64.222.1}"

if [ "${K3SM_LAB:-}" != 1 ] || [ "$(id -u)" -ne 0 ]; then
	echo "----------------------------------------"
	echo "B222 INTEGRATION tier — NOT RUN (requires root: creating the lo0 alias $ALIAS needs \`ifconfig lo0 alias\`)."
	echo "  Run it with:  sudo K3SM_LAB=1 $SELF"
	skipped "b222.I1  \`k3sm server --node-ip $ALIAS\` (a NON-loopback bind) reaches 'control plane healthy' — requires root"
	skipped "b222.I2  the written k3sm.kubeconfig names https://$ALIAS:<api-port> — requires root"
else
	echo "----------------------------------------"
	echo "B222 INTEGRATION tier: adding lo0 alias $ALIAS and booting a server bound to it"
	IWD="$(mktemp -d /tmp/b222.XXXXXX)"
	SRV_PID=""
	int_cleanup() {
		[ -n "$SRV_PID" ] && kill -TERM "$SRV_PID" 2>/dev/null || true
		ifconfig lo0 -alias "$ALIAS" 2>/dev/null || true
		rm -rf "$IWD"
	}
	trap int_cleanup EXIT INT TERM

	API_PORT="${B222_API_PORT:-6455}"
	KINE_PORT="${B222_KINE_PORT:-2390}"
	SCHED_PORT="${B222_SCHED_PORT:-10289}"
	KCM_PORT="${B222_KCM_PORT:-10287}"
	KUBELET_PORT="${B222_KUBELET_PORT:-10280}"

	if ifconfig lo0 alias "$ALIAS"/32; then
		ladder ok "b222.I0  lo0 alias $ALIAS created"
		# --node-ip alone is enough: with no --mesh-ip, BindAddress is empty and the
		# derivation falls to the NodeIP rung, so the apiserver binds $ALIAS ONLY.
		# That is the same wedge the mesh path hits, without needing wireguard.
		# --network none keeps this to the control plane: the assertion is the
		# "control plane healthy" line, which the server logs immediately after the
		# executor's healthz wait returns — the exact wait that hung before the fix.
		( cd "$K3SM_ROOT" && CGO_ENABLED=1 go run ./cmd/k3sm server \
			--work-dir "$IWD/server" --node-name b222 --node-ip "$ALIAS" \
			--runtime hostprocess --network none --pod-root "$IWD/pods" \
			--api-port "$API_PORT" --kine-port "$KINE_PORT" \
			--scheduler-port "$SCHED_PORT" --controller-manager-port "$KCM_PORT" \
			--kubelet-port "$KUBELET_PORT" \
			--ingress-http-port 0 --ingress-https-port 0 \
			> "$IWD/server.log" 2>&1 ) &
		SRV_PID=$!

		# Generous: as root, `go run` compiles into root's cold GOCACHE, and a first
		# boot downloads + ad-hoc-signs the control-plane binaries.
		healthy=no
		for _ in $(seq 1 600); do
			if grep -q "control plane healthy" "$IWD/server.log" 2>/dev/null; then healthy=ok; break; fi
			kill -0 "$SRV_PID" 2>/dev/null || break
			sleep 1
		done
		if [ "$healthy" = ok ]; then
			ladder ok "b222.I1  \`k3sm server --node-ip $ALIAS\` (NON-loopback bind) reached 'control plane healthy'"
		else
			tail -30 "$IWD/server.log" 2>/dev/null || true
			ladder no "b222.I1  \`k3sm server --node-ip $ALIAS\` reached 'control plane healthy' (it did not — RED-before shape: the healthz probe dials 127.0.0.1 while the apiserver binds $ALIAS)"
		fi

		KCFG="$IWD/server/k3sm.kubeconfig"
		if [ -f "$KCFG" ] && grep -qF "https://$ALIAS:$API_PORT" "$KCFG"; then
			ladder ok "b222.I2  the written k3sm.kubeconfig names https://$ALIAS:$API_PORT"
		else
			ladder no "b222.I2  the written k3sm.kubeconfig names https://$ALIAS:$API_PORT (got: $(grep -o 'server: [^ ]*' "$KCFG" 2>/dev/null || echo '<no kubeconfig>'))"
		fi
	else
		ladder no "b222.I0  lo0 alias $ALIAS created (ifconfig failed — is $ALIAS already in use?)"
	fi
	int_cleanup
	trap - EXIT INT TERM
fi

echo "----------------------------------------"
echo "B222: $PASS passed, $FAIL failed, $SKIP skipped"
[ "$FAIL" -eq 0 ] || exit 1
if [ "$SKIP" -eq 0 ]; then
	echo "================ B222 GREEN (CI + integration) ================"
else
	echo "================ B222 GREEN (CI tier; $SKIP integration rung(s) SKIPPED — see above) ================"
fi

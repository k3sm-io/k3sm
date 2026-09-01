#!/usr/bin/env bash
#
# k3sm B213 acceptance gate — the runnable proof that a node's kubelet SERVING cert
# chains to the CA the apiserver was told to verify it against.
#
# The defect (lab D6, observed on a live two-Mac cluster): `k3sm server --mesh-ip`
# starts the apiserver with --kubelet-certificate-authority=<cluster CA>, but
# kubeletServingTLS ALWAYS minted certs.SelfSignedServing and never consumed the
# cluster-CA-issued keypair the join wire had been delivering since M3.0. Every node
# therefore presented a cert chaining to nothing:
#
#   Error from server: Get "https://<node>:10250/containerLogs/...":
#   x509: certificate signed by unknown authority
#
# — kubectl logs/exec broken CLUSTER-WIDE while every node reported Ready. It was
# proven on the control-plane node's own kubelet, which is the half the original
# prescription missed: that node never joins, so consuming the join response repairs
# only WORKERS. The server must mint its own from the same cluster CA.
#
# The fix, in one sentence per role: a worker uses the pair its join delivered; a
# mesh server mints its own (365d, in memory, SANs covering every address the
# apiserver may dial it at); single-node keeps self-signing, because that posture
# names no --kubelet-certificate-authority and nothing would verify a CA-issued leaf.
# Neither role falls back — a missing pair or a failed mint stops the node.
#
# TWO TIERS, split by what can be proven without booting a cluster:
#
#   CI TIER (always runs, GOARCH=arm64 CGO_ENABLED=1 pinned) — the unit-provable
#   half: the issued pair is what :10250 presents and it chains to the cluster CA;
#   B176's client-auth stamping survives on the same config; the half-pair refusal
#   names the SERVER as the cause; the join-delivered pair reaches the worker's node
#   and an empty one refuses the start; the server's own mint chains to the cluster
#   CA and its SAN set covers the divergent registered InternalIP of the no-datapath
#   posture; a CA that cannot issue FAILS CLOSED rather than degrading to
#   self-signed; --kubelet-certificate-authority is emitted IFF Config.KubeletCAFile
#   is set (the DESIGN §5c divergence this change is most likely to perturb); and the
#   rotation report lists the newly re-minted artifact. Plus structural pins, so the
#   gate reddens if a call site is deleted or a second self-signing path appears.
#   RED BEFORE: on the unmodified tree kubeletServingTLS takes no pair and
#   setServerKubeletServing does not exist, so the Go legs fail to build and every
#   structural pin fails.
#
#   LAB TIER (K3SM_LAB=1, a dev Mac; NO root) — the live proof, over the real TLS
#   handshake: boot `k3sm server --mesh-ip 127.0.0.1 --network none` — the FLAG
#   alone, no mesh device, so this gate does not secretly depend on the M14.2
#   server-side mesh bring-up — verify the cert :10250 actually presents against
#   <workDir>/tls/cluster-ca.crt and that its SANs cover the address the node
#   REGISTERED, then run `kubectl logs` on a Running pod, which is the apiserver
#   making that judgement itself rather than openssl making it. Then the same boot
#   WITHOUT --mesh-ip must present a self-signed cert, which is what keeps the dev
#   posture pinned rather than merely unbroken. It needs no root (the datapath is
#   off and every port is off-default), but it downloads the control-plane payload on
#   a cold cache and mutates host listeners, so it is opt-in. Without K3SM_LAB the
#   lab rungs are announced LAB-PENDING and never silently pass.
#
# WHAT THIS GATE DOES NOT PROVE: the round trip against a JOINED WORKER. One Mac has
# no second node, so the worker path — the join-delivered pair, d3 — is exercised
# here only in unit form. That leg is the M14.3 two-Mac session; it is announced
# LAB-PENDING below and never counted as a pass.
#
# The GOARCH=arm64 pin is a CORRECTNESS requirement, not hygiene: this Mac's Go
# toolchain may itself be x86_64-under-Rosetta, and the product is darwin/arm64-only.
#
# Usage:  hack/acceptance/B213.sh            # CI tier only
#         K3SM_LAB=1 hack/acceptance/B213.sh # + the live mesh/single-node boots
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
K3SM_ROOT="$(cd "$HERE/../.." && pwd)"
SELF="$HERE/B213.sh"
NODE_GO="$K3SM_ROOT/cmd/k3sm/node.go"
AGENT_GO="$K3SM_ROOT/cmd/k3sm/agent.go"
SERVER_GO="$K3SM_ROOT/cmd/k3sm/server.go"
SERVING_GO="$K3SM_ROOT/pkg/certs/serving.go"
ROTATE_GO="$K3SM_ROOT/pkg/executor/rotate.go"
DESIGN_MD="$K3SM_ROOT/docs/DESIGN.md"

PASS=0; FAIL=0
ladder() { if [ "$1" = ok ]; then echo "PASS  $2"; PASS=$((PASS+1)); else echo "FAIL  $2"; FAIL=$((FAIL+1)); fi; }
lab_pending() { echo "LAB-PENDING  $1"; }

echo "==> k3sm B213 acceptance (the kubelet serving cert chains to the cluster CA the apiserver verifies against)"

# ---- b213.0 — the gate parses and every wiring source exists ----------------
b0=ok
[ -f "$SELF" ] && bash -n "$SELF" || b0=no
for f in "$NODE_GO" "$AGENT_GO" "$SERVER_GO" "$SERVING_GO" "$ROTATE_GO" "$DESIGN_MD"; do
	[ -f "$f" ] || b0=no
done
ladder "$b0" "b213.0  gate parses (bash -n) + node.go, agent.go, server.go, certs/serving.go, executor/rotate.go, DESIGN.md present"
if [ "$b0" != ok ]; then
	echo "----------------------------------------"
	echo "B213: the gate or a wiring source is missing/unparseable — nothing else can run" >&2
	echo "B213: $PASS passed, $FAIL failed" >&2
	exit 1
fi

# ---- b213.1 — the serving cert is a PARAMETER, not always self-signed -------
# The shipped bug was a single unconditional certs.SelfSignedServing call. It may
# now appear only inside the fallback, and only in that one file: a second call site
# in server.go or agent.go would be the defect re-entering through another door.
p=ok
grep -qE 'func kubeletServingTLS\(auth \*provider\.KubeletEndpointAuth, servingCertPEM, servingKeyPEM \[\]byte' "$NODE_GO" || p=no
grep -qE 'tls\.X509KeyPair\(servingCertPEM, servingKeyPEM\)' "$NODE_GO" || p=no
grep -qE 'errHalfKubeletServingPair' "$NODE_GO" || p=no
# The CALL form (a trailing paren), so a doc comment naming the function — which
# both files legitimately do — is not mistaken for a second self-signing path.
[ "$(grep -c 'certs\.SelfSignedServing(' "$NODE_GO")" = 1 ] || p=no
grep -q 'certs\.SelfSignedServing(' "$SERVER_GO" && p=no
grep -q 'certs\.SelfSignedServing(' "$AGENT_GO" && p=no
ladder "$p" "b213.1  kubeletServingTLS consumes an issued keypair; self-signing survives as the single dev fallback and nowhere else"

# ---- b213.2 — the worker hop (join response -> in-process node) -------------
a=ok
grep -qE 'kubeletServingCertPEM: res\.KubeletServingCertPEM' "$AGENT_GO" || a=no
grep -qE 'kubeletServingKeyPEM:  res\.KubeletServingKeyPEM' "$AGENT_GO" || a=no
grep -qE 'if err := requireJoinedServingPair\(res\); err != nil' "$AGENT_GO" || a=no
ladder "$a" "b213.2  agentNodeOptions passes the join-delivered pair through, and runAgent refuses a join that carried none"

# ---- b213.3 — the control-plane half (the observed defect) -----------------
s=ok
grep -qE 'if err := setServerKubeletServing\(&nodeOpts, hierarchy, opts\.meshIP\); err != nil' "$SERVER_GO" || s=no
grep -qE 'hierarchy\.Cluster\.IssueServing\(' "$SERVER_GO" || s=no
grep -qE 'kubeletServingValidFor = 365 \* 24 \* time\.Hour' "$SERVER_GO" || s=no
grep -qE 'proxyableNodeIP\(advertised\)' "$SERVER_GO" || s=no
ladder "$s" "b213.3  a mesh server mints its OWN cluster-CA serving cert (365d, SANs including the derived InternalIP)"

# The ORDER: the mint reads the finished nodeOpts, so it must sit after the literal
# and before the node starts. A mint placed earlier would compute its SAN set off
# fields that are not filled in yet — the SAN-mismatch reproduction of this defect.
lit_ln="$(grep -n 'nodeOpts := nodeOptions{' "$SERVER_GO" | head -1 | cut -d: -f1 || true)"
mint_ln="$(grep -n 'setServerKubeletServing(&nodeOpts, hierarchy' "$SERVER_GO" | head -1 | cut -d: -f1 || true)"
start_ln="$(grep -n 'startNode(ctx, nodeOpts)' "$SERVER_GO" | head -1 | cut -d: -f1 || true)"
if [ -n "$lit_ln" ] && [ -n "$mint_ln" ] && [ -n "$start_ln" ] &&
	[ "$lit_ln" -lt "$mint_ln" ] && [ "$mint_ln" -lt "$start_ln" ]; then
	ladder ok "b213.3  nodeOptions literal(:$lit_ln) < setServerKubeletServing(:$mint_ln) < startNode(:$start_ln)"
else
	ladder no "b213.3  ordering: nodeOptions literal(:${lit_ln:-none}) < setServerKubeletServing(:${mint_ln:-none}) < startNode(:${start_ln:-none})"
fi

# ---- b213.4 — the rotation report stays complete ---------------------------
r=ok
grep -qE 'kubeletServingArtifact\(workDir\),' "$ROTATE_GO" || r=no
grep -qE 'func kubeletServingArtifact\(workDir string\) RotationArtifact' "$ROTATE_GO" || r=no
ladder "$r" "b213.4  reissuedArtifacts lists the newly re-minted kubelet serving pair (the report's completeness contract)"

# ---- b213.5 — the docs describe the mechanism, not the aspiration ----------
d=ok
grep -q 'two mint sites and one anchor' "$DESIGN_MD" || d=no
grep -q 'setServerKubeletServing' "$DESIGN_MD" || d=no
grep -q 'SCOPE — this is the SINGLE-NODE, dev and standalone' "$SERVING_GO" || d=no
grep -q 'B213' "$SERVING_GO" || d=no
ladder "$d" "b213.5  DESIGN §5c names both mint sites, and SelfSignedServing's doc scopes itself to the dev posture"

# ---- Go leg runner (GOARCH=arm64 CGO_ENABLED=1) ----------------------------
GOFLAGS_ENV=(env GOARCH=arm64 CGO_ENABLED=1)

# run_test <id> <min-subtests> <TestName> <pkg> [extra go test flags...]
# Asserts the leg actually RAN: `go test -run <filter>` EXITS 0 on a zero-match
# filter, so a renamed test would read PASS forever.
run_test() {
	local id="$1" min="$2" name="$3" pkg="$4"; shift 4
	local out rc=0 ran
	out="$(cd "$K3SM_ROOT" && "${GOFLAGS_ENV[@]}" go test -count=1 -v "$@" -run "^${name}\$" "$pkg" 2>&1)" || rc=$?
	if [ "$rc" -ne 0 ]; then
		printf '%s\n' "$out" | tail -30
		ladder no "$id  $name ($pkg) passed"
		return
	fi
	if printf '%s\n' "$out" | grep -qE 'no tests to run|no test files'; then
		ladder no "$id  $name ($pkg) actually RAN — go test reported no tests to run (renamed test?)"
		return
	fi
	if ! printf '%s\n' "$out" | grep -qE "^[[:space:]]*--- PASS: ${name}( |\$)"; then
		ladder no "$id  $name ($pkg) actually RAN — no top-level --- PASS line"
		return
	fi
	ran="$(printf '%s\n' "$out" | grep -cE "^[[:space:]]*--- PASS: ${name}/" || true)"
	if [ "$ran" -ge "$min" ]; then
		ladder ok "$id  $name ($pkg): $ran subtests passed (min $min)"
	else
		ladder no "$id  $name ($pkg): only $ran subtests passed, want >= $min"
	fi
}

# ---- b213.6 — the serving half of :10250 (d1/d2) ---------------------------
run_test "b213.6" 0 TestKubeletServingTLSUsesIssuedPair        ./cmd/k3sm/
run_test "b213.6" 0 TestKubeletServingTLSSelfSignedDefault     ./cmd/k3sm/
run_test "b213.6" 2 TestKubeletServingTLSRejectsHalfPair       ./cmd/k3sm/

# ---- b213.7 — the worker path (d3) -----------------------------------------
run_test "b213.7" 4 TestAgentNodeOptionsCarriesServingPair     ./cmd/k3sm/

# ---- b213.8 — the control-plane path, incl. fail-closed (d4) ---------------
run_test "b213.8" 3 TestServerMeshNodeOptionsMintFromClusterCA ./cmd/k3sm/
run_test "b213.8" 3 TestServerMeshMintFailsClosedWithoutCA     ./cmd/k3sm/

# ---- b213.9 — the apiserver flag pin + the rotation report (d5) ------------
run_test "b213.9" 2 TestApiserverKubeletCAFlagIffConfigured    ./pkg/executor/
run_test "b213.9" 2 TestRotationReportsTheKubeletServingPair   ./pkg/executor/

# ---- b213.10 — the B176 neighbour, unchanged -------------------------------
# This change edits the function that carries the CLIENT half. Presenting a
# verifiable serving cert while losing tls.RequireAndVerifyClientCert would trade
# this defect for a worse one, so the end-to-end authn proof runs here too.
run_test "b213.10" 5 TestKubeletEndpointRequiresClientCert     ./pkg/provider/ -race

# ============================================================================
# LAB TIER — live TLS against a real :10250 (K3SM_LAB=1, a dev Mac; no root).
# ============================================================================
if [ "${K3SM_LAB:-}" != 1 ]; then
	echo "----------------------------------------"
	echo "B213 LAB tier (set K3SM_LAB=1 on a dev Mac to run; no root needed, ~5 min on a cold payload cache):"
	lab_pending "b213.L1  \`k3sm server --mesh-ip 127.0.0.1 --network none\` reaches apiserver healthz AND registers a node serving :10250"
	lab_pending "b213.L2  the cert :10250 presents VERIFIES against <workDir>/tls/cluster-ca.crt (RED before: self-signed certificate — B176's client-cert requirement does not hide this, the server cert is sent before client auth completes)"
	lab_pending "b213.L3  that leaf's SANs cover the address the node REGISTERED as its InternalIP"
	lab_pending "b213.L4  kubectl logs on a Running pod completes the apiserver->:10250 round trip (RED before: x509: certificate signed by unknown authority — the exact lab symptom)"
	lab_pending "b213.L5  a SINGLE-NODE boot still presents a SELF-SIGNED cert (the dev posture, pinned)"
	lab_pending "b213.L6  [two-Mac harness] the same round trip against a JOINED WORKER — hack/lab/m3.sh at the M14.3 session, NOT provable on one Mac"
else
	LAB_ROOT="${K3SM_B213_LAB_ROOT:-/tmp/k3sm-b213}"
	LAB_BIN="$LAB_ROOT/k3sm"
	LAB_API_PORT=6457; LAB_KINE_PORT=2397; LAB_KUBELET_PORT=10267
	LAB_SCHED_PORT=11271; LAB_KCM_PORT=11269
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
		LAB_PID=""
	}
	trap lab_down EXIT INT TERM

	mkdir -p "$LAB_ROOT"
	if (cd "$K3SM_ROOT" && "${GOFLAGS_ENV[@]}" go build -o "$LAB_BIN" ./cmd/k3sm); then
		ladder ok "b213.L0  built the k3sm binary under test"
	else
		ladder no "b213.L0  built the k3sm binary under test"
	fi

	# lab_boot <workdir> <node-name> [extra flags...] — boots a control plane and
	# waits for healthz. The bin/ payload cache is preserved across boots (a fresh
	# download per posture would double a cold run for no added proof), while the
	# datastore and the PKI are removed: a work dir that once booted the OTHER
	# posture carries the other posture's CA, which is exactly the confusion these
	# rungs exist to detect.
	lab_boot() {
		local wd="$1" node="$2"; shift 2
		mkdir -p "$wd/bin"
		find "$wd" -mindepth 1 -maxdepth 1 ! -name bin -exec rm -rf {} + 2>/dev/null || true
		nohup env CGO_ENABLED=1 "$LAB_BIN" server \
			--work-dir "$wd" --node-name "$node" --node-ip 127.0.0.1 \
			--runtime hostprocess --network none --pod-root "$LAB_ROOT/pods" \
			--api-port "$LAB_API_PORT" --kine-port "$LAB_KINE_PORT" \
			--kubelet-port "$LAB_KUBELET_PORT" \
			--scheduler-port "$LAB_SCHED_PORT" --controller-manager-port "$LAB_KCM_PORT" \
			--ingress-http-port 0 --ingress-https-port 0 \
			"$@" > "$wd.log" 2>&1 &
		LAB_PID=$!
		# healthz alone is NOT the readiness this gate needs, for two reasons the
		# m14-servermesh gate learned the hard way. A `k3sm server` that dies
		# mid-bring-up can leave an apiserver child answering "ok" — a healthz-only
		# wait reports a healthy cluster over a corpse — and the in-process node's
		# :10250 listener comes up several steps AFTER healthz, so probing the
		# certificate at healthz races bring-up and reads nothing.
		local kc="$wd/bin/kubectl" n=0 healthy=no
		while [ "$n" -lt 200 ]; do
			kill -0 "$LAB_PID" 2>/dev/null || return 1
			if [ -x "$kc" ] && [ "$("$kc" --kubeconfig "$wd/k3sm.kubeconfig" get --raw /healthz 2>/dev/null)" = ok ]; then
				healthy=ok; break
			fi
			sleep 3; n=$((n+1))
		done
		[ "$healthy" = ok ] || return 1
		n=0
		while [ "$n" -lt 100 ]; do
			kill -0 "$LAB_PID" 2>/dev/null || return 1
			if [ "$("$kc" --kubeconfig "$wd/k3sm.kubeconfig" get node "$node" -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}' 2>/dev/null)" = "True" ] &&
				nc -z 127.0.0.1 "$LAB_KUBELET_PORT" 2>/dev/null; then
				return 0
			fi
			sleep 3; n=$((n+1))
		done
		return 1
	}

	# presented_leaf <outfile> — the certificate :10250 actually sends. openssl's
	# handshake FAILS here by design (B176 requires a client cert this gate does not
	# hold), and that is irrelevant: the server certificate is sent before client
	# auth completes, so the chain is on the wire either way.
	presented_leaf() {
		local n=0
		while [ "$n" -lt 10 ]; do
			kill -0 "$LAB_PID" 2>/dev/null || return 1
			openssl s_client -connect "127.0.0.1:$LAB_KUBELET_PORT" -showcerts </dev/null 2>/dev/null \
				| openssl x509 -outform pem > "$1" 2>/dev/null || true
			[ -s "$1" ] && return 0
			sleep 2; n=$((n+1))
		done
		return 1
	}

	if [ "$FAIL" -eq 0 ]; then
		MESH_WD="$LAB_ROOT/mesh"
		echo "----------------------------------------"
		echo "B213 LAB tier: booting a MESH-PATH control plane (mutates this Mac's :$LAB_API_PORT/:$LAB_KINE_PORT/:$LAB_KUBELET_PORT listeners)"
		if lab_boot "$MESH_WD" b213mesh --mesh-ip 127.0.0.1; then
			ladder ok "b213.L1  \`k3sm server --mesh-ip 127.0.0.1 --network none\` reached healthz and registered a Ready node serving :$LAB_KUBELET_PORT"
		else
			tail -25 "$MESH_WD.log" >&2
			ladder no "b213.L1  \`k3sm server --mesh-ip 127.0.0.1 --network none\` reached healthz and registered a Ready node serving :$LAB_KUBELET_PORT"
		fi

		LEAF="$LAB_ROOT/kubelet-leaf.pem"
		CLUSTER_CA="$MESH_WD/tls/cluster-ca.crt"
		if [ -n "$LAB_PID" ] && presented_leaf "$LEAF" && [ -s "$CLUSTER_CA" ]; then
			if openssl verify -CAfile "$CLUSTER_CA" "$LEAF" >/dev/null 2>&1; then
				ladder ok "b213.L2  the cert :10250 presents VERIFIES against $CLUSTER_CA"
			else
				ladder no "b213.L2  the cert :10250 presents VERIFIES against $CLUSTER_CA — $(openssl verify -CAfile "$CLUSTER_CA" "$LEAF" 2>&1 | tail -1)"
			fi
			# The address the node told the apiserver to dial. The apiserver runs
			# --kubelet-preferred-address-types=InternalIP, so a SAN that misses it is
			# the same broken logs/exec with a different error string.
			KC="$MESH_WD/bin/kubectl"
			internal="$("$KC" --kubeconfig "$MESH_WD/k3sm.kubeconfig" get node b213mesh -o jsonpath='{.status.addresses[?(@.type=="InternalIP")].address}' 2>/dev/null || true)"
			if [ -n "$internal" ] && openssl x509 -in "$LEAF" -noout -text | tr ',' '\n' | grep -qE "IP Address:${internal}\$"; then
				ladder ok "b213.L3  the presented leaf's SANs cover the registered InternalIP $internal"
			else
				ladder no "b213.L3  the presented leaf's SANs cover the registered InternalIP ${internal:-<unread>} — SANs: $(openssl x509 -in "$LEAF" -noout -ext subjectAltName 2>/dev/null | tail -1)"
			fi
		else
			ladder no "b213.L2  read the certificate :10250 presents (no leaf on the wire)"
			ladder no "b213.L3  the presented leaf's SANs cover the registered InternalIP"
		fi

		# L4 — the END-TO-END round trip, and the one rung that speaks the language of
		# the bug report: `kubectl logs` goes apiserver -> node :10250 over exactly the
		# TLS the rungs above inspect. It is a stronger statement than either of them,
		# because it is the apiserver's own verification rather than openssl's.
		if [ -n "$LAB_PID" ]; then
			KC="$MESH_WD/bin/kubectl"
			kcm() { "$KC" --kubeconfig "$MESH_WD/k3sm.kubeconfig" "$@"; }
			logs_out=""
			if kcm apply -f "$K3SM_ROOT/examples/hello-native.yaml" >/dev/null 2>&1; then
				n=0
				while [ "$n" -lt 45 ] && [ "$(kcm get pod hello-native -o jsonpath='{.status.phase}' 2>/dev/null)" != Running ]; do
					sleep 2; n=$((n+1))
				done
				logs_out="$(kcm logs hello-native 2>&1 | head -5)"
			fi
			case "$logs_out" in
			*"hello from a k3sm native pod"*)
				ladder ok "b213.L4  kubectl logs completed the apiserver->:10250 round trip on the mesh path" ;;
			*"unknown authority"*)
				ladder no "b213.L4  kubectl logs: $logs_out — this IS the B213 symptom; the node's serving cert does not chain to the CA the apiserver verifies against" ;;
			*)
				ladder no "b213.L4  kubectl logs completed the apiserver->:10250 round trip — got: ${logs_out:-<no output>}" ;;
			esac
			kcm delete pod hello-native --wait=false >/dev/null 2>&1 || true
		else
			ladder no "b213.L4  kubectl logs completed the apiserver->:10250 round trip (no live server)"
		fi
		lab_down

		# The dev posture, pinned. Without this rung the gate would still pass if the
		# fix had made EVERY node serve a cluster-CA cert, silently changing the
		# single-node path this item deliberately leaves alone.
		SOLO_WD="$LAB_ROOT/solo"
		echo "B213 LAB tier: booting a SINGLE-NODE control plane (the self-signed posture, pinned)"
		if lab_boot "$SOLO_WD" b213solo; then
			SOLO_LEAF="$LAB_ROOT/kubelet-leaf-solo.pem"
			if presented_leaf "$SOLO_LEAF" && ! openssl verify -CAfile "$MESH_WD/tls/cluster-ca.crt" "$SOLO_LEAF" >/dev/null 2>&1 &&
				[ "$(openssl x509 -in "$SOLO_LEAF" -noout -issuer)" = "$(openssl x509 -in "$SOLO_LEAF" -noout -subject | sed 's/^subject=/issuer=/')" ]; then
				ladder ok "b213.L5  the single-node boot still presents a SELF-SIGNED cert (the dev posture the apiserver does not verify)"
			else
				ladder no "b213.L5  the single-node boot still presents a SELF-SIGNED cert — issuer=$(openssl x509 -in "$SOLO_LEAF" -noout -issuer 2>/dev/null)"
			fi
		else
			tail -25 "$SOLO_WD.log" >&2
			ladder no "b213.L5  the single-node boot reached healthz and registered a Ready node"
		fi
		lab_down
	fi
	lab_pending "b213.L6  [two-Mac harness] the same round trip against a JOINED WORKER — the M14.3 session, NOT provable on one Mac"
fi

echo "----------------------------------------"
echo "B213: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ] || exit 1
if [ "${K3SM_LAB:-}" = 1 ]; then
	echo "================ B213 GREEN (CI + LAB tiers) ================"
else
	echo "================ B213 GREEN (CI tier; the lab rungs are owed) ================"
fi

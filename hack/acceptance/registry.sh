#!/usr/bin/env bash
#
# k3sm ingest-registry acceptance — the runnable proof that `k3sm server
# --registry-port <p>` serves a node-local OCI registry an operator can push a
# locally built image into and a Pod can pull it back out of.
#
# It exists because the whole point of the feature is a path no unit test can
# reach: a real registry process, a real push over HTTP, a real image pull by the
# node's runtime under `imagePullPolicy: Always`. A green unit suite proves the
# config renders and the credential hashes; only this gate proves an image got
# from a directory into a running Pod.
#
# TWO TIERS, split by what can be proven without a live cluster:
#
#   CI TIER (always runs, GOARCH=arm64 CGO_ENABLED=1 pinned) — the unit-provable
#   half: the loopback-bind refusal (a non-loopback bind is an ERROR, at both the
#   constructor and the config render), the config's anonymous-read /
#   authenticated-write access control, the credential contract `k3sm image push`
#   reads, the per-node cluster Service and its hand-written EndpointSlice
#   (mesh-else-gateway endpoint choice, and the loopback refusal that keeps the
#   registry's own listener out of the slice), and the KEP-1755 document's
#   three-field render.
#
#   LIVE TIER (needs $KUBECONFIG) — the registry actually serving: the KEP-1755
#   ConfigMap names a port something answers on, the credential file is where the
#   contract says at mode 600, an authenticated push succeeds, an unauthenticated
#   push is REFUSED, an anonymous pull succeeds, a native Pod naming
#   `localhost:<port>/<ref>` with `imagePullPolicy: Always` reaches Running, and
#   the node's registry Service answers the dist-spec probe at its VIP.
#
#   LAB TIER (human-run, K3SM_LAB) — the one leg neither tier above can reach: a
#   Linux-guest Pod pulling from `registry-<node>.k3sm-registry.svc:<port>`. It
#   needs a vm-capable Mac with a guest actually booted, so it is announced OWED
#   rather than skipped silently.
#
# Without $KUBECONFIG the live rungs are announced LIVE-PENDING and never fail —
# and the summary says so in as many words, so an exit 0 from a CI-tier-only run
# cannot be misread as "the registry works".
#
# The GOARCH=arm64 pin is a CORRECTNESS requirement, not hygiene: a Mac's Go
# toolchain may itself be x86_64-under-Rosetta, and an unpinned build produces an
# x86_64 binary this arm64-only product cannot run.
#
# Usage:
#   hack/acceptance/registry.sh                       # CI tier only
#   KUBECONFIG=/path/to/kubeconfig \
#     hack/acceptance/registry.sh                     # + the live tier
#
# Environment:
#   KUBECONFIG          a cluster started with --registry-port <p> (enables the live tier)
#   K3SM_REGISTRY_PORT  override the port instead of reading it from KEP-1755
#   K3SM_WORK_DIR       the control-plane work dir holding the push credential
#   K3SM_CLUSTER_DOMAIN the cluster DNS suffix (default cluster.local)
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
K3SM_ROOT="$(cd "$HERE/../.." && pwd)"
SELF="$HERE/registry.sh"

PASS=0; FAIL=0; PENDING=0
ladder() { if [ "$1" = ok ]; then echo "PASS  $2"; PASS=$((PASS+1)); else echo "FAIL  $2"; FAIL=$((FAIL+1)); fi; }
pending() { echo "PEND  $1"; PENDING=$((PENDING+1)); }

echo "==> k3sm ingest-registry acceptance"

# ---- registry.0 — the gate parses and its sources exist --------------------
b0=ok
[ -f "$SELF" ] && bash -n "$SELF" || b0=no
[ -d "$K3SM_ROOT/pkg/registrysvc" ] || b0=no
[ -f "$K3SM_ROOT/cmd/k3sm/registry.go" ] || b0=no
ladder "$b0" "registry.0  gate parses (bash -n) + pkg/registrysvc and the server wiring are present"
if [ "$b0" != ok ]; then
	echo "----------------------------------------"
	echo "registry: the gate or its sources are missing/unparseable — nothing else can run" >&2
	echo "registry: $PASS passed, $FAIL failed" >&2
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

# ---- registry.1 — the loopback-bind refusal (the security posture) ---------
# Pull is anonymous and push is plain HTTP, so the whole posture rests on nothing
# off-host reaching the listener. Both the constructor and the config render must
# refuse a non-loopback address; either one alone would be defeated by the other.
run_test "registry.1a" 9 TestNewBindDiscipline ./pkg/registrysvc/
run_test "registry.1b" 5 TestRenderConfigRefusesNonLoopback ./pkg/registrysvc/

# ---- registry.2 — the rendered config's access control ---------------------
run_test "registry.2" 3 TestRenderConfigShape ./pkg/registrysvc/

# ---- registry.3 — the credential contract `k3sm image push` reads ----------
run_test "registry.3a" 4 TestWriteCredential ./pkg/registrysvc/
run_test "registry.3b" 7 TestLocalRegistryAuthTargeting ./cmd/k3sm/
run_test "registry.3c" 3 TestRegistryAuthChainOrder ./cmd/k3sm/

# ---- registry.4 — the wiring: default-off, dev-on, never fatal -------------
run_test "registry.4a" 3 TestStartIngestRegistry ./cmd/k3sm/
run_test "registry.4b" 2 TestDevEnablesTheIngestRegistry ./pkg/dev/

# ---- registry.11 — the per-node cluster Service (CI half) -----------------
# The ONE cluster address a native Pod, a vm guest and the host all reach this
# node's registry at. The endpoint is the RELAY's address, never the registry's
# own loopback listener — EndpointSlice validation refuses a loopback address at
# the apiserver, and the renderer refuses it here, where the reason can be named.
run_test "registry.11a" 9 TestClusterEndpointAddress ./pkg/registrysvc/
run_test "registry.11b" 3 TestClusterService ./pkg/registrysvc/
run_test "registry.11c" 4 TestClusterEndpointSlice ./pkg/registrysvc/
run_test "registry.11d" 8 TestPublishClusterService ./pkg/registrysvc/
run_test "registry.11e" 4 TestRemoveClusterService ./pkg/registrysvc/
# The spellings runtimed must treat as naming THIS node's own registry, so a Pod
# that pulls by the Service name gets the same brokering as one that pulls by
# localhost.
run_test "registry.11f" 4 TestClusterLocalAuthorities ./pkg/registrysvc/
# The KEP-1755 document in both shapes: three addresses on a node that has a
# cluster Service, two on a node that has no relay at all.
run_test "registry.11g" 3 TestHostingDocument ./pkg/registrysvc/

# ---- LIVE TIER ------------------------------------------------------------
if [ -z "${KUBECONFIG:-}" ]; then
	pending "registry.5  live: KEP-1755 discovery names a serving port          (set KUBECONFIG)"
	pending "registry.6  live: the push credential is at the documented path    (set KUBECONFIG)"
	pending "registry.7  live: an authenticated push succeeds                   (set KUBECONFIG)"
	pending "registry.8  live: an unauthenticated push is refused               (set KUBECONFIG)"
	pending "registry.9  live: an anonymous pull succeeds                       (set KUBECONFIG)"
	pending "registry.10 live: a Pod pulls localhost:<p>/probe:t and runs       (set KUBECONFIG)"
	pending "registry.12 live: the per-node registry Service + EndpointSlice exist (set KUBECONFIG)"
	pending "registry.13 live: the Service VIP answers the dist-spec /v2/ probe  (set KUBECONFIG)"
	pending "registry.14 lab:  a vm-guest Pod pulls by the Service name          (OWED — human-run)"
	echo "----------------------------------------"
	echo "registry: $PASS passed, $FAIL failed, $PENDING LIVE-PENDING"
	[ "$FAIL" -eq 0 ] || exit 1
	echo "registry: CI TIER GREEN — the LIVE tier did NOT run, so this exit 0 does NOT mean the registry serves."
	echo "          Start a cluster with --registry-port and re-run with KUBECONFIG set."
	exit 0
fi

command -v kubectl >/dev/null || { echo "kubectl is required for the live tier" >&2; exit 1; }
command -v curl >/dev/null || { echo "curl is required for the live tier" >&2; exit 1; }
kubectl get --raw /healthz >/dev/null || { echo "the cluster at \$KUBECONFIG is not serving" >&2; exit 1; }

NS=default
# The cluster DNS suffix the Service authority is rendered with. It matches the
# server's --cluster-domain; override when a cluster was started with a custom one.
CLUSTER_DOMAIN="${K3SM_CLUSTER_DOMAIN:-cluster.local}"
TMP="$(mktemp -d)"
cleanup() {
	kubectl delete pod registry-probe -n "$NS" --ignore-not-found --wait=false >/dev/null 2>&1 || true
	rm -rf "$TMP"
}
trap cleanup EXIT

# ---- registry.5 — KEP-1755 discovery names a port something answers on -----
# The ConfigMap is how a tool is supposed to find the registry, so the gate finds
# it that way too: reading the port from the cluster is itself the assertion that
# discovery works, and a hand-set K3SM_REGISTRY_PORT is only the escape hatch.
HOSTING="$(kubectl get configmap local-registry-hosting -n kube-public \
	-o jsonpath='{.data.localRegistryHosting\.v1}' 2>/dev/null || true)"
PORT="${K3SM_REGISTRY_PORT:-}"
if [ -z "$PORT" ]; then
	PORT="$(printf '%s\n' "$HOSTING" | sed -n 's/^host:[[:space:]]*"\{0,1\}localhost:\([0-9]\{1,\}\)"\{0,1\}[[:space:]]*$/\1/p' | head -1)"
fi
if [ -z "$PORT" ]; then
	ladder no "registry.5a KEP-1755 local-registry-hosting in kube-public names a port (got: ${HOSTING:-absent})"
	echo "----------------------------------------"
	echo "registry: the cluster publishes no registry address — was it started with --registry-port? ($PASS passed, $((FAIL)) failed)" >&2
	exit 1
fi
ladder ok "registry.5a KEP-1755 local-registry-hosting in kube-public names localhost:$PORT"

# The per-node registry Service is the ground truth for the in-cluster address:
# it exists exactly on a node that has a relay to answer it (a mesh address, or a
# vm network). hostFromClusterNetwork must agree with it in BOTH directions — a
# published address with no Service sends every reader at a name that resolves to
# nothing, and a Service nobody is told about is a name nobody uses.
SVC_NS=k3sm-registry
SVC_NAME="$(kubectl get svc -n "$SVC_NS" \
	-o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}' 2>/dev/null | grep '^registry-' | head -1 || true)"
HFCN="$(printf '%s\n' "$HOSTING" | sed -n 's/^hostFromClusterNetwork:[[:space:]]*"\{0,1\}\([^"[:space:]]*\)"\{0,1\}[[:space:]]*$/\1/p' | head -1)"
if [ -n "$SVC_NAME" ]; then
	if [ "$HFCN" = "$SVC_NAME.$SVC_NS.svc.$CLUSTER_DOMAIN:$PORT" ]; then
		ladder ok "registry.5b KEP-1755 hostFromClusterNetwork names the node's registry Service ($HFCN)"
	else
		ladder no "registry.5b KEP-1755 hostFromClusterNetwork names the node's registry Service (got '${HFCN:-absent}', want $SVC_NAME.$SVC_NS.svc.$CLUSTER_DOMAIN:$PORT)"
	fi
elif [ -z "$HFCN" ]; then
	ladder ok "registry.5b KEP-1755 omits hostFromClusterNetwork on a node with no registry Service to answer it"
else
	ladder no "registry.5b KEP-1755 publishes hostFromClusterNetwork '$HFCN' with no registry Service in $SVC_NS to answer it"
fi
if [ "$(curl -s -o /dev/null -w '%{http_code}' -m 10 "http://127.0.0.1:$PORT/v2/" || true)" = "200" ]; then
	ladder ok "registry.5c the published port answers the dist-spec /v2/ probe"
else
	ladder no "registry.5c the published port answers the dist-spec /v2/ probe"
fi

# ---- registry.6 — the credential is where the contract says ---------------
WORK_DIR="${K3SM_WORK_DIR:-}"
if [ -z "$WORK_DIR" ]; then
	for cand in "/var/lib/k3sm/server" "$HOME/.k3sm/server"; do
		[ -f "$cand/registry/push-credential.json" ] && { WORK_DIR="$cand"; break; }
	done
fi
CRED="$WORK_DIR/registry/push-credential.json"
if [ -n "$WORK_DIR" ] && [ -f "$CRED" ]; then
	ladder ok "registry.6a the push credential is at <work-dir>/registry/push-credential.json"
	MODE="$(stat -f '%Lp' "$CRED" 2>/dev/null || stat -c '%a' "$CRED" 2>/dev/null || echo '?')"
	if [ "$MODE" = "600" ]; then
		ladder ok "registry.6b the push credential is mode 600"
	else
		ladder no "registry.6b the push credential is mode 600 (got $MODE) — a readable credential is a writable image store"
	fi
else
	ladder no "registry.6a the push credential is at <work-dir>/registry/push-credential.json (set K3SM_WORK_DIR; looked in '${WORK_DIR:-/var/lib/k3sm/server}')"
	ladder no "registry.6b the push credential is mode 600 (no credential file to check)"
fi

# ---- build the probe image and the k3sm binary that pushes it -------------
K3SM_BIN="$TMP/k3sm"
(cd "$K3SM_ROOT" && "${GOFLAGS_ENV[@]}" go build -o "$K3SM_BIN" ./cmd/k3sm) \
	|| { echo "could not build k3sm for the live tier" >&2; exit 1; }
CTX="$TMP/ctx"
mkdir -p "$CTX"
(cd "$K3SM_ROOT" && env GOARCH=arm64 CGO_ENABLED=0 go build -o "$CTX/hello-http" ./e2e/testdata/cmd/hello-http) \
	|| { echo "could not build the hello-http fixture" >&2; exit 1; }
cat > "$CTX/Dockerfile" <<'DOCKEREOF'
FROM scratch
COPY hello-http /bin/hello-http
ENTRYPOINT ["/bin/hello-http", "--id", "registry-probe", "--addr", ":8080"]
DOCKEREOF
LAYOUT="$TMP/layout"
if (cd "$CTX" && "$K3SM_BIN" build --tag "localhost:$PORT/probe:t" --format oci --output "$LAYOUT" .) >/dev/null 2>&1; then
	ladder ok "registry.7a  k3sm build --format oci produced a probe layout"
else
	ladder no "registry.7a  k3sm build --format oci produced a probe layout"
fi

# ---- registry.7 — an authenticated push succeeds --------------------------
# No credential is passed: push must FIND this node's own, which is the wiring
# under test. K3SM_REGISTRY_TOKEN is cleared so an ambient one cannot mask it.
PUSH_OUT="$TMP/push.out"
if env -u K3SM_REGISTRY_TOKEN "$K3SM_BIN" image push --work-dir "${WORK_DIR:-/var/lib/k3sm/server}" \
	"$LAYOUT" "localhost:$PORT/probe:t" >"$PUSH_OUT" 2>&1; then
	ladder ok "registry.7b  k3sm image push authenticated with the node's own credential"
else
	tail -10 "$PUSH_OUT"
	ladder no "registry.7b  k3sm image push authenticated with the node's own credential"
fi

# ---- registry.8 — an unauthenticated push is REFUSED ----------------------
# A blob-upload POST is the first write the dist-spec push does, so a 401 here is
# the registry refusing the write, not a route that happens not to exist.
ANON_CODE="$(curl -s -o /dev/null -w '%{http_code}' -m 10 -X POST \
	"http://127.0.0.1:$PORT/v2/registry-anon-probe/blobs/uploads/" || true)"
if [ "$ANON_CODE" = "401" ]; then
	ladder ok "registry.8  an unauthenticated push is refused 401"
else
	ladder no "registry.8  an unauthenticated push is refused 401 (got HTTP ${ANON_CODE:-none}) — anyone on this host could write an image the cluster runs"
fi

# ---- registry.9 — an anonymous pull SUCCEEDS ------------------------------
# The mirror image of rung 8, and just as load bearing: the node's runtime pulls
# with no credential, so a registry that authenticated reads would break the pull
# it exists to serve.
PULL_CODE="$(curl -s -o /dev/null -w '%{http_code}' -m 10 \
	-H 'Accept: application/vnd.oci.image.manifest.v1+json' \
	"http://127.0.0.1:$PORT/v2/probe/manifests/t" || true)"
if [ "$PULL_CODE" = "200" ]; then
	ladder ok "registry.9  an anonymous pull of the pushed manifest succeeds"
else
	ladder no "registry.9  an anonymous pull of the pushed manifest succeeds (got HTTP ${PULL_CODE:-none})"
fi

# ---- registry.10 — a Pod pulls the pushed image and runs ------------------
# imagePullPolicy: Always is the point of the whole feature. It forces the node's
# runtime through a real registry pull on every start, which is exactly the
# kubelet semantic `k3sm image load` cannot exercise.
kubectl delete pod registry-probe -n "$NS" --ignore-not-found --wait=true >/dev/null 2>&1 || true
kubectl apply -f - >/dev/null <<PODEOF
apiVersion: v1
kind: Pod
metadata:
  name: registry-probe
  namespace: $NS
spec:
  nodeSelector: {kubernetes.io/os: darwin}
  tolerations: [{operator: Exists}]
  restartPolicy: Never
  containers:
  - name: probe
    image: localhost:$PORT/probe:t
    imagePullPolicy: Always
    ports: [{containerPort: 8080}]
PODEOF
if kubectl wait --for=condition=Ready pod/registry-probe -n "$NS" --timeout=180s >/dev/null 2>&1; then
	ladder ok "registry.10 a Pod pulled localhost:$PORT/probe:t (imagePullPolicy: Always) and reached Ready"
else
	echo "--- pod status ---"
	kubectl get pod registry-probe -n "$NS" -o wide 2>&1 | tail -5 || true
	kubectl describe pod registry-probe -n "$NS" 2>&1 | tail -25 || true
	ladder no "registry.10 a Pod pulled localhost:$PORT/probe:t (imagePullPolicy: Always) and reached Ready"
fi

# ---- registry.12 — the per-node Service and its hand-written EndpointSlice --
# A selector-less Service plus a slice written by k3sm: there is no Pod to select,
# because the registry is a child process reached through the relay. The endpoint
# must be NON-LOOPBACK — 127.0.0.1 is every caller's own address, and the
# apiserver refuses one in a slice anyway, so a loopback value here would mean the
# object never landed.
if [ -z "$SVC_NAME" ]; then
	pending "registry.12 the per-node registry Service exists (this node has no mesh address and no vm network)"
	pending "registry.13 the Service VIP answers /v2/ (no Service to dial)"
else
	SVC_IP="$(kubectl get svc "$SVC_NAME" -n "$SVC_NS" -o jsonpath='{.spec.clusterIP}' 2>/dev/null || true)"
	SVC_SEL="$(kubectl get svc "$SVC_NAME" -n "$SVC_NS" -o jsonpath='{.spec.selector}' 2>/dev/null || true)"
	SVC_PORT="$(kubectl get svc "$SVC_NAME" -n "$SVC_NS" -o jsonpath='{.spec.ports[0].port}' 2>/dev/null || true)"
	EP_ADDR="$(kubectl get endpointslice "$SVC_NAME" -n "$SVC_NS" -o jsonpath='{.endpoints[0].addresses[0]}' 2>/dev/null || true)"
	EP_READY="$(kubectl get endpointslice "$SVC_NAME" -n "$SVC_NS" -o jsonpath='{.endpoints[0].conditions.ready}' 2>/dev/null || true)"
	if [ -n "$SVC_IP" ] && [ "$SVC_IP" != "None" ] && [ "$SVC_PORT" = "$PORT" ] && [ -z "$SVC_SEL" ]; then
		ladder ok "registry.12a $SVC_NS/$SVC_NAME is a selector-less ClusterIP Service on port $PORT (VIP $SVC_IP)"
	else
		ladder no "registry.12a $SVC_NS/$SVC_NAME is a selector-less ClusterIP Service on port $PORT (clusterIP='${SVC_IP:-none}' port='${SVC_PORT:-none}' selector='${SVC_SEL:-none}')"
	fi
	case "${EP_ADDR:-none}" in
	none | 127.* | ::1) ladder no "registry.12b the EndpointSlice carries a NON-loopback endpoint (got '${EP_ADDR:-absent}') — the Service would have a VIP and no reachable backend" ;;
	*) ladder ok "registry.12b the EndpointSlice carries the relay address $EP_ADDR, not the registry's loopback listener" ;;
	esac
	if [ "$EP_READY" = "true" ]; then
		ladder ok "registry.12c the endpoint is explicitly Ready"
	else
		ladder no "registry.12c the endpoint is explicitly Ready (got '${EP_READY:-absent}') — a nil Ready reads as not-ready and the Service has no backend"
	fi

	# ---- registry.13 — the VIP actually answers -------------------------------
	# The host reaches a VIP through its lo0 alias, and the userspace proxy dials
	# the backend host-side — so a 200 here proves the whole chain the in-pod
	# address depends on: name -> VIP -> proxy -> relay -> loopback registry.
	VIP_CODE="$(curl -s -o /dev/null -w '%{http_code}' -m 10 "http://$SVC_IP:$PORT/v2/" || true)"
	if [ "$VIP_CODE" = "200" ]; then
		ladder ok "registry.13 the registry Service VIP answers the dist-spec /v2/ probe (http://$SVC_IP:$PORT)"
	else
		ladder no "registry.13 the registry Service VIP answers the dist-spec /v2/ probe (http://$SVC_IP:$PORT, got HTTP ${VIP_CODE:-none})"
	fi
fi

# ---- registry.14 — the vm-guest leg (LAB, human-run) -----------------------
# Neither tier above can reach it: it needs a vm-capable Mac with a guest booted,
# pulling by the Service name over plain HTTP. Announced OWED so an exit 0 here is
# never read as covering it.
pending "registry.14 lab: a vm-guest Pod pulls $SVC_NAME.$SVC_NS.svc:$PORT over plain HTTP (OWED — human-run)"

echo "----------------------------------------"
echo "registry: $PASS passed, $FAIL failed, $PENDING pending"
[ "$FAIL" -eq 0 ] || exit 1
echo "registry: the LAB rung above is OWED — the vm-guest pull by Service name is human-run."
echo "=========== INGEST REGISTRY GREEN ==========="

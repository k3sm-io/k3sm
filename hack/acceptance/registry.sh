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
#   reads, and the KEP-1755 document's deliberately absent hostFromClusterNetwork.
#
#   LIVE TIER (needs $KUBECONFIG) — the registry actually serving: the KEP-1755
#   ConfigMap names a port something answers on, the credential file is where the
#   contract says at mode 600, an authenticated push succeeds, an unauthenticated
#   push is REFUSED, an anonymous pull succeeds, and a native Pod naming
#   `localhost:<port>/<ref>` with `imagePullPolicy: Always` reaches Running.
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

# ---- LIVE TIER ------------------------------------------------------------
if [ -z "${KUBECONFIG:-}" ]; then
	pending "registry.5  live: KEP-1755 discovery names a serving port          (set KUBECONFIG)"
	pending "registry.6  live: the push credential is at the documented path    (set KUBECONFIG)"
	pending "registry.7  live: an authenticated push succeeds                   (set KUBECONFIG)"
	pending "registry.8  live: an unauthenticated push is refused               (set KUBECONFIG)"
	pending "registry.9  live: an anonymous pull succeeds                       (set KUBECONFIG)"
	pending "registry.10 live: a Pod pulls localhost:<p>/probe:t and runs       (set KUBECONFIG)"
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
# hostFromClusterNetwork must be ABSENT: a vm Pod is a Linux guest with its own
# loopback, so any value there would tell a guest to pull from itself.
if printf '%s\n' "$HOSTING" | grep -q 'hostFromClusterNetwork'; then
	ladder no "registry.5b KEP-1755 document omits hostFromClusterNetwork (a vm guest's loopback answers nothing)"
else
	ladder ok "registry.5b KEP-1755 document omits hostFromClusterNetwork (a vm guest's loopback answers nothing)"
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

echo "----------------------------------------"
echo "registry: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ] || exit 1
echo "=========== INGEST REGISTRY GREEN ==========="

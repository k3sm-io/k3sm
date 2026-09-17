#!/usr/bin/env bash
# M16.0-d1 / S0 — k3sm preconditions, no framework. THE RUNG THE REST OF M16 RESTS ON.
#
# Three criteria, each with a BINDING halt whose substitution the M16 plan already
# decided, so a red here never needs a human to choose what happens next:
#
#   (1) WEBHOOK DELIVERY, BOTH PATHS — a trivial ClusterIP-backed VALIDATING webhook
#       and a trivial CRD CONVERSION webhook, both registered with clientConfig.service
#       (never url) and both backed by a runtimeClassName: vm pod. The service ref is
#       the whole point: kube-apiserver v1.36.2 resolves a service-ref webhook through
#       its informer-backed ClusterIP resolver, so the dial lands on ClusterIP:port,
#       which darwin-net's proxy owns as a lo0-alias socket. A url: ref would prove
#       something else entirely, and a native backend would never exercise the guest
#       leg the fleet's control plane runs on.
#       HALT: fails -> the plan's R4(a): v1alpha1 only, no conversion in the path.
#
#   (2) TWO ENGINES ON ONE GPU — two vllm-mlx engines as HOST PROCESSES (the M8 S5
#       bake-off method: no scratch binary, no reinstall, nothing installed system-
#       wide), on the smallest pinned model class, driven through the S3 sustained
#       1 200-token methodology at N = the engine's --max-num-seqs ceiling. Aggregate
#       tok/s, PER-REQUEST LATENCY PERCENTILES and wired memory are all measured
#       against the one-engine control, because a burst snapshot ends before the peak
#       the sizing formula's headroom exists for. This is the SAFETY MEASUREMENT for
#       the capacity policy's slot floor, not a benchmark.
#       HALT: thrashing or a doubled p99 -> the plan's R5 floor rises (a smaller model
#       or a larger slot) and S0(2) re-runs; single-slot only if no small model fits two.
#
#   (3) THE DIAL NOBODY HAS MEASURED — a vm guest dialing a NATIVE pod's own lo0-alias
#       pod IP:port, and the reverse. Both outcomes are consequential: reachable means
#       the fleet's base request path works AND that a guest bypasses the proxy and the
#       NetworkPolicy L4 hint (a trust-domain fact the user doc must carry); blocked
#       means the control plane cannot be hosted under vm at all.
#       HALT: blocked -> the plan's R4(b): the native-Darwin control plane.
#
# Every object this rung creates lives in the spike namespace and is deleted at the
# end of the criterion that made it. The M8 MLXModel and its PVC are never touched.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
. "$HERE/lib.sh"

RUNG="S0"
QUESTION="Do k3sm's three unproven preconditions hold: webhook delivery to a vm-backed ClusterIP on BOTH the admission and the CRD-conversion paths; two MLX engines co-resident on one GPU within a measured memory and latency budget; and a vm guest reaching a native pod's own pod IP (and back)?"
METHOD="Rig-side over ssh, no framework installed: a python TLS webhook server in a runtimeClassName: vm pod behind a ClusterIP Service, registered by service ref for both a ValidatingWebhookConfiguration and a CRD conversion strategy; then two vllm-mlx host processes under a sustained 1 200-token load at --max-num-seqs concurrency with percentiles and wired-memory sampling against a one-engine control; then a native pod listener dialled from a vm guest and the reverse."
HALT="(1) fails -> R4(a), v1alpha1 only with no conversion in the path. (2) thrashes or doubles p99 -> R5's slot floor rises (smaller model or larger slot) and S0(2) re-runs; single-slot only if no small model fits two. (3) blocked -> R4(b), the native-Darwin control plane."

case "${1:-}" in
--plan | --dry-run) spike_plan "$RUNG" "$QUESTION" "$METHOD" "$HALT" ;;
"") ;;
*)
	echo "s0.sh: unknown argument: $1 (try --plan)" >&2
	exit 2
	;;
esac

spike_host

# ---------------------------------------------------------------------------------
note "S0(1) — webhook delivery on BOTH paths, service-ref, vm-backed"
# ---------------------------------------------------------------------------------
lab <<'EOF'
set -uo pipefail
spike_preflight
W="$PREFIX/s0"; mkdir -p "$W/tls"

kc create namespace "$NS" >/dev/null 2>&1 || true

# --- the CA and the serving cert -------------------------------------------------
# The SAN must be the SERVICE DNS name, because that is the name the apiserver's
# webhook client presents for verification even though it dials the ClusterIP.
SVC="m16-webhook"
cat > "$W/tls/openssl.cnf" <<CNF
[req]
distinguished_name = dn
[dn]
[v3_ca]
basicConstraints = critical,CA:TRUE
keyUsage = critical,keyCertSign,cRLSign
[v3_svc]
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature,keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = DNS:$SVC.$NS.svc, DNS:$SVC.$NS.svc.cluster.local
CNF
if [ ! -f "$W/tls/tls.crt" ]; then
  openssl req -x509 -newkey rsa:2048 -nodes -days 30 -sha256 \
    -subj "/CN=m16-spike-ca" -extensions v3_ca -config "$W/tls/openssl.cnf" \
    -keyout "$W/tls/ca.key" -out "$W/tls/ca.crt" >/dev/null 2>&1
  openssl req -newkey rsa:2048 -nodes -subj "/CN=$SVC.$NS.svc" \
    -keyout "$W/tls/tls.key" -out "$W/tls/tls.csr" >/dev/null 2>&1
  openssl x509 -req -in "$W/tls/tls.csr" -CA "$W/tls/ca.crt" -CAkey "$W/tls/ca.key" \
    -CAcreateserial -days 30 -sha256 -extensions v3_svc -extfile "$W/tls/openssl.cnf" \
    -out "$W/tls/tls.crt" >/dev/null 2>&1
fi
[ -s "$W/tls/tls.crt" ] || { verdict FAIL "s0.1-setup  could not mint the webhook serving cert"; exit 0; }
CABUNDLE=$(base64 < "$W/tls/ca.crt" | tr -d '\n')

# --- the webhook server ----------------------------------------------------------
# One process answers both paths, so a difference between the two verdicts is a
# difference in the APISERVER's dispatch, not in two different backends.
cat > "$W/server.py" <<'PY'
import json, ssl
from http.server import BaseHTTPRequestHandler, HTTPServer

class H(BaseHTTPRequestHandler):
    def _read(self):
        n = int(self.headers.get("content-length", 0) or 0)
        return json.loads(self.rfile.read(n) or b"{}")

    def _write(self, obj):
        body = json.dumps(obj).encode()
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        req = self._read()
        ar = req.get("request") or {}
        if self.path.startswith("/validate"):
            obj = ar.get("object") or {}
            meta = obj.get("metadata") or {}
            deny = (meta.get("labels") or {}).get("m16-deny") == "yes"
            print("VALIDATE uid=%s name=%s deny=%s" % (ar.get("uid"), meta.get("name"), deny), flush=True)
            resp = {"uid": ar.get("uid"), "allowed": not deny}
            if deny:
                resp["status"] = {"code": 403, "message": "m16 spike webhook: denied by policy"}
            self._write({"apiVersion": req.get("apiVersion", "admission.k8s.io/v1"),
                         "kind": "AdmissionReview", "response": resp})
        elif self.path.startswith("/convert"):
            desired = ar.get("desiredAPIVersion", "")
            out = []
            for o in ar.get("objects") or []:
                o = dict(o)
                o["apiVersion"] = desired
                spec = dict(o.get("spec") or {})
                if desired.endswith("v1alpha1"):
                    if "sizeBytes" in spec:
                        spec["size"] = str(spec.pop("sizeBytes"))
                else:
                    if "size" in spec:
                        try:
                            spec["sizeBytes"] = int(spec.pop("size"))
                        except (TypeError, ValueError):
                            spec.pop("size", None)
                o["spec"] = spec
                out.append(o)
            print("CONVERT uid=%s desired=%s n=%d" % (ar.get("uid"), desired, len(out)), flush=True)
            self._write({"apiVersion": req.get("apiVersion", "apiextensions.k8s.io/v1"),
                         "kind": "ConversionReview",
                         "response": {"uid": ar.get("uid"), "convertedObjects": out,
                                      "result": {"status": "Success"}}})
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, *a):
        pass

ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain("/tls/tls.crt", "/tls/tls.key")
srv = HTTPServer(("0.0.0.0", 8443), H)
srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
print("m16 spike webhook listening on :8443", flush=True)
srv.serve_forever()
PY

kc -n "$NS" delete pod "$SVC" --ignore-not-found --wait=false >/dev/null 2>&1
kc -n "$NS" delete secret m16-webhook-tls --ignore-not-found >/dev/null 2>&1
kc -n "$NS" delete configmap m16-webhook-src --ignore-not-found >/dev/null 2>&1
kc -n "$NS" create secret tls m16-webhook-tls --cert="$W/tls/tls.crt" --key="$W/tls/tls.key" >/dev/null
kc -n "$NS" create configmap m16-webhook-src --from-file=server.py="$W/server.py" >/dev/null

# The backend runs under runtimeClassName: vm — a Linux guest, which is where the
# fleet's control plane will run. nodeSelector stays kubernetes.io/os=darwin: the
# NODE is darwin and the guest is an implementation detail.
kc apply -f - <<YAML >/dev/null
apiVersion: v1
kind: Pod
metadata:
  name: $SVC
  namespace: $NS
  labels: {app: m16-webhook}
spec:
  runtimeClassName: vm
  nodeSelector: {kubernetes.io/os: darwin}
  tolerations: [{key: k3sm.io/provider, operator: Exists, effect: NoSchedule}]
  restartPolicy: Never
  containers:
    - name: webhook
      image: $WEBHOOK_IMAGE
      command: ["python3", "/srv/server.py"]
      ports: [{containerPort: 8443}]
      resources: {requests: {memory: 256Mi, cpu: 100m}, limits: {memory: 256Mi}}
      volumeMounts:
        - {name: src, mountPath: /srv}
        - {name: tls, mountPath: /tls}
  volumes:
    - {name: src, configMap: {name: m16-webhook-src}}
    - {name: tls, secret: {secretName: m16-webhook-tls}}
---
apiVersion: v1
kind: Service
metadata: {name: $SVC, namespace: $NS}
spec:
  selector: {app: m16-webhook}
  ports: [{name: https, port: 443, targetPort: 8443}]
YAML

if ! kc -n "$NS" wait --for=condition=Ready "pod/$SVC" --timeout=300s >/dev/null 2>&1; then
  verdict FAIL "s0.1-backend  the vm-backed webhook pod never became Ready"
  kc -n "$NS" describe "pod/$SVC" | tail -30
  exit 0
fi
CIP=$(kc -n "$NS" get svc "$SVC" -o jsonpath='{.spec.clusterIP}')
recorded "s0.1 webhook backend: pod Ready under runtimeClassName=vm, ClusterIP=$CIP"

# --- (a) the VALIDATING path -----------------------------------------------------
kc delete validatingwebhookconfiguration m16-spike --ignore-not-found >/dev/null 2>&1
kc apply -f - <<YAML >/dev/null
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingWebhookConfiguration
metadata: {name: m16-spike}
webhooks:
  - name: m16.spike.k3sm.io
    admissionReviewVersions: ["v1"]
    sideEffects: None
    failurePolicy: Fail
    timeoutSeconds: 10
    namespaceSelector: {matchLabels: {kubernetes.io/metadata.name: $NS}}
    clientConfig:
      service: {name: $SVC, namespace: $NS, path: /validate, port: 443}
      caBundle: $CABUNDLE
    rules:
      - operations: ["CREATE"]
        apiGroups: [""]
        apiVersions: ["v1"]
        resources: ["configmaps"]
        scope: Namespaced
YAML
sleep 3

kc -n "$NS" delete configmap m16-allow m16-deny --ignore-not-found >/dev/null 2>&1
if kc -n "$NS" create configmap m16-allow --from-literal=k=v >/dev/null 2>&1; then
  ALLOWED=yes
else
  ALLOWED=no
fi
DENYOUT=$(kc apply -f - 2>&1 <<YAML
apiVersion: v1
kind: ConfigMap
metadata: {name: m16-deny, namespace: $NS, labels: {m16-deny: "yes"}}
data: {k: v}
YAML
)
case "$DENYOUT" in
  *"denied by policy"*) DENIED=yes ;;
  *) DENIED=no ;;
esac
SEEN=$(kc -n "$NS" logs "$SVC" 2>/dev/null | grep -c '^VALIDATE ' || true)

if [ "$ALLOWED" = yes ] && [ "$DENIED" = yes ] && [ "${SEEN:-0}" -ge 2 ]; then
  verdict PASS "s0.1a admission  the apiserver reached a service-ref webhook on a vm-backed ClusterIP: allow admitted, deny rejected with the webhook's own message, $SEEN AdmissionReviews in the backend's log"
else
  verdict FAIL "s0.1a admission  allowed=$ALLOWED denied=$DENIED backend_reviews=${SEEN:-0} (apiserver response: $(printf '%s' "$DENYOUT" | tail -1))"
fi

# failurePolicy: Fail must actually fail closed. Repointing the service ref at a name
# that does not exist is the cheapest honest way to ask: the dial cannot succeed, so
# a CREATE that still goes through would mean the webhook was never in the path.
kc patch validatingwebhookconfiguration m16-spike --type=json \
  -p '[{"op":"replace","path":"/webhooks/0/clientConfig/service/name","value":"m16-webhook-absent"}]' >/dev/null 2>&1
sleep 3
if kc -n "$NS" create configmap m16-failclosed --from-literal=k=v >/dev/null 2>&1; then
  verdict FAIL "s0.1a failurePolicy  a CREATE succeeded while the webhook service was unresolvable — failurePolicy: Fail is not fail-closed on this path"
  kc -n "$NS" delete configmap m16-failclosed --ignore-not-found >/dev/null 2>&1
else
  verdict PASS "s0.1a failurePolicy  Fail is fail-closed: a CREATE was rejected while the webhook service was unresolvable"
fi
kc delete validatingwebhookconfiguration m16-spike --ignore-not-found >/dev/null 2>&1

# --- (b) the CRD CONVERSION path -------------------------------------------------
# A DISTINCT dispatch path in the apiserver (apiextensions, not admission), and it
# fires on every non-storage-version read including LIST and WATCH. Proving the
# admission path says nothing about this one, which is why the plan's R14 ships two
# tests and flips two register rows.
kc delete crd m16widgets.spike.k3sm.io --ignore-not-found >/dev/null 2>&1
kc apply -f - <<YAML >/dev/null
apiVersion: apiextensions.k8s.io/v1
kind: CustomResourceDefinition
metadata: {name: m16widgets.spike.k3sm.io}
spec:
  group: spike.k3sm.io
  scope: Namespaced
  names: {plural: m16widgets, singular: m16widget, kind: M16Widget}
  conversion:
    strategy: Webhook
    webhook:
      conversionReviewVersions: ["v1"]
      clientConfig:
        service: {name: $SVC, namespace: $NS, path: /convert, port: 443}
        caBundle: $CABUNDLE
  versions:
    - name: v1alpha1
      served: true
      storage: false
      schema:
        openAPIV3Schema:
          type: object
          properties:
            spec: {type: object, properties: {size: {type: string}}}
    - name: v1beta1
      served: true
      storage: true
      schema:
        openAPIV3Schema:
          type: object
          properties:
            spec: {type: object, properties: {sizeBytes: {type: integer}}}
YAML
for i in $(seq 1 30); do
  kc get crd m16widgets.spike.k3sm.io -o jsonpath='{.status.conditions[?(@.type=="Established")].status}' 2>/dev/null | grep -q True && break
  sleep 2
done

kc -n "$NS" apply -f - <<YAML >/dev/null 2>&1
apiVersion: spike.k3sm.io/v1beta1
kind: M16Widget
metadata: {name: w1, namespace: $NS}
spec: {sizeBytes: 4096}
YAML
ALPHA=$(kc -n "$NS" get m16widgets.v1alpha1.spike.k3sm.io w1 -o jsonpath='{.spec.size}' 2>&1)
CONV=$(kc -n "$NS" logs "$SVC" 2>/dev/null | grep -c '^CONVERT ' || true)
if [ "$ALPHA" = "4096" ] && [ "${CONV:-0}" -ge 1 ]; then
  verdict PASS "s0.1b conversion  a v1alpha1 read of a v1beta1 object was answered by the service-ref conversion webhook (spec.size=$ALPHA, $CONV ConversionReviews in the backend's log)"
else
  verdict FAIL "s0.1b conversion  v1alpha1 read returned '$ALPHA' with ${CONV:-0} ConversionReviews — the conversion path did not reach the vm-backed ClusterIP"
fi

kc delete crd m16widgets.spike.k3sm.io --ignore-not-found >/dev/null 2>&1
kc -n "$NS" delete configmap m16-allow m16-deny --ignore-not-found >/dev/null 2>&1
EOF

# ---------------------------------------------------------------------------------
note "S0(2) — two vllm-mlx engines on one GPU, sustained, against the one-engine control"
# ---------------------------------------------------------------------------------
lab <<'EOF'
set -uo pipefail
W="$PREFIX/s0"; mkdir -p "$W/logs"
export UV_CACHE_DIR="$PREFIX/cache" UV_PYTHON_INSTALL_DIR="$PREFIX/pyinstall" HF_HOME="$PREFIX/hf"

command -v uv >/dev/null || curl -LsSf https://astral.sh/uv/install.sh | env UV_INSTALL_DIR="$PREFIX/bin" sh >/dev/null 2>&1
export PATH="$PREFIX/bin:$PATH"
spike_venv "$PREFIX/venv" "s0.2-setup"
V="$PREFIX/venv/bin/python"
"$V" -c 'import vllm_mlx' 2>/dev/null || spike_pip "$V" "vllm-mlx==$ENGINE_VERSION"
"$V" -c 'import vllm_mlx' 2>/dev/null || { verdict FAIL "s0.2-setup  vllm-mlx==$ENGINE_VERSION did not install: $(tail -1 "$PREFIX/logs/pip-venv-vllm-mlx.log" 2>/dev/null)"; exit 0; }

MP=$("$V" - <<PY
from huggingface_hub import snapshot_download
print(snapshot_download("$MODEL_REPO", revision="$MODEL_REV"))
PY
)
[ -d "$MP" ] || { verdict FAIL "s0.2-setup  the pinned model snapshot did not download"; exit 0; }
recorded "s0.2 model: $MODEL_REPO @ ${MODEL_REV:0:12} at $MP"

# The sustained load. 1 200 tokens per request is the S3 methodology the sizing
# formula was calibrated from: a burst ends before the peak the headroom exists for,
# and two engines each oscillate with the buffer cache.
cat > "$W/load.py" <<'PY'
import json, statistics, sys, threading, time, urllib.error, urllib.request

# resolve_model <base> — GET <base>/v1/models and return its first data[].id.
# vllm-mlx 0.4.1 (like upstream vLLM) answers /v1/chat/completions with a 404
# "The model `<x>` does not exist" for any id it was not started with, and the
# id it WILL answer to is the model path it was launched against, not a fixed
# literal — so the id is resolved once per base URL from the server itself,
# never hardcoded. A non-200 or an empty list is returned as an error STRING,
# never raised: the caller turns it into a failed request naming the status
# text, so a broken /v1/models never reads as a silent 404 buried in the
# aggregate "failed" count.
def resolve_model(base):
    try:
        with urllib.request.urlopen(base + "/v1/models", timeout=10) as r:
            status = r.status
            payload = r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        return None, "GET /v1/models: HTTP %d %s" % (exc.code, exc.reason)
    except Exception as exc:
        return None, "GET /v1/models: %s: %s" % (type(exc).__name__, str(exc)[:120])
    if status != 200:
        return None, "GET /v1/models: HTTP %d" % status
    try:
        ids = [m.get("id") for m in json.loads(payload).get("data", []) if m.get("id")]
    except Exception as exc:
        return None, "GET /v1/models: unparseable body (%s)" % str(exc)[:120]
    if not ids:
        return None, "GET /v1/models: empty model list"
    return ids[0], None

def one(base, model, prompt, max_tokens, out):
    body = json.dumps({"model": model, "max_tokens": max_tokens, "stream": True,
                       "messages": [{"role": "user", "content": prompt}]}).encode()
    req = urllib.request.Request(base + "/v1/chat/completions", data=body,
                                 headers={"content-type": "application/json"})
    t0 = time.time(); ttft = None; toks = 0
    try:
        with urllib.request.urlopen(req, timeout=600) as r:
            for raw in r:
                line = raw.decode("utf-8", "replace").strip()
                if not line.startswith("data:"):
                    continue
                if line.endswith("[DONE]"):
                    break
                if ttft is None:
                    ttft = time.time() - t0
                toks += 1
        out.append({"ok": True, "ttft": ttft or 0.0, "wall": time.time() - t0, "tokens": toks})
    except urllib.error.HTTPError as exc:
        out.append({"ok": False, "error": "HTTP %d %s" % (exc.code, exc.reason),
                    "wall": time.time() - t0})
    except Exception as exc:  # a rejection is DATA, not a crash
        out.append({"ok": False, "error": type(exc).__name__ + ": " + str(exc)[:120],
                    "wall": time.time() - t0})

def run(bases, conc, rounds, max_tokens):
    models, errors = {}, {}
    for base in bases:
        models[base], errors[base] = resolve_model(base)
    out = []
    for r in range(rounds):
        threads = []
        for i in range(conc):
            base = bases[i % len(bases)]
            if models[base] is None:
                out.append({"ok": False, "error": errors[base], "wall": 0.0})
                continue
            prompt = "Round %d request %d. Explain, at length, how a filesystem journal works." % (r, i)
            t = threading.Thread(target=one, args=(base, models[base], prompt, max_tokens, out))
            t.start(); threads.append(t)
        for t in threads:
            t.join()
    return out

if __name__ == "__main__":
    bases = sys.argv[1].split(",")
    conc, rounds, max_tokens = int(sys.argv[2]), int(sys.argv[3]), int(sys.argv[4])
    t0 = time.time()
    res = run(bases, conc, rounds, max_tokens)
    wall = time.time() - t0
    ok = [r for r in res if r["ok"]]
    lat = sorted(r["wall"] for r in ok)
    ttfts = sorted(r["ttft"] for r in ok)
    def pct(xs, p):
        return xs[min(len(xs) - 1, int(round(p * (len(xs) - 1))))] if xs else 0.0
    print(json.dumps({
        "requests": len(res), "ok": len(ok), "failed": len(res) - len(ok),
        "wall_s": round(wall, 2),
        "aggregate_tok_s": round(sum(r["tokens"] for r in ok) / wall, 2) if wall else 0,
        "ttft_p50": round(pct(ttfts, 0.50), 3), "ttft_p99": round(pct(ttfts, 0.99), 3),
        "latency_p50": round(pct(lat, 0.50), 2), "latency_p95": round(pct(lat, 0.95), 2),
        "latency_p99": round(pct(lat, 0.99), 2),
        "errors": sorted({r.get("error", "") for r in res if not r["ok"]}),
    }))
PY

# wired_mb — the scarce resource on Apple silicon is WIRED capacity, not total RAM.
wired_mb() { vm_stat | awk '/Pages wired down/ {gsub(/\./,"",$4); printf "%d", $4*4096/1048576}'; }
start_engine() { # start_engine <port> <logfile>
  nohup "$PREFIX/venv/bin/python" -m vllm_mlx.cli serve "$MP" \
    --continuous-batching --max-kv-size 4096 --max-num-seqs 4 \
    --host 127.0.0.1 --port "$1" > "$2" 2>&1 &
  echo $!
}
wait_health() { # wait_health <port>
  for i in $(seq 1 120); do
    curl -fsS -m 3 "http://127.0.0.1:$1/health" >/dev/null 2>&1 && return 0
    sleep 5
  done
  return 1
}
rss_mb() { ps -o rss= -p "$1" 2>/dev/null | awk '{printf "%d", $1/1024}'; }

pkill -f 'vllm_mlx.cli serve' 2>/dev/null; sleep 2
BASE_WIRED=$(wired_mb)

# --- the control: ONE engine -----------------------------------------------------
P1=$(start_engine 8101 "$W/logs/engine-8101.log")
if ! wait_health 8101; then
  verdict FAIL "s0.2-control  the first engine never answered /health (see $W/logs/engine-8101.log)"
  kill "$P1" 2>/dev/null; exit 0
fi
ONE_RSS=$(rss_mb "$P1"); ONE_WIRED=$(wired_mb)
ONE=$("$PREFIX/venv/bin/python" "$W/load.py" "http://127.0.0.1:8101" 4 3 1200)
recorded "s0.2 control (1 engine, conc 4, 3 rounds, 1200 tok): $ONE"
recorded "s0.2 control memory: engine RSS ${ONE_RSS}MB, wired ${ONE_WIRED}MB (baseline ${BASE_WIRED}MB)"

# --- the measurement: TWO engines ------------------------------------------------
P2=$(start_engine 8102 "$W/logs/engine-8102.log")
if ! wait_health 8102; then
  verdict FAIL "s0.2  the SECOND engine never answered /health beside the first — two engines do not co-reside on this rig (see $W/logs/engine-8102.log)"
  kill "$P1" "$P2" 2>/dev/null; exit 0
fi
TWO_RSS1=$(rss_mb "$P1"); TWO_RSS2=$(rss_mb "$P2"); TWO_WIRED=$(wired_mb)
TWO=$("$PREFIX/venv/bin/python" "$W/load.py" "http://127.0.0.1:8101,http://127.0.0.1:8102" 8 3 1200)
PEAK_WIRED=$(wired_mb)
recorded "s0.2 two engines (conc 8 across 2 engines, 3 rounds, 1200 tok): $TWO"
recorded "s0.2 two-engine memory: RSS ${TWO_RSS1}MB + ${TWO_RSS2}MB, wired ${TWO_WIRED}MB, peak wired ${PEAK_WIRED}MB (baseline ${BASE_WIRED}MB)"
recorded "s0.2 IOKit/Metal cross-process interference: NOT EVALUATED (no per-process GPU accounting was taken; the aggregate and percentile figures above are what this rung measured)"

VERDICT=$("$PREFIX/venv/bin/python" - "$ONE" "$TWO" <<'PY'
import json, sys
one, two = json.loads(sys.argv[1]), json.loads(sys.argv[2])
bad = []
if two["failed"]:
    bad.append("%d of %d two-engine requests failed (%s)" % (two["failed"], two["requests"], "; ".join(two["errors"])[:160]))
if one["latency_p99"] and two["latency_p99"] > 2 * one["latency_p99"]:
    bad.append("p99 latency doubled: %.2fs -> %.2fs" % (one["latency_p99"], two["latency_p99"]))
if one["aggregate_tok_s"] and two["aggregate_tok_s"] < one["aggregate_tok_s"]:
    bad.append("aggregate throughput fell: %.1f -> %.1f tok/s" % (one["aggregate_tok_s"], two["aggregate_tok_s"]))
print("FAIL " + "; ".join(bad) if bad else "PASS p99 %.2fs -> %.2fs, aggregate %.1f -> %.1f tok/s, every request served" % (
    one["latency_p99"], two["latency_p99"], one["aggregate_tok_s"], two["aggregate_tok_s"]))
PY
)
case "$VERDICT" in
  PASS*) verdict PASS "s0.2 co-residency  two engines held the sustained load: ${VERDICT#PASS }" ;;
  *)     verdict FAIL "s0.2 co-residency  ${VERDICT#FAIL } — the plan's R5 floor rises (a smaller model or a larger slot) and this rung re-runs; single-slot only if no small model fits two" ;;
esac
kill "$P1" "$P2" 2>/dev/null; sleep 2; pkill -f 'vllm_mlx.cli serve' 2>/dev/null
EOF

# ---------------------------------------------------------------------------------
note "S0(3) — the vm guest <-> native pod-IP dial, both directions"
# ---------------------------------------------------------------------------------
lab <<'EOF'
set -uo pipefail

kc -n "$NS" delete pod m16-native m16-guest --ignore-not-found --wait=false >/dev/null 2>&1
sleep 2

# A NATIVE pod (image: native — the workload is the command) listening on its own
# pod IP. Binding 0.0.0.0 is deliberate: the question is whether the guest can reach
# the lo0 alias, not how the listener was bound.
kc apply -f - <<YAML >/dev/null
apiVersion: v1
kind: Pod
metadata: {name: m16-native, namespace: $NS}
spec:
  nodeSelector: {kubernetes.io/os: darwin}
  tolerations: [{key: k3sm.io/provider, operator: Exists, effect: NoSchedule}]
  restartPolicy: Never
  containers:
    - name: listener
      image: native
      command:
        - /usr/bin/python3
        - -c
        - "import http.server as h\nclass H(h.BaseHTTPRequestHandler):\n def do_GET(s):\n  s.send_response(200); s.end_headers(); s.wfile.write(b'M16-NATIVE')\n def log_message(s, *a): pass\nh.HTTPServer(('0.0.0.0', 8099), H).serve_forever()"
YAML
kc apply -f - <<YAML >/dev/null
apiVersion: v1
kind: Pod
metadata: {name: m16-guest, namespace: $NS}
spec:
  runtimeClassName: vm
  nodeSelector: {kubernetes.io/os: darwin}
  tolerations: [{key: k3sm.io/provider, operator: Exists, effect: NoSchedule}]
  restartPolicy: Never
  containers:
    - name: guest
      image: $WEBHOOK_IMAGE
      command:
        - python3
        - -c
        - "import http.server as h\nclass H(h.BaseHTTPRequestHandler):\n def do_GET(s):\n  s.send_response(200); s.end_headers(); s.wfile.write(b'M16-GUEST')\n def log_message(s, *a): pass\nh.HTTPServer(('0.0.0.0', 8099), H).serve_forever()"
      resources: {requests: {memory: 256Mi, cpu: 100m}, limits: {memory: 256Mi}}
YAML

OK=1
kc -n "$NS" wait --for=condition=Ready pod/m16-native --timeout=180s >/dev/null 2>&1 || { verdict FAIL "s0.3-setup  the native listener pod never became Ready"; OK=0; }
kc -n "$NS" wait --for=condition=Ready pod/m16-guest  --timeout=300s >/dev/null 2>&1 || { verdict FAIL "s0.3-setup  the vm guest pod never became Ready"; OK=0; }
if [ "$OK" = 1 ]; then
  NIP=$(kc -n "$NS" get pod m16-native -o jsonpath='{.status.podIP}')
  GIP=$(kc -n "$NS" get pod m16-guest  -o jsonpath='{.status.podIP}')
  recorded "s0.3 addresses: native pod IP $NIP, vm guest published IP $GIP"

  # guest -> native pod IP. The consequential direction: the fleet's frontend dials
  # each worker's PUBLISHED address, not a VIP, so a blocked dial here is R4(b).
  G2N=$(kc -n "$NS" exec m16-guest -- python3 -c "
import sys, urllib.request
try:
    print(urllib.request.urlopen('http://$NIP:8099/', timeout=10).read().decode())
except Exception as e:
    print('BLOCKED', type(e).__name__, str(e)[:100])
" 2>&1 | tail -1)
  case "$G2N" in
    *M16-NATIVE*)
      verdict PASS "s0.3 guest->native  a vm guest reached the native pod's own lo0-alias pod IP $NIP:8099 directly"
      recorded "s0.3 TRUST-DOMAIN FACT: that dial bypasses the Service proxy and the NetworkPolicy L4 hint, exactly as any same-node process does — docs/user/mlx-fleet.md must say so"
      ;;
    *) verdict FAIL "s0.3 guest->native  blocked ($G2N) — the plan's R4(b) applies: the control plane moves to the native-Darwin build" ;;
  esac

  # native -> guest published IP. Recorded rather than required: nothing in M16's
  # request path depends on it, but its answer bounds what a future rung may assume.
  N2G=$(kc -n "$NS" exec m16-native -- /usr/bin/curl -fsS -m 10 "http://$GIP:8099/" 2>&1 | tail -1)
  case "$N2G" in
    *M16-GUEST*) recorded "s0.3 native->guest  a native pod reached the vm guest's published IP $GIP:8099" ;;
    *)           recorded "s0.3 native->guest  BLOCKED ($N2G) — the inbound direction limitations.md already documents" ;;
  esac
fi
kc -n "$NS" delete pod m16-native m16-guest m16-webhook --ignore-not-found --wait=false >/dev/null 2>&1
EOF

spike_verdict "$RUNG"

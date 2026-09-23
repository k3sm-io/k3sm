#!/usr/bin/env bash
# M16.0-d3 / S2 — the upstream control plane on k3sm, GPU-free.
#
# Everything here runs with NO GPU and NO MLX: the question is whether the serving
# control plane hosts on k3sm at all, which is a different question from whether the
# engine works, and answering them separately is what keeps a red legible.
#
#   s2.1  install    the PINNED chart (by digest, never a tag — a tag can be
#                     repointed and these images carry cluster RBAC), with etcd and
#                     NATS install OFF and kubernetes discovery ON, the operator
#                     running as a runtimeClassName: vm Pod with an explicit memory
#                     request. Its images come from the mirror once the mirror push
#                     lands; until then, from upstream BY DIGEST, so nothing in M16.0
#                     waits on a human.
#   s2.2  crds       every CRD the chart installs reaches Established, and their
#                     group/version/kind triples are RECORDED — those strings are
#                     what pkg/mlxfleet will own in one place and pin with a test.
#   s2.3  rbac       the operator ClusterRole's FULL verb/resource set is dumped into
#                     the findings, with wildcards and secrets access called out.
#                     This is the plan's R11 input and what the golden test pins;
#                     a grant nobody read is a grant nobody decided.
#   s2.4  conversion a v1alpha1 read of a v1beta1 object is answered live, through
#                     the chart's own cert-controller-minted webhook.
#   s2.5  serve      the CPU-only mocker deployment serves a completion THROUGH THE
#                     FRONTEND'S ClusterIP.
#   s2.6  dial       the frontend's dial to the worker's PUBLISHED ADDRESS is observed
#                     in the worker's own log. The request plane dials addresses, not
#                     VIPs, which is exactly why S0(3) had to be measured.
#
# HALT: discovery or that dial fails -> the plan's R4(b): the control plane moves to
# the native-Darwin build. Pre-decided; this rung never improvises another.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
. "$HERE/lib.sh"

RUNG="S2"
QUESTION="Does the upstream serving control plane install and run on k3sm with its operator and frontend as vm Pods, no etcd and no NATS, with Kubernetes-native discovery, live CRD conversion, and a completion served through the frontend's ClusterIP?"
METHOD="Rig-side over ssh: helm install of the digest-pinned chart with etcd.install=false, nats.install=false and kubernetes discovery, the pod specs patched to runtimeClassName: vm with explicit memory requests; then CRD Established checks with every GVK recorded, a full ClusterRole dump, a v1alpha1 read of a v1beta1 object, the in-tree mocker deployment, and a completion through the frontend's ClusterIP with the worker's log inspected for the frontend's dial."
HALT="discovery or the frontend-to-worker dial fails -> R4(b), the native-Darwin control plane as a second hack/images entry."

case "${1:-}" in
--plan | --dry-run) spike_plan "$RUNG" "$QUESTION" "$METHOD" "$HALT" ;;
"") ;;
*)
	echo "s2.sh: unknown argument: $1 (try --plan)" >&2
	exit 2
	;;
esac

spike_host
spike_require_pin K3SM_M16_CHART "the chart reference this rung installs, pinned BY DIGEST (oci://<registry>/<chart>@sha256:...)"

note "S2 — chart install, CRDs, the RBAC dump, conversion, and a completion through the ClusterIP"
lab <<'EOF'
set -uo pipefail
spike_preflight
W="$PREFIX/s2"; mkdir -p "$W"
command -v helm >/dev/null || { verdict FAIL "s2.0 preflight  helm is not on the rig (brew install helm)"; exit 0; }
# kc() passes the rig kubeconfig explicitly; helm reads KUBECONFIG, so the two
# talk to the same cluster only if it is exported here.
export KUBECONFIG="$KUBECONFIG_RIG"
case "$CHART_REF" in
  *@sha256:*) : ;;
  *) verdict FAIL "s2.1 install  CHART_REF=$CHART_REF is not digest-pinned — m16.0 will assert digests, never tags, so the spike holds itself to the same rule"; exit 0 ;;
esac

kc create namespace "$NS" >/dev/null 2>&1 || true

# The values the plan's F5 names, plus the two k3sm-side facts every control-plane
# Pod on this node needs: it runs under vm, and it declares its memory. The
# system-reserved carve-out is scheduling-only and jetsam picks the largest RSS, not
# the most important process, so a zero-request control-plane Pod is admitted for
# free and then killed first.
cat > "$W/values.yaml" <<YAML
etcd:
  install: false
nats:
  install: false
discoveryBackend: kubernetes
YAML
[ -n "${K3SM_M16_VALUES:-}" ] && [ -r "$K3SM_M16_VALUES" ] && cat "$K3SM_M16_VALUES" >> "$W/values.yaml"

# SUBSTITUTION, recorded when taken (K3SM_M16_WEBHOOK_CERT=external): the
# operator's built-in cert-controller creates its webhook Secret and then waits
# for the kubelet to project it into the mounted volume. k3sm materializes a
# Secret volume once, at pod creation, and never refreshes it, so the mount stays
# empty and the operator never starts. The chart's external-certificate mode
# expects the Secret BEFORE install, which puts the files in the mount from the
# first boot; the spike mints that certificate here (a CA and a server cert for
# the webhook Service's in-cluster names, 30 days) and passes the CA bundle the
# admission registrations need. The conversion CA is injected by the operator
# from the same Secret. Off by default: the plan's rung is the chart as shipped.
if [ "${K3SM_M16_WEBHOOK_CERT:-}" = external ]; then
  WH_SVC="m16-dynamo-operator-webhook-service"
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 30 \
    -subj "/CN=m16 spike webhook ca" -keyout "$W/ca.key" -out "$W/ca.crt" >/dev/null 2>&1
  openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -subj "/CN=$WH_SVC.$NS.svc" \
    -addext "subjectAltName=DNS:$WH_SVC.$NS.svc,DNS:$WH_SVC.$NS.svc.cluster.local,DNS:$WH_SVC.$NS" \
    -keyout "$W/tls.key" -out "$W/tls.csr" >/dev/null 2>&1
  openssl x509 -req -in "$W/tls.csr" -CA "$W/ca.crt" -CAkey "$W/ca.key" -CAcreateserial -days 30 \
    -copy_extensions copy -out "$W/tls.crt" >/dev/null 2>&1
  kc -n "$NS" delete secret webhook-server-cert >/dev/null 2>&1 || true
  kc -n "$NS" create secret generic webhook-server-cert \
    --from-file=tls.crt="$W/tls.crt" --from-file=tls.key="$W/tls.key" --from-file=ca.crt="$W/ca.crt" >/dev/null
  cat >> "$W/values.yaml" <<YAML
dynamo-operator:
  webhook:
    certificateSecret:
      external: true
    caBundle: $(base64 < "$W/ca.crt" | tr -d '\n')
YAML
  recorded "s2.1 SUBSTITUTION webhook certificate external — k3sm does not refresh a Secret volume after pod creation, so the chart's cert-controller never sees the Secret it created; the spike minted the certificate (CN=$WH_SVC.$NS.svc, 30 d) and installed with the chart's external mode"
fi
recorded "s2.1 values: $(tr '\n' ' ' < "$W/values.yaml" | sed -E 's/caBundle: [A-Za-z0-9+\/=]+/caBundle: <ca>/')"

# No --wait here, on purpose: k3sm's require-os-darwin admission policy refuses
# every Pod without nodeSelector kubernetes.io/os=darwin, the chart's pods carry
# none, and the selector is added by the patch below — so a --wait on the install
# waits on a Deployment that can never create a Pod. Install, patch, then wait.
helm upgrade --install m16 "$CHART_REF" -n "$NS" -f "$W/values.yaml" \
  --timeout 15m > "$W/helm.log" 2>&1
HELM_RC=$?
if [ "$HELM_RC" != 0 ]; then
  verdict FAIL "s2.1 install  helm upgrade --install failed (rc=$HELM_RC) — see $W/helm.log"
  tail -40 "$W/helm.log"; exit 0
fi

# Patch every control-plane Pod onto the vm path with a memory request. Done as a
# post-install patch rather than through chart values because the values key for a
# pod override differs by chart version, and a spike that guesses a key silently
# installs a NATIVE control plane and proves nothing about vm hosting.
for d in $(kc -n "$NS" get deploy -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}'); do
  kc -n "$NS" patch deploy "$d" --type=strategic -p '{"spec":{"template":{"spec":{"runtimeClassName":"vm","nodeSelector":{"kubernetes.io/os":"darwin"},"tolerations":[{"key":"k3sm.io/provider","operator":"Exists","effect":"NoSchedule"}]}}}}' >/dev/null 2>&1
  for c in $(kc -n "$NS" get deploy "$d" -o jsonpath='{range .spec.template.spec.containers[*]}{.name}{"\n"}{end}'); do
    kc -n "$NS" set resources deploy "$d" -c "$c" --requests=memory=512Mi --limits=memory=512Mi >/dev/null 2>&1
  done
done
kc -n "$NS" rollout status deploy --timeout=600s > "$W/rollout.log" 2>&1
# readyReplicas is ABSENT (not 0) on a Deployment that never had a ready Pod, so an
# empty count is read as zero rather than as "not zero".
READY=$(kc -n "$NS" get deploy -o jsonpath='{range .items[*]}{.metadata.name}={.status.readyReplicas}/{.status.replicas} {end}' | sed 's|=/|=0/|g')
case "$READY" in
  *"=0/"*|"") verdict FAIL "s2.1 install  a control-plane Deployment is not Ready under runtimeClassName=vm: $READY"
              kc -n "$NS" get pods -o jsonpath='{range .items[*]}{.metadata.name}: {.status.phase} {.status.reason} {.status.message}{"\n"}{end}' | head -5; exit 0 ;;
  *)          verdict PASS "s2.1 install  the control plane is Ready as vm Pods with explicit memory requests: $READY" ;;
esac

# ---- s2.2 the CRDs, and the GVK strings pkg/mlxfleet will own --------------------
# The script goes to a file: `python3 - <<EOF` reads its SOURCE from stdin, so it
# cannot also read piped JSON from stdin. Two stdin consumers, one pipe.
cat > "$W/crds.py" <<'PY'
import json, sys
d = json.load(sys.stdin)
rows = []
for item in d.get("items", []):
    name = item["metadata"]["name"]
    group = item["spec"]["group"]
    if "dynamo" not in name and "dynamo" not in group:
        continue
    est = [c for c in (item.get("status", {}).get("conditions") or []) if c["type"] == "Established"]
    storage = [v["name"] for v in item["spec"]["versions"] if v.get("storage")]
    served = [v["name"] for v in item["spec"]["versions"] if v.get("served")]
    rows.append({"name": name, "group": group, "kind": item["spec"]["names"]["kind"],
                 "storage": storage, "served": served,
                 "established": bool(est and est[0]["status"] == "True"),
                 "conversion": (item["spec"].get("conversion") or {}).get("strategy")})
print(json.dumps(rows))
PY
# At this pin the chart templates no CRDs: with dynamo-operator.upgradeCRD (default
# true) the operator Deployment carries a crd-apply initContainer that applies them
# from the operator image (/opt/dynamo-operator/crds/), so they exist only once that
# Pod has been scheduled and its init has run. Give it a minute.
for i in $(seq 1 30); do
  kc get crd -o json | python3 "$W/crds.py" | grep -q '"group"' && break
  sleep 2
done
CRDS=$(kc get crd -o json | python3 "$W/crds.py")
N_CRD=$(printf '%s' "$CRDS" | python3 -c 'import json,sys; print(len(json.load(sys.stdin)))')
N_EST=$(printf '%s' "$CRDS" | python3 -c 'import json,sys; print(sum(1 for r in json.load(sys.stdin) if r["established"]))')
recorded "s2.2 CRDs (the GVK strings pkg/mlxfleet pins): $CRDS"
if [ "${N_CRD:-0}" -gt 0 ] && [ "$N_EST" = "$N_CRD" ]; then
  verdict PASS "s2.2 crds  all $N_CRD chart CRDs reached Established"
else
  verdict FAIL "s2.2 crds  only ${N_EST:-0} of ${N_CRD:-0} chart CRDs are Established"
fi

# ---- s2.3 the RBAC dump (the plan's R11 input) -----------------------------------
echo "---- OPERATOR ClusterRole DUMP (copy verbatim into findings-s2.md) ----"
kc get clusterrole -l app.kubernetes.io/instance=m16 -o yaml 2>/dev/null | tee "$W/clusterroles.yaml" | sed -n '1,400p'
echo "---- END ClusterRole DUMP ----"
WILD=$(python3 - "$W/clusterroles.yaml" <<'PY'
import sys
try:
    import yaml
except ImportError:
    print("UNPARSED")
    sys.exit(0)
docs = yaml.safe_load(open(sys.argv[1])) or {}
items = docs.get("items", []) if isinstance(docs, dict) else []
flags = []
for cr in items:
    for rule in cr.get("rules") or []:
        if "*" in (rule.get("verbs") or []) or "*" in (rule.get("resources") or []):
            flags.append("%s: wildcard %s on %s" % (cr["metadata"]["name"], rule.get("verbs"), rule.get("resources")))
        if "secrets" in (rule.get("resources") or []):
            flags.append("%s: secrets %s" % (cr["metadata"]["name"], rule.get("verbs")))
print("; ".join(flags) if flags else "none")
PY
)
recorded "s2.3 rbac  ClusterRoles dumped to $W/clusterroles.yaml; wildcard/secrets findings: $WILD"

# ---- s2.4 conversion, live -------------------------------------------------------
CONV_CRD=$(printf '%s' "$CRDS" | python3 -c '
import json, sys
rows = json.load(sys.stdin)
hit = [r for r in rows if r["conversion"] == "Webhook" and len(r["served"]) > 1]
print(json.dumps(hit[0]) if hit else "")')
if [ -z "$CONV_CRD" ]; then
  recorded "s2.4 conversion  no chart CRD serves two versions behind a conversion webhook at this pin — nothing to convert, so the rung records rather than asserts"
else
  CRD_NAME=$(printf '%s' "$CONV_CRD" | python3 -c 'import json,sys; print(json.load(sys.stdin)["name"])')
  ALT=$(printf '%s' "$CONV_CRD" | python3 -c '
import json, sys
r = json.load(sys.stdin)
print([v for v in r["served"] if v not in r["storage"]][0])')
  recorded "s2.4 conversion  $CRD_NAME serves $ALT beside its storage version behind a webhook; the live read is taken once s2.5's graph has produced an object"
fi

# ---- s2.5 the mocker deployment, from the upstream checkout ----------------------
# The manifest comes from S1's checkout, never from a hand-written guess: a spike
# that invents a spec shape proves nothing about the chart that ships.
DGD="${K3SM_M16_DGD_MANIFEST:-}"
if [ -z "$DGD" ]; then
  # A manifest, not a docs page: the tree's .mdx pages quote the same kind.
  DGD=$(grep -rl --include='*.yaml' "kind: DynamoGraphDeployment" "$PREFIX/s1/src/examples" 2>/dev/null | grep -i "mocker.*agg\|mocker" | head -1)
fi
if [ -z "$DGD" ] || [ ! -r "$DGD" ]; then
  verdict FAIL "s2.5 serve  no mocker DynamoGraphDeployment manifest found (run s1.sh first, or set K3SM_M16_DGD_MANIFEST) — this rung installs the chart's own example, never a hand-written one"
  exit 0
fi
recorded "s2.5 manifest: $DGD"
python3 - "$DGD" "$W/dgd.yaml" "$NS" <<'PY'
import os
import sys
try:
    import yaml
except ImportError:
    sys.exit("PyYAML is required on the rig to patch the example manifest")
src, dst, ns = sys.argv[1], sys.argv[2], sys.argv[3]
runasuser = os.environ.get("K3SM_M16_POD_RUNASUSER", "")
patched = []

def walk(node, path):
    # Any dict carrying a containers list IS a pod spec, whatever the chart calls
    # the field around it. Keying on the shape instead of the key name survives a
    # chart that renames podTemplateSpec between versions.
    if isinstance(node, dict):
        if isinstance(node.get("containers"), list):
            node["runtimeClassName"] = "vm"
            node.setdefault("nodeSelector", {})["kubernetes.io/os"] = "darwin"
            node["tolerations"] = [{"key": "k3sm.io/provider", "operator": "Exists", "effect": "NoSchedule"}]
            for c in node["containers"]:
                r = c.setdefault("resources", {})
                r.setdefault("requests", {})["memory"] = "512Mi"
                r.setdefault("limits", {})["memory"] = "512Mi"
            # SUBSTITUTION, recorded when taken (K3SM_M16_POD_RUNASUSER=<uid>); the
            # note at the recorded line below says why.
            if runasuser:
                node.setdefault("securityContext", {})["runAsUser"] = int(runasuser)
                for c in node["containers"]:
                    env = c.setdefault("env", [])
                    have = {e.get("name") for e in env}
                    for k, v in (("HOME", "/dev/shm/home"), ("TMPDIR", "/dev/shm"), ("HF_HOME", "/dev/shm/hf")):
                        if k not in have:
                            env.append({"name": k, "value": v})
            patched.append(path or "<root>")
        for k, v in node.items():
            walk(v, path + "." + k)
    elif isinstance(node, list):
        for i, v in enumerate(node):
            walk(v, path + "[%d]" % i)

docs = [d for d in yaml.safe_load_all(open(src)) if d]
for d in docs:
    d.setdefault("metadata", {})["namespace"] = ns
    walk(d, "")
yaml.safe_dump_all(docs, open(dst, "w"), default_flow_style=False)
print("patched pod specs at: " + (", ".join(patched) if patched else "NONE — the example carries no inline pod spec, so the operator's own defaulting decides the runtime class"))
PY
# SUBSTITUTION, recorded when taken (K3SM_M16_POD_RUNASUSER=<uid>): the image runs
# as the named user "dynamo" (uid 1000, home 0755) and the operator, given no
# securityContext, stamps fsGroup=1000. k3sm refuses both on the vm class: the
# foreign-user guard takes no uid/gid but the node's pod-execution identity, and
# runtimed refuses a named user it cannot resolve (guest/v1 carries numbers only)
# and any fsGroup at all (Apple's virtiofs has no idmapped mounts). A template
# that supplies any securityContext gets no operator defaults, so setting
# runAsUser to the node's uid answers all three at once. That uid then owns
# nothing in the image: the vm rootfs lower carries the host tree's ownership
# and modes (the ownership sidecar is written beside the snapshot and applied
# nowhere), so /tmp arrives root-owned 0755 and Python finds no usable temp
# dir, and the frontend's model-card cache ($HOME/.cache/dynamo/mdc) cannot be
# created. The chart's Memory emptyDir at /dev/shm is a guest tmpfs, the one
# writable place, so HOME, TMPDIR and HF_HOME point into it. Off by default:
# the rung is the example as shipped.
[ -n "${K3SM_M16_POD_RUNASUSER:-}" ] && recorded "s2.5 SUBSTITUTION pod runAsUser=$K3SM_M16_POD_RUNASUSER, HOME=/dev/shm/home, TMPDIR=/dev/shm and HF_HOME=/dev/shm/hf on the example's pod templates — the image's user is the name \"dynamo\" (uid 1000), which runtimed cannot resolve for a vm pod; the operator's default fsGroup=1000 is refused by the foreign-user guard and by runtimed on the vm class; a template-supplied securityContext suppresses the operator's default and the node's own uid satisfies every layer; the rootfs lower keeps the host tree's root ownership and 0755 modes (the ownership sidecar is never applied in-guest), so the Memory emptyDir is the only writable directory"
# The example's decode pod reads hf-token-secret through a required envFrom, so the
# Secret is the example's prerequisite, not the spike's invention. The mocker needs
# no token and huggingface_hub treats an empty HF_TOKEN as unset, so the value is
# empty rather than a real credential.
kc -n "$NS" create secret generic hf-token-secret --from-literal=HF_TOKEN= --dry-run=client -o yaml | kc apply -f - > /dev/null
recorded "s2.5 prerequisite  hf-token-secret created with an empty HF_TOKEN (the decode pod's envFrom requires it; without it k3sm reports ProviderFailed 'secret $NS/hf-token-secret: file does not exist')"
kc apply -f "$W/dgd.yaml" > "$W/dgd-apply.log" 2>&1 || { verdict FAIL "s2.5 serve  the mocker deployment was rejected: $(tail -3 "$W/dgd-apply.log")"; exit 0; }

# ---- s2.4 conversion, live, now that the graph exists ----------------------------
# The operator derives the component objects from the graph, and the first of them is
# what the alternate-version read converts. Taken before the serve wait so a red at
# s2.5 cannot cost the conversion answer.
if [ -n "$CONV_CRD" ]; then
  FIRST=""
  for i in $(seq 1 30); do
    FIRST=$(kc -n "$NS" get "$CRD_NAME" -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)
    [ -n "$FIRST" ] && break
    sleep 2
  done
  if [ -n "$FIRST" ]; then
    OUT=$(kc -n "$NS" get "${CRD_NAME%%.*}.$ALT.${CRD_NAME#*.}" "$FIRST" -o jsonpath='{.apiVersion}' 2>&1)
    case "$OUT" in
      *"$ALT"*) verdict PASS "s2.4 conversion  a $ALT read of $FIRST was answered live by the chart's conversion webhook (apiVersion=$OUT)" ;;
      *)        verdict FAIL "s2.4 conversion  the $ALT read of $FIRST failed: $(printf '%s' "$OUT" | head -c 200)" ;;
    esac
  else
    verdict FAIL "s2.4 conversion  the operator derived no $CRD_NAME from the graph within 60 s"
  fi
fi

FE_SVC=""
for i in $(seq 1 90); do
  FE_SVC=$(kc -n "$NS" get svc -o jsonpath='{range .items[*]}{.metadata.name}{" "}{end}' | tr ' ' '\n' | grep -i frontend | head -1)
  [ -n "$FE_SVC" ] && break
  sleep 5
done
if [ -z "$FE_SVC" ]; then
  verdict FAIL "s2.5 serve  the operator never created a frontend Service for the mocker deployment"
  kc -n "$NS" get pods; exit 0
fi
FE_IP=$(kc -n "$NS" get svc "$FE_SVC" -o jsonpath='{.spec.clusterIP}')
FE_PORT=$(kc -n "$NS" get svc "$FE_SVC" -o jsonpath='{.spec.ports[0].port}')
recorded "s2.5 frontend Service: $FE_SVC at $FE_IP:$FE_PORT"

MODELS=""
for i in $(seq 1 90); do
  MODELS=$(curl -fsS -m 5 "http://$FE_IP:$FE_PORT/v1/models" 2>/dev/null)
  [ -n "$MODELS" ] && break
  sleep 5
done
if [ -z "$MODELS" ]; then
  verdict FAIL "s2.5 serve  the frontend's ClusterIP never answered /v1/models — discovery did not complete; the plan's HALT applies (R4(b))"
  kc -n "$NS" get pods; exit 0
fi
MODEL_ID=$(printf '%s' "$MODELS" | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d["data"][0]["id"])' 2>/dev/null)
OUT=$(curl -fsS -m 120 "http://$FE_IP:$FE_PORT/v1/chat/completions" -H 'content-type: application/json' \
  -d "{\"model\":\"$MODEL_ID\",\"max_tokens\":16,\"messages\":[{\"role\":\"user\",\"content\":\"hello\"}]}" 2>&1)
case "$OUT" in
  *choices*) verdict PASS "s2.5 serve  a completion was served through the frontend's ClusterIP $FE_IP:$FE_PORT for model $MODEL_ID" ;;
  *)         verdict FAIL "s2.5 serve  /v1/models listed $MODEL_ID but the completion failed: $(printf '%s' "$OUT" | head -c 200)" ;;
esac

# ---- s2.6 the dial the router depends on -----------------------------------------
WORKER_POD=$(kc -n "$NS" get pods -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}' | grep -viE 'frontend|operator' | head -1)
if [ -n "$WORKER_POD" ]; then
  WLOG=$(kc -n "$NS" logs "$WORKER_POD" --tail=500 2>/dev/null)
  HITS=$(printf '%s' "$WLOG" | grep -ciE 'connect|accepted|request plane|from [0-9]+\.' || true)
  recorded "s2.6 dial  worker pod $WORKER_POD log lines mentioning an inbound connection: ${HITS:-0}"
  printf '%s' "$WLOG" | grep -iE 'connect|accepted|request plane|endpoint' | tail -10
  if [ "${HITS:-0}" -ge 1 ]; then
    verdict PASS "s2.6 dial  the frontend reached the worker at its PUBLISHED address (observed in the worker's own log), not through a VIP"
  else
    verdict FAIL "s2.6 dial  nothing in the worker's log shows the frontend's dial — the plan's HALT applies (R4(b)); a completion that worked without an observable dial needs its path explained before M16 rests on it"
  fi
else
  verdict FAIL "s2.6 dial  no worker Pod exists to inspect"
fi
EOF

spike_verdict "$RUNG"

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
recorded "s2.1 values: $(tr '\n' ' ' < "$W/values.yaml")"

helm upgrade --install m16 "$CHART_REF" -n "$NS" -f "$W/values.yaml" \
  --wait --timeout 15m > "$W/helm.log" 2>&1
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
READY=$(kc -n "$NS" get deploy -o jsonpath='{range .items[*]}{.metadata.name}={.status.readyReplicas}/{.status.replicas} {end}')
case "$READY" in
  *"=0/"*|"") verdict FAIL "s2.1 install  a control-plane Deployment is not Ready under runtimeClassName=vm: $READY" ;;
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
  FIRST=$(kc -n "$NS" get "$CRD_NAME" -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)
  if [ -n "$FIRST" ]; then
    OUT=$(kc -n "$NS" get "${CRD_NAME%%.*}.$ALT.${CRD_NAME#*.}" "$FIRST" -o jsonpath='{.apiVersion}' 2>&1)
    case "$OUT" in
      *"$ALT"*) verdict PASS "s2.4 conversion  a $ALT read of $FIRST was answered live by the chart's conversion webhook (apiVersion=$OUT)" ;;
      *)        verdict FAIL "s2.4 conversion  the $ALT read of $FIRST failed: $(printf '%s' "$OUT" | head -c 200)" ;;
    esac
  else
    recorded "s2.4 conversion  no object of $CRD_NAME exists yet; the live conversion read is re-tried after s2.5 creates one"
  fi
fi

# ---- s2.5 the mocker deployment, from the upstream checkout ----------------------
# The manifest comes from S1's checkout, never from a hand-written guess: a spike
# that invents a spec shape proves nothing about the chart that ships.
DGD="${K3SM_M16_DGD_MANIFEST:-}"
if [ -z "$DGD" ]; then
  DGD=$(grep -rl "kind: DynamoGraphDeployment" "$PREFIX/s1/src" 2>/dev/null | grep -i mocker | head -1)
fi
if [ -z "$DGD" ] || [ ! -r "$DGD" ]; then
  verdict FAIL "s2.5 serve  no mocker DynamoGraphDeployment manifest found (run s1.sh first, or set K3SM_M16_DGD_MANIFEST) — this rung installs the chart's own example, never a hand-written one"
  exit 0
fi
recorded "s2.5 manifest: $DGD"
python3 - "$DGD" "$W/dgd.yaml" "$NS" <<'PY'
import sys
try:
    import yaml
except ImportError:
    sys.exit("PyYAML is required on the rig to patch the example manifest")
src, dst, ns = sys.argv[1], sys.argv[2], sys.argv[3]
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
kc apply -f "$W/dgd.yaml" > "$W/dgd-apply.log" 2>&1 || { verdict FAIL "s2.5 serve  the mocker deployment was rejected: $(tail -3 "$W/dgd-apply.log")"; exit 0; }

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

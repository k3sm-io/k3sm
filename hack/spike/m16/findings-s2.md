# S2 findings — the control plane on k3sm, GPU-free (M16.0-d3)

> **Status: RUN 2026-09-21 → 2026-09-23, twelve runs on the single-node dev tier named
> under Rig.** s2.1–s2.4 pass on a tree carrying k3sm #447 plus the two provider fixes
> that S2 itself surfaced, with **two substitutions and one prerequisite recorded**
> below. s2.5 and s2.6 are filled from the last run (see the scoreboard). Every stop
> along the way was a k3sm or runtimed property of the `vm` RuntimeClass that only a
> real operator image could show; they are listed run by run under "What k3sm refused,
> run by run" and summarized under "Gaps recorded for k3sm and runtimed". The chart, its
> images and the example are exactly the pin's; nothing was hand-written. Re-running
> the script overwrites rig state under `$PREFIX`; it does not rewrite this file.

> **Rig substitution.** The host named under Rig below is not the sanctioned M16 rig
> (the laptop dev Mac: Apple M2, 8 CPU, 8 GiB): it is an
> outside machine with roughly **8x** that memory budget (Apple M4 Max, 64 GiB), the
> exact constraint the sanctioned rig's second rung exists to exercise. Whether these
> runs stand as recorded on that substitute, or must be re-run on the sanctioned rig
> before acceptance, is a question for the maintainers, not decided here.

> **Sanctioned-rig attempt, 2026-09-24 (recorded separately before this file merged).**
> The maintainers ran the same rung on the sanctioned rig at upstream digests. It
> exited 1 at s2.1 after 10m06s: the operator Deployment never created a Pod, because
> the rung patches the pod specs onto the darwin node only after the helm wait, and
> the cluster's admission policy rejects every Pod not selecting the darwin os label,
> so the wait can only end in the progress deadline. No later criterion ran, and the
> plan's halt condition was not reached. That attempt therefore neither confirms nor
> contradicts the runs recorded here; it shows the rung's patch ordering must move
> before the wait for a sanctioned-rig rerun to answer anything.

## Question

Does the upstream serving control plane install and run on k3sm with its operator and
frontend as `vm` Pods, **no etcd and no NATS**, Kubernetes-native discovery, live CRD
conversion, and a completion served through the frontend's ClusterIP? And what,
exactly, does installing it grant?

## Method

Rig-side over ssh: `helm upgrade --install` of the **digest-pinned** chart (a tag can
be repointed, and these images carry cluster RBAC) with `etcd.install=false`,
`nats.install=false` and `discoveryBackend=kubernetes`; every control-plane Pod
patched onto `runtimeClassName: vm` with an explicit memory request; then the CRD
Established checks with **every GVK recorded**, a full `ClusterRole` dump, a
v1alpha1 read of a v1beta1 object, the chart's own CPU-only mocker deployment, and a
completion through the frontend's ClusterIP with the worker's log inspected for the
frontend's dial to its **published address**.

## Halt (binding, substitution pre-decided)

Discovery or the frontend→worker dial fails → **R4(b)**: the native-Darwin control
plane as a second `hack/images/` entry.

## Scoreboard

| criterion | verdict | evidence |
|---|---|---|
| s2.1 chart installed; control plane Ready as `vm` Pods with memory requests | **PASS** (substitution: external webhook certificate) | `helm upgrade --install` by digest with `etcd.install=false nats.install=false discoveryBackend=kubernetes`; the operator Deployment patched onto `runtimeClassName: vm`, `kubernetes.io/os=darwin`, the provider toleration and a 512Mi request; `m16-dynamo-operator-controller-manager` 1/1 Running on every run from run 6 on. Stock main refused the Pod twice before that (`spec.serviceAccountName` downward-API field, then no kubernetes Service env); with the chart's own cert-controller the Pod never became Ready (k3sm materializes a Secret volume once); see the substitutions section |
| s2.2 every chart CRD Established | **PASS** | all **6** chart CRDs Established, live, on every run from run 6 on; the GVK table below is the apiserver's answer and matches `pkg/mlxfleet`'s pins byte for byte (`hack/spike/m16` run 6, `crds-live.txt`) |
| s2.3 operator `ClusterRole` dumped; wildcards / secrets called out | RECORDED | 12 ClusterRoles dumped; `manager-role` has 51 rules over 22 API groups, **no wildcard** verb, resource or group; `secrets` create/get/list/update/watch + delete/patch cluster-wide (the operator's built-in cert-controller writes `webhook-server-cert`); the cert-manager Role is namespaced. Verbatim below; equal to `pkg/mlxfleet`'s pinned grant |
| s2.4 a v1alpha1 read answered by the conversion webhook | **PASS** (live, runs 8–11) | `kubectl get dynamocomponentdeployments.v1alpha1.nvidia.com <the graph's first component>` returned through the operator's conversion webhook, a `vm` Pod behind a ClusterIP Service with the CA the spike minted; the apiserver's reply carried its own `nvidia.com/v1alpha1 DynamoComponentDeployment is deprecated` warning, which is the v1alpha1 route answering |
| s2.5 a completion through the frontend's ClusterIP | **FAIL** — discovery completed, the model never materialized (runs 11–12) | the worker registered (DynamoWorkerMetadata + EndpointSlice present, model card published, `/v1/metadata` served on its system port) and the frontend saw the instance within a second; `/v1/models` answered 200 after 100 s and listed nothing for the remaining 450 s while the frontend's discovery controller retried every 30 s on `fetching http://192.168.64.16:9090/v1/metadata/…/config.json: tcp connect error: No route to host (os error 113)` — the worker's self-detected address is its guest's NAT lease, and another guest cannot reach it. All three Pods stayed Running 1/1 throughout |
| s2.6 the frontend's dial observed in the worker's own log | **FAIL** — the dial is the failure above, seen from the frontend's side | the script's s2.6 step did not run (s2.5 exits on its red), so this cell is filled from the frontend's own log rather than the worker's: the frontend dialed the worker at the address the worker published, `192.168.64.16:9090`, and got EHOSTUNREACH fourteen times over five minutes. The worker's log shows no inbound connection. This is the pre-decided halt: **R4(b) applies** |

## Substitutions taken (recorded on the verdict lines, off by default)

The rung is the chart and the example as shipped; each substitution stands in for one
k3sm property that stopped the run, is switched on by one variable, and is printed as a
`RECORDED` line whenever it is taken.

| knob | stands in for | what the spike does |
|---|---|---|
| `K3SM_M16_WEBHOOK_CERT=external` | k3sm materializes a Secret volume once, at pod creation, and never refreshes it, so the operator's cert-controller writes `webhook-server-cert` and then waits forever for the kubelet to project it (run 4: nine minutes, six liveness restarts) | mints a CA and a server certificate for the webhook Service's in-cluster names (30 days), creates the Secret before install, installs in the chart's external-certificate mode and passes the CA bundle; the conversion CA is injected by the operator from the same Secret |
| `K3SM_M16_POD_RUNASUSER=<node uid>` | four `vm`-class refusals met in turn (runs 6–11): the foreign-user guard refuses the operator's default `fsGroup: 1000`; runtimed refuses any fsGroup on the vm class (no idmapped mounts on Apple's virtiofs); runtimed refuses the image's named `USER dynamo`; and the rootfs lower keeps the host tree's root ownership and 0755 modes because the ownership sidecar is never applied in-guest, so uid 250 can write nowhere in the image | sets `securityContext.runAsUser` to the node's pod-execution uid on the example's pod templates — the operator injects none of its defaults once a template supplies any securityContext — and points `HOME`, `TMPDIR` and `HF_HOME` at the chart's Memory emptyDir (`/dev/shm`, a guest tmpfs mounted `mode=1777`), the one directory that uid can write |
| prerequisite, not a substitution | the example's decode pod reads `hf-token-secret` through a required `envFrom`; the upstream install pages create it by hand | creates the Secret with an **empty** `HF_TOKEN` (huggingface_hub reads an empty token as unset; the mocker fetches only `config.json` and the tokenizer files, from a public, ungated repo) |

## What k3sm refused, run by run

Single-node dev tier, `k3sm dev up --datapath` as root, chart pulled by digest. "tree"
names what the node ran: `main` at c142f19, then the fixes S2 itself produced.

| run | tree | stopped at | what it showed | disposition |
|---|---|---|---|---|
| 1 | main | `helm install` | the chart's pods carry no `kubernetes.io/os=darwin` nodeSelector; `k3sm-require-os-darwin` refuses them as shipped | script: install, patch, then wait |
| 2 | main | pod translation | `spec.serviceAccountName` downward-API field unresolved; every later verdict vacuous (0 CRDs, manifest search hit a docs page) | k3sm #447 |
| 3 | main + #447 | guest boot | no `KUBERNETES_SERVICE_HOST`/`_PORT` in any pod: the kubelet's Service env was never injected, so no in-cluster client-go ever worked; `crd-apply` init dies | fix ready (stacked on #447) |
| 4 | + svc-env | status | a pod-level runtimed refusal left the pod tracked; the status sync overwrote `ProviderFailed` with `ContainerCreating` forever | fix ready |
| 4 | + svc-env | readiness | Secret volumes are materialized once at pod creation and never refreshed; the operator's cert-controller waited 9 min through 6 liveness restarts | gap; substitution: external certificate |
| 5–6 | + untrack | mocker pods | operator Ready, 6 CRDs Established, ClusterRole dumped, graph accepted, frontend Service created — and no Pod: the operator's default `fsGroup: 1000` is refused by `k3sm-reject-foreign-user`, silently from the operator's side | gap |
| 7 | + untrack | the node | pods reach runtimed for the first time; `fsGroup` refused outright on the vm class (`fsGroup is not supported on the vm RuntimeClass on this platform: applying it requires idmapped mounts, and this host's virtiofs rejects them`); decode also needs the example's `hf-token-secret` | M11 S3 gate; Secret created |
| 8 | + untrack | the image | **s2.4 passes live**; runtimed refuses the image's named `USER dynamo` (`the image runs as a named user the host cannot resolve and the guest cannot be told`); the frontend's first pull loses a rename race with the decode pod's pull of the same image | named user: documented future work; **pull race: new runtimed bug** |
| 9 | + untrack | the container | templates get `runAsUser=<node uid>`; **both containers start** and exit 1: `No usable temporary directory found in ['/tmp', '/var/tmp', '/usr/tmp', '/workspace']` — the image's `/tmp` is 1777 but the rootfs lower shows the host tree's `root 0755`, because the Linux dialect's ownership sidecar is written beside the snapshot and applied nowhere in-guest (`runtimed/docs/PHASES.md` M11.2-d4 — the ownership sidecar, `ownership.jsonl`, apply step; not the native-sidecar-container concept at k3sm's own `docs/PHASES.md` M10.2) | **new runtimed gap** |
| 10 | + untrack | the script | with `TMPDIR`/`HF_HOME` on the tmpfs the **frontend is Running and Ready** 72 s after creation, its Kubernetes discovery daemon watching EndpointSlices and DynamoWorkerMetadata; the script took the first 200 from `/v1/models` (an empty list) as discovery complete and asked for a completion against no model (404). The decode pod lost the pull race again at +42 s and k3sm's back-off retry had its container running at +88 s | script: wait for a listed model |
| 11 | + untrack | the frontend's cache | **all three pods Running 1/1**; the worker registered (DynamoWorkerMetadata + EndpointSlice, model card published, endpoint on its guest address `192.168.64.15:42759`, not its pod IP `100.64.0.5`); the frontend saw the instance, then retried every 30 s on `creating MDC blobs dir /home/dynamo/.cache/dynamo/mdc/blobs: Permission denied` — the model-card cache is `$HOME/.cache/dynamo/mdc`, HOME only | HOME moves to the tmpfs |
| 12 | + untrack | **the dial** | with `HOME` on the tmpfs too, the frontend materialized nothing for a different reason: every fetch of the worker's model card at `http://192.168.64.16:9090/v1/metadata/…` failed `No route to host`. The worker bound and published its guest lease (`192.168.64.16`, eth0); the frontend sits at `192.168.64.17` on the same NAT segment; darwin-net's own measurement (`pkg/podnet/doc.go:152`, `docs/user/limitations.md` "from a vm Pod's guest to another vm Pod's guest on the same node: blocked") is reproduced exactly | **HALT — R4(b)** |

(A thirteenth start on 2026-09-23 never reached the cluster: helm's chart fetch failed on
`lookup nvcr.io: no such host`, a host DNS blip; the driver now resolves the registry
before stopping the installed cluster.)

## Gaps recorded for k3sm and runtimed

Each was found by running the pin's real images as `vm` Pods; none is the spike's to
fix. File:line against the trees named under Rig.

1. **`spec.serviceAccountName` downward-API field unresolved** — k3sm #447 (fix open).
2. **The kubernetes Service environment is never injected** into any pod, so in-cluster
   client-go never worked in a k3sm pod — fix branch, stacked on #447.
3. **A pod-level runtimed refusal is overwritten by the status sync** (`ProviderFailed` →
   `ContainerCreating` forever) — fix branch; it rewrites one pinned contract.
4. **Secret and ConfigMap volumes are materialized once and never refreshed** — the
   operator's cert-controller pattern (write a Secret, wait for the kubelet to project
   it) cannot complete on k3sm.
5. **The foreign-user guard applies to `vm` pods** (`pkg/policy/admission.go:786`); the
   M11 ledger already names the vm exemption as deferred. The operator's default
   `fsGroup: 1000` is refused silently from the operator's side.
6. **fsGroup is unsupported on the vm class** (`runtimed/pkg/runtime/vmcontainers.go:110`):
   the M11 S3 idmapped-mount gate, refused rather than ignored, by design.
7. **A named image `USER` is refused on the vm class** (`vmcontainers.go:427`): guest/v1
   carries numeric ids only; named as future apis work in the code.
8. **The ownership sidecar is written and never applied in-guest**
   (`runtimed/pkg/image/unpack.go:495` writes it; `ReadOwnershipSidecar` has only test
   callers; `pkg/guestinit` has no apply step; `runtimed/docs/PHASES.md` M11.2-d4 — the
   ownership sidecar (`ownership.jsonl`) apply step, not the native-sidecar-container
   concept at k3sm's own `docs/PHASES.md` M10.2 — lists it as delivered). Every file
   in a vm rootfs is root-owned with host modes, so a non-root image has no writable
   directory in its own tree.
9. **Two concurrent pulls of one reference race at the index commit**
   (`runtimed/pkg/image/index.go:437-456`: the temp name is `.index-<key>`, shared by
   both writers; the loser's rename fails ENOENT). Deterministic for a two-pod graph on
   an uncached image; k3sm's pull back-off recovers it in about 45 s.
10. **Status fidelity, three nits**: a missing required `envFrom` Secret surfaces as
    `ProviderFailed` … `file does not exist` where kubelet says
    `CreateContainerConfigError`; an `INVALID_POD_BOX` verdict on a pull retry is classed
    as pull back-off (`runtimed_pull.go:120`) so the pod reads `ImagePullBackOff` for a
    pod-spec refusal; a liveness restart leaves `restartCount` at 0.
11. **A `vm` pod that self-detects its address publishes its guest lease, and no other
    guest can reach it.** The worker bound and published its request-plane endpoint and
    its system port on `192.168.64.16`, eth0's NAT lease, while the EndpointSlice carries
    `100.64.0.5`; the frontend's dial to it failed `No route to host`. This is not a k3sm
    bug: `pkg/podnet/doc.go:152` records guest-to-guest as unreachable at L2 and L3 on
    the tested rig, `docs/user/limitations.md` publishes the same row as **blocked**, and
    the documented path between `vm` Pods is each Pod's own Service ClusterIP, which the
    guest can reach. A guest also receives no `K3SM_POD_IP` (`pkg/provider/translate.go:128`,
    the bind-discipline env is gated to distinct-/32 host-process pods) and owns no
    interface carrying its pod IP, so it has nothing routable to publish even if told to.
    The request plane dials addresses, not VIPs (S0(3)); on k3sm, a control plane whose
    components find each other by self-detected address cannot run as `vm` Pods on one
    node. That is the halt's condition.

## Consequence recorded here

**R4(b) applies**: the control plane moves to the native-Darwin build as a second
`hack/images/` entry. S1 already holds the darwin/arm64 build of the runtime at the pin
(its wheel hash recorded per build), so the halt lands on something that exists. As
native Darwin processes the frontend and the workers each get a `/32` on `lo0` and the
bind discipline that pins them to it, so a self-detected address IS the pod IP and
same-node dials stay on loopback — the property this rung found `vm` Pods cannot have.

What S2 did establish, with two substitutions, holds regardless of the halt and is what
the fleet package pins: the chart installs by digest with etcd and NATS off; the operator
runs as a `vm` Pod; the six CRDs Establish and their conversion webhook answers live; the
operator's grant is exactly the recorded one; Kubernetes-native discovery delivers a
worker's registration to the frontend within a second of the card being published.

## The GVK strings (what `pkg/mlxfleet` pins)

The apiserver's answer on the dev tier (runs 6–11; `kubectl get crd -o json` reduced by
`s2.sh`), identical to `deploy/operator/config/crd/bases/` at b83b1d93 and to the set
`pkg/mlxfleet` pins:

| CRD | group | kind | served | storage | conversion |
|---|---|---|---|---|---|
| dynamographdeployments | nvidia.com | DynamoGraphDeployment | v1alpha1, v1beta1 | v1beta1 | Webhook (`dynamo-operator-webhook-service` `/convert`) |
| dynamocomponentdeployments | nvidia.com | DynamoComponentDeployment | v1alpha1, v1beta1 | v1beta1 | Webhook |
| dynamographdeploymentrequests | nvidia.com | DynamoGraphDeploymentRequest | v1alpha1, v1beta1 | v1beta1 | Webhook |
| dynamographdeploymentscalingadapters | nvidia.com | DynamoGraphDeploymentScalingAdapter | v1alpha1, v1beta1 | v1beta1 | Webhook |
| dynamomodels | nvidia.com | DynamoModel | v1alpha1 | v1alpha1 | None |
| dynamoworkermetadatas | nvidia.com | DynamoWorkerMetadata | v1alpha1 | v1alpha1 | None |

The plan's S2 row expects **nine** CRDs to reach Established; the operator image at
v1.5.0 ships **six** (`deploy/operator/Dockerfile` copies exactly
`config/crd/bases/`, and that directory holds six). The count in the row was written
against an earlier upstream ref; the pin, not the row, is the source of truth, and the
apiserver Established exactly these six.

The conversion webhook is the operator's own, behind a ClusterIP Service, with the CA
bundle injected by the operator at startup (its built-in cert mode; cert-manager is
off by default). That is precisely S0's criterion (1) on the real control plane: the
apiserver dials a service-ref conversion webhook backed by a `vm` Pod, and the
operator refuses to start without the CA injected, so a broken conversion path fails
closed rather than silently.

## The operator `ClusterRole`, verbatim

> Paste the dump here. This is the R11 input and what the golden test pins: a grant
> nobody read is a grant nobody decided. Any wildcard verb or resource, and any
> `secrets` access outside the webhook cert's namespace, is called out by name.

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: m16-dynamo-operator-manager-role
  labels:
    app.kubernetes.io/instance: m16
    app.kubernetes.io/managed-by: Helm
    app.kubernetes.io/name: dynamo-operator
    app.kubernetes.io/version: 1.5.0
    helm.sh/chart: dynamo-operator-1.5.0
rules:
- apiGroups:
  - ''
  resources:
  - configmaps
  - events
  - services
  verbs:
  - create
  - delete
  - get
  - list
  - patch
  - update
  - watch
- apiGroups:
  - ''
  resources:
  - nodes
  - pods/log
  verbs:
  - get
- apiGroups:
  - ''
  resources:
  - persistentvolumeclaims
  verbs:
  - create
  - delete
  - get
  - list
  - watch
- apiGroups:
  - ''
  resources:
  - pods
  verbs:
  - delete
  - deletecollection
  - get
  - list
  - patch
  - watch
- apiGroups:
  - ''
  resources:
  - secrets
  - serviceaccounts
  verbs:
  - create
  - get
  - list
  - update
  - watch
- apiGroups:
  - apiextensions.k8s.io
  resources:
  - customresourcedefinitions
  verbs:
  - get
  - list
  - patch
  - update
  - watch
- apiGroups:
  - apiextensions.k8s.io
  resources:
  - customresourcedefinitions/status
  verbs:
  - get
  - patch
  - update
- apiGroups:
  - apps
  resources:
  - daemonsets
  verbs:
  - get
  - list
  - watch
- apiGroups:
  - apps
  resources:
  - deployments
  verbs:
  - create
  - delete
  - get
  - list
  - patch
  - update
  - watch
- apiGroups:
  - authentication.k8s.io
  resources:
  - tokenreviews
  verbs:
  - create
- apiGroups:
  - authorization.k8s.io
  resources:
  - subjectaccessreviews
  verbs:
  - create
- apiGroups:
  - autoscaling
  resources:
  - horizontalpodautoscalers
  verbs:
  - create
  - delete
  - get
  - list
  - patch
  - update
  - watch
- apiGroups:
  - batch
  resources:
  - jobs
  verbs:
  - create
  - delete
  - get
  - list
  - patch
  - update
  - watch
- apiGroups:
  - coordination.k8s.io
  resources:
  - leases
  verbs:
  - create
  - delete
  - get
  - list
  - patch
  - update
  - watch
- apiGroups:
  - discovery.k8s.io
  resources:
  - endpointslices
  verbs:
  - get
  - list
  - watch
- apiGroups:
  - events.k8s.io
  resources:
  - events
  verbs:
  - create
  - delete
  - get
  - list
  - patch
  - update
  - watch
- apiGroups:
  - grove.io
  resources:
  - clustertopologybindings
  - podcliques
  - podcliquescalinggroups
  verbs:
  - get
  - list
  - watch
- apiGroups:
  - grove.io
  resources:
  - podcliques/scale
  - podcliquescalinggroups/scale
  verbs:
  - get
  - patch
  - update
- apiGroups:
  - grove.io
  resources:
  - podcliquesets
  verbs:
  - create
  - delete
  - get
  - list
  - patch
  - update
  - watch
- apiGroups:
  - inference.networking.k8s.io
  resources:
  - inferencepools
  verbs:
  - create
  - delete
  - get
  - list
  - patch
  - update
  - watch
- apiGroups:
  - leaderworkerset.x-k8s.io
  resources:
  - leaderworkersets
  verbs:
  - create
  - delete
  - get
  - list
  - patch
  - update
  - watch
- apiGroups:
  - networking.istio.io
  resources:
  - destinationrules
  - virtualservices
  verbs:
  - create
  - delete
  - get
  - list
  - patch
  - update
  - watch
- apiGroups:
  - networking.k8s.io
  resources:
  - ingressclasses
  - ingresses
  verbs:
  - create
  - delete
  - get
  - list
  - patch
  - update
  - watch
- apiGroups:
  - nvidia.com
  resources:
  - dynamocomponentdeployments
  - dynamographdeploymentrequests
  - dynamographdeployments
  - dynamographdeploymentscalingadapters
  - dynamomodels
  verbs:
  - create
  - delete
  - get
  - list
  - patch
  - update
  - watch
- apiGroups:
  - nvidia.com
  resources:
  - dynamocomponentdeployments/finalizers
  - dynamographdeploymentrequests/finalizers
  - dynamographdeployments/finalizers
  - dynamomodels/finalizers
  verbs:
  - update
- apiGroups:
  - nvidia.com
  resources:
  - dynamocomponentdeployments/status
  - dynamographdeploymentrequests/status
  - dynamographdeployments/status
  - dynamographdeploymentscalingadapters/status
  - dynamomodels/status
  verbs:
  - get
  - patch
  - update
- apiGroups:
  - nvidia.com
  resources:
  - podsnapshots
  verbs:
  - delete
  - get
  - list
  - patch
  - watch
- apiGroups:
  - nvidia.com
  resources:
  - snapshotjobs
  verbs:
  - create
  - delete
  - get
  - list
  - patch
  - watch
- apiGroups:
  - rbac.authorization.k8s.io
  resources:
  - clusterroles
  verbs:
  - get
  - list
  - watch
- apiGroups:
  - rbac.authorization.k8s.io
  resources:
  - rolebindings
  verbs:
  - create
  - delete
  - get
  - list
  - update
  - watch
- apiGroups:
  - rbac.authorization.k8s.io
  resources:
  - roles
  verbs:
  - create
  - get
  - list
  - update
  - watch
- apiGroups:
  - resource.k8s.io
  resources:
  - deviceclasses
  - resourceclaims
  verbs:
  - get
  - list
  - watch
- apiGroups:
  - resource.k8s.io
  resources:
  - resourceclaimtemplates
  verbs:
  - create
  - delete
  - get
  - list
  - patch
  - update
  - watch
- apiGroups:
  - scheduling.run.ai
  resources:
  - queues
  verbs:
  - get
  - list
- apiGroups:
  - scheduling.volcano.sh
  resources:
  - podgroups
  verbs:
  - create
  - delete
  - get
  - list
  - patch
  - update
  - watch
- apiGroups:
  - ''
  resources:
  - persistentvolumeclaims
  verbs:
  - patch
  - update
- apiGroups:
  - ''
  resources:
  - secrets
  verbs:
  - delete
  - patch
- apiGroups:
  - ''
  resources:
  - endpoints
  verbs:
  - get
  - list
  - watch
- apiGroups:
  - ''
  resources:
  - serviceaccounts
  verbs:
  - delete
  - patch
- apiGroups:
  - admissionregistration.k8s.io
  resources:
  - mutatingwebhookconfigurations
  verbs:
  - create
  - delete
  - get
  - list
  - patch
  - update
  - watch
- apiGroups:
  - apiextensions.k8s.io
  resources:
  - customresourcedefinitions
  verbs:
  - create
  - delete
  - get
  - list
  - patch
  - update
  - watch
- apiGroups:
  - ''
  resources:
  - pods
  verbs:
  - create
  - update
- apiGroups:
  - inference.networking.x-k8s.io
  resources:
  - inferencepools
  - inferenceobjectives
  - inferencemodelrewrites
  verbs:
  - get
  - list
  - watch
- apiGroups:
  - nvidia.com
  resources:
  - dynamoworkermetadatas
  verbs:
  - create
  - delete
  - get
  - list
  - patch
  - update
  - watch
- apiGroups:
  - nvidia.com
  resources:
  - dynamocomponentdeployments/finalizers
  - dynamographdeploymentrequests/finalizers
  - dynamographdeployments/finalizers
  - dynamomodels/finalizers
  verbs:
  - update
- apiGroups:
  - nvidia.com
  resources:
  - dynamocomponentdeployments/status
  - dynamographdeploymentrequests/status
  - dynamographdeployments/status
  - dynamographdeploymentscalingadapters/status
  - dynamomodels/status
  verbs:
  - get
  - patch
  - update
- apiGroups:
  - nvidia.com
  resources:
  - dynamographdeploymentscalingadapters/scale
  verbs:
  - get
  - patch
  - update
- apiGroups:
  - rbac.authorization.k8s.io
  resources:
  - clusterrolebindings
  verbs:
  - create
  - delete
  - get
  - list
  - patch
  - update
  - watch
- apiGroups:
  - rbac.authorization.k8s.io
  resources:
  - clusterroles
  verbs:
  - create
  - delete
  - patch
  - update
- apiGroups:
  - rbac.authorization.k8s.io
  resources:
  - rolebindings
  verbs:
  - patch
- apiGroups:
  - rbac.authorization.k8s.io
  resources:
  - roles
  verbs:
  - delete
  - patch
```

## Rig

| | |
|---|---|
| host | the M16 rig, reached over the harness's ssh path (`K3SM_M16_HOST`; a local shim for these runs) |
| SoC / memory | Apple M4 Max, 64 GiB (Mac16,6) |
| macOS | 26.6.2 |
| k3sm | single-node **dev tier**, `k3sm dev up --datapath` as root (pods run as the node's pod-execution uid 250); tree = `main` c142f19 + #447 + the Service-env and untrack fixes; guest kernel/initramfs at the pinned set |
| chart | `oci://nvcr.io/nvidia/ai-dynamo/dynamo-platform@sha256:ff09c3bd…` (v1.5.0); images by the chart's own digests; example `examples/backends/mocker/deploy/agg.yaml` at b83b1d93 |
| dates (local) | 2026-09-21 → 2026-09-23, twelve runs |

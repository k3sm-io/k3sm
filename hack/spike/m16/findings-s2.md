# S2 findings — the control plane on k3sm, GPU-free (M16.0-d3)

> **Status: RUN 2026-09-21, blocked at s2.1 on stock k3sm; rerun pending.** On the
> single-node dev Mac named under Rig the chart installs, but the operator Pod is
> refused by k3sm's own env resolver: the chart's operator container reads
> `spec.serviceAccountName` through the downward API and k3sm did not resolve that
> field (fix: PR #447). With no operator Pod there is no `crd-apply` init, so s2.2
> onward ran against an empty CRD list and their verdicts below are **artifacts of
> s2.1**, not answers. The rerun is against a tree carrying #447. The GVK table below
> is taken from the CRD sources at the pin, marked as such, until the live rerun
> confirms it. Re-running the script overwrites rig state under `$PREFIX`; it does
> not rewrite this file.

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
| s2.1 chart installed; control plane Ready as `vm` Pods with memory requests | FAIL (k3sm, fixed in #447) | `helm upgrade --install` by digest with `etcd.install=false nats.install=false discoveryBackend=kubernetes` succeeded; the operator Pod sat `Pending` / `ProviderFailed` with `unsupported downward-API field path "spec.serviceAccountName"` (the `manager` container injects `POD_SERVICE_ACCOUNT` from that field). The chart's Pods also carry no `kubernetes.io/os=darwin` nodeSelector, so k3sm's `require-os-darwin` policy refuses them until the post-install patch adds it (script fixed to install, patch, then wait) |
| s2.2 every chart CRD Established | NOT REACHED | 0 CRDs present: at this pin the chart templates none; the operator Deployment's `crd-apply` initContainer applies six from the operator image, and that Pod never ran |
| s2.3 operator `ClusterRole` dumped; wildcards / secrets called out | RECORDED | 12 ClusterRoles dumped; `manager-role` has 51 rules over 22 API groups, **no wildcard** verb, resource or group; `secrets` create/get/list/update/watch + delete/patch cluster-wide (the operator's built-in cert-controller writes `webhook-server-cert`); the cert-manager Role is namespaced. Verbatim below |
| s2.4 a v1alpha1 read answered by the conversion webhook | NOT REACHED | the run recorded "no CRD serves two versions" because the CRD list was empty; the sources say four of six do (below) |
| s2.5 a completion through the frontend's ClusterIP | NOT REACHED | the manifest search matched a docs page; fixed to `examples/*.yaml` |
| s2.6 the frontend's dial observed in the worker's own log | NOT REACHED | |

## The GVK strings (what `pkg/mlxfleet` pins)

From `deploy/operator/config/crd/bases/` at b83b1d93 (**source, not live**; the rerun
replaces this with the apiserver's answer):

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
rerun reports whatever the apiserver Establishes.

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
| host | the M16 rig, reached over the harness's ssh path (`K3SM_M16_HOST`) |
| SoC / memory | Apple M4 Max, 64 GiB (Mac16,6) |
| macOS | 26.6.2 |
| k3sm | the installed cluster (stock main at the time of the run) |
| date (UTC) | 2026-09-21 |

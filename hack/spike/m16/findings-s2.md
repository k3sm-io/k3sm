# S2 findings — the control plane on k3sm, GPU-free (M16.0-d3)

> **Status: NOT YET RUN.** Write-back target for `hack/spike/m16/s2.sh`.

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
| s2.1 chart installed; control plane Ready as `vm` Pods with memory requests | | |
| s2.2 every chart CRD Established | | |
| s2.3 operator `ClusterRole` dumped; wildcards / secrets called out | | |
| s2.4 a v1alpha1 read answered by the conversion webhook | | |
| s2.5 a completion through the frontend's ClusterIP | | |
| s2.6 the frontend's dial observed in the worker's own log | | |

## The GVK strings (what `pkg/mlxfleet` pins)

| CRD | group | kind | served | storage | conversion |
|---|---|---|---|---|---|
| | | | | | |

## The operator `ClusterRole`, verbatim

> Paste the dump here. This is the R11 input and what the golden test pins: a grant
> nobody read is a grant nobody decided. Any wildcard verb or resource, and any
> `secrets` access outside the webhook cert's namespace, is called out by name.

```yaml
```

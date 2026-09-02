# Storage

Persistent storage in k3sm uses a **local-path** provisioner with **node affinity**.

## Storage model

- **ConfigMaps and Secrets** are served by the apiserver and materialized into the Pod by the node.
- **`emptyDir` and projected volumes** work as ephemeral per-Pod storage.
- **PersistentVolumes** use a **local-path** provisioner: a PVC is satisfied by a directory on a node's
  APFS filesystem, and the resulting PV carries **node affinity** pinning it to the node that holds the
  data.

## Node affinity is load-bearing

Because a local-path PV lives on one node's disk, a Pod that mounts it can only be scheduled onto **that
node**. In a [multi-node](multi-node.md) cluster this means stateful Pods are pinned to wherever their
data lives — plan placement accordingly.

## Every claim must name the class

`local-path` is **not** marked as the cluster's default StorageClass. That is deliberate: a PVC that did
not ask for node-local storage is never silently bound to a volume that pins its Pod to one machine.

The practical consequence is that **`storageClassName: local-path` is required on every PVC**. A claim
that omits it matches no class, stays `Pending` indefinitely, and the Pod that mounts it reports
`pod has unbound immediate PersistentVolumeClaims` — which names the symptom, not this cause.

```sh
kubectl get storageclass    # local-path, with no (default) marker — by design
```

## Example

```yaml
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: data
spec:
  accessModes: ["ReadWriteOnce"]
  storageClassName: local-path
  resources:
    requests:
      storage: 1Gi
```

Mount it in a Pod as usual; the provisioner allocates a local-path PV with node affinity.

A claim mounted by a `runtimeClassName: vm` Pod works the same way and is reached over a virtiofs share
rather than a bind mount. Its data is durable across the Pod's lifetime: files written in the guest land
on the host under the claim's directory, owned by the `_k3sm` service user. See
[`vm` RuntimeClass](vm-runtimeclass.md) for the ownership ceilings that follow from that.

## What is not supported (yet)

- **Volume resize, snapshots, and generic ephemeral volumes** are **planned**, not present — see
  [Limitations](limitations.md).
- **`hostPath` bind mounts** and `terminationMessagePath` file mounts are a documented ceiling on the
  native substrate (no Linux bind mounts) — see [Limitations](limitations.md).
- Networked / distributed storage classes are out of scope for the local-path model.

## Next

- [Concepts](concepts.md) — the storage model in context.
- [Backup & restore](backup-restore.md) — the control-plane datastore (distinct from PV data).
- [Limitations](limitations.md) — the storage ceilings.

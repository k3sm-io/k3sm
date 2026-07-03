# Storage

Persistent storage in k3sm uses a **local-path** provisioner with **node affinity**.

## The model

- **ConfigMaps and Secrets** are served by the apiserver and materialized into the Pod by the node.
- **`emptyDir` and projected volumes** work as ephemeral per-Pod storage.
- **PersistentVolumes** use a **local-path** provisioner: a PVC is satisfied by a directory on a node's
  APFS filesystem, and the resulting PV carries **node affinity** pinning it to the node that holds the
  data.

## Node affinity is load-bearing

Because a local-path PV lives on one node's disk, a Pod that mounts it can only be scheduled onto **that
node**. In a [multi-node](multi-node.md) cluster this means stateful Pods are pinned to wherever their
data lives — plan placement accordingly.

## Example

```yaml
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: data
spec:
  accessModes: ["ReadWriteOnce"]
  resources:
    requests:
      storage: 1Gi
```

Mount it in a Pod as usual; the provisioner allocates a local-path PV with node affinity.

## What is not supported (yet)

- **Volume resize, snapshots, and generic ephemeral volumes** are **planned**, not present — see
  [limitations.md](limitations.md).
- **`hostPath` bind mounts** and `terminationMessagePath` file mounts are a documented ceiling on the
  native substrate (no Linux bind mounts) — see [limitations.md](limitations.md).
- Networked / distributed storage classes are out of scope for the local-path model.

## Next

- [concepts.md](concepts.md) — the storage model in context.
- [backup-restore.md](backup-restore.md) — the control-plane datastore (distinct from PV data).
- [limitations.md](limitations.md) — the storage ceilings.

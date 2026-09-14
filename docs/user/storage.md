# Storage

Persistent storage in k3sm uses a **local-path** provisioner with **node affinity**.

## Storage Model

- **ConfigMaps and Secrets** are served by the apiserver and materialized into the Pod by the node.
- **`emptyDir` and projected volumes** work as ephemeral per-Pod storage.
- **PersistentVolumes** use a **local-path** provisioner: a PVC is satisfied by a directory on a node's
  APFS filesystem, and the resulting PV carries **node affinity** pinning it to the node that holds the
  data. Binding is `WaitForFirstConsumer`, so the scheduler picks the node before the volume exists.

## Node Affinity Pins the Pod

Because a local-path PV lives on one node's disk, a Pod that mounts it can only be scheduled onto **that
node**. In a [multi-node](multi-node.md) cluster this means stateful Pods are pinned to wherever their
data lives, so plan placement accordingly.

## Capacity Is Best-Effort

PersistentVolume data and the kine datastore share one APFS volume, so a volume that grows without
bound can fill the disk the datastore sits on. `capacity.storage` records what the claim asked for; it
is not a quota. Over-commit is not refused when the volume binds. It surfaces later as a write
failure (`ENOSPC`) inside the Pod. See [The Data Volume](#the-data-volume) below for how to bound it.

## The Data Volume

`sudo k3sm install --data-volume` puts the data root on a dedicated APFS volume instead of a plain
directory on the boot disk. It creates a case-sensitive APFS volume in the boot container, mounts
it at `/var/lib/k3sm` with `nobrowse,nosuid,nodev`, and hides it from Finder. Spotlight does not
index the volume: it is mounted `nobrowse` and carries a `.metadata_never_index` marker. Time
Machine excludes it: k3sm sets the exclusion attribute on the mountpoint.

The volume carries a **quota**, 100 GiB by default, set with `--data-volume-size` (a floor of 32
GiB is enforced, because runtimed's reclaim ladder and the node's DiskPressure floor are absolute
byte counts and a smaller volume would live permanently inside the band that triggers reclamation).
The quota is what makes "bounded" true: without one, a volume can still grow to fill its container,
which is exactly the plain-directory posture this feature replaces. `k3sm image prune` reclaims
space by removing unused image layers, but the kine datastore and PersistentVolume data only grow,
so watch them yourself. `k3sm status` warns once usage passes 90% of the quota.

APFS fixes a volume's quota at creation; no `diskutil` command changes it afterward. To use a
different size, back up your data, run `sudo k3sm datavol delete --yes`, reinstall with
`--data-volume-size`, and restore. See [Backup & restore](backup-restore.md).

If `/var/lib/k3sm` already holds data as a plain directory, install migrates it onto the new
volume: it stops the daemons, copies the tree, and verifies the copy (file counts, sizes, modes,
and a hash of the kine datastore) before renaming the old tree aside to
`/var/lib/k3sm.pre-volume`. It stays there until you remove it; `k3sm status` shows it as a
`pre-volume` row with its size and age. Expect the cluster to be down for the length of the copy.
Pass `--remove-old-data-root` to delete the old tree automatically once the copy verifies.

`--data-volume-encrypt` creates the volume with a random passphrase, generated locally and kept in
the System keychain, which unlocks the volume at boot. Any root process on the booted Mac can
still read that passphrase through `security`. Without the flag, the volume is still
hardware-encrypted on Apple silicon (every APFS volume is), but that encryption is not gated on
your FileVault password, so do not assume FileVault protects your cluster data unless you pass
`--data-volume-encrypt`. Migrating an existing data root onto an encrypted volume requires
`--remove-old-data-root`, because a plaintext copy of the same data sitting beside an encrypted
volume is not encryption.

The volume is declared twice: an `/etc/fstab` line, so `diskarbitrationd` and an older k3sm binary
both still mount it, and a k3sm record that carries the volume's name, quota, and encryption state
for `k3sm status` to report. A LaunchDaemon, `io.k3sm.datavol`, mounts the volume at boot; `k3sm
status` shows it as a `datavol` row, `ok` once it has mounted successfully, `fail` if the last run
did not, with a remedy of `sudo k3sm datavol mount`.

Three commands manage the volume directly:

- `sudo k3sm datavol mount` mounts the recorded volume; it is what `io.k3sm.datavol` runs at boot,
  and it is safe to run by hand at any time.
- `k3sm datavol status` reports the volume, its quota, its usage, and any leftover pre-migration
  copy, without privilege.
- `sudo k3sm datavol delete --yes` destroys the volume and every declaration of it. It never
  touches a `.pre-volume` copy.

`sudo k3sm uninstall` keeps the volume mounted and declared, and prints both `sudo k3sm install
--data-volume` to reinstall onto it and `sudo k3sm datavol delete --yes` to remove it for good.

If you already declared a volume in `/etc/fstab` by hand, it keeps working: `sudo k3sm install
--data-volume` adopts it on the next run and keeps your existing fstab line rather than replacing
it.

## Every Claim Must Name the Class

`local-path` is **not** marked as the cluster's default StorageClass, so a PVC that did not ask for
node-local storage is never silently bound to a volume that pins its Pod to one machine.

Every PVC therefore needs **`storageClassName: local-path`**. A claim that omits it matches no class,
stays `Pending` indefinitely, and the Pod that mounts it reports
`pod has unbound immediate PersistentVolumeClaims`, which names the symptom rather than this cause.

```sh
kubectl get storageclass    # local-path, with no (default) marker, by design
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

## What Is Not Supported (Yet)

- **Volume resize, snapshots, and generic ephemeral volumes** are **planned**, not present. See
  [Limitations](limitations.md).
- **`hostPath` bind mounts** and `terminationMessagePath` file mounts are a documented ceiling on the
  native substrate (no Linux bind mounts). See [Limitations](limitations.md).
- Networked / distributed storage classes are out of scope for the local-path model.

## Next

- [Concepts](concepts.md) puts the storage model in context.
- [Backup & restore](backup-restore.md) covers the control-plane datastore, which is distinct from PV data.
- [Limitations](limitations.md) lists the storage ceilings.

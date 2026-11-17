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
  copy, without privilege. `-o json` prints the same report as `record` (the declaration, or
  `null`), `mounted`, `statfs` (present only while mounted: `totalBytes`, `availBytes`, `usedBytes`
  and `usedSource`, which is `statfs`, `apfs` or `unknown`; read `usedSource` before trusting
  `usedBytes`, which is absent when no probe could measure it) and `preVolume` (`present`,
  `bytes`). Scripts and the k3sm app read this shape.
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
A Pod placed with `nodeName` skips the scheduler, so it waits on the node instead: it stays
`ContainerCreating` with a `FailedMount` Event that ends in `PVC is not bound`, and starts once the
claim binds.

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

## Host Shares for Native Pods

A native Pod is a macOS process with no mount namespace, so k3sm cannot bind a host directory to a
new path inside it. What it can do is let the Pod reach a host directory **at that directory's own
path**. The node admin decides which paths; a Pod spec cannot. The list is a root-owned file,
`/Library/k3sm.host-shares`, kept with `k3sm share`:

```sh
sudo k3sm share add /Users/you/Code/app              # read-write directory
sudo k3sm share add --read-only /Volumes/datasets    # read-only directory
sudo k3sm share add --socket /Users/you/run/app.sock # one Unix socket, connect only
sudo k3sm share remove /Users/you/Code/app
k3sm share list
```

A share covers everything below the path. When one share sits inside another, the more specific
one decides, so `--read-only` on a subdirectory of a read-write share keeps that subdirectory
read-only. k3sm refuses system and k3sm trees, `/Users` itself, a
whole home directory, a dot directory and a home's `Library`. Under `/Users` a share names a project
below a home, never the home.

### Delegating a Prefix So Later Shares Need No sudo

The node admin can delegate a directory to one user, once. After that, the user adds and removes
shares under it as themselves:

```sh
sudo k3sm share delegate --user you /Users/you/Code   # once, by the node admin
k3sm share add /Users/you/Code/app                     # later, as you, no sudo
k3sm share add --socket /Users/you/Code/run/q.sock
k3sm share remove /Users/you/Code/app
sudo k3sm share undelegate --user you                  # take it back
```

The delegation is a line in the root-owned `/Library/k3sm.host-shares`. The shares a user adds live
in a file the user owns, `/Library/k3sm.host-shares.d/<uid>/host-shares`, in a directory the
delegation creates for them. That file is not trusted. Every time a Pod is created, the node checks
each of its lines against the delegation again, and admits a line only when all of these hold:

- the path is the delegated directory or under it, in any letter case;
- no part of the path is a symlink;
- the delegated directory, and every directory from it down to the path, is owned by the delegated
  user, and the path's first part names the same directory the admin delegated;
- the path passes the same rules as any share (no system or k3sm tree, no dot directory or `Library`
  under a home, ASCII only).

A line that fails is not admitted, and `k3sm share list` shows it under "not admitted" with the
reason. Editing the file by hand therefore admits nothing `k3sm share add` would refuse.

### Limiting a Share to Namespaces

By default a share admits a Pod in any namespace. `--namespace` limits it to Pods in the namespaces
you name, and can be repeated:

```sh
sudo k3sm share add --namespace build /Volumes/datasets
k3sm share add --namespace yurei-app /Users/you/Code/app
k3sm share add --namespace team-a --namespace 'team-b-*' /Users/you/Code/shared
```

Each value is a namespace name, or a prefix pattern ending in one `*`: `team-b-*` admits every
namespace whose name starts with `team-b-`. A bare `*` is refused; leave `--namespace` out for every
namespace.

A pattern admits any namespace anyone can create with that prefix, now or later. Scope a share by a
pattern only where creating namespaces is controlled by you, the cluster operator, and end the
prefix at a hyphen (`yurei-*`, not `yurei*`, which would also admit a namespace named `yureish`). In the file a limited share is one line with a `namespaces=` field:

```text
<mode> <path> [namespaces=<ns>,<ns>,...]
rw /Users/you/Code/app namespaces=yurei-app
ro /Volumes/datasets namespaces=build,team-b-*
rw /opt/scratch
```

A line with no `namespaces=` field admits every namespace, as every line did before the field
existed, so an existing list reads and behaves the same. A `namespaces=` field that is empty,
repeats a name, or holds anything but a namespace name or a prefix pattern makes the whole file
invalid, and nothing in that file is shared, so a typo never leaves a share open to every namespace.

Namespace scope decides what the cluster can schedule onto a share. It is not isolation between
Pods on one node: every native Pod on a node runs as the same user and can reach the node's
runtime, so a Pod that is already compromised can ask for another namespace's shares. Keep
untrusted workloads off a node with shares they must not reach, or run them under the `vm`
RuntimeClass.

When a Pod mounts a `hostPath`, the node looks only at the lines that admit the Pod's namespace. A
line for other namespaces is as if it were not there, so a `--read-only` line for one namespace
narrows that namespace only. Among the lines that admit the Pod, in this order:

1. the most specific path decides;
2. on the same path, the line that names the Pod's namespace most specifically decides: an exact
   name, then a pattern (the longer prefix first), then a line for every namespace;
3. only between lines equally specific does read-write win.

So a narrower line always beats a broader one, whatever its mode: `ro /c namespaces=team-x` beside
`rw /c namespaces=team-*` gives `team-x` read-only, and `ro /c namespaces=guest-*` beside a `rw /c`
for every namespace gives every `guest-` namespace read-only. A Pod in a namespace no line
admits is refused with a `FailedHostShare` Event that names the Pod's own namespace. The Event never
says which namespaces a share does admit.

One path may have a line per namespace set, each with its own mode, so a tree can be read-write
for one namespace and read-only for others:

```text
rw /Users/you/Code namespaces=yurei-system
ro /Users/you/Code namespaces=yurei-*
```

`yurei-system` matches `yurei-*` as well, but the first line names it exactly, so it gets read-write;
every other `yurei-` namespace matches only the pattern and gets read-only, and its read-write mount
is refused.

A share for every namespace keeps admitting every namespace that no narrower line for its path
names, so a namespace you leave out of every line still gets it. To narrow a share to named
namespaces, replace it. `k3sm share add` of a path that is already listed replaces the
path's line for the same namespaces, and a line for every namespace and a namespaced line replace
each other, so adding the path with `--namespace` narrows it. Lines for other namespace sets stay.
`k3sm share remove <path>` removes every line for the path; with `--namespace` it removes only the
line for exactly those namespaces. `k3sm share list` shows each line with its namespaces.

The node admin can also cap the namespaces a delegated user's shares may name:

```sh
sudo k3sm share delegate --user you --namespaces 'yurei-*' /Users/you/Code
```

The delegation line in the root-owned file then reads
`delegate uid=<uid> user=you modes=<modes> namespaces=yurei-* /Users/you/Code`.
Under a cap, each namespace a user's share names must be within it: a name must equal a capped name
or start with a capped pattern's prefix, and a pattern must be at least as narrow as a capped
pattern (`yurei-app-*` is within `yurei-*`, `yu*` is not). A share the user adds with no
`--namespace` takes the cap. A line outside the cap is not admitted and shows under "not admitted"
in `k3sm share list`. A delegation with no `--namespaces` lets the user choose any namespaces, or
none.

Running `sudo k3sm share delegate` again for the same user and prefix replaces the delegation.
With `--namespaces` it sets the new cap. Without it, a capped delegation is refused, because the
user's shares that name no namespace would then admit every namespace; pass `--no-namespace-cap` to
drop the cap on purpose, and k3sm lists each share that widens.

Each node reads its own `/Library/k3sm.host-shares`, so each node enforces its own lines. Give every
node that may run the Pod the same lines.

Upgrade every node before you add a `namespaces=` field. A k3sm release older than the field reads
a file that has one as invalid and shares nothing from it, so a node not yet upgraded refuses those
Pods (fails closed) rather than sharing more.

The namespace and the mode are enforced by the Pod's sandbox profile, per Pod. The file permissions
`k3sm share add` sets for `_k3sm` (below) are per path: a path that is read-write for one namespace
gets the read-write entry, and a read-only line for another namespace relies on the profile, not on
the permissions, to stay read-only.

#### Per-Project Shares (Yureisha)

Yureisha runs its controller in `yurei-system` and each project in its own namespace,
`yurei-<project>`. Shared as one read-write line for every namespace, `/Users/you/Code` lets any
project's Pod write every repository. Instead, keep the code root read-write for `yurei-system`,
give every project namespace the root read-only, and give each project its own repositories
read-write:

```sh
sudo k3sm share delegate --user you --modes rw,ro,socket --namespaces 'yurei-*' /Users/you/Code   # once
k3sm share add --namespace yurei-system /Users/you/Code             # replaces the line for every namespace
k3sm share add --read-only --namespace 'yurei-*' /Users/you/Code
k3sm share add --namespace yurei-app /Users/you/Code/app
k3sm share add --namespace yurei-site /Users/you/Code/site
```

Your list then holds:

```text
rw /Users/you/Code namespaces=yurei-system
ro /Users/you/Code namespaces=yurei-*
rw /Users/you/Code/app namespaces=yurei-app
rw /Users/you/Code/site namespaces=yurei-site
```

A Pod in `yurei-app` can mount `/Users/you/Code/app` read-write, and `/Users/you/Code` or any other
repository under it only read-only. A Pod in `yurei-system` can mount the whole tree read-write. A
Pod in any namespace outside `yurei-*`, such as `default`, can mount none of it. If
`/Users/you/Code` was added by the node admin rather than under the delegation, make the first two
lines with `sudo k3sm share add` instead.

A Pod mounts a share with a `hostPath` volume whose `mountPath` equals `hostPath.path`, with no
`subPath`, and with `readOnly: true` when the share is read-only:

```yaml
spec:
  volumes:
    - name: app
      hostPath:
        path: /Users/you/Code/app
        type: Directory
  containers:
    - name: work
      image: native
      command: ["/bin/sh", "-c", "cd /Users/you/Code/app && make"]
      volumeMounts:
        - name: app
          mountPath: /Users/you/Code/app
```

The node decides the volume twice, in the node daemon before the Pod is created and in the runtime
when it writes the Pod's Seatbelt profile, both from the same file. A volume the list does not
admit, or one mounted at another path, refuses the Pod with a Warning Event whose reason is
`FailedHostShare`. Each admitted volume is recorded with a Normal `HostShareGranted` Event on the Pod
and a `host share granted` line in the node log.

The list is read when a Pod is created. A Pod that is running keeps what it was given until it is
recreated, and a Pod the node re-attaches after a restart gets only what the list holds then.

**Who owns the files.** Pods run as the `_k3sm` user, not as you, and k3sm cannot map them to your
user. The Seatbelt grant does not change file permissions, so `k3sm share add` also sets them, and
prints exactly what it changed:

- read-write: an inheritable access-control entry for `_k3sm` on the directory and on every
  directory and file under it that you own, and the same entry for you, so you keep full access to
  what a Pod creates;
- read-only: a read entry for `_k3sm`;
- socket: a connect entry for `_k3sm` on the socket;
- search for `_k3sm` on each parent directory you own that `_k3sm` cannot already pass through.

It never follows a symlink, and it leaves alone a file with more than one hard link and anything
you do not own. (`chmod -R +a` is not a safe way to do this by hand: it follows symlinks inside the
tree and puts the entry on their targets.) `k3sm share remove` takes the `_k3sm` entries back,
unless another share still covers the path; your own entries stay. `--no-acl` leaves permissions
alone. Files a Pod creates are owned by `_k3sm`. Git refuses a repository owned by another user, so
a Pod that runs git in a share sets `safe.directory` for it, for example with the environment
variables `GIT_CONFIG_COUNT=1`, `GIT_CONFIG_KEY_0=safe.directory` and `GIT_CONFIG_VALUE_0=<path>`.

**What a share is.** Every native Pod on a node runs as the same user, so a share is reachable by
every Pod that mounts it, in every namespace its line admits, and by nothing else. A namespace limit
decides which Pods the cluster can give a share to; it is not a wall between Pods on one node,
because a native Pod can reach the node's runtime directly and name another namespace there. Share only what you would let any workload you
schedule on this node read and, for a read-write share, change. `vm` Pods cannot mount host shares.

A read-write share of a repository lets a Pod change what you later run there yourself: git hooks
under `.git/hooks`, a `.envrc`, editor task files, build scripts. Treat a Pod with a read-write
share as able to run code as you the next time you work in that tree. A delegation does not change
this: it lets you, rather than the node admin, decide which of your trees every Pod on the node can
reach. A hard link inside a share reaches its file wherever that file lives. A Pod cannot make one
to a file outside its shares, but you can, to any file in a directory you can search. The node's
image store, Pod trees and volumes under `/var/lib/k3sm` are closed to every user but `_k3sm`, so
they cannot be linked. The status records, the artifact views and the node logs (which admin users
can read) can be, and a Pod could then rewrite the linked file, so delegate a prefix only to a user
you trust not to do that. A share on a
case-sensitive volume is refused, because the sandbox matches paths without regard to case.

`k3sm share` takes ASCII paths only and refuses a system, k3sm or home path in any letter case,
because APFS and the sandbox both compare paths without regard to case.

## Exposing a Pod Volume to a Host User

A host share lets a Pod reach a host directory. An exposure is the other direction: a native Pod
publishes one of its volumes to one named account on the Mac, so a tool you run there can read (or
read and write) what the Pod writes, such as a Unix socket or a status file. The node admin decides
which accounts may receive exposures from which namespaces; a Pod spec cannot.

A Pod asks for it with an inline CSI volume whose driver is `expose.k3sm.io`. k3sm handles that
driver itself, so no CSI driver or `CSIDriver` object is installed for it:

```yaml
spec:
  volumes:
    - name: sockets
      csi:
        driver: expose.k3sm.io
        volumeAttributes:
          user: you        # required: the host account that receives it
          access: read     # optional: read (the default) or read-write
  containers:
    - name: app
      image: native
      volumeMounts:
        - name: sockets
          mountPath: /var/run/app
```

The node refuses the Pod, with a Warning Event whose reason is `FailedExposure`, when the volume is
not on a native Pod, names an account the node does not have, sets an attribute other than `user`
and `access`, sets `fsType`, `readOnly: true` or `nodePublishSecretRef`, is mounted with a `subPath`
or `readOnly`, or no grant admits it. Any other CSI driver is refused as before.

The node admin grants it once, as root:

```sh
sudo k3sm expose allow --user you --namespace apps            # read
sudo k3sm expose allow --user you --namespace apps,tools --access read-write
k3sm expose list
sudo k3sm expose revoke --user you --namespace tools          # one namespace
sudo k3sm expose revoke --user you                            # the whole grant
```

The grant is a line in the root-owned `/Library/k3sm.host-shares`, beside the shares. It names the
account by uid and by its current name, so a renamed or recycled uid gets nothing; the namespaces
whose Pods may expose to it; and the highest access it may get. `allow` adds namespaces to the
account's grant and, with `--access`, sets its access (a new grant is `read`). System accounts are
refused. The node checks the grant every time a Pod is created, in the node daemon and again in the
runtime. An admitted volume is recorded with a Normal `ExposureGranted` Event naming the account,
the access and the host path.

**Where it is.** The volume lives on the host at
`/var/lib/k3sm/expose/<namespace>/<pod>/<volume>` for the Pod's lifetime: created empty when the Pod
is created and removed when it is deleted, like an `emptyDir`. The Pod reaches it at its
`mountPath`. The `expose` directory and the namespace and Pod directories below it can be passed
through but not listed, so the account reaches the path it is told and cannot see who else exposes
what.

**Read or read-write.** The account gets an inheritable access-control entry on the volume
directory, so what the Pod creates later carries it too. `read` lets it list and read; `read-write`
also lets it create, change and delete, and gives `_k3sm` the same entry so the Pod keeps access to
what the account creates. Connecting to a Unix socket needs write permission on the socket itself,
so a `read` exposure reaches a socket the Pod creates with mode 0666, and a socket with mode 0600
needs `read-write`.

**Revoke.** `revoke` removes the grant, then strips the account's entries from every live exposure
in the affected namespaces. It never follows a symlink and never goes below the volume directory,
which is 0700, so without its entry the account reaches nothing under it. It tries every live
exposure even when one fails, and any failure is an error, not a warning. Run the same `revoke`
again to finish: with no grant left it still removes the account's remaining entries. A Pod that is running keeps its directory until it is recreated, and a Pod
created after the revoke is refused.

**What remains.** An account with a `read-write` exposure can create files in it, so the hard-link
risks of a read-write share apply there too. Files in an exposure are owned by `_k3sm`; a user who
knows their path and has a read-write share could hard-link one the account can read into that
share, and a Pod that mounts the share could then rewrite it. A program in the Pod that resolves the
real path of its mount sees the host path.

## What Is Not Supported (Yet)

- **Volume resize, snapshots, and generic ephemeral volumes** are **planned**, not present. See
  [Limitations](limitations.md).
- **`hostPath` bind mounts** and `terminationMessagePath` file mounts are a documented ceiling on the
  native substrate (no Linux bind mounts). A native Pod can reach a host directory only through a
  host share, at its own path (above). See [Limitations](limitations.md).
- Networked / distributed storage classes are out of scope for the local-path model.

## Next

- [Concepts](concepts.md) puts the storage model in context.
- [Backup & restore](backup-restore.md) covers the control-plane datastore, which is distinct from PV data.
- [Limitations](limitations.md) lists the storage ceilings.

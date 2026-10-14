# Install

How k3sm installs, and why it needs admin rights only once.

## One-Time Admin Step

k3sm runs **without per-command `sudo`**. A single privileged install creates the accounts and
daemons that everything after it runs under:

```sh
sudo k3sm install
```

The install script cannot pass extra flags, so if you want the data root on its own size-capped
APFS volume, run `sudo k3sm install --data-volume` after the script, or in place of it if you
already have the binary. See [The Data Volume](storage.md#the-data-volume).

That step:

- creates the dedicated unprivileged **`_k3sm`** user,
- installs the minimal root networking helper (`k3sm-netd`, the `io.k3sm.netd` LaunchDaemon) and
  the `_k3sm` LaunchDaemon that runs the node: `io.k3sm.server` on the control-plane Mac, or
  `io.k3sm.agent` on a worker installed with `--agent` (`RunAtLoad` / `KeepAlive`, boot-surviving),
- with `--data-volume`, installs the root `io.k3sm.datavol` LaunchDaemon, which mounts the data
  volume at boot,
- links **`/usr/local/bin/k3sm`** so `k3sm` is a command your shell can find,
- writes an **admin kubeconfig** to the invoking user's home directory.

After install, `k3sm kubectl …` and Pod lifecycle run as you / `_k3sm` with **no `sudo`**.
[The privilege model](../privilege-model.md) documents the full trust model. It is the same
privileged-helper pattern the desktop container tools and Linux VM managers use, applied to k3sm,
and one residual limitation remains (no per-pod uid isolation).

## What Gets Installed Where

- The `k3sm` binary in **`/Library/k3sm`** (`root:wheel`), whichever channel delivered it (with the
  script, pin `K3SM_INSTALL_VERSION` to reinstall a prior release, since the assets stay on GitHub
  Releases; the planned Homebrew channel will retain the previous version, so rollback there will
  not need a rebuild).
- The launcher, a symlink **`/usr/local/bin/k3sm` → `/Library/k3sm/k3sm`**. `/usr/local/bin` is
  the first entry in `/etc/paths`, so every terminal opened after the install finds `k3sm` with no
  profile edit; a terminal that was already open may need `hash -r` or simply a new window. Because
  it is a symlink rather than a copy, the daemons and your shell always run the same binary. If
  something other than a symlink already sits at that path, install refuses to replace it and says so.
  The directory holding the launcher must be owned by `root` and not writable by anyone else,
  because root's PATH searches it: anyone who can write there could leave a `k3sm` of their own for
  a later `sudo k3sm …` to run. A Mac whose Homebrew uses the x86_64 `/usr/local` prefix usually has a `/usr/local/bin`
  owned by the user who installed Homebrew, so install stops before writing anything and prints the
  exact `chown`/`chmod` to run (`sudo chown root:wheel /usr/local/bin && sudo chmod 755 /usr/local/bin`).
- LaunchDaemons under the `io.k3sm.*` reverse-DNS labels. The control plane's plist is `0600`
  (root-only), since the arguments it carries can include a credential in a flag you added.
- The cluster admin token in **`/var/lib/k3sm/server/token`**, mode `0600` and owned by the
  `_k3sm` service account. The daemon is told where its token is, never what it is, so the token
  does not appear in the plist, in `ps`, or in `launchctl print`. `k3sm uninstall` removes it.
  Because that plist is `0600`, `k3sm status` run without `sudo` reports the server's launchd
  arguments row as unreadable as this user, which never changes the verdict, and `sudo k3sm status`
  shows it.
- The kine/SQLite datastore under the server work directory (see [Backup & restore](backup-restore.md)).
- An empty auto-deploy manifest directory, **`/var/lib/k3sm/manifests`**, owned by `root:wheel`,
  mode `0755` (see below).

## Auto-Deploy Manifests

Like k3s's `server/manifests`, the server applies every manifest you drop into
**`/var/lib/k3sm/manifests`**, on start and whenever the directory changes (with a sweep every
60 seconds as a backstop). Unlike k3s, the directory sits outside the server's work directory and
belongs to root, because every pod on a k3sm node runs as the same service user and could otherwise
write into it.

- **Ownership.** The directory and every file in it must be owned by `root` and must not be
  writable by group or others. Anything else is skipped with a log line. Write files with `sudo`,
  for example `sudo install -m 0644 addon.yaml /var/lib/k3sm/manifests/`.
- **What is read.** Files ending in `.yaml`, `.yml` or `.json`. A name starting with `.` or `_` is
  ignored, which is how you park a file without deleting it. Symlinks are ignored. Several
  documents in one file are fine, and a `kind: List` or a top-level JSON array is applied item by
  item (the List's own metadata is ignored).
- **Apply-only.** Objects are applied with server-side apply under the field manager
  `k3sm-manifest-dir`, never forced. When a field in the file is owned by another manager (for
  example, one you changed with `kubectl edit`), that object is not applied and the server records
  a Warning Event with reason `ManifestFieldConflict` on it, naming the file and the other manager.
  The file is not retried until you change it. Nothing is ever deleted: removing a file, or removing an object from a file, leaves the
  object in the cluster until you delete it with `kubectl`.
- **Refused kinds.** RBAC objects (`rbac.authorization.k8s.io`: Roles, ClusterRoles, bindings),
  admission objects (`admissionregistration.k8s.io`: webhooks, admission policies), Secrets and
  ServiceAccounts are refused and logged; the rest of the file still applies. Create Secrets and
  ServiceAccounts with `kubectl`. The server applies manifests as the `kube-system/k3sm-manifests`
  ServiceAccount, which may only create and patch common workload and configuration kinds
  (Deployments, DaemonSets, StatefulSets, Jobs, CronJobs, Pods, Services, ConfigMaps, PVCs,
  Ingresses, NetworkPolicies, StorageClasses, HPAs, PDBs, MLXModels), plus HelmCharts and
  HelmChartConfigs through a separate ClusterRole (see [Helm charts](helm.md)). A Pod may run as any existing
  ServiceAccount in its namespace, the standard ceiling for anything that can create workloads. It
  cannot create namespaces, so create one first with `kubectl`. Nothing is ever deleted, so remove
  a mistaken object with `kubectl`.
- **Change tracking.** Every applied object carries the annotation `manifests.k3sm.io/sha256`, the
  checksum of the file it came from. An unchanged file is not applied again.
- **Adapt stock manifests.** A manifest written for Linux has no `kubernetes.io/os: darwin`
  nodeSelector and no toleration for the `k3sm.io/provider` taint. It still applies, but its pods
  are refused or never scheduled. The server records a Warning Event with reason
  `ManifestNeedsDarwinScheduling` on such an object, naming both fields; add them to the pod
  template.

`k3sm uninstall` keeps the directory and its contents with the rest of your cluster data.

## Install Channels

k3sm's distribution ships in three generations, listed in shipping order:

1. **The install script (gen 1, first to ship):**

   ```sh
   curl -fsSL https://k3sm.io/install.sh | sh
   ```

   The script preflights (Apple silicon, macOS 26+), downloads the release tarball and its
   checksums from GitHub Releases, verifies the sha256, prints exactly what it is about to do,
   and then runs `sudo k3sm install`. The verification checks **same-origin integrity**, meaning
   the tarball matches the checksums published beside it. It does not check publisher identity;
   provenance (Developer ID + notarization) arrives with gen 3. Environment variables set the
   options. `K3SM_INSTALL_VERSION` pins a release, and it is also the repair path, since an
   unpinned re-run jumps to latest. The variable must reach `sh`, so it goes after the pipe:
   `curl -fsSL https://k3sm.io/install.sh | K3SM_INSTALL_VERSION=v0.1.7 sh` (v0.1.7 is the current
   release; the [releases page](https://k3sm.io/releases/) lists every version you can pin).
   `K3SM_INSTALL_DOWNLOAD_ONLY=1` downloads and verifies into
   the current directory without ever running `sudo`, so you can inspect first. Re-running the
   one-liner upgrades in place, and both daemons restart briefly (see [Upgrade](upgrade.md)).

2. **Homebrew (gen 2)** is planned, and the `k3sm-io/tap` is not published yet. When it ships, run
   `brew install k3sm-io/tap/k3sm`, then `sudo k3sm install`.

3. **Notarized `.pkg` (gen 3)** is a signed, stapled installer package for offline and managed
   installs.

> **Status:** pre-release builds are published; the script resolves the newest one, and a pin
> via `K3SM_INSTALL_VERSION` always wins. The `k3sm-io/tap` is not published yet. The Homebrew
> channel and the `.pkg` arrive with the first stable release.

Every channel manages the same `/Library/k3sm`. Once more than one has shipped, run
`sudo k3sm install` after switching so the daemons run the newly delivered binary, or run
`sudo k3sm uninstall` first for a clean cutover.

### Installing From k3sm.app

The k3sm app installs, updates and uninstalls with the same `/Library/k3sm`. It never runs k3sm
from its own bundle as root: it copies the bundle into a new directory under
`/Library/k3sm.staging`, checks the copy's signature, and runs
`k3sm install --from-staging <dir>` from that copy. The install refuses to run unless:

- the directory sits directly inside `/Library/k3sm.staging`, both are owned by `root:wheel` with
  mode `0700`, and no part of the path is a symlink;
- every file in the directory is owned by `root`, writable by nobody else, and none is a symlink,
  a special file, or setuid or setgid;
- the running `k3sm` and every file it installs come from that directory;
- a `--token-file` sits directly inside the directory, owned by `root` with mode `600` and one
  link (it is removed as soon as it is read);
- the version is a release version no older than the installed one;
- on an update, the new `k3sm` is signed by the same Developer ID team as the installed one.

Pass `--allow-downgrade` to install an older version on purpose (or over an install whose version
cannot be read). A plain `sudo k3sm install` makes none of these checks and is unchanged.

## Secrets Encryption at Rest

Secrets are stored unencrypted in the datastore by default. To encrypt them at rest, ask for it
on the install that creates the cluster:

```sh
sudo k3sm install --secrets-encryption
```

The install generates a random 32-byte key on this Mac and writes two files before the control
plane first starts, both owned by `_k3sm` with mode `0600` in a `0700` directory:

- `/var/lib/k3sm/server/cred/encryption-config.yaml`, the API server's encryption configuration,
  which holds the key,
- `/var/lib/k3sm/server/cred/encryption-config.sha256`, a fingerprint of that key.

The API server then encrypts every Secret it writes with the `secretbox` provider
(XSalsa20-Poly1305). k3s offers `secretbox` too; its default is `aescbc`, which the Kubernetes
documentation no longer recommends. The configuration lists no plaintext (`identity`) provider, so
the API server does not read or write unencrypted Secrets. Other resources, such as ConfigMaps, are
not encrypted.

Check the state at any time:

```sh
sudo k3sm secrets-encrypt status
```

It prints `enabled`, `disabled`, or `refused` with the reason, the provider, the configuration
path and its mode. It never prints the key. It exits non-zero when the files are in a state that
stops the control plane from starting.

**Back up the key with the datastore.** Copy `/var/lib/k3sm/server/cred` every time you back up
`state.db` or take a snapshot, and keep the two copies together.

- Losing the key makes every Secret unreadable, including node passwords and bootstrap tokens.
- A snapshot does not contain the key.
- Restoring a snapshot taken under another key, or before encryption was enabled, leaves Secrets
  unreadable.

**There is no way back.** An older k3sm, or this one with the files removed, cannot read the
encrypted Secrets. This release has no key rotation and no command to decrypt the datastore.

**Refusals.** The install stops, before it changes anything, when:

- this data root already holds a datastore (an existing cluster cannot be switched over in this
  release; encryption is for a fresh install only),
- the server's carried arguments include `--cluster-init` or `--server-join` (every server would
  need the same key, and k3sm does not distribute one),
- the install is a worker (`--agent`).

A later `sudo k3sm install` without the option keeps the key and the encryption. Passing the
option again once the cluster has started is refused. To enable encryption on a cluster that has
never held workloads, remove the data root and reinstall with the option. The `.bak` copies k3sm
keeps beside `state.db` hold encrypted Secrets and are useless without the key. The control
plane refuses to start, and stays parked until the files are fixed, when the configuration is
present without its fingerprint, when the fingerprint is present without the configuration, or
when the two do not match. Restore both files from the backup taken with `state.db`. `k3sm
uninstall` keeps both files with the rest of your cluster data.

## Network Exposure

Every listener a node opens, and the addresses it binds:

| Listener | Port | Binds |
|---|---|---|
| kubelet API (logs, exec, metrics) | `10250` (`--kubelet-port` on a server) | the node's own address only: its mesh address once joined, its pod-range address on a single node, `127.0.0.1` on a single node under `--network none` |
| NodePort Services | `30000-32767` | follows LAN access: every interface (or the `--nodeport-addresses` set) when on, `127.0.0.1` and the node's own address when off |
| LoadBalancer Services | each Service's `port` | follows LAN access: every interface when on, `127.0.0.1` and the node's own address when off |
| Ingress host (server) | `80`, `443` (`--ingress-http-port`, `--ingress-https-port`) | follows LAN access: every interface when on, the node's own address when off |
| wireguard mesh | `51820/udp` | every interface; it answers only peers holding a cluster key |
| apiserver (server) | `6444` (`--api-port`) | `127.0.0.1` on a single server; the mesh address only on a server with `--mesh-ip` |
| worker join (server with `--mesh-ip`) | `9345` | every interface, because a joining worker has no mesh yet; every request needs the cluster join token |
| embedded etcd peer (HA servers) | `--etcd-peer-port` | the `--etcd-peer-ip` address you name; peers need a peer certificate |
| ingest registry (opt-in, `--registry-port`) | the chosen port | `127.0.0.1`, plus a relay on the mesh address and the `vm` NAT gateway |
| cluster DNS and ClusterIP Services | Service ports | their virtual IPs, aliased on `lo0` |
| datastore, scheduler, controller-manager (server) | their own ports | `127.0.0.1` |

The kubelet API binds exactly the address the node registers as its `InternalIP`, never every
interface. If that address is missing when the node starts (a joined worker under `--network
none`, for example), the node refuses to start and names the address. The standalone `k3sm node`
command is the exception: its `--listen` address is the operator's choice and may still be the
wildcard.

### LAN access

One switch decides whether the workload listeners (NodePort, LoadBalancer and the ingress host)
answer on the networks this Mac is attached to:

```sh
sudo k3sm network lan off      # only this Mac and the cluster mesh
sudo k3sm network lan on       # every network this Mac is on
k3sm network lan status        # the setting, what it covers, what it does not
```

With LAN access off, those listeners bind `127.0.0.1` and the node's own address (its mesh address
once joined, its pod-range address on a single node), so other nodes reach them over the mesh and
nothing on your Wi-Fi or Ethernet does. With it on, they bind every interface.

- New installs start with LAN access off. An existing install keeps LAN access on across an upgrade,
  so nothing it serves stops answering. `sudo k3sm install --lan on` or `--lan off` sets it at
  install time.
- The change applies live, without restarting pods: the node daemon binds the new addresses first
  and only then closes the old ones. Connections already open finish; new connections from the LAN
  are refused. The command then checks the node daemon's listening sockets itself (with `lsof`, as
  root) rather than taking the daemon's word for it. If any listener cannot move, or the sockets do
  not match, the previous setting is restored and checked the same way, and the command says why. If
  even the restore fails, it says so and exits `4`. If the node daemon does not apply it live, the
  command restarts the daemon in place instead (pods keep running) and says so.
- `k3sm network lan status` and `k3sm status` show the recorded setting and, run as root, the state
  the node daemon reports serving, and say when the two differ. With no setting recorded they say
  that LAN access is on because nothing is recorded.
- The record must be a regular file owned by root and writable by no one else. Anything else is
  treated as unusable, and the node daemon serves LAN access off until it is set again.
- On a stopped node the setting is recorded and applies at `sudo k3sm start`.
- With LAN access off, a LoadBalancer port below 1024 is not served on that node, because macOS
  lets only root bind a specific address below 1024; use a port of 1024 or above, or turn LAN
  access on. The ingress host still serves `80` and `443` on the node's own address, but not on
  `127.0.0.1`.
- The switch does not cover the apiserver (loopback, or the mesh address), the wireguard mesh port
  (it answers only cluster peers) or the worker join port. A new worker joins over the LAN, so the
  join port stays reachable with LAN access off, and every request to it needs the cluster join
  token.
- The setting is kept in `/Library/Preferences/io.k3sm.network.json`, beside the other install
  arguments, and survives a reinstall and an uninstall. `k3sm status` shows it, and `k3sm status -o
  json` carries it as `network` (see [Status JSON](status-json.md#network)).

### NodePort addresses

With LAN access on, NodePorts follow upstream and bind every interface unless
`--nodeport-addresses` narrows them. With LAN access off, NodePorts bind `127.0.0.1` and the node's
own address whatever `--nodeport-addresses` says.

```sh
sudo k3sm install --nodeport-addresses local
sudo k3sm install --agent --server <control-plane> --token-file <file> --nodeport-addresses local
```

`local` is loopback (`127.0.0.1`) plus the node's own address, the same set LAN access off uses.
The value can also be a comma-separated list of IPv4 CIDRs, the kube-proxy `--nodeport-addresses`
shape, mixed with `local` if you like (`local,10.0.0.0/8`). Each NodePort then binds every matching
address of this Mac, or none of them if any bind fails. See [Limitations](limitations.md) for the
reserved ports and the other networking caveats.

- The setting is IPv4 only. An IPv6 range is refused.
- It needs the node datapath. A non-empty value beside `--network none` is refused, on `k3sm
  install`, `k3sm server` and `k3sm agent` alike.
- It is resolved when the daemon starts and again at every LAN access change, against the addresses
  this Mac has then. A value that matches no address refuses the start. An address that appears
  later (a new network) is used after the next restart or LAN access change.
- It is recorded with the other install arguments and kept across a reinstall and an uninstall.
  Surrounding spaces are ignored. `sudo k3sm install --nodeport-addresses ""` (or a value of only
  spaces) returns to every interface.
- `k3sm server` and `k3sm agent` take the same flag directly.

## Uninstalling

```sh
sudo k3sm uninstall
```

It stops and removes the k3sm LaunchDaemons (the data-volume daemon too, when there is one), removes `/Library/k3sm`, and removes the
`/usr/local/bin/k3sm` launcher, but only that link, and only while it still points at
`/Library/k3sm/k3sm`. A file you put there yourself, or a link you re-pointed at something else, is
left exactly as it is. It also flushes the pf anchor an older release loaded for the mesh (k3sm itself
loads no pf rule). Your cluster data, the `_k3sm` user, and your kubeconfig are kept, so a
reinstall picks up where you left off; to remove those too, see
[Remove Everything](#remove-everything). The server's admin token is removed, because a reinstall
mints a new one. The command prints the full list of what it kept. If you
installed a data volume, it stays mounted and declared; the command prints `sudo k3sm install
--data-volume` to reinstall onto it and `sudo k3sm datavol delete --yes` to remove it for good.

Uninstall also removes `/Library/k3sm.staging`, the directory the k3sm app copies itself into, and
refuses to run while the app is in the middle of an install.

### Server Flags Across A Reinstall

Any flag you added to the server daemon yourself, such as `--mesh-ip` or `--registry-port`, is
carried into the plist every install renders. Install reads them from the installed daemon, and
records them in `/Library/Preferences/io.k3sm.server-args.json`, so they survive an uninstall too.
That file is root-owned and root-readable only, because a flag can carry a credential. `k3sm status`
shows what the installed server is running with, on the `server-args` row.

The record is written at install time. A flag you edit directly into the daemon's plist is picked up
by the next `sudo k3sm install`, and until then it exists only in the plist, so an uninstall before
that install loses it. Running `sudo k3sm install` after an edit is what makes it durable.

The installed daemon wins while it is there, so a reset means clearing both sources:

```sh
sudo k3sm uninstall                                          # removes the daemon and its flags
sudo rm /Library/Preferences/io.k3sm.server-args.json        # discards the recorded ones
sudo k3sm install                                            # renders the stock template
```

That discards the flags the file lists, and nothing else. Your cluster data is untouched. An
install refuses a carried `--datastore-endpoint` or `--datastore-endpoint-file`, because v0.1.6
removed external-datastore HA. The experimental two-server control plane uses embedded etcd
instead; see [High availability](ha.md).

Install warns when it finds neither source on a data root that already holds cluster state, which is
what a Mac uninstalled by an older version looks like. The flags are gone on such a Mac, and install
says so rather than starting single-node in silence.

### Remove Everything

```sh
sudo k3sm uninstall --purge --yes
```

This runs the uninstall above and then removes what it keeps:

- the cluster data in `/var/lib/k3sm`: the datastore, images, and volumes
- the data volume, if you installed one, together with its keychain item, its `/etc/fstab` line,
  and `/Library/Preferences/io.k3sm.datavol.json`
- the daemon logs in `/var/log/k3sm`
- the recorded arguments in `/Library/Preferences/io.k3sm.server-args.json` or
  `io.k3sm.agent-args.json`
- the `k3sm` context in your `~/.kube/config`, and the cluster and user entries only that context
  used; every other entry in the file is kept
- the `_k3sm` user, if macOS allows it (see below)

macOS asks a person at the screen to approve deleting a user account, so the purge may not be able
to delete `_k3sm` by itself. It removes everything else first, then leaves the account disabled
(hidden, no login shell, no home directory) and prints the command that finishes the job: run
`sudo dscl . -delete Users/_k3sm` in Terminal and click Allow when macOS asks to administer your
computer. A leftover account is harmless, and running the purge again tries the deletion again.

It cannot be undone. Without `--yes` the command changes nothing and lists what it would delete.
k3s's `k3s-uninstall.sh` removes everything with no prompt; k3sm asks for `--yes` on purpose,
because this deletes a user account and the cluster's datastore.

Run it before `brew uninstall k3sm`: the `k3sm` binary is what performs the purge.

Before deleting anything it checks that the data directories are the ones install created, and it
stops without removing anything if a check fails. Install marks each directory with a
`.k3sm-dataroot` file; a Mac installed by an older version has no marker, so run
`sudo k3sm install` once (it writes the markers) and then the purge. It never deletes into a
mounted filesystem, and it stops if any k3sm daemon or `_k3sm` process is still running after it
tries to stop them.

Copies outside these paths, such as Time Machine backups or APFS snapshots, are not touched.

## Verifying

```sh
k3sm version        # prints the k3sm version + the Kubernetes control-plane pin (see the Version Support page)
k3sm status         # what is running: daemons, apiserver, node, workloads, data root
k3sm kubectl get nodes
```

## Next

- [Stopping and starting](stop-start.md) covers `k3sm stop` and `start`, and how a reinstall treats a stopped node.
- [Quickstart](quickstart.md) runs your first Pod.
- [kubectl access](kubectl-access.md) covers kubeconfig details.
- [Upgrade](upgrade.md) explains how upgrades restart the daemon.
- Read [Limitations](limitations.md) before relying on k3sm.

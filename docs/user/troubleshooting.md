# Troubleshooting

When a k3sm cluster does not behave. Start with `k3sm status`, then the common failure modes below.

## Start with `k3sm status`

`k3sm status` is one screen covering the two LaunchDaemons, the apiserver, the node, the workloads, the
data root, the datastore and your kubeconfig. A one-line verdict sits at the top, and the command that
fixes whatever is down sits at the bottom.

A healthy cluster looks like this:

```
k3sm running: 1/1 nodes ready                               v0.1.1 · kube v1.37.1 · macOS 26.1

    install     ok          /Library/k3sm/k3sm · launcher /usr/local/bin/k3sm · 2 LaunchDaemons in /Library/LaunchDaemons
    netd        running     pid 512 · socket /var/lib/k3sm/run/netd.sock
    server      running     pid 840
    apiserver   ready       https://127.0.0.1:6444 readyz ok
    node        ready       1/1 nodes ready · my-mac kubelet v1.37.1
    workloads   ok          3 running
    data-root   ok          /var/lib/k3sm (apfs volume k3sm, 29.9G of 100G used, mounted)
    datastore   ok          kine sqlite, wal, user_version 1
    kubeconfig  ok          ~/.kube/config context "k3sm"

Next: k3sm kubectl get pods -A
```

A control plane that will not start looks like this. The verdict names the cause, and the server row
quotes the last line of its log:

```
k3sm stopped: io.k3sm.server is crash-looping (12 runs, last exit 1)  v0.1.1 · kube v1.37.1 · macOS 26.1

    install     ok          /Library/k3sm/k3sm · launcher /usr/local/bin/k3sm · 2 LaunchDaemons in /Library/LaunchDaemons
    netd        running     pid 512 · socket /var/lib/k3sm/run/netd.sock
    server      crash-loop  12 runs, last exit 1
      log: level=ERROR msg="control plane exited" err="bind: address already in use" (×12)
    apiserver   down        https://127.0.0.1:6444: connection refused
    node        unknown     apiserver unreachable
    workloads   unknown     apiserver unreachable
    data-root   ok          /var/lib/k3sm (apfs volume k3sm, 29.9G of 100G used, mounted)
    datastore   ok          kine sqlite, wal, user_version 1
    kubeconfig  ok          ~/.kube/config context "k3sm"

Next: sudo launchctl kickstart -k system/io.k3sm.server
      k3sm status logs server
```

Three more views go deeper when the overview is not enough:

```sh
k3sm status daemons          # per-daemon detail: run count, last exit, plist and log paths
k3sm status cluster          # readyz, node, workloads by phase, datastore, runtime daemon
k3sm status logs server      # tail a daemon's log (netd or server; both when omitted)
```

And two flags for scripts and for watching a restart:

```sh
k3sm status -o json          # the machine interface; the text screen is rendered from it
k3sm status daemons -o json  # a cheap launchd-only probe, safe to poll
k3sm status --wait           # poll until the cluster is running, or --timeout elapses
k3sm status --watch -o json | your-tool   # a stream: one JSON report per change
```

Both JSON shapes are versioned; [Status JSON](status-json.md) is their contract.

### CPU and memory: `k3sm status top`

`k3sm status top` lists each node's CPU and memory use against what it can allocate, with its pod
count and the age of the sample, then the busiest pods by CPU and then memory:

```sh
k3sm status top                       # one screen
k3sm status top --watch=2s            # re-render every 2 seconds
k3sm status top --sort memory -n default --limit 10
k3sm status top -o json               # the same rows, for scripts
```

The figures come from metrics-server (the `metrics.k8s.io` API, the same source as `kubectl top`).
metrics-server samples every 15 seconds, so `--watch` reads it at most every 5 seconds whatever the
interval; the age column shows how old each node's sample is. A node it has not sampled yet says
`no metrics yet`. When the metrics API is not available, the first line gives the reason and
message from the `v1beta1.metrics.k8s.io` APIService, and the tables list nodes and pods without
usage. `--sort`, `-n` and `--limit` shape the pod table only; the node table always covers the
whole cluster. The view exits 0 when it read the cluster, with or without metrics, and 6 when it
could not.

Under `sudo`, the view reads with your own `~/.kube/config` and the installed k3sm context when it
can list nodes, because a worker's node credential may read only its own node; it refuses that file
if you do not own it, if others can write it, or if it runs a credential plugin or reads its
credential from another file, and when no credential can list nodes it says to run the view
without `sudo`.

The exit code is the verdict, so a script can branch on it. `k3sm status --help` lists the codes.

Rows say `needs-admin` when only root can run the check, such as the runtime socket. Nothing has
failed there; run `sudo k3sm status` for those rows. A row says `unknown` when the report could not
see the answer from your account another way, for example when the apiserver does not answer.

## Logs

k3sm daemons run as launchd jobs under the `io.k3sm.*` labels and log to the unified log system:

```sh
log show --predicate 'subsystem BEGINSWITH "io.k3sm"' --last 10m
launchctl print system/io.k3sm.server     # daemon state (label may differ per role)
```

Not everything lands there. The server process's own structured logs (the LoadBalancer decider, the
ingress host, the control-plane supervisor) go to **stderr**, which launchd routes to
**`/var/log/k3sm/server.log`**. The unified-log predicate above shows none of them.

The `/var/log/k3sm` directory and the daemon log files in it (`server.log`, `netd.log`,
`datavol.log`) are readable by root and by members of the `admin` group only, because they carry
daemon arguments, cluster endpoints and failure detail. Read them with `sudo` if your account is not
an administrator of the Mac. `k3sm status` prints "not readable by this account" in place of a log
tail it cannot read.

## `k3sm: command not found` After Install

Install links `/usr/local/bin/k3sm` → `/Library/k3sm/k3sm`. If the shell cannot find it:

```sh
ls -l /usr/local/bin/k3sm     # should be a symlink into /Library/k3sm
echo $PATH                    # should contain /usr/local/bin
/Library/k3sm/k3sm version    # always works, the binary itself
```

- **The link is there but the shell does not see it.** A terminal opened *before* the install may
  have cached the old lookup. Run `hash -r`, or open a new window.
- **`/usr/local/bin` is missing from `PATH`.** It is the first entry in `/etc/paths`, so a login
  shell normally has it; a `PATH` that is overwritten (rather than appended to) in a shell profile
  can drop it. Add it back, or invoke `/Library/k3sm/k3sm` directly.
- **A regular file sits at `/usr/local/bin/k3sm`.** Install refuses to replace anything that is not
  a symlink, because that file belongs to something else. Move it aside and re-run
  `sudo k3sm install`.
- **Install failed with `refusing to link into /usr/local/bin`.** The directory is not root-owned,
  or it is group/other-writable, which would let another account swap the launcher out from under
  you. Fix it and re-run the install:

  ```sh
  sudo chown root:wheel /usr/local/bin && sudo chmod 755 /usr/local/bin
  sudo k3sm install
  ```

## `kubeconfig … not found` From `k3sm kubectl`

`k3sm kubectl` and `k3sm kubeconfig` say this when they were pointed at a specific server work
directory that holds no admin kubeconfig, or when they found no credentials at all. Which one it is
depends on how you ran them:

- **`K3SM_WORK_DIR` is set.** That names one server and is never second-guessed, so if the directory
  holds no kubeconfig the command stops there. Point it at the right work directory, or unset it.
- **Nothing was found anywhere.** The message names both places it looked. If you are root or the
  `_k3sm` service user, that means the control plane has not written its kubeconfig. Check the
  server is actually up (see below) and read its log.
- **Your own kubeconfig has no `k3sm` context.** For an ordinary account that context is the way in,
  because the installed server's work directory belongs to the service user and is not readable by
  you:

  ```sh
  kubectl config get-contexts    # is there a k3sm context?
  sudo k3sm install              # idempotent; re-merges it into ~/.kube/config
  k3sm kubeconfig --write        # with the context in place, refreshes it (--path writes elsewhere)
  ```

See [kubectl access](kubectl-access.md) for the full resolution order.

## Control Plane Startup Failure

- Run `k3sm status` first. It says whether the server daemon is running, crash-looping, stopped
  or not loaded, and it quotes the last line of the server log for the two failure cases.
- Confirm install completed: `k3sm version` and `sudo k3sm install` (idempotent).
- Check the datastore is present and not locked. The kine/SQLite DB lives under the server work
  directory (see [Backup & restore](backup-restore.md)).
- Restart the daemon: `launchctl kickstart -k system/io.k3sm.server` (label per your role).

### The Data Root Is Declared But Not Mounted

If you keep `/var/lib/k3sm` on its own APFS volume, declared either in `/etc/fstab` or by `sudo k3sm
install --data-volume`, that volume must be mounted **before** the daemons start. When it is not,
writes land on the boot disk in the bare mountpoint and shadow the real volume, which looks exactly
like an empty cluster. `k3sm status` reports the data root as `not-mounted` and the verdict as
`stopped`, because the daemons refuse to run against an unmounted mountpoint rather than build a
second, empty datastore on top of your data.

```sh
sudo k3sm datavol mount
sudo launchctl kickstart -k system/io.k3sm.netd
sudo launchctl kickstart -k system/io.k3sm.server
```

If the volume was never declared with a k3sm record (an `/etc/fstab` line you wrote yourself, with
no `sudo k3sm install --data-volume` run since), `datavol mount` has nothing to work from and you
mount it by hand instead. Check first: `ls /var/lib/k3sm/run` must list only the netd socket before
you remove it, because anything else there is data the remove would delete.

```sh
diskutil info /var/lib/k3sm                     # the Device Node line names the volume
sudo rm -r /var/lib/k3sm/run                    # the shadow holds only the netd socket
sudo diskutil mount -mountPoint /var/lib/k3sm /dev/diskNsM
sudo launchctl kickstart -k system/io.k3sm.netd
sudo launchctl kickstart -k system/io.k3sm.server
```

`sudo k3sm install` refuses to run until the volume is mounted, so mount it first and then re-run the
install if you were in the middle of one.

### The Data Root Has The Wrong Owner

The data root itself, `/var/lib/k3sm`, belongs to root (`root:wheel`, mode `0755`), the same way
k3s keeps its data dir. The directories the daemons write under it (`run`, `server`, `agent`,
`pods`, `storage`, the image store) belong to the unprivileged `_k3sm` service user, and the
node's mesh keys live in `/var/lib/k3sm/keys`, which only root can read or change. If the root is
owned by anyone else, `k3sm status` reports the data root as `wrong-owner` with the uid it found.
A root owned by `_k3sm` is the layout older releases left behind. Restarting the netd helper
realigns the ownership:

```sh
sudo launchctl kickstart -k system/io.k3sm.netd
sudo k3sm install                               # the authoritative repair, and idempotent
```

## Stuck or Crash-Looping Pods

On the **default runtime** (what every installed cluster runs), `restartPolicy` **is** honored. The
container is restarted in place with an upstream-shaped `CrashLoopBackOff` backoff, and
`kubectl get pod` shows the restart count climbing. If yours is not restarting, work through these:

- Is it a plain init container? A non-sidecar init container that fails is **not** re-run in
  place. That is the one remaining restart gap on the default runtime, and only a controller
  replacing the Pod unsticks it.
- Did you start the node with `--runtime hostprocess`? That explicit rootless-dev opt-out honors
  no `restartPolicy` at all. An exited container is reaped once and never respawned. Drop the flag
  to get the default runtime back.
- Is the Pod's policy `Never`, or is it a `Job` that has already succeeded? Both are working as
  specified.
- Restart count stuck at 0 on a `vm` Pod? Run `kubectl describe pod`. When the node refuses the
  restart, each attempt records a Warning `Failed` Event, `Error: restart container <name>: <cause>`,
  and the cause follows the `CrashLoopBackOff` message in the container's state. If it says
  restarting a container in place is not supported by the guest this Pod booted, delete the Pod: its
  replacement boots a guest that supports it. The node keeps retrying under the backoff until then.
- Stuck rather than exiting? Check the Pod was **adapted** to the native image model, because a raw
  Linux image cannot run as a Darwin process (see [Images](images.md)).

See [Limitations](limitations.md#restartpolicy-is-honored-on-the-default-runtime-not-on-the-hostprocess-opt-out)
for the precise scope.

## A Pod's Image Will Not Pull

A container whose image cannot be resolved does **not** fail the rest of the Pod. The Pod is
created, the containers that can start do start, and the one that cannot sits `Waiting` with the
reason `kubectl get pod` prints in its `STATUS` column. The Pod's phase stays `Pending` while any
container waits, and the restart count stays at 0, because a container that never started has not
restarted.

Read the reason first, because each one has a different recovery:

| Reason | What it means | How it recovers |
|---|---|---|
| `ErrImagePull` | The attempt that just failed: the registry pull, the `imagePullSecret`, the platform match, or the signature gate. | Retried automatically, 10s then 20s, doubling to a 300s ceiling. |
| `ImagePullBackOff` | The same container between attempts. | Nothing to do; the next attempt is already scheduled. |
| `ErrImageNeverPull` | `imagePullPolicy: Never` and the image is not in this node's store. Nothing is pulled and no registry is contacted. | Load it (`k3sm image load`), then wait for the node to re-check: up to two resync intervals, about 20s. |
| `CreateContainerConfigError` | The container's run spec could not be built: a missing ConfigMap or Secret key, an env reference that does not resolve, an entrypoint the image config does not supply. | Fix the referenced object, then wait for the node to re-check: up to two resync intervals, about 20s. |
| `InvalidImageName` | The reference does not parse. | Only a spec change helps: `kubectl set image`, or delete and recreate. Parsing the same string again cannot give a different answer. |

`kubectl describe pod` carries the same story as Events. `Pulling` opens every attempt and names
the image; `Pulled` closes a successful one, saying either how long the fetch took or that the image
was already on the machine. On the failing side: `Failed` on each failed attempt, `BackOff` when a
retry is scheduled, `InspectFailed` for an unparseable reference, and `ErrImageNeverPull` each time
the node re-checks for an image that policy forbids it to fetch. A container whose image is a host
binary gets no `Pulling` or `Pulled` at all, because nothing is fetched for it: that is the native
sentinel, or an absolute path on a container that sets neither `command` nor `args`. Give such a
container a `command` and the reference is treated as an image again.

One attempt announces `Pulling` for **every** container of the Pod, not just the one that is behind.
The node resolves a Pod's images in order inside a single start attempt, so a later container's
`Pulled` reports a wait that includes the earlier containers' fetches. That is what the
`(… including waiting)` figure means here, and it is why the two durations in a `Pulled` message can
be far apart. The message also omits the image-size clause upstream Kubernetes appends: the runtime
reports no size for a resolution, and a fabricated byte count would be worse than a shorter sentence.

Four things worth knowing before you debug further:

- **On the `vm` RuntimeClass, one bad image holds the whole Pod.** A `vm` Pod is a single guest, so
  an image that will not resolve fails the guest build rather than leaving one container behind.
  Every container reports `Pending`: the container the failure names carries the reason and the
  message, and the others read `ContainerCreating`, because they never started for a reason of their
  own. The Pod is kept and the create is retried on the same schedule described above, so nothing
  goes `Failed` and no controller churns replacements. A host-process Pod behaves as the paragraph
  at the top of this section says: its other containers start and keep running.
- **The message is bounded.** The waiting message and the `Failed` event carry a truncated copy of
  the underlying error, where upstream Kubernetes prints it whole. The full text, including the
  registry response, is in the node log (`/var/log/k3sm/server.log`, or `agent.log` on a worker, or `log show
  --predicate 'subsystem == "io.k3sm.node"'`).
- **The schedule is per Pod and per image.** Ten Pods referencing one bad image are ten independent
  retry schedules, exactly as they would be on a kubelet. Restarting the node daemon resets every
  schedule to the 10s base, so a restart is the fastest way to retry everything at once after you
  fix a registry.
- **Deleting and recreating the Pod resets its backoff.** The schedule lives in the running daemon
  and is keyed to the Pod, so a fresh Pod starts at 10s again rather than inheriting a 300s wait.

## DNS From Inside a Pod Does Not Resolve Cluster Names

On the default runtime this should work. Service A records, headless Services, StatefulSet per-Pod
names, SRV and PTR all resolve. Check these in order:

- Is the lookup coming from `/bin/sh` or another `/usr/bin` tool? macOS strips
  `DYLD_INSERT_LIBRARIES` from SIP platform binaries, so k3sm's `getaddrinfo` shim never loads into
  them and their lookups go to the **host** resolver. Do the lookup from your compiled workload
  instead. macOS imposes that limit; it is not a misconfiguration.
- Is the Pod's `dnsPolicy` `Default` or `None`? Neither selects cluster DNS, so nothing is
  injected. Use `ClusterFirst` (the default when the field is unset).
- Is it an AAAA lookup? k3sm's CIDRs are IPv4; AAAA is never answered.
- Are you on `--runtime hostprocess`? In-pod cluster DNS is not wired there, so every lookup goes
  to the host resolver. The `vm` RuntimeClass does not share this gap; cluster DNS works there.

See [Limitations](limitations.md#dns-what-resolves-and-on-which-runtime-path) for the full
per-path picture.

## UDP Service Failures

Only cluster DNS on `:53` uses UDP today; general UDP Services (ClusterIP **and** NodePort) are deferred.
See [Limitations](limitations.md).

## LoadBalancer Stuck `<pending>`

Start with the Service's Events, which name the cause when k3sm knows it:

```sh
kubectl describe service <name>
```

- **`NoEligibleNodes`**. No node may host the Service: its `svclb.k3sm.io/lbpool` label names a pool
  no node is in, or allow-list mode is on (some node carries `svclb.k3sm.io/enablelb=true`) and no
  node in the pool is enabled. See [Multi-node](multi-node.md#node-pools).
- **`HostNotBound`**. The named node was chosen but could not bind every port of the Service. Read
  that node's log for the reason below. A chosen node that has never reported at all, such as a
  worker still running an older k3sm during an upgrade, raises no event: the server logs that the
  node has not reported, and leaves it out of the Service's status until it does.

Do not look in the unified log for the rest. The LoadBalancer decider and the ingress host log
through `slog` to **stderr**, which the launchd job routes to a file, so the
`log show --predicate 'subsystem BEGINSWITH "io.k3sm"'` command at the top of this page shows **nothing**
for them. Read the file instead: `server.log` on the server, `agent.log` on a joined worker, which
is where that node's listeners log:

```sh
grep svclb /var/log/k3sm/server.log | tail -50
grep svclb /var/log/k3sm/agent.log | tail -50
grep ingress /var/log/k3sm/server.log | tail -50
```

The server logs one line at start naming its own node and the address it publishes for it, and every
node logs one line when its listeners start:

```
svclb: loadbalancer decider starting self=node-a self_addr=100.64.0.1 hold_down=30s mesh_peers=true
svclb: loadbalancer hoster starting node=node-a bind=0.0.0.0
```

Then look for one of these:

- **`svclb: loadbalancer port is RESERVED by a k3sm wildcard listener`**. The Service declares a port
  k3sm's own listeners own (the NodePort range `30000-32767`, or the kubelet API port `10250`) or a
  macOS host-service port (`22`, `53`, `88`, `445`, `548` or `631`). No
  listener is bound and the status stays empty, because taking `10250` would break
  `kubectl logs`/`exec`/`top` on this node. Pick a different `spec.ports[].port`. Normally the API
  rejects such a Service at `kubectl apply` with a message naming the port; if it did not, the admission
  policy failed to provision, and the log carries a matching `provision reserved-loadbalancer-port DENY
  policy` error.
- **`svclb: listener bind failed`**. Something else already holds that wildcard port. The log line
  carries the exact diagnostic command; run it:

  ```sh
  lsof -nP -iTCP:<port> -sTCP:LISTEN
  ```

  The usual culprits are another process on the Mac, a **pod** (macOS has no network namespaces, so pods
  share the node's port space; see [Limitations](limitations.md)), or a second LoadBalancer Service
  declaring the same port. k3sm never picks a different port for you.
- **`loadbalancer/ingress status will not list this node: no advertisable node address could be derived`**.
  The listeners are bound and serving, but there is no address that would be correct to publish, so
  the server's node is left out rather than advertised at an unreachable address. A worker is listed
  at the mesh address the server recorded when it joined. Check `kubectl get node -o wide` shows a non-loopback
  `INTERNAL-IP`, and that you did not start the server with `--network none`.
- **`ingress bind retries exhausted`**. The ingress listeners gave up (bounded retry, no port
  fallback). Free the port and restart the daemon.

Restart the control plane after fixing the conflict:

```sh
sudo launchctl kickstart -k system/io.k3sm.server
```

A `<pending>` Service is not visible in `kubectl describe`, because k3sm has no `EventRecorder` for
this path yet (the event pipeline is planned). The log file is the only place the reason appears.

## `kubectl top` Returns No Metrics

k3sm ships metrics-server as an add-on, and every server applies it, single-node included, once the
server's own node has its kubelet certificate from the cluster CA and a node has registered. Until
then `kubectl top` has no data. Check which case you are in:

```sh
kubectl get apiservice v1beta1.metrics.k8s.io
kubectl get nodes -l node-role.kubernetes.io/control-plane=true
kubectl -n kube-system get pods -l k8s-app=metrics-server -o wide
```

No APIService means the add-on was not applied yet. The server re-checks every two minutes and
applies it once its node has started and registered, so a fresh install or an upgrade gets it within
a few minutes of the server coming up. An APIService that is not `Available` means the metrics-server Pod in `kube-system` is not
Ready yet. The Pod runs only on a server node, so a Pod left `Pending` with no server node listed by
the second command means no server has labelled its Node yet; each server does that at start.
`kubectl top node` shows host-wide figures for every Ready node. See
[kubectl access](kubectl-access.md) and [Limitations](limitations.md#headline-divergences).

## `kubectl exec -it` or `attach` Into a Linux Pod Is Refused

Both verbs are served by the Pod's guest, so the refusal message says which half is missing.

- **"…does not advertise the … capability … recreate the pod"**. The Pod is running a guest image
  older than the one this node pins, which can only happen under a development override. Delete and
  recreate the Pod so it boots the pinned image.
- **`FailedPrecondition` on attach**. The container kept no stdin to write to. Set `stdin: true`
  (and `tty: true` if you want a terminal) on the container and recreate the Pod; stdio is decided
  when the container starts, not when you attach.
- **`Unimplemented` on `kubectl attach -i` / `-t`**. That Pod is on the default native path, where
  attach is output-only. Use `kubectl exec -it`, or the `vm` RuntimeClass. See
  [Limitations](limitations.md).

A garbled first screen after attaching is not a failure, because attach replays a bounded buffer and
can start mid-escape-sequence. Redraw with `Ctrl-L`.

## A Pod Cannot Pull From the Node-Local Registry

- **Connection refused**. The registry is **off by default**. Start the server with
  `--registry-port <port>` (or use `k3sm dev`, which enables it), and read the published port back
  from the `local-registry-hosting` ConfigMap in `kube-public` rather than remembering it.
- **A Pod under `runtimeClassName: vm` cannot reach it at all.** The guest has its own loopback, and
  the registry listens only on the node's. That is a documented limit, not a misconfiguration. Use
  a registry the guest can reach, or load the image into the node's store directly.
- **Push denied**. Pushes need the per-boot credential, pulls do not. If the control plane runs as
  a different user than the one you are pushing from, point push at its state directory with
  `--work-dir`.

See [Node-local registry](registry.md) for the full model.

## Certificate Nearing Expiry

Component certificates are re-issued on every control-plane boot, so a restart renews them.
`sudo k3sm certificate rotate` reports what a restart would re-issue (and both CA pins, which
never change); `--restart` performs it. Rotation does **not** revoke anything and does not cover
worker-node certs, so read [Certificates](certificates.md) before you rely on it.

## Rosetta-Selecting Pods Stuck Pending

The node advertises a capability label only when its start-time probe said yes.

1. Check what the node advertises:
   `kubectl get nodes -L k3sm.io/virtualization,k3sm.io/rosetta,k3sm.io/rosetta-linux`.
2. If the key is missing, the node's log carries **two** lines for it: one naming the `condition` and the
   `reason` (`NotInstalled`, `TranslationFailed`, `NotSupported`, `QueryFailed`, `VMBackendUnavailable`)
   explaining why the capability was not advertised, and one naming the `label` key that was therefore
   left absent. Grep the log for the key itself (`k3sm.io/rosetta-linux`) and you land on it.
3. `k3sm.io/rosetta-linux` needs **both** virtualization and guest Rosetta. A node with
   `k3sm.io/rosetta` but no `k3sm.io/virtualization` will **never** carry it.
4. Installed Rosetta after the node came up? The probes run once at daemon start, so restart it:
   `sudo launchctl kickstart -k system/io.k3sm.server`.
5. Your Pod must also keep `kubernetes.io/os: darwin` in its `nodeSelector`; a Pod with only the
   capability key is rejected with a `422`. See
   [`vm` RuntimeClass](vm-runtimeclass.md#node-capability-labels).
6. Scheduled, but stuck `ProviderFailed` with a `ProviderCreateFailed` event naming a platform
   mismatch? (`kubectl describe pod` shows it, and it is never `ImagePullBackOff`.) The Rosetta labels
   are **advertised but not yet honored** at pull. Multi-arch selection itself works, and k3sm reads the
   manifest list and picks a platform, but `linux/amd64` is not among the platforms it will accept
   on either path today. The guest path itself (`runtimeClassName: vm`, `linux/arm64`) is built and
   works; the node's VM host attaches no Rosetta directory share to its guests, so nothing inside a
   guest could translate an amd64 payload yet. An amd64-only image is therefore refused at pull
   rather than started and left to crash. That is a documented gap, not a broken node; see
   [`vm` RuntimeClass](vm-runtimeclass.md#rosetta-labels-advertised-only).

## Multi-Node Join Fails

- Re-mint the token (`sudo k3sm token create`); tokens expire.
- Confirm the agent can reach the server on `6443` and the wireguard mesh is up. See
  [Multi-node](multi-node.md).

## The Thunderbolt Interconnect Is Not Used

Start with `sudo k3sm doctor` on each cabled Mac. Its rows starting with `ic-` check `bridge0` and
its Thunderbolt members, the netd socket, the node's interconnect address, the peers, the attached
Pods, cable loops and stray state, and each row that is not a pass prints the command that fixes
it. Then:

- Run `k3sm status` on the control plane. A `disabled` interconnect row means nobody armed it; run
  `k3sm interconnect enable` there. A node named as out of range has a cluster index above 30 and
  never gets an address.
- Read the Pod's `k3sm.io/InterconnectAttached` condition
  (`kubectl get pod <name> -o jsonpath='{.status.conditions}'`). A `False` condition names why the
  attach was refused, and the Pod's Warning Events say the same.
- A listener has to bind `$K3SM_INTERCONNECT_IP` to be reached over the cable. A wildcard bind stays
  on the Pod IP.
- A peer that stops answering is often asleep. Thunderbolt has no Wake-on-LAN; `k3sm doctor`'s
  `ic-sleep` row prints the setting that keeps it awake.

See [Interconnects](interconnects.md) for how the cable is armed and used.

## A Node Went Offline and Pods Are Stuck Terminating

A Mac that goes away while it is running Pods leaves them stuck: `kubectl get pod` shows them
`Terminating` indefinitely, because nothing on that Mac can confirm the container is actually gone.
Work through this in order.

- **Confirm the Mac is genuinely off, not asleep or off-network.** Ping its LAN address, and check
  how long `kubectl get node <name>` has shown it `NotReady` (the age of that condition, not the
  node). A Mac that is asleep or briefly disconnected heals itself on wake and needs nothing below;
  do not tell a node that is coming back that it is out of service.
- **If the Mac is coming back**, stop after applying the taint below and remove it once the node
  rejoins. Deleting the node is only for a Mac that is actually leaving the cluster; see
  [Removing a worker](multi-node.md#removing-a-worker) for that flow instead.
- **Apply the out-of-service taint** once you are sure the Mac is not coming back on its own.
  Check first: the Mac is powered off or disconnected for good, not asleep, because the taint lets
  its Pods be deleted while their containers may still run there:

  ```sh
  kubectl taint node <name> node.kubernetes.io/out-of-service=nodeshutdown:NoExecute
  ```

  `k3sm status` prints this exact command in the workloads row once a Pod has been stuck
  terminating on a `NotReady` node for more than two minutes, so you rarely have to type it from
  memory. The taint tells the pod garbage collector it may finish deleting Pods bound to that node.
  It rechecks every 20 seconds (the pinned v1.37 podgc interval), so a stuck Pod clears within
  about that long of the taint landing.
- **Remove the taint once the node is back:**

  ```sh
  kubectl taint node <name> node.kubernetes.io/out-of-service:NoExecute-
  ```
- **Force-delete as a last resort**, only if a Pod is still stuck after the taint, or you cannot
  wait for it. Check first: the Pod has no attached volume another copy could write to at the same
  time:

  ```sh
  kubectl delete pod <name> --grace-period=0 --force
  ```

  A force-deleted Pod may still be running on the partitioned Mac. The cluster starts a
  replacement, and two copies can run at once until the Mac returns and is cleaned up. For a Pod
  with attached storage the stakes are higher: check the volume's node binding first, because two
  writers on one volume corrupt data where two stateless copies merely waste cycles.
- **Prevent one offline node from freezing a rollout.** A DaemonSet's default `RollingUpdate`
  strategy waits for every existing Pod to be replaced in place, so a node that never reports back
  holds up the whole rollout. Set `maxSurge: 1` and `maxUnavailable: 0` on the DaemonSet's
  `updateStrategy.rollingUpdate` so a new Pod comes up beside the old one instead of waiting for a
  slot an offline node will never free.

## Checks That Need sudo

Some rows read files or sockets that only root may open: the runtime daemon's socket, the datastore
file, the serving certificate, the etcd and mesh records, the installed daemon's plist. Run as an
ordinary account, `k3sm status` reports those rows as `needs-admin` (or `unknown` with `sudo k3sm
status` as the remedy) instead of guessing. A `needs-admin` row never moves the verdict, and it does
not mean anything is wrong. Run the same report as an administrator to get the answer:

```sh
sudo k3sm status
```

If the row is still `unknown` under sudo, the file it reads is missing or damaged, and the row's
detail names it.

## A k3sm Daemon Is Not Running

The `netd`, `server` and `agent` rows report what launchd says about each LaunchDaemon. Read the
state first:

- **`not-loaded`**: nothing runs the daemon. The install is incomplete or was partly removed; `sudo
  k3sm install` puts it back and is safe to re-run.
- **`disabled`**: launchd will not start it, not even at boot. If you ran `k3sm stop`, that is on
  purpose and `sudo k3sm start` brings it back (see [Stopping and starting](stop-start.md)).
  Otherwise re-enable it with `sudo launchctl enable system/<label>`, then restart it.
- **`stopped`**: it is loaded but not running. Restart it with `sudo launchctl kickstart -k
  system/<label>`.
- **`failed`** or **`crash-loop`**: it exited with an error. The row quotes the last line of its
  log, and `k3sm status logs <row>` prints more. Fix what the log names, then restart it.
- **`unknown`** with a warning: launchd says it is running but its process is gone. Restart it.

The labels are `io.k3sm.netd`, `io.k3sm.server` on a control-plane Mac and `io.k3sm.agent` on a
worker. When netd is down, pods on that Mac lose their network and cluster names stop resolving on
the host.

## The Crash-Loop Breaker Tripped

When a control-plane component crashes again and again, or the control plane fails to come up
several times in a row, the server daemon parks itself: it stays running so launchd does not keep
restarting it, but it serves nothing. `k3sm status` reports the server row as `crash-loop` with the
time the breaker tripped.

A server that was killed outright leaves its control-plane processes running. Its next start stops
the ones it left behind before starting its own, so they do not count toward the breaker; a process
holding the datastore port that this server did not start is still refused. A server parked on the
crash-loop breaker keeps its work dir locked, so stop it (`sudo k3sm stop` or `launchctl bootout`)
before a restore.

1. Read what it recorded. The row's remedy names the crash-loop record; each entry carries the
   failing component and the tail of its log:

   ```sh
   k3sm status logs server
   sudo tail -n 50 /var/lib/k3sm/server/crashloop.json
   ```

2. Fix the fault it names. A fault that cannot heal on retry (a bad flag, a missing file) is
   quoted in the row's remedy with the command that repairs it. A breaker tripped by repeated loss
   of the leader lease points at etcd quorum or an overloaded apiserver; check the etcd and
   apiserver rows on every server.
3. Clear the record. The parked daemon notices and restarts the control plane by itself:

   ```sh
   sudo k3sm server --clear-crashloop
   ```

## The Staged Control Plane Does Not Match This Build

Each k3sm build carries the Kubernetes control-plane binaries it was tested with, and stages them
when it installs. The server row warns when the binaries that are actually serving differ from the
ones this build pins:

- **Older than this build**: k3sm was upgraded but the control-plane binaries were not re-staged,
  so the previous Kubernetes version is still serving. Re-run `sudo k3sm install`; the next start
  of the server picks up the new set.
- **Newer than this build**: the daemon refuses to downgrade the control plane and keeps serving
  the newer set. Install a k3sm release whose control-plane version is at or above the staged one.

## A Node Is Not Ready

The `node` row counts the cluster's nodes that report `Ready`, and the `heartbeat` row says
whether this Mac's own node still reports in on time. A node stops being `Ready` when its daemon
stopped, its Mac is asleep or off the network, or its credential expired.

```sh
k3sm kubectl get nodes
k3sm kubectl describe node <name>      # the conditions say which check failed and since when
```

- On the Mac that is not ready, run `k3sm status`. Its daemon rows and its `apiserver` row usually
  name the cause.
- A stale heartbeat on a running node points at the node daemon itself. Read `k3sm status logs
  server` (or `agent` on a worker) and restart it if it is wedged.
- A worker whose credential expired needs to join again; see [Multi-node](multi-node.md#joining-an-agent).
- A Mac that is gone for good leaves its pods stuck terminating; see
  [the section below](#a-node-went-offline-and-pods-are-stuck-terminating).

## The etcd Member Is Unhealthy

On a server that runs embedded etcd, the `etcd` row reads the member's status record, which the
running server rewrites every minute. What it reports, and what to do:

- **NOSPACE alarm, or nearing the quota**: the database reached its backend quota and the cluster
  turned read-only, or is about to. Compact the keyspace to the current revision, defragment every
  member, then disarm the alarm. Writes resume only after the disarm.
- **No leader**: the member cannot see a majority of servers, so the cluster accepts no writes.
  Start the other servers; each waits for its peers. If a majority is gone for good, stop the
  daemon on one survivor, run `sudo k3sm server --cluster-reset` there, and start it again. Check
  first: take a snapshot of the survivor, and be sure the other servers will not come back, because
  a reset makes this server a cluster of one and the others must re-join with wiped etcd data.
- **Peer address drift**: the member is registered under an address that is no longer this
  server's, so its peers cannot reach it. Restore the previous address (`--etcd-peer-ip`); server
  addresses must be stable, for example through a DHCP reservation. Otherwise remove the member
  through another server and re-join this one with a wiped etcd data directory.
- **Another alarm, such as CORRUPT**: read `k3sm status logs server` for the cause. A corrupt member
  must be removed and re-joined with a wiped etcd data directory.
- **The record is stale or does not parse**: the server stopped refreshing it. Read the server log
  for the reason.

See [High availability](ha.md) and [Backup & restore](backup-restore.md) before you remove or
reset a member.

## A Service Routes to the Wrong Backends

The `services` row compares the Service proxy's own record of what it routes with the Ready
endpoints the API holds. When they differ, traffic for those Service ports may reach the wrong
pods, or none.

- Wait a minute. The proxy re-lists Services and EndpointSlices every 30 seconds and repairs a
  lost update by itself.
- If the row still differs, restart the server:

  ```sh
  sudo launchctl kickstart -k system/io.k3sm.server
  ```

- If the row says Services could not be listed, check that the API answers for your account:
  `k3sm kubectl get endpointslices -A`.
- Right after a start the row may say the proxy has not recorded yet. It does so 30 seconds after
  the server starts.

## The Ingest Registry

A server started with `--registry-port` runs a node-local registry and records whether it is
serving. The `ingest-registry` row checks that record against the registry itself:

- **`down`**: the registry was recorded as serving but does not answer on its port, so pushes and
  pulls through it fail. Restart the server, which restarts the registry:
  `sudo launchctl kickstart -k system/io.k3sm.server`.
- **`disabled`**: the server gave up starting it, and the row's detail says why (for example, the
  port is already in use). Fix that cause, or choose another `--registry-port`, then restart the
  server.
- **The record does not parse, or names an unknown state**: restart the server, which rewrites the
  record. An unknown state means the record was written by a newer k3sm than the one you ran the
  report with.

See [Node-local registry](registry.md) and
[A Pod Cannot Pull From the Node-Local Registry](#a-pod-cannot-pull-from-the-node-local-registry).

## The Runtime Daemon Is Unhealthy

The runtime daemon starts, stops and inspects the containers on its node. Its socket is
owner-only, so an ordinary account sees the `runtimed` row as `needs-admin`; run `sudo k3sm
status` for the answer. When it does not answer, or reports itself unhealthy, pods on that node
may not start. The row names the conditions that are not true. Restart the node daemon, which
restarts the runtime with it:

```sh
sudo launchctl kickstart -k system/io.k3sm.server   # io.k3sm.agent on a worker
```

If it stays unhealthy, read `k3sm status logs server` (or `agent`). A `NetworkReady` condition
that is false points at netd: check the `netd` row.

## The Node Resolver Does Not Answer

Cluster names (`*.svc` and the cluster domain) resolve through a resolver on each node, which netd
publishes into the host's resolver configuration. Two rows cover it:

- **`dns`** asks the resolver for the `kubernetes` Service. If it does not answer over UDP, or
  answers with no address, restart the node daemon:
  `sudo launchctl kickstart -k system/io.k3sm.server` (`io.k3sm.agent` on a worker). If it answers
  over TCP but not UDP, its UDP socket stopped receiving, and the same restart fixes it. A
  `--dns-vip` that is not an IP address serves no resolver at all; re-run `sudo k3sm install` with a
  valid address, or without the flag.
- **`node-resolver`** checks that the host routes cluster names to that resolver. If the entry is
  missing, or netd is not running to maintain it, restart netd, which republishes it:

  ```sh
  sudo launchctl kickstart -k system/io.k3sm.netd
  ```

  `scutil --dns` shows the host resolver configuration directly.

For names that fail only inside a pod, see
[DNS From Inside a Pod Does Not Resolve Cluster Names](#dns-from-inside-a-pod-does-not-resolve-cluster-names).

## Host Binaries Changed After a macOS Update

Pods that start through `/bin/sh` run re-signed copies of a few host binaries, which carry k3sm's
DNS and path shims. A macOS update replaces the originals, and the copies then lag behind. The
`shadow-shells` row reports `drift` with the binaries that changed, `missing` when no copies exist,
and a warning when the copies come from an older install that lacks some this k3sm makes. Re-run
the install, which re-makes the set from the current host binaries:

```sh
sudo k3sm install
```

## Next

- [Stopping and starting](stop-start.md) covers a node that reads as stopped on purpose, and a stop that left something behind.
- [FAQ](faq.md) has quick answers.
- [Limitations](limitations.md) answers whether something is a bug or a documented gap.
- [Backup & restore](backup-restore.md) covers recovering the datastore.
- [Certificates](certificates.md) covers the PKI, rotation, and its limits.

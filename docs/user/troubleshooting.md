# Troubleshooting

When a k3sm cluster does not behave. Start with logs, then the common failure modes below.

## Logs

k3sm daemons run as launchd jobs under the `io.k3sm.*` labels and log to the unified log system:

```sh
log show --predicate 'subsystem BEGINSWITH "io.k3sm"' --last 10m
launchctl print system/io.k3sm.server     # daemon state (label may differ per role)
```

Not everything lands there. The server process's own structured logs (the LoadBalancer controller, the
ingress host, the control-plane supervisor) go to **stderr**, which launchd routes to
**`/var/log/k3sm/server.log`** — the unified-log predicate above shows none of them.

## Control Plane Startup Failure

- Confirm install completed: `k3sm version` and `sudo k3sm install` (idempotent).
- Check the datastore is present and not locked — the kine/SQLite DB lives under the server work
  directory (see [Backup & restore](backup-restore.md)).
- Restart the daemon: `launchctl kickstart -k system/io.k3sm.server` (label per your role).

## Stuck or Crash-Looping Pods

On the **default runtime** (what every installed cluster runs), `restartPolicy` **is** honored: the
container is restarted in place with an upstream-shaped `CrashLoopBackOff` backoff, and
`kubectl get pod` shows the restart count climbing. If yours is not restarting, work through these:

- **Is it a plain init container?** A non-sidecar init container that fails is **not** re-run in
  place — that is the one remaining restart gap on the default runtime. Only a controller replacing
  the Pod unsticks it.
- **Did you start the node with `--runtime hostprocess`?** That explicit rootless-dev opt-out honors
  no `restartPolicy` at all — an exited container is reaped once and never respawned. Drop the flag
  to get the default runtime back.
- **Is the Pod's policy `Never`, or is it a `Job` that has already succeeded?** Both are working as
  specified.
- **Stuck rather than exiting?** Check the Pod was **adapted** to the native image model — a raw
  Linux image cannot run as a Darwin process (see [Images](images.md)).

See [Limitations](limitations.md#restartpolicy--honored-on-the-default-runtime-not-on-the-hostprocess-opt-out)
for the precise scope.

## DNS From Inside a Pod Does Not Resolve Cluster Names

On the default runtime this should work — Service A records, headless Services, StatefulSet per-Pod
names, SRV and PTR all resolve. Check these in order:

- **Is the lookup coming from `/bin/sh` or another `/usr/bin` tool?** macOS strips
  `DYLD_INSERT_LIBRARIES` from SIP platform binaries, so k3sm's `getaddrinfo` shim never loads into
  them and their lookups go to the **host** resolver. Do the lookup from your compiled workload
  instead — this is a substrate ceiling, not a misconfiguration.
- **Is the Pod's `dnsPolicy` `Default` or `None`?** Neither selects cluster DNS, so nothing is
  injected. Use `ClusterFirst` (the default when the field is unset).
- **Is it an AAAA lookup?** k3sm's CIDRs are IPv4; AAAA is never answered.
- **Are you on `--runtime hostprocess` or the `vm` RuntimeClass?** In-pod cluster DNS is not wired on
  either — every lookup goes to the host resolver.

See [Limitations](limitations.md#dns--what-resolves-and-on-which-runtime-path) for the full
per-path picture.

## UDP Service Failures

Only cluster DNS on `:53` uses UDP today; general UDP Services (ClusterIP **and** NodePort) are deferred.
See [Limitations](limitations.md).

## LoadBalancer Stuck `<pending>`

**Do not look in the unified log for this one.** The LoadBalancer controller and the ingress host log
through `slog` to **stderr**, which the launchd job routes to a file — the
`log show --predicate 'subsystem BEGINSWITH "io.k3sm"'` command at the top of this page shows **nothing**
for them. Read the file instead:

```sh
grep svclb /var/log/k3sm/server.log | tail -50
grep ingress /var/log/k3sm/server.log | tail -50
```

The controller emits one line at start carrying **both** addresses — they are different:

```
svclb: loadbalancer controller starting bind=0.0.0.0 advertise=100.64.0.1
```

Then look for one of these:

- **`svclb: loadbalancer port is RESERVED by a k3sm wildcard listener`** — the Service declares a port
  k3sm's own listeners own: the NodePort range `30000-32767`, or the kubelet API port `10250`. No
  listener is bound and the status stays empty **on purpose** (taking `10250` would break
  `kubectl logs`/`exec`/`top` on this node). Pick a different `spec.ports[].port`. Normally the API
  rejects such a Service at `kubectl apply` with a message naming the port; if it did not, the admission
  policy failed to provision — the log carries a matching `provision reserved-loadbalancer-port DENY
  policy` error.
- **`svclb: listener bind failed`** — something else already holds that wildcard port. The log line
  carries the exact diagnostic command; run it:

  ```sh
  lsof -nP -iTCP:<port> -sTCP:LISTEN
  ```

  The usual culprits are another process on the Mac, a **pod** (macOS has no network namespaces, so pods
  share the node's port space — see [Limitations](limitations.md)), or a second LoadBalancer Service
  declaring the same port. k3sm never picks a different port for you.
- **`loadbalancer/ingress status will stay EMPTY: no advertisable node address could be derived`** — the
  listeners are bound and serving, but there is no address that would be correct to publish, so nothing is written
  rather than advertising an unreachable one. Check `kubectl get node -o wide` shows a non-loopback
  `INTERNAL-IP`, and that you did not start the server with `--network none`.
- **`ingress bind retries exhausted`** — the ingress listeners gave up (bounded retry, no port
  fallback). Free the port and restart the daemon.

Restart the control plane after fixing the conflict:

```sh
sudo launchctl kickstart -k system/io.k3sm.server
```

**A `<pending>` Service is not visible in `kubectl describe`** — k3sm has no `EventRecorder` for this
path yet (the event pipeline is planned), so the log file is the only place the reason appears.

## `kubectl top` Returns No Metrics

k3sm ships no metrics-server and has no CPU accounting; install a metrics-server operator if you need the
`metrics.k8s.io` verb. See [kubectl access](kubectl-access.md) and [Limitations](limitations.md).

## Certificate Nearing Expiry

Component certificates are re-issued on every control-plane boot, so a restart renews them.
`sudo k3sm certificate rotate` reports what a restart would re-issue (and both CA pins, which
never change); `--restart` performs it. Rotation does **not** revoke anything and does not cover
worker-node certs — see [Certificates](certificates.md) before you rely on it.

## Rosetta-Selecting Pods Stuck Pending

The node advertises a capability label only when its start-time probe said yes.

1. Check what the node advertises:
   `kubectl get nodes -L k3sm.io/virtualization,k3sm.io/rosetta,k3sm.io/rosetta-linux`.
2. If the key is missing, the node's log carries **two** lines for it: one naming the `condition` and the
   `reason` (`NotInstalled`, `TranslationFailed`, `NotSupported`, `QueryFailed`, `VMBackendUnavailable`)
   explaining why the capability was not advertised, and one naming the `label` key that was therefore
   left absent — grep the log for the key itself (`k3sm.io/rosetta-linux`) and you land on it.
3. `k3sm.io/rosetta-linux` needs **both** virtualization and guest Rosetta. A node with
   `k3sm.io/rosetta` but no `k3sm.io/virtualization` will **never** carry it — that is correct, not a bug.
4. Installed Rosetta after the node came up? The probes run once at daemon start — restart it:
   `sudo launchctl kickstart -k system/io.k3sm.server`.
5. Your Pod must also keep `kubernetes.io/os: darwin` in its `nodeSelector`; a Pod with only the
   capability key is rejected with a `422`. See
   [`vm` RuntimeClass](vm-runtimeclass.md#node-capability-labels).
6. **Scheduled, but `ImagePullBackOff` with a platform error?** The two Rosetta labels are **advertised
   but not yet honored**. Multi-arch selection itself works — k3sm reads the manifest list and picks a
   platform — but `linux/amd64` is not among the platforms it will accept, because
   translating an amd64 payload happens inside a guest and that guest path does not run yet. So an
   amd64-only image is refused at pull rather than started and left to crash. That is a documented
   gap, not a broken node; see
   [`vm` RuntimeClass](vm-runtimeclass.md#rosetta-labels-advertised-only).

## Multi-Node Join Fails

- Re-mint the token (`sudo k3sm token create`) — tokens expire.
- Confirm the agent can reach the server on `6443` and the wireguard mesh is up. See
  [Multi-node](multi-node.md).

## Next

- [FAQ](faq.md) — quick answers.
- [Limitations](limitations.md) — is this a bug or a documented gap?
- [Backup & restore](backup-restore.md) — recover the datastore.
- [Certificates](certificates.md) — the PKI, rotation, and its limits.

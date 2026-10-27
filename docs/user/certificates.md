# Certificates

k3sm mints its own PKI at first boot and re-issues the control plane's leaf certificates on
**every** boot. `k3sm certificate rotate` is the supported way to force that re-issue and to
verify the certificate authorities came through it untouched.

> Read [Limitations](limitations.md) for what k3sm does **not** do here. Most importantly,
> rotation does not revoke anything.

## Two CAs

k3sm stands up two independent self-signed CAs under the server work dir's `tls/` directory
(the k3s server-CA / client-CA split):

| CA | File | Role |
|---|---|---|
| **cluster CA** | `tls/cluster-ca.crt` | The serving anchor. A join token embeds `K10<sha256(cluster CA)>`; a joining node pins it. Issues kubelet-serving certs and the apiserver serving cert, on a single-node server as on a multi-node one, plus the image registry's serving cert and the server's one-day update-signing cert. |
| **signing CA** | `tls/signing-ca.crt` | The apiserver's `--client-ca-file`. Issues the `system:node:<name>` client certs and the scheduler / controller-manager client certs. |

**Neither CA is ever re-minted.** Re-minting the cluster CA would invalidate the pin in every
join token and every node's kubeconfig; re-minting the signing CA would invalidate every client
certificate at once. There is no CA-replacement flow. `k3sm certificate rotate-ca` exists only
to say so explicitly. Replacing a CA means recreating the cluster.

## The Request-Header CA

One more CA, `tls/request-header-ca.crt`, backs the Kubernetes aggregation layer. The apiserver trusts
a client certificate that chains to it, with the name `system:auth-proxy`, to say which user and
groups a request is for, so it can forward requests to an extension apiserver on a user's behalf. It
issues one thing, that front-proxy client certificate (`client-auth-proxy.crt` in the server work
dir), which is re-issued on every boot like the other leaves. It is separate from the signing CA on
purpose: a certificate it issues can act as any user, so no node or component certificate may chain
to it.

It is created on the first boot of a release that has the aggregation layer, on a single server or on
the first server of an HA cluster. A server started with `--server-join` never creates it and imports
it from the server it joins through. It is not part of the join token pin, and
`k3sm certificate rotate` never rotates it. The `request-header` row of `k3sm status` shows its pin.
For an HA upgrade see [HA](ha.md#upgrading-an-ha-cluster-to-the-aggregation-layer).

## What Rotation Is

Every control-plane boot re-issues the CA-signed leaves unconditionally: the scheduler and
controller-manager client-cert kubeconfigs, the apiserver serving cert, and the server node's own
kubelet serving cert, which the cluster CA signs on a single-node server as on a multi-node one and
which is held in memory, never written to disk. A restart therefore *is* the rotation.

The image registry's serving certificate and the managed update's signing certificate are also
held in memory, and the server replaces each before it expires, without a restart.

Both serving certs are issued for one year, and only a boot re-issues them. A server that runs more
than 365 days without a restart serves an expired kubelet certificate until it is restarted.
Until then metrics-server cannot scrape that node, and on a multi-node server `kubectl logs` and
`exec` against it fail too. `k3sm certificate rotate` wraps that restart with
checks:

1. verify the CA hierarchy is present and complete (reading only the certificates, never a CA
   private key);
2. record both CA pins;
3. report, or note the daemon's current pid and restart the `io.k3sm.server` LaunchDaemon;
4. re-verify both pins are byte-for-byte the same;
5. wait, with a bounded timeout, for launchd to report a **new** instance that is serving;
6. re-verify both pins once more, now that the new control plane has booted on them.

Step 5 is stricter than it looks. `launchctl kickstart -k` returns as soon as the restart is
*requested*, and the outgoing control plane keeps its listeners for several seconds while it shuts
its components down, so "the apiserver answers" alone would be satisfied by the instance that is
going away, and a daemon that never came back would be reported as a success. The wait therefore
requires a **changed launchd pid** as well as a healthy answer, and the answer must come from a TLS
peer whose certificate chains to the cluster CA k3sm already holds on disk. A different process
holding the port is not the control plane coming back, and is reported as a failure.

It writes **nothing** into the work dir, because the daemon runs as the unprivileged `_k3sm` user:
a root-written file there would make the *next* boot fail with EACCES, and launchd's `KeepAlive`
would turn that into an invisible restart loop.

## Usage

```sh
# Report only (the default): prints the CA pins, what a restart re-issues, and the blast radius.
sudo k3sm certificate rotate

# Perform the rotation: restart the control plane and verify it comes back.
sudo k3sm certificate rotate --restart
```

Run it with `sudo`: the state root belongs to the `_k3sm` service user and restarting a
LaunchDaemon in the system domain is a root operation. Without `sudo` the work dir resolves to
your own home, which has no CA hierarchy, and the command exits non-zero rather than creating
one.

| Flag | Meaning |
|---|---|
| `--restart` (alias `--yes`) | Restart. Without it the command only reports. |
| `--work-dir <dir>` | The control-plane state root. Defaults to this posture's work dir. |
| `--apiserver-port <n>` | The port the post-restart health probe checks (default `6444`). |

The command exits non-zero (and says where to look) if the hierarchy is missing or damaged, if
the daemon is not loaded, if a CA pin changed, or if a new instance of the control plane does not
come back and serve.

## Blast Radius

A rotation restarts the control-plane daemon, which is **not** a graceful, in-place reload:

- Pods survive. A rotation restarts the daemon with `launchctl kickstart -k`, and the new daemon
  re-attaches to every Pod whose processes are still alive, keeping its Pod IP and its listeners (see
  [What Survives a Node-Daemon Restart](limitations.md#what-survives-a-node-daemon-restart)).
  A Pod that did not survive is recreated only if a controller owns it.
- The apiserver is unavailable for roughly 5–90 seconds while kine and the apiserver come
  back and the watch cache is rebuilt.
- On an HA control plane the scheduler / controller-manager leader-election leases flap.

Treat it like a node restart, because it is one. See [Upgrade](upgrade.md) for the same
restart model applied to a version bump.

## What Is Not Rotated

| Not rotated | Why |
|---|---|
| The cluster, signing and request-header CAs | Re-minting either orphans every node; see above. |
| `apiserver-certs/` | The self-signed serving material of releases before the apiserver's certificate came from the cluster CA. Nothing reads it now. It is kept for one release so a rollback to the previous release still finds it, and a later release removes it. |
| The admin kubeconfig and `tokens.csv` | The admin credential is a static bearer token set at install time, not a CA-signed identity. Re-run `sudo k3sm install` to change it. |
| `sa.key` / `sa.pub` | The service-account signing keypair. Replacing it invalidates every issued ServiceAccount token. |
| Join tokens (`k3sm token create`) and the HA server-join secret | Separate credentials with their own lifecycle. Worker tokens are TTL-bounded; mint a new one when you need one. |
| **Worker / agent node certificates** | A node's client and kubelet-serving certs are re-issued when the **agent** restarts and re-runs its join, which needs a fresh join token. Rotating the server does not touch them. |

## Upgrading a Single-Node Server

Releases before this one let a single-node apiserver sign its own certificate in
`apiserver-certs/`. This release serves a certificate signed by the cluster CA instead, so the
trust anchor changes.

Back up both directories before you upgrade, because a rollback to the previous release relies on
the old files:

```sh
sudo cp -a /var/lib/k3sm/server/tls /var/lib/k3sm/server/apiserver-certs <backup-dir>
```

Upgrade with `sudo k3sm install`. It rewrites the admin kubeconfig to pin the cluster CA, and every
namespace's `kube-root-ca.crt` becomes the cluster CA. A Pod that read its `ca.crt` at start fails
with "unknown authority" until it is restarted. `sudo k3sm status` shows whether the admin
kubeconfig still pins the cluster CA on its `admin-kubeconfig` row.

Rolling back works the other way round. Reinstalling the previous release publishes its self-signed
certificate in `kube-root-ca.crt` again and rewrites the admin kubeconfig, so a Pod that read the
cluster CA fails with "unknown authority" until it is restarted.

## Rotation Does Not Revoke

k3sm publishes no CRL and no OCSP responder, and `--client-ca-file` trust is CA-wide: the
apiserver accepts *any* unexpired certificate signed by the signing CA. A certificate superseded
by a rotation therefore **stays valid until it expires** (component certs are issued for one
year).

Rotation is renewal hygiene, keeping certificates well away from expiry. It is **not** a response
to a compromised credential. There is no supported way to invalidate one leaf certificate today.
If a control-plane credential is compromised, the remedy is to recreate the cluster.

## Next

- [Troubleshooting](troubleshooting.md), when the control plane does not come back.
- [Multi-node](multi-node.md), for join tokens and the CA pin a joining node checks.
- [Limitations](limitations.md), the gaps.

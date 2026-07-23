# Certificates

k3sm mints its own PKI at first boot and re-issues the control plane's leaf certificates on
**every** boot. `k3sm certificate rotate` is the supported way to force that re-issue and to
verify the certificate authorities came through it untouched.

> Read [limitations.md](limitations.md) for what k3sm does **not** do here — most importantly,
> rotation does not revoke anything.

## The two CAs

k3sm stands up two independent self-signed CAs under the server work dir's `tls/` directory
(the k3s server-CA / client-CA split):

| CA | File | Role |
|---|---|---|
| **cluster CA** | `tls/cluster-ca.crt` | The serving anchor. A join token embeds `K10<sha256(cluster CA)>`; a joining node pins it. Issues kubelet-serving certs and the multi-node apiserver serving cert. |
| **signing CA** | `tls/signing-ca.crt` | The apiserver's `--client-ca-file`. Issues the `system:node:<name>` client certs and the scheduler / controller-manager client certs. |

**Neither CA is ever re-minted.** Re-minting the cluster CA would invalidate the pin in every
join token and every node's kubeconfig; re-minting the signing CA would invalidate every client
certificate at once. There is no CA-replacement flow — `k3sm certificate rotate-ca` exists only
to say so explicitly. Replacing a CA means recreating the cluster.

## What rotation actually is

Every control-plane boot re-issues the CA-signed leaves unconditionally: the scheduler and
controller-manager client-cert kubeconfigs, and (on a multi-node server) the apiserver serving
cert. A restart therefore *is* the rotation. `k3sm certificate rotate` is the safe wrapper
around it:

1. verify the CA hierarchy is present and complete (reading only the certificates — never a CA
   private key);
2. record both CA pins;
3. report, or note the daemon's current pid and restart the `io.k3sm.server` LaunchDaemon;
4. re-verify both pins are byte-for-byte the same;
5. wait, with a bounded timeout, for launchd to report a **new** instance that is serving;
6. re-verify both pins once more, now that the new control plane has booted on them.

Step 5 is stricter than it looks. `launchctl kickstart -k` returns as soon as the restart is
*requested*, and the outgoing control plane keeps its listeners for several seconds while it shuts
its components down — so "the apiserver answers" alone would be satisfied by the instance that is
going away, and a daemon that never came back would be reported as a success. The wait therefore
requires a **changed launchd pid** as well as a healthy answer, and the answer must come from a TLS
peer whose certificate chains to a CA k3sm already holds on disk (the cluster CA on a multi-node
server, the apiserver's own self-signed cert on a single-node one). A different process holding the
port is not the control plane coming back, and is reported as a failure.

It writes **nothing** into the work dir. That is deliberate: the daemon runs as the unprivileged
`_k3sm` user, so a root-written file there would make the *next* boot fail with EACCES — and
launchd's `KeepAlive` would turn that into an invisible restart loop.

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
| `--restart` (alias `--yes`) | Actually restart. Without it the command only reports. |
| `--work-dir <dir>` | The control-plane state root. Defaults to this posture's work dir. |
| `--apiserver-port <n>` | The port the post-restart health probe checks (default `6444`). |

The command exits non-zero — and says where to look — if the hierarchy is missing or damaged, if
the daemon is not loaded, if a CA pin changed, or if a new instance of the control plane does not
come back and serve.

## Blast radius

A rotation restarts the control-plane daemon, which is **not** a graceful, in-place reload:

- **Every pod on the node is destroyed.** Pods are in-process children of the daemon; there is no
  durable pod-to-IP manifest, and startup reconciliation sweeps every k3sm-owned `lo0` alias.
  Controller-owned pods (Deployments, StatefulSets) are recreated; bare pods are not.
- **The apiserver is unavailable for roughly 5–90 seconds** while kine and the apiserver come
  back and the watch cache is rebuilt.
- On an HA control plane the scheduler / controller-manager leader-election leases flap.

Treat it like a node restart, because it is one. See [upgrade.md](upgrade.md) for the same
restart model applied to a version bump.

## What is not rotated

| Not rotated | Why |
|---|---|
| The cluster CA and signing CA | Re-minting either orphans every node — see above. |
| `apiserver-certs/` | The apiserver's own self-signed serving material. It is also the controller-manager's `--root-ca-file` and therefore the source of every pod's projected `kube-root-ca.crt`; replacing it is a cluster-wide trust event. Out of scope. |
| The admin kubeconfig and `tokens.csv` | The admin credential is a static bearer token set at install time, not a CA-signed identity. Re-run `sudo k3sm install` to change it. |
| `sa.key` / `sa.pub` | The service-account signing keypair. Replacing it invalidates every issued ServiceAccount token. |
| Join tokens (`k3sm token create`) and the HA server-join secret | Separate credentials with their own lifecycle. Worker tokens are TTL-bounded; mint a new one when you need one. |
| **Worker / agent node certificates** | A node's client and kubelet-serving certs are re-issued when the **agent** restarts and re-runs its join, which needs a fresh join token. Rotating the server does not touch them. |

## Rotation does not revoke

k3sm publishes no CRL and no OCSP responder, and `--client-ca-file` trust is CA-wide: the
apiserver accepts *any* unexpired certificate signed by the signing CA. A certificate superseded
by a rotation therefore **stays valid until it expires** (component certs are issued for one
year).

So rotation is renewal hygiene — keeping certificates well away from expiry — **not** a response
to a compromised credential. There is no supported way to invalidate one leaf certificate today.
If a control-plane credential is compromised, the honest remedy is to recreate the cluster.

## Next

- [troubleshooting.md](troubleshooting.md) — when the control plane does not come back.
- [multi-node.md](multi-node.md) — join tokens and the CA pin a joining node checks.
- [limitations.md](limitations.md) — the honest gaps.

# Multi-node

Joining more than one Mac into a single k3sm cluster.

> **Status: EXPERIMENTAL.** Multi-node ships as documented **EXPERIMENTAL** and is **not**
> launch-blocking; its de-EXPERIMENTAL graduation is the **v0.3** milestone. Treat it as
> preview-quality until then. See [Limitations](limitations.md).

## Mesh Model

One Mac runs the control plane (`k3sm server`); additional Macs join as **agents** running the Virtual
Kubelet node. Nodes are connected by a **wireguard mesh** (the `MeshPeer` model), so Pods and Services
can be reached across machines.

## Joining an Agent

On the server, mint a join token:

```sh
sudo k3sm token create
```

Run it with `sudo`: the cluster CA whose hash the token pins lives in the control-plane state root,
which belongs to the `_k3sm` service user. Without `sudo` the work dir resolves to your own home and
the command exits non-zero rather than inventing a CA there.

On the agent Mac:

```sh
sudo k3sm install
k3sm agent --server https://<server-host>:6443 --token <token>
```

The agent authenticates with the bootstrap token, receives its node credentials, and its wireguard peer
**public** key is registered in the `MeshPeer` records held in the datastore. Private keys never leave
the node — the `MeshPeer` records carry public keys only.

## What Crosses Nodes

- **Services** resolve cluster-wide via the userspace Service proxy.
- **Mesh traffic** between Pods on different nodes rides the wireguard tunnel with per-peer symmetric
  `AllowedIPs`.

## Caveats

- Per-pod IP identity and headless/StatefulSet DNS records are present, but multi-node as a whole is
  EXPERIMENTAL — validate cross-node resolution for your own workload rather than assuming it. See
  [Limitations](limitations.md).
- A cluster upgrade is a **node-by-node** rolling restart of the launchd daemons; see
  [Upgrade](upgrade.md).
- For a highly-available control plane, see [HA](ha.md) (also EXPERIMENTAL).

## Next

- [HA](ha.md) — HA control plane.
- [Upgrade](upgrade.md) — the rolling-restart model.
- [Troubleshooting](troubleshooting.md) — join and mesh failures.

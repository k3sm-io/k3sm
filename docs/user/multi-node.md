# Multi-node

Joining more than one Mac into a single k3sm cluster.

> **Status: EXPERIMENTAL.** Multi-node (M6) ships as documented **EXPERIMENTAL** — a v0.3 headline, not
> launch-blocking. Treat it as preview-quality. See [limitations.md](limitations.md).

## The model

One Mac runs the control plane (`k3sm server`); additional Macs join as **agents** running the Virtual
Kubelet node. Nodes are connected by a **wireguard mesh** (the `MeshPeer` model), so Pods and Services
can be reached across machines.

## Joining an agent

On the server, mint a join token:

```sh
k3sm token create
```

On the agent Mac:

```sh
sudo k3sm install
k3sm agent --server https://<server-host>:6443 --token <token>
```

The agent authenticates with the bootstrap token, receives its node credentials, and its wireguard peer
**public** key is registered in the `MeshPeer` records held in the datastore. Private keys never leave
the node — the `MeshPeer` records carry public keys only.

## What crosses nodes

- **Services** resolve cluster-wide via the userspace Service proxy.
- **Mesh traffic** between Pods on different nodes rides the wireguard tunnel with per-peer symmetric
  `AllowedIPs`.

## Caveats

- Per-pod IP identity and headless/StatefulSet DNS across nodes are **planned, not present** — see
  [limitations.md](limitations.md).
- A cluster upgrade is a **node-by-node** rolling restart of the launchd daemons; see
  [upgrade.md](upgrade.md).
- For a highly-available control plane, see [ha.md](ha.md) (also EXPERIMENTAL).

## Next

- [ha.md](ha.md) — HA control plane.
- [upgrade.md](upgrade.md) — the rolling-restart model.
- [troubleshooting.md](troubleshooting.md) — join and mesh failures.

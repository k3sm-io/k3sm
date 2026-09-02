# kubectl access

Talking to a k3sm cluster with `kubectl`.

## Bundled Path

k3sm ships a `kubectl` passthrough that uses the admin kubeconfig written by `sudo k3sm install`:

```sh
k3sm kubectl get nodes
k3sm kubectl get pods -A
```

This is the simplest path and needs no extra setup after install.

## Using a Standalone kubectl

`sudo k3sm install` **merges** an admin cluster/user/context into the invoking user's
`~/.kube/config`, preserving whatever was already there. So after install your own `kubectl` reaches
the cluster with no `KUBECONFIG` export at all:

```sh
kubectl config get-contexts    # the k3sm context is there
kubectl get nodes
```

To get the kubeconfig somewhere else — a second machine, a CI secret, a file of its own — use
**`k3sm kubeconfig`**, which prints the admin kubeconfig on stdout, or merges it into a file you name:

```sh
k3sm kubeconfig > ~/k3sm.yaml                  # print it
k3sm kubeconfig --write --path ~/other.yaml    # merge it into another kubeconfig
```

Note that `k3sm kubectl` is a **pure passthrough** to the bundled `kubectl` with `KUBECONFIG` preset —
every subcommand under it is the upstream one, and none of them knows anything about k3sm's own
layout. `k3sm kubeconfig` is the k3sm-specific verb.

Because the control plane is a **real upstream kube-apiserver**, standard clients, RBAC, and API
machinery work normally. The divergences are on the **node** side (how Pods run), not the API surface —
see [Concepts](concepts.md).

## Auth Model

Access is authenticated via the kubeconfig credentials generated at install time and scoped by RBAC.
The bootstrap/join credentials for adding nodes are separate — see [Multi-node](multi-node.md).

## Things That Behave Differently Through kubectl

- **`kubectl top`** needs an **operator-installed metrics-server**; k3sm does not ship one and has no CPU
  accounting, so `top` and HPA-on-CPU do not work out of the box — see [Limitations](limitations.md).
- **`kubectl exec` / `logs` / `port-forward`** target native processes via the node; behavior tracks the
  Virtual Kubelet surface.

## Next

- [Install](install.md) — where the kubeconfig comes from.
- [Quickstart](quickstart.md) — first commands.
- [Troubleshooting](troubleshooting.md) — connection failures.

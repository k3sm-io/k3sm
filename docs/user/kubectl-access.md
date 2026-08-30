# kubectl access

Talking to a k3sm cluster with `kubectl`.

## The bundled path

k3sm ships a `kubectl` passthrough that uses the admin kubeconfig written by `sudo k3sm install`:

```sh
k3sm kubectl get nodes
k3sm kubectl get pods -A
```

This is the simplest path and needs no extra setup after install.

## Using a standalone kubectl

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

(There is no `k3sm kubectl config` that reports a k3sm-specific path: `k3sm kubectl` is a pure
passthrough to the bundled `kubectl`, so `k3sm kubectl config` is upstream `kubectl config` and knows
nothing about k3sm's layout.)

Because the control plane is a **real upstream kube-apiserver**, standard clients, RBAC, and API
machinery work normally. The divergences are on the **node** side (how Pods run), not the API surface —
see [concepts.md](concepts.md).

## Auth model

Access is authenticated via the kubeconfig credentials generated at install time and scoped by RBAC.
The bootstrap/join credentials for adding nodes are separate — see [multi-node.md](multi-node.md).

## Things that behave differently through kubectl

- **`kubectl top`** needs an **operator-installed metrics-server**; k3sm does not ship one and has no CPU
  accounting, so `top` and HPA-on-CPU do not work out of the box — see [limitations.md](limitations.md).
- **`kubectl exec` / `logs` / `port-forward`** target native processes via the node; behavior tracks the
  Virtual Kubelet surface.

## Next

- [install.md](install.md) — where the kubeconfig comes from.
- [quickstart.md](quickstart.md) — first commands.
- [troubleshooting.md](troubleshooting.md) — connection failures.

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

The install step writes an **admin kubeconfig** into the invoking user's home directory. Point your own
`kubectl` (or any client) at it:

```sh
export KUBECONFIG="$HOME/.kube/k3sm.yaml"   # path as reported by `k3sm install` / `k3sm kubectl config`
kubectl get nodes
```

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

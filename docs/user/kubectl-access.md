# kubectl access

Talking to a k3sm cluster with `kubectl`.

## Bundled Path

k3sm ships a `kubectl` passthrough that already knows how to reach the cluster:

```sh
k3sm kubectl get nodes
k3sm kubectl get pods -A
```

This is the simplest path and needs no extra setup after install, because it picks whichever
credentials exist for the account running it:

- As root, or as the `_k3sm` service user the control plane runs as, it uses the admin kubeconfig in
  the server's own work directory, run through the `kubectl` the server downloaded there.
- As you, it uses the `k3sm` context that `sudo k3sm install` merged into your `~/.kube/config` (or
  into `$KUBECONFIG`, if you set one), run through the `kubectl` the installer put under
  `/Library/k3sm`. The server's work directory belongs to the service user and is not readable by
  your account; it does not need to be.

`KUBECONFIG` and `--context` behave as they do for `kubectl`. On that second path k3sm selects the
`k3sm` context for you, but only as a default that your own arguments override, so
`k3sm kubectl --context=prod get nodes` talks to `prod`. Set `K3SM_WORK_DIR` to name a server started
with a non-default `--work-dir`; that pins its work-dir kubeconfig and never falls back to yours.

## Using a Standalone kubectl

`sudo k3sm install` **merges** an admin cluster/user/context into the invoking user's
`~/.kube/config`, preserving whatever was already there. So after install your own `kubectl` reaches
the cluster with no `KUBECONFIG` export at all:

```sh
kubectl config get-contexts    # the k3sm context is there
kubectl get nodes
```

The context is named `k3sm` by default. `sudo k3sm install --kubeconfig-name <name>` merges it under
`<name>` instead (as the cluster, user and context name); the name is remembered, so `k3sm kubectl`,
`k3sm kubeconfig` and `uninstall --purge` use it. A name that already belongs to an entry k3sm did
not create is refused. `k3sm kubeconfig --write --target-name <name>` merges under a different name
than the one it reads.

To get the kubeconfig somewhere else, onto a second machine, into a CI secret, or into a file of its
own, use **`k3sm kubeconfig`**, which prints the admin kubeconfig on stdout, or merges it into a file
you name:

```sh
k3sm kubeconfig > ~/k3sm.yaml                  # print it
k3sm kubeconfig --write --path ~/other.yaml    # merge it into another kubeconfig
```

Apart from choosing those credentials, `k3sm kubectl` is a **pure passthrough** to the
bundled `kubectl`. Every subcommand under it is the upstream one, and none of them knows anything
about k3sm's own layout. `k3sm kubeconfig` is the k3sm-specific verb, and it finds the cluster the
same two ways `k3sm kubectl` does.

Because the control plane is an upstream kube-apiserver, standard clients, RBAC, and API
machinery work normally. The divergences are on the **node** side, in how Pods run, rather than in
the API surface. See [Concepts](concepts.md).

## Auth Model

Access is authenticated via the kubeconfig credentials generated at install time and scoped by RBAC.
The kubeconfig also pins the apiserver's own certificate, so your `kubectl` verifies the control
plane it hands that credential to rather than trusting whatever answers on the port; on a first
install, before the control plane has minted that certificate, the kubeconfig falls back to
unverified TLS until the next `sudo k3sm install` picks the certificate up.
The bootstrap/join credentials for adding nodes are separate; see [Multi-node](multi-node.md).

## Things That Behave Differently Through kubectl

- **`kubectl top pod`** works where k3sm's metrics-server add-on runs: on a server installed with
  `--mesh-ip`. A single-node server without `--mesh-ip` does not run it. Native Pods report the CPU
  time and memory their processes used. HPA on CPU is served but advisory, because no CPU limit is
  enforced. `kubectl top node` shows host-wide figures for every Ready node, workers included. See
  [Limitations](limitations.md#headline-divergences).
- **`kubectl exec` / `logs` / `port-forward`** target native processes via the node; behavior tracks the
  Virtual Kubelet surface.

## Next

- [Install](install.md), where the kubeconfig comes from.
- [Quickstart](quickstart.md), the first commands.
- [Troubleshooting](troubleshooting.md), for connection failures.

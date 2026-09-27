# Helm Charts

k3sm installs Helm charts the way k3s does. You describe a release with a `HelmChart` object, and
the server keeps it installed by running `helm` in a Job. Delete the object and the release is
uninstalled.

The API is `helm.k3sm.io/v1`, a copy of k3s's `helm.cattle.io/v1`: the same kinds (`HelmChart`,
`HelmChartConfig`), the same field names, and the same status conditions. Only the group differs.

```yaml
apiVersion: helm.k3sm.io/v1
kind: HelmChart
metadata:
  name: podinfo
  namespace: kube-system
spec:
  repo: https://stefanprodan.github.io/podinfo
  chart: podinfo
  version: 6.7.1
  targetNamespace: apps
  createNamespace: true
  valuesContent: |
    replicaCount: 1
  set:
    ui.message: hello
```

Apply it with `kubectl apply`, or drop the file into the auto-deploy directory,
`/var/lib/k3sm/manifests` (see [Installation](install.md)), exactly as you would drop it into
k3s's `server/manifests`.

## What Runs

- The server runs a helm controller. It creates a Job named `helm-install-<name>` in the
  HelmChart's namespace, and on deletion a Job named `helm-delete-<name>`.
- The Job is a native pod. Its command is the pinned `helm` (v4.3.0) that ships in the k3sm payload
  beside `kubectl`; there is no helm container image.
- The release is named after the HelmChart and installed into `targetNamespace`, or the HelmChart's
  own namespace when that is empty.
- The Job runs `helm upgrade --install` with `--wait` and `--timeout` (`spec.timeout`, default
  `5m0s`). `valuesContent` is passed as a values file, then the HelmChartConfig overlay, then each
  `set` entry.
- `kubectl get helmcharts -A` shows the Job and whether the last run failed.
- Only one server runs the controller at a time. It holds the `kube-system/k3sm-helm-controller`
  Lease.
- During a Lease partition an HA pair can briefly run two controllers. Every write is idempotent or
  guarded by the HelmChart's UID, so the overlap is harmless.

## Chart Sources

- `repo` plus `chart`: a chart name resolved against a repository.
- `chart` alone: an `oci://` reference or a chart URL.
- `chartContent`: a base64-encoded chart archive (`.tgz`) carried in the HelmChart itself. Use it
  for air-gapped installs: nothing is fetched. The archive is stored in a ConfigMap, so it must
  stay under 1 MiB.
- When both `chart` and `chartContent` are set, `chartContent` wins and `chart`, `repo` and
  `version` are ignored (k3s semantics).
- `http://` is refused for `repo` and `chart`. The apiserver rejects it, and the controller refuses
  anything that slips past that check with the `Failed` condition, reason `InsecureRepo`, and
  creates no Job. Use `https://` or `oci://`. This is stricter than k3s, deliberately: the Job runs
  as cluster-admin.
- Repository credentials, a custom CA, `insecureSkipTLSVerify` and `plainHTTP` are not supported.
  Those k3s fields are reserved.

## Network Access

- A Job that fetches a chart (`repo`, `oci://` or a URL) carries the `k3sm.io/internet-egress`
  annotation, so it can reach the internet.
- A `chartContent` install carries no egress annotation. It talks only to the apiserver.

## The Job Identity

- Each HelmChart gets a ServiceAccount, `helm-<name>`, in its namespace, bound to `cluster-admin`
  by the ClusterRoleBinding `helm-<namespace>-<name>`. This is the k3s identity: helm installs
  arbitrary objects.
- The binding lives as long as the HelmChart and is deleted when its uninstall finishes.
- Any pod in the HelmChart's namespace can run as that ServiceAccount while it exists. k3sm has no
  per-pod uid isolation, so keep untrusted pods out of that namespace. `kube-system` is the usual
  home for HelmCharts.
- The manifest directory's identity may create HelmCharts, through a ClusterRole of its own,
  `k3sm-manifest-helm`. The directory is writable only by root, so only root on the node (or the
  admin kubeconfig) can start a cluster-admin install.

## HelmChartConfig

- A `HelmChartConfig` with the same name and namespace as a HelmChart overlays values on it. Its
  `valuesContent` is applied after the HelmChart's own values, so it wins.
- Its `failurePolicy` and `forceConflicts` override the HelmChart's when set (k3s semantics).
- Changing either object reruns the install: the Job is replaced when the HelmChart spec or any of
  those three HelmChartConfig fields changes.

## Failures

- A Job retries under `backOffLimit` (`spec.backOffLimit`, default 1000) and is stopped after twice
  the timeout (`activeDeadlineSeconds`), so a broken install cannot keep spawning pods.
- A failed Job sets the `Failed` condition and records a `HelmChartInstallFailed` Warning Event on
  the HelmChart. Read the output with `kubectl logs -n <namespace> job/helm-install-<name>`.
- `failurePolicy: reinstall` (the default) deletes the failed Job and runs the install again.
  `failurePolicy: abort` leaves the failed Job and its logs in place until you change the spec.
- A server restart during a Job reruns it. `helm upgrade --install` is idempotent, so a rerun
  converges.

## Deleting a Chart

- Deleting a HelmChart runs `helm uninstall <name> -n <namespace> --ignore-not-found` in
  `helm-delete-<name>`, then deletes the Job identity and releases the finalizer
  `helm.k3sm.io/uninstall`. The delete Job is kept for 10 minutes for inspection.
- If the uninstall fails or times out, the finalizer is released anyway and a
  `HelmChartUninstallFailed` Warning Event names the release. The HelmChart goes away, but the
  release may remain. Remove it with `helm uninstall <name> -n <namespace>`.
- Removing a file from `/var/lib/k3sm/manifests` does not delete its HelmChart. Remove the file,
  then `kubectl delete helmchart`, or the next sweep applies the file again.

## Timing

- The first install after a server boot can take about 2 minutes: the manifest sweep, the CRD
  becoming established, and the controller taking its Lease all come first.

## Limits

- The server never downloads `helm` while it runs as the launchd daemon. When the payload lacks it,
  the controller logs the missing binary, re-checks the work dir every minute, and starts once a
  reinstall stages it. A server started from a development shell (one with `gh` on `PATH`) fetches
  the pinned release instead and verifies it against the pinned digest.
- `helm` is ad hoc signed, like every binary k3sm stages. A node whose signature policy requires
  notarized binaries cannot run it, and HelmCharts do not install there.
- The Job runs on the native path. A chart's own workloads still need the Darwin scheduling fields
  (see [Supported workloads](what-runs.md)), or `runtimeClassName: vm` for Linux images.
- Only the server that holds the Lease clears finalizers. A HelmChart deleted while no server runs
  the controller stays `Terminating` until one does.

## Rolling Back k3sm

A HelmChart that is being deleted keeps its finalizer until this controller releases it. Before
reverting to a k3sm release without HelmChart support, check that no HelmChart is `Terminating`:

```sh
kubectl get helmcharts -A
```

If one is stuck after a rollback, clear it by hand. Removing the finalizer skips the controller's
cleanup, so also delete the chart's cluster-admin ClusterRoleBinding and its ServiceAccount, or both
stay in the cluster for good:

```sh
kubectl patch helmchart <name> -n <namespace> --type merge -p '{"metadata":{"finalizers":null}}'
kubectl delete clusterrolebinding helm-<namespace>-<name>
kubectl delete serviceaccount helm-<name> -n <namespace>
```

The release is not uninstalled either. Run `helm uninstall <name> -n <targetNamespace>` first if
you want it gone.

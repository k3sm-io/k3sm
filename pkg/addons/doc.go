/*
Copyright The k3sm Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Package addons holds k3sm's two manifest reconcilers, the k3s AddonManager
// analogs: the embedded add-on set (Reconciler, below) and the operator's
// root-owned manifest directory (ManifestDir, § The manifest directory).
//
// On every server start it walks a manifest tree, decodes each YAML document into
// an unstructured object, and server-side-applies it with a stable k3sm field
// manager. The production tree holds one add-on today, metrics-server
// (manifests/metrics-server.yaml: upstream v0.9.0, its RBAC verbatim, the
// Deployment adapted to run the Linux image as a vm pod on a Darwin node), so a
// stock server issues one apply per object in that file on every start.
//
// # Why the manifests are compiled in, not read from disk
//
// k3s reconciles a server/manifests directory under its data dir with admin
// credentials. The embedded set deliberately does NOT, and the difference is a
// security boundary rather than a packaging preference:
//
//   - every k3sm pod runs as the same _k3sm uid (there is no per-pod uid isolation —
//     see docs/privilege-model.md), so POSIX permissions are no barrier between a pod
//     and the control plane's own work dir; and
//   - the server work dir is not inside runtimed's sandbox-protected prefix set, so a
//     pod can write into it; and
//   - the reconciler applies what it reads with the system:masters admin kubeconfig.
//
// Composed, an on-disk manifest directory would widen the set of principals that
// reach cluster-admin from {holders of the 0600 admin kubeconfig} to {every pod on
// the node}, without the change containing a single RBAC object. Compiling the
// manifests into the binary via embed.FS removes the ingress rather than guarding it:
// there is no writable path, no new principal, and manifest integrity is inherited
// from the signed binary.
//
// The fs.FS the Reconciler takes is a TEST seam, not an operator-facing one. Do not
// bind it to a directory, a ConfigMap, a URL, or a flag. The operator-drop ingress is
// ManifestDir, which settles each of those questions separately (next section).
//
// # The manifest directory
//
// ManifestDir applies the operator's manifests from install.ManifestDir
// (/var/lib/k3sm/manifests). It is safe where a work-dir directory applied as
// system:masters was not, because of four properties, all load-bearing:
//
//   - Location and ownership. The directory is a root:wheel 0755 sibling of the
//     server work dir under the root-owned data root, never inside the service user's
//     tree. The directory and every file are refused unless root-owned and not
//     group/other-writable, judged on the OPENED file (O_RDONLY|O_NOFOLLOW) so the
//     check covers exactly the bytes read. Symlinks, names starting with "." or "_",
//     and anything but .yaml/.yml/.json are skipped; files are bounded in size and
//     count.
//   - Identity. Applies run as the kube-system/k3sm-manifests ServiceAccount
//     (pkg/rbac.ProvisionManifestApplier: create and patch only, on a fixed list of
//     workload and configuration kinds; no read, no delete, and no RBAC, admission,
//     Secret, ServiceAccount, namespace, CRD or MeshPeer write). The admin client
//     only provisions that identity and mints its token through the TokenRequest
//     API; the token lives in memory and is refreshed before it expires.
//   - Refused kinds. RBAC (rbac.authorization.k8s.io), admission
//     (admissionregistration.k8s.io), Secret and ServiceAccount objects are refused
//     (logged with the file and object, skipped, the rest of the file still applied)
//     before the apiserver is called. A Secret or ServiceAccount is provisioned by
//     kubectl or by k3sm's Go paths, never from this directory: a manifest able to
//     create a service-account-token Secret could mint the token of any existing
//     ServiceAccount. A divergence from k3s, which applies anything; RBAC an add-on
//     needs is provisioned in Go. The remaining ceiling is the standard one for any
//     workload creator: a Pod may run as any existing ServiceAccount in its
//     namespace.
//   - Apply-only. Server-side apply under ManifestFieldManager, never forced (SSA
//     conflicts only with OTHER managers, so an unforced apply takes over nothing an
//     operator set by hand). A conflicting file is parked until its bytes change, and a
//     Warning Event (ConflictEventReason) naming the file and the conflicting managers is
//     recorded on the object, so the conflict is visible to kubectl. A v1 List or a
//     top-level array is applied item by item; the List's own metadata is ignored. Nothing is ever deleted: removing a file leaves its
//     objects (the k3s semantic), and an object dropped from a still-present file
//     also stays (the divergence, until a Get-by-name ownership-record prune lands;
//     never a LIST diff, never keyed on k3sm.io/managed).
//     A mistaken object is removed with kubectl.
//
// HelmCharts: the one indirect path to cluster-admin. The same identity may also
// create, patch and get helm.k3sm.io HelmChart and HelmChartConfig objects, through a
// ClusterRole of its own (pkg/rbac's k3sm-manifest-helm, never merged into the
// bounded list above). A HelmChart dropped here makes the helm controller run a Job
// as a per-chart ServiceAccount bound to cluster-admin, which installs whatever the
// chart holds, RBAC and admission objects included. That is the k3s shape (a file in
// server/manifests already acts as the server). The directory is root-only, so the
// principals that can author such a chart stay {root on the node, the admin
// kubeconfig}; what the chart adds is its Job identity, which any pod in the
// HelmChart's namespace could also run as for the chart's lifetime (docs/user/helm.md
// says to keep untrusted pods out of that namespace). The escalation-prevention bound
// above holds for every kind this reconciler applies EXCEPT what a HelmChart installs.
//
// It sweeps on start, on every fsnotify event (debounced), and every
// ManifestSweepInterval as the backstop. A file whose sha256 matches its last settled
// apply is skipped; the sha256 is also stamped as ManifestChecksumAnnotation on every
// applied object, which is content-derived, so a restart that re-applies an unchanged
// file writes nothing new. A missing directory is the normal case and not an error.
// Every failure is logged and the sweep carries on; a transient one is retried on the
// next sweep, a deterministic one (a refused kind, a decode error, a field conflict)
// waits for the file to change.
//
// The Darwin authoring trap: a stock manifest's Pod template carries neither the
// kubernetes.io/os=darwin nodeSelector nor the k3sm.io/provider toleration, so its
// Deployment applies cleanly while every Pod is rejected by admission or left
// Unschedulable. Such an object is still applied, and a Warning Event
// (DarwinSchedulingEventReason) naming both fields is recorded on it.
//
// # Converge-only: this reconciler never deletes
//
// It issues exactly one verb: server-side apply (an apply-type PATCH). It never
// DELETEs, and it never LISTs.
//
// Both halves are deliberate. A prune keyed on the k3sm.io/managed label would be
// catastrophic — that label is stamped by seven other packages, so a label-selector
// prune would delete PersistentVolumes pinning user data, the kube-dns Service, the
// node-datapath ClusterRoleBinding every joined worker needs, the admission policies,
// the default LimitRange, and the vm RuntimeClass. And a LIST may not authorize a
// DELETE here at all: under the pinned kine, ConsistentListFromCache is GA-locked true
// while the watch-progress fix is absent, so a LIST's freshness is unproven BY
// CONSTRUCTION (the same ban pkg/rbac already documents).
//
// The safe form of prune is an ownership record the reconciler itself writes, resolved
// by authoritative Get-by-name — deletion only for an object the embedded set once
// contained and no longer does. That is not built here: the production set is one add-on
// that has never dropped an object, so a persistent ownership record would be unexercised
// machinery. Until it is,
// removing a manifest from the embedded tree leaves its object in the cluster for an
// operator to remove. That is also the k3s semantic for a removed FILE, so the divergence
// is bounded to objects dropped from a still-present file.
//
// Converge-only additionally makes the reconciler safe under HA with no coordination:
// k3sm has no in-Go leader-election primitive, and an apply-only reconciler on a second
// server converges to the same state instead of racing a peer's prune.
//
// # Failure posture: log-and-continue, never fail-closed
//
// A per-object failure (an unmappable GVK, a decode error, an apply rejection) does not
// abort the rest of the set, and Converge's error is advisory: the caller logs it and
// continues bring-up. This matches the sibling boot provisioners (policy.EnsureDarwinAdmission,
// runtimeclass.Provision) and is required, not merely convenient — the launchd job runs with
// KeepAlive true, so a startup-fatal manifest error would be an unbounded respawn loop in
// which the apiserver never stays up long enough to serve the kubectl delete that would fix
// it. Only pkg/rbac is fail-closed, and it is bounded over a fixed in-binary graph.
//
// # Known ceilings
//
//   - Readiness: Converge runs after the executor reports the control plane healthy, not
//     against /readyz. The shipped set is built-in kinds only, which the apiserver accepts
//     as soon as it serves; an add-on that must not race informer sync needs the readiness
//     probe added first. A discovery failure while building the RESTMapper skips the whole
//     set for that boot (logged), and the next server start retries it.
//   - CRDs (the embedded Reconciler only): its RESTMapper is built once from discovery, so
//     a custom resource applied in the same pass as its own CRD will not map. Applying a CRD
//     plus its CRs needs an Established wait and a mapper reset; today the set contains
//     neither. ManifestDir is not affected: it resets its deferred mapper on a no-match and
//     retries the file on the next sweep.
//   - No status wait: an applied object's controller-side readiness is not awaited.
//   - No disable toggle: the manifest directory is always reconciled when it exists.
//     An operator switch to turn it off (the k3s --disable analog) is a follow-up;
//     until then an empty or absent directory is how it is left inert.
package addons

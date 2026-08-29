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

// Package addons is k3sm's embedded add-on manifest reconciler — the k3s
// AddonManager analog, with the filesystem removed.
//
// On every server start it walks a manifest tree, decodes each YAML document into
// an unstructured object, and server-side-applies it with a stable k3sm field
// manager. It is the substrate the shipped add-ons (metrics-server first) build on;
// the production tree ships EMPTY of product manifests today, so a stock server
// converges an empty set and issues no API calls at all.
//
// # Why the manifests are compiled in, not read from disk
//
// k3s reconciles a server/manifests directory. k3sm deliberately does NOT, and the
// difference is a security boundary rather than a packaging preference:
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
// bind it to a directory, a ConfigMap, a URL, or a flag. An operator-drop ingress is a
// separate design that must first settle the applying identity (a bounded
// ServiceAccount, never system:masters — so the apiserver's escalation-prevention
// gives a free ceiling), a root-owned location outside the work dir, O_NOFOLLOW
// regular-file-only reads with content-free error paths, per-file size and count
// bounds, and a GVK denylist.
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
// contained and no longer does. That is not built here: the production set is empty, so
// a persistent ownership record would be pure unexercised machinery. Until it is,
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
// # Known ceilings (honest, and bounded by the empty production set)
//
//   - Readiness: Converge runs after the executor reports the control plane healthy, not
//     against /readyz. With an empty set that is unobservable; an add-on that must not race
//     informer sync needs the readiness probe added first.
//   - CRDs: the RESTMapper is built once from discovery, so a custom resource applied in the
//     same pass as its own CRD will not map. Applying a CRD plus its CRs needs an Established
//     wait and a mapper reset; today the set contains neither.
//   - No status wait: an applied object's controller-side readiness is not awaited.
package addons

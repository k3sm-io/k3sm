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

// Package rbac provisions, idempotently at server start, the minimal RBAC graph
// that MUST exist before the apiserver enforces --authorization-mode=Node,RBAC
// (the M4.1 flip from AlwaysAllow). It runs in cmd/k3sm/server.go's step-3
// provisioning slot — after the apiserver is healthy, BEFORE the VK node and the
// worker-join supervisor start — so a joining worker's bindings already exist, and
// it is FAIL-CLOSED: a provisioning failure halts bring-up rather than the
// log-and-continue pattern the admission policies use, because a half-applied graph
// under an enforcing authorizer silently locks workers out.
//
// # Why a flip alone would lock workers out
//
// The flip is advertised as a pure authorizer switch, and it is — but only because
// every IN-PROCESS server component (the in-process VK node, the scheduler and
// controller-manager, the provisioners, the bootstrap enroller) authenticates with
// the static admin token, which the token file maps to the system:masters group;
// system:masters bypasses RBAC, so those components keep working with the authorizer
// on, needing no two-phase restart. The real lock-out risk is a JOINED WORKER: its
// Service proxy, per-node DNS resolver, and mesh watcher authenticate as
// system:node:<name> (the M3 node cert), and they get/list/watch services,
// endpointslices (discovery.k8s.io), and meshpeers (net.k3sm.io) — none of which the
// Node authorizer nor the stock system:node ClusterRole grant. The node-datapath
// ClusterRole this package binds to the system:nodes group is THE fix.
//
// # What it provisions (ONLY k3sm-named objects)
//
//   - the node-datapath ClusterRole + a ClusterRoleBinding to the system:nodes
//     group, granting read (get/list/watch) on services, endpointslices, and
//     meshpeers — keeping a joined worker's datapath alive after the flip;
//   - the in-pod reader Role + RoleBinding (namespaced) for the in-pod-kubectl
//     reference ServiceAccount, so the M2 in-pod-kubectl conformance path stays green
//     under default-deny (see ConformanceServiceAccount).
//
// # What it deliberately does NOT touch
//
// It never creates or mutates the apiserver's auto-reconciled default system:*
// ClusterRoles / ClusterRoleBindings (system:node, cluster-admin, the system:masters
// binding, …). Those have a second writer — the apiserver's bootstrap-policy
// reconciler — and two writers fight. It only REFERENCES the system:nodes group (as a
// binding subject); it never authors a system:* object. Provisioning is
// Create-tolerate-AlreadyExists (idempotent, no read to decide); it never LISTs to
// decide what to provision — a watch-cache LIST under the pinned kine v1.14.2, where
// ConsistentListFromCache is GA-locked true, can read stale and double-provision or
// skip. Any existence check is an authoritative Get-by-name, never a LIST.
//
// # Component-identity divergence (documented, adopted, NOT expanded)
//
// In M4.1, RBAC is enforced for WORKLOADS and joined-worker system:node identities;
// the in-process control-plane components (VK node, scheduler, controller-manager,
// provisioners, enroller) RETAIN system:masters. Moving them to per-component client
// certs is a DEFERRED follow-up: it would break the pure-switch property (the boot
// would need component certs provisioned and a re-bootstrap) for no M4.1 benefit,
// since those components run in the trusted single _k3sm process. The MeshPeer
// write-guard (bootstrap.AuthorizeMeshPeerWrite) stays load-bearing and PERMANENT:
// NodeRestriction admission covers only core node-owned resources, never the
// net.k3sm.io/MeshPeer CRD, so the node identity gets meshpeers READ via the
// node-datapath ClusterRole while the WRITE stays server-mediated.
package rbac

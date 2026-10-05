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

// Package executor brings up the k3sm control plane: kube-apiserver,
// kube-scheduler, kube-controller-manager, and kine (the etcd-over-SQLite shim).
//
// # Strategy
//
// hard cut (greenfield): this package productizes the VALIDATED bring-up spike
// (hack/lib/clusterup.sh) into a Go Executor with a Supervised strategy that
// os/exec-supervises the four components as CHILD PROCESSES — it ensures the
// prebuilt darwin/arm64 control-plane binaries (kwok-ci/k8s; upstream refuses to
// ship them, k/k#118359), builds kine from source with cgo, ad-hoc signs every
// Mach-O so it can exec, writes the SA keypair + static token + kubeconfig, and
// starts kine → apiserver → scheduler → controller-manager, scoping KCM's
// --controllers to drop the node-side controllers that assume real Linux
// kubelets.
//
// The from-source IN-PROCESS embedding the DESIGN sketched (the k3s
// pkg/executor/embed pattern, one set of goroutines in this process) is DEFERRED
// to a future milestone: Wave-0 confirmed importing the apiserver/scheduler/KCM
// command trees from k3s-io/kubernetes into this module is infeasible today (the
// monorepo's internal package graph does not vendor cleanly here). The Embedded
// strategy is a stub that returns ErrEmbeddedNotImplemented so the seam is in
// place for when that lands.
//
// # Lifecycle
//
// Start brings the components up in dependency order and blocks until the
// apiserver reports healthz ok (or ctx ends). Stop tears them down in REVERSE —
// the apiserver first (so it drains and stops writing), then scheduler and
// controller-manager, then kine LAST (so no component loses its datastore
// mid-shutdown), and finally closes the SQLite database. The whole lifecycle is
// ctx-driven.
//
// # Auth posture
//
// The apiserver enforces Node,RBAC by default (DefaultAuthorizationMode); the
// static bearer token remains for the in-process Virtual Kubelet node, the
// post-bring-up provisioning client, and the healthz probe.
//
// # HA datastore
//
// Strategy: hard cut. The default stays single-node kine->SQLite (WAL), byte-unchanged.
// Setting Config.Etcd selects the HA posture, the k3s embedded-etcd shape: every
// control-plane server runs ONE etcd member as a supervised child in place of kine,
// and its apiserver talks only to that local member. HA is etcd-FROM-INIT
// (greenfield): an existing SQLite cluster is never converted, and --cluster-init over
// a non-empty state.db is refused (ErrClusterInitOverSQLite).
//
// Build: etcd is built exactly like kine — out-of-module from an embedded wrapper
// module at the pinned DefaultEtcdVersion, CGO_ENABLED=0, behind a versioned marker,
// through the same staged-child protocol — and is staged only in the etcd posture.
//
// Listeners: the client listener is loopback only (https://127.0.0.1:<KinePort>), so
// no etcd client endpoint is reachable off-host; the apiserver reaches it with a client
// certificate (--etcd-cafile/--etcd-certfile/--etcd-keyfile). The peer listener is on
// the server's LAN address (--etcd-peer-ip; never the mesh, never loopback:
// ErrEtcdNeedsNodeIP),
// and the metrics listener is loopback. Peer and client traffic are mutual TLS under two
// dedicated etcd CAs inside the k3sm hierarchy (pkg/certs), distinct from the cluster
// and signing CAs, so no Kubernetes client certificate is an etcd identity and no etcd
// certificate is a Kubernetes one.
//
// Join: the first server forms a one-member cluster (EtcdInit). Every other server
// (EtcdJoin) is added as a LEARNER by an existing server and starts with the member
// set it was handed; it is promoted to a voting member only once it serves
// (EtcdConfig.Promote), so a joiner that fails to start never costs the cluster its
// quorum. A restart (an existing <WorkDir>/etcd/member, EtcdMemberExists) is never
// re-added or re-promoted.
//
// Quorum: after its member serves, bring-up waits for a leader with no expiry and
// outside every bring-up deadline, recording no failure: a peer that is still booting
// is not this server's fault, and a two-server cluster cold-starting one Mac at a time
// must not park the first one. Only the etcd child exiting is a failure. The server
// holds <WorkDir>/server.lock for its whole life and reports the member's state in
// <WorkDir>/etcd-status.json.
//
// Recovery: ClusterReset (k3sm server --cluster-reset) restarts the local member once
// with --force-new-cluster, refused while the daemon holds the work-dir lock or with no
// member to reset, and succeeds only when the member list is exactly this member.
// SnapshotEtcd streams an online snapshot of the local member to a 0600 file and
// verifies it; restoring one is not supported in this release
// (ErrEtcdRestoreUnsupported).
//
// # Leader election
//
// Only the apiserver is active/active in HA. The scheduler and controller-manager run
// with --leader-elect, derived from the posture (Config.leaderElect): false
// single-node (one candidate, no lease churn — the single-node default) and
// true in HA, so exactly one server's scheduler/KCM is active (two active schedulers
// would double-bind pods; two KCMs would double-reconcile). The leader-election Leases
// (coordination.k8s.io, kube-system/kube-scheduler + kube-controller-manager) are
// authorized by the apiserver's auto-created system:kube-scheduler /
// system:kube-controller-manager bootstrap RBAC, which binds the components' OWN
// per-component identities — no pkg/rbac object is needed.
//
// # Component identities (k3s alignment)
//
// The scheduler and controller-manager authenticate with their OWN signing-CA-issued
// client certs (CN=system:kube-scheduler / system:kube-controller-manager) via
// per-component kubeconfigs (provisionComponentCerts), NOT the shared system:masters
// admin token — so the apiserver's bootstrap RBAC actually constrains them (the k3s
// model, with no shared component identity). The KCM additionally runs
// with --use-service-account-credentials=true, so each controller authenticates as its
// own system:controller:<name> service account. --client-ca-file is set unconditionally
// (single-node included) so those client certs authenticate. The server's in-process VK
// node authenticates the same way, as system:node:<node name> in system:nodes with a
// signing-CA cert cmd/k3sm mints in memory on every boot. The post-bring-up admin client
// (and the server-side controllers on it), kubectl, and the healthz probe still carry the
// system:masters admin token. That narrows the node client only: the server process
// still holds the admin kubeconfig and the signing CA.
package executor

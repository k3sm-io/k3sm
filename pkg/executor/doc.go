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
// Strategy: phased (named exception: kine/SQLite datastore migration). The default
// stays single-node kine->SQLite (WAL). Setting
// Config.DatastoreEndpoint to a Postgres DSN switches kine to Postgres (pure-Go
// jackc/pgx/v5) so 2+ control-plane servers can share ONE datastore — the single
// source of truth, no etcd quorum (the k3s external-datastore-HA topology). The
// apiserver still points at the LOCAL kine on 127.0.0.1; each server runs its own
// kine against the shared Postgres.
//
// HA is Postgres-FROM-INIT (greenfield): there is NO live SQLite->Postgres data
// conversion — the single-node SQLite default is untouched, and the only path from an
// existing SQLite cluster to Postgres is an operator kine dump/restore (in-place
// conversion is out of scope). BOTH postures run the SAME pinned kine build
// (DefaultKineVersion, a >=0.16 release built CGO_ENABLED=0 against the pure-Go
// modernc.org/sqlite backend), which carries the kine#577 watch-progress-notify fix;
// the SQLite/Postgres split is a driver choice inside one binary, not a second
// version. Moving an EXISTING single-node datastore onto a new pin is a one-way
// migration, so the boot takes a verified pre-migration snapshot first
// (snapshotBeforeKineUpgrade — TRUNCATE-checkpointed, integrity-checked, write-once,
// with the superseded kine binary preserved beside it). The multi-writer
// watch-staleness soak (a consistent LIST on server B immediately after server A's
// committed write, under sustained churn — the kine#577 failure mode) is the LAB
// production-trust gate (hack/lab/m6.sh), not a unit-provable property.
//
// Secret handling: the operator's DSN may carry a password, but it must never land
// on argv (world-readable via ps) or in a 0644 log. startKine relocates it to a 0600
// PGPASSFILE handed to the kine child (kineSecretEnv); only the password-stripped DSN
// reaches kine's --endpoint. pgx reads the password from PGPASSFILE as the libpq env
// fallback. Component logs are mode 0600 for the same reason.
//
// Connection pool / Postgres SPOF: kine's --datastore-max-open-connections defaults
// to 0 (UNLIMITED), so N servers against one Postgres could exhaust its
// max_connections; kineArgs pins per-server bounds (see datastore.go) so 2*pool stays
// within the Postgres default max_connections (100). SQLite's _busy_timeout has no
// Postgres analog — under contention Postgres relies on its own statement/lock
// timeouts (an operator postgresql.conf concern: set statement_timeout /
// idle_in_transaction_session_timeout / lock_timeout). The write-latency tradeoff is
// explicit: SQLite WAL is a local sub-millisecond fsync; Postgres adds a network
// round-trip per write. HA buys control-plane PROCESS redundancy (kill one server,
// the other serves), NOT datastore redundancy — Postgres becomes the operator-managed
// datastore SPOF; its own HA/backup (a pg_dump/PITR runbook, streaming replication,
// or a managed Postgres) is the operator's responsibility, as in k3s.
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
// (single-node included) so those client certs authenticate. The in-process VK node, the
// post-bring-up provisioning client, and the healthz probe still carry the system:masters
// admin token: the embedded node cannot move to a system:node identity until the
// Virtual-Kubelet secret/configmap informers are scoped (they LIST/WATCH cluster-wide,
// which the Node authorizer does not grant).
package executor

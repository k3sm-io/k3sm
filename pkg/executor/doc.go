// Package executor brings up the k3sm control plane: kube-apiserver,
// kube-scheduler, kube-controller-manager, and kine (the etcd-over-SQLite shim).
//
// # Strategy
//
// hard cut (greenfield): M1 productizes the VALIDATED M0 spike
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
// # Auth posture (M1)
//
// M1 keeps the spike's AlwaysAllow authorization + a static bearer token so the
// existing M0 Virtual Kubelet node still registers unchanged. Real RBAC + issued
// node certs are an M3/M4 concern.
package executor

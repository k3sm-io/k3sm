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

// Package dev owns the `k3sm dev` disposable single-node dev-cluster lifecycle:
// a durable per-instance registry, per-instance port/workdir allocation,
// pre-flight reclaim (lo0 alias flush + stale-pid reap), a --datapath singleton
// lock, kubeconfig merge/cleanup, `load` staging, and the SAFE/UNSAFE fidelity
// banner surfaced at every entry point.
//
// It is a THIN lifecycle over the stable seams the rest of k3sm already exposes:
//   - executor.Supervised (via a detached `k3sm server` child) boots the real
//     upstream control plane (apiserver v1.36.2 + KCM + scheduler) + a real node.
//   - hostnet.Mode (network=none rootless / network=direct root) selects the
//     datapath posture.
//
// Honest positioning (docs/conformance-profile.md):
// this is "more than envtest — a real control plane + a real single node," NOT
// "kind" — k3sm is deliberately non-conformant, so the SAFE (declarative API,
// develop freely) vs NEEDS-datapath vs UNFAITHFUL axis is warned at every entry
// point rather than buried.
//
// Root posture: rootless up = runtimed + network=none (Seatbelt self-confines,
// no root); --datapath = euid 0 + network=direct (real Service/DNS/pod-IP). The
// runtime is runtimed (Seatbelt-confined) by default; the lifecycle provisions the
// k3sm-execshim helper (build+sign into a shared dev-bin cache, prepended to the
// detached server's PATH) so runtimed's sandbox backend can init. If the helper
// cannot be built (an installed k3sm with no workspace source) it falls back to
// hostprocess with a loud UNCONFINED notice rather than crashing — honest, never a
// silent degrade; the effective runtime is recorded in the manifest and shown by
// `list`.
//
// Pod-support DYLD shims: cmd/k3sm resolves the path-rebase and getaddrinfo shims
// as SIBLINGS of the running executable, and `k3sm dev` re-execs a `go build`
// binary, so it found neither — absolute volume mounts ENOENT'd in-pod and cluster
// Service names NXDOMAIN'd. The lifecycle therefore stages both into
// DefaultPodShimDir (under /Library, the only tree inside the pod Seatbelt read
// baseline) and passes them as --path-shim / --dns-shim. Staging needs root, and
// the DNS shim additionally needs a live datapath (no resolver binds the DNS VIP
// under network=none); an unstageable shim degrades with a notice, never fatally.
//
// Testability: every syscall the lifecycle needs (ifconfig lo0 alias listing,
// flushing an alias, process-liveness/kill, flock) is behind the System
// interface, so the registry round-trip, port allocation, pre-flight reclaim
// logic, and the fidelity banner are unit-tested with fakes — no real ifconfig,
// flock, or kill in a unit test.
package dev

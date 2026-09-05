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

// Package builder manages k3sm's in-cluster buildkitd engine: the RUN-capable
// build daemon that `k3sm build` drives when a Dockerfile is more than COPY.
//
// # Shape
//
// The engine is one long-lived `vm` Pod running the pinned upstream
// moby/buildkit image, a ClusterIP Service fronting its tcp listener, and a
// PersistentVolumeClaim holding its build cache. buildkitd runs GUEST-ROOT
// inside its own micro-VM: the VM is the isolation boundary, so the Pod carries
// NO securityContext (k3sm admission rejects a foreign runAsUser, and a rootless
// daemon cannot mount the cgroups and create the containers a build needs). This
// is the sanctioned builder posture: the foreign-user admission policy never
// fires, because there is no foreign user.
//
// # The three lifecycle verbs
//
//   - Up ensures the PVC, Pod and Service, then waits for a REGISTERED buildkit
//     worker — polled through an exec of `buildctl debug workers`, never the
//     socket: buildkitd binds its listener before the OCI worker finishes
//     initialising, so a socket-ready check hands a build a daemon that will
//     never answer.
//   - Down deletes the Pod and Service and KEEPS the cache PVC — a rebuilt
//     engine finds a warm layer cache.
//   - Status reports where in the state machine the engine is, legibly, so an
//     absent stack names its own fix rather than surfacing an opaque dial error.
//
// # The build-path seam
//
// Endpoint returns the `tcp://<clusterIP>:<port>` address a buildx remote driver
// dials. `k3sm build`'s full path (a follow-up that depends on this landing) is
// the sole consumer: it will run the bundled buildx with
// `--driver remote <Endpoint()>` against this engine, auto-routing COPY-only
// Dockerfiles to the native fast path. This package deliberately does NOT change
// `k3sm build` — it only provides the endpoint.
//
// The ClusterIP dial (not a pod-IP or a new vmhost socket forward) is the chosen
// path because the ClusterIP is STABLE across a Pod reschedule and k3sm's
// userspace Service proxy already makes ClusterIPs host-dialable via lo0 aliases
// — no new named seam, and nothing that a reschedule invalidates.
//
// # The buildx pin
//
// buildx is a separate release from the buildkit image. Until the release-time
// source-built buildx leg lands (see the TODO in buildx.go — a goreleaser
// packaging follow-up), the engine stages a DIGEST-PINNED, sha256-verified buildx
// into its cache: the pin is a Go constant here, injected into the Pod as env, so
// there is exactly one place the version and hash live.
//
// # The in-pod payload
//
// assets/entrypoint.sh is the whole in-pod payload, embedded in the binary and
// delivered as the Pod's command. It self-mounts /proc, cgroup2 and a devtmpfs
// (TOLERANT of a runtimed that already provides them — the per-container prereq
// change landing in parallel), loop-mounts an ext4 image on the PVC for buildkit
// state (virtiofs cannot host an overlay upperdir and pins ownership), stages the
// verified buildx, writes the buildkitd config, and execs buildkitd with both a
// unix socket (for the readiness exec) and a tcp listener (for the Service).
//
// # Testability
//
// Everything above the kube API is a pure renderer (spec.go) or a small state
// machine over two injected seams — a kubernetes.Interface and an Execer — so the
// spec shape, the pin wiring, the state transitions and the legible-absence
// contract are all unit-provable with a fake clientset and a fake exec. The live
// path (a real worker, a real build) is hack/acceptance/builder.sh's owed tier.
package builder

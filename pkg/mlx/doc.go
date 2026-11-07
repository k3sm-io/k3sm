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

// Package mlx renders an MLXModel into the API objects that serve it — a
// StatefulSet, its headless governing Service, and the stable ClusterIP Service
// clients talk to — and derives that model's status back from the pods those
// objects produce.
//
// This package is the PURE half of the MLX operator. Render is spec in, objects
// out; DeriveStatus is observed pod and probe state in, status out. Neither
// performs IO, reads cluster state, writes anything, or starts anything — so the
// serving shape and the whole status machine are each decided by a table test
// rather than by watching a cluster. The reconcile loop that applies the
// objects, probes the replicas, and PATCHes the status through the status
// subresource lives elsewhere.
//
// Five properties of the rendered shape are load bearing, and each exists
// because its absence fails in a way a functional test would not notice:
//
//   - READINESS ONLY, NO LIVENESS OR STARTUP PROBE. A model's first start is an
//     unbounded download-then-load window (tens of minutes for a large model). A
//     liveness or startup probe turns that window into a kill, and the restart
//     re-downloads from zero — a crash loop that never converges and looks like
//     a slow network. Readiness alone keeps the replica out of the Service until
//     it can serve, which is the only thing a probe is needed for here.
//
//   - CONTROLLER ownerReferences ON EVERY OBJECT. Without them `kubectl delete
//     mlxmodel` cascades nothing: the StatefulSet, both Services, and (through
//     the retention policy below) the cache PVCs all outlive the object that
//     asked for them, and the leak is invisible until a node fills up.
//
//   - persistentVolumeClaimRetentionPolicy whenDeleted: Delete. ownerReferences
//     do NOT cascade through the PVCs a StatefulSet creates from a
//     volumeClaimTemplate, so deleting the MLXModel would otherwise strand one
//     model-sized volume per replica. whenScaled stays Retain deliberately: a
//     scale-down is reversible and the cache it would destroy costs another full
//     download to rebuild.
//
//   - THE MEMORY-DERIVED ENGINE PINS, and --continuous-batching beside them.
//     The KV cache grows with every generated token and no killer below k3sm's
//     own sampler catches the overrun, so an unpinned context turns a
//     load-time-sized memory limit into a deterministic mid-generation kill;
//     and the serving engine batches concurrent requests only when told to,
//     answering HTTP 503 to all but one client otherwise — with a healthy
//     /health and a green readiness probe, so nothing else reports it. Both are
//     derived and rendered in sizing.go, which also carries the MEASURED engine
//     command-line surface every rendered option is checked against — the model
//     is a positional there, and a pinned revision has no option at all and is
//     expressed as a path into the cache volume (see modelReference).
//
//   - THE FIXED GUARDRAIL STANZA — the kubernetes.io/os=darwin nodeSelector, the
//     mlx.k3sm.io/gpu.present selector, the k3sm provider toleration, and the
//     GPU extended resource in BOTH requests and limits. These are template
//     content, not user input: k3sm's own admission policy rejects pod CREATEs
//     that lack them, and the rejection lands on the StatefulSet controller
//     rather than on the operator — so a missing stanza surfaces as a
//     StatefulSet that quietly never creates a pod, with the reason buried in
//     controller-manager events.
//
// The status half is bound by what those properties leave observable. With a
// readiness probe and nothing else, a not-ready replica is one bit; the operator
// splits it into Downloading and Loading using its own serving-surface probe
// verdict (injected, never fetched here), and claims nothing that would need a
// liveness signal the pod deliberately does not carry. Phase is a projection of
// the Ready condition rather than a second computation beside it, and the
// endpoint is published only while the model is Ready — see DeriveStatus.
//
// Every identifier that crosses a process boundary — the GPU resource name, the
// GPU presence label, the provider taint key — is taken from its owning package
// (k3sm.io/apis/mlx/v1alpha1, k3sm.io/k3sm/pkg/policy) and never respelled here.
// A literal copy compiles perfectly while being wrong.
package mlx

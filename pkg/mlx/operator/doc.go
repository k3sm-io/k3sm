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

// Package operator is the reconcile loop that turns an MLXModel into running
// serving objects and reports back what those objects did.
//
// It is the IMPURE half of the MLX operator, and it is a separate package for
// that reason alone: k3sm.io/k3sm/pkg/mlx is pure — spec in, objects out;
// observation in, status out — and everything that opens a socket, applies an
// object, or reads a clock lives here. So the serving shape and the whole status
// machine stay decidable by a table test, and this package holds only the
// plumbing between them.
//
// # Shape
//
// One informer over MLXModels, one informer over the pods those models own, and
// a SINGLE workqueue worker. The worker serializes every reconcile by model key,
// so nothing here needs a lock and no Context is stored in a struct. It mirrors
// pkg/provisioner deliberately: same start-after-the-apiserver-is-healthy,
// drain-before-teardown lifetime, same resync-re-delivers-everything recovery
// after a control-plane restart.
//
// # Order of operations, and why it is the order
//
// A reconcile does five things, and the first is the one that must not move:
//
//  1. VALIDATE THE FIT BEFORE RENDERING. A spec asking for more unified memory
//     than the node's GPU facts can fund gets a Failed status and NO objects.
//     Applying first and letting the pod die at load time would be worse than
//     useless: the StatefulSet restarts it, the download starts over, and the
//     only symptom is a model that never becomes ready. Validation before render
//     is what makes "this will never fit" a legible status instead of a crash
//     loop. See ValidateFit.
//
//  2. RENDER, from the pure package. A render error is also terminal — it means
//     the spec is wrong, not that the cluster is busy — so it is reported as a
//     status and NOT requeued, because retrying a bad spec forever produces
//     nothing but log volume.
//
//  3. STAMP THE PULL SECRET, if one exists. The serving image lives in a private
//     registry, so the rendered pod needs imagePullSecrets or it pulls
//     anonymously and fails at materialize. It is stamped from a conventional
//     secret name in the model's own namespace and ONLY when that Secret
//     actually exists: naming a Secret that does not exist is itself a pull
//     failure, so stamping unconditionally would break every public-image
//     deployment to serve the private-image one.
//
//  4. APPLY, by forced server-side apply. Each object is applied under this
//     package's own field manager, which is what makes drift converge: a hand-
//     edited replica count or a deleted probe comes back on the next pass rather
//     than being merged with.
//
//  5. DERIVE AND WRITE STATUS, conditions first, through the status subresource.
//     The status write is skipped when nothing changed, so an idle model does not
//     generate a write per resync.
//
// # What this package deliberately does not do
//
// It does not delete anything. Every applied object carries a controller
// ownerReference to its MLXModel, so deleting the model cascades to the
// StatefulSet, both Services, and — through the StatefulSet's own
// whenDeleted: Delete retention policy — the per-replica cache volumes. A
// reconcile that also deleted would be a second, racing deletion path with no
// way to tell an orphan from an object the garbage collector has not reached yet.
package operator

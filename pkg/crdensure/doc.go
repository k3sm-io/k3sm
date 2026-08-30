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

// Package crdensure server-side-applies ONE CustomResourceDefinition manifest
// and waits until the API server has established it.
//
// It is deliberately NEUTRAL: it embeds nothing, knows no group, and holds no
// list of CRDs. A caller hands it the bytes of exactly the one manifest it means
// to apply — k3sm's MLX operator hands it k3sm.io/apis/config/crd.MLXModelCRD()
// — so "which CRDs does this binary create" is answered by reading the call
// sites, not by reading whatever happens to be embedded here.
//
// That neutrality is the whole reason this package exists as its own package.
// The MeshPeer CRD sits beside the MLXModel manifest in the same apis directory
// and is applied out-of-band by the existing bootstrap path; adopting it into
// this ensure owes a mesh-regression check and must be a deliberate act. Had
// this package globbed a manifest directory, or grown a package-level set of
// "the CRDs k3sm applies", MeshPeer would have been enlisted by accident and the
// bootstrap path would have gained a second, competing writer with no diff to
// review.
//
// # Server-side apply, forced, under one field manager
//
// The manifest is applied as a raw apply-patch under the bare "k3sm" field
// manager (DefaultFieldManager), with Force set. Three consequences, each
// load-bearing:
//
//   - CONVERGENCE ON DRIFT. Server-side apply removes the fields this manager
//     previously set and no longer sets, so a schema that has drifted — a
//     property added by an older binary, a validation rule since deleted — is
//     brought back to the shipped bytes rather than merely being added to. An
//     Update would need read-modify-write and a conflict loop; a Create would
//     converge nothing after the first boot.
//
//   - FORCE. Without it, a field some other manager has claimed (an operator's
//     one-off kubectl apply, most plausibly) wedges convergence permanently and
//     the only symptom is a CRD that silently stops tracking the binary. Force
//     takes those fields back. Fields this manager never sets are still left
//     alone, so an operator's genuinely additive edits elsewhere in the object
//     survive.
//
//   - THE BYTES ARE APPLIED VERBATIM. The manifest is converted from YAML to
//     JSON and validated as a CustomResourceDefinition, but the JSON that goes
//     on the wire is the manifest's own, never a re-marshalling of a typed
//     struct. A round trip through the compiled-in Go type would silently drop
//     any field that type does not know about, which for a schema document is
//     the difference between applying the CRD that shipped and applying the
//     subset of it this client-go understands.
//
// # Established is awaited, not assumed
//
// Apply returns as soon as the object is persisted, which is BEFORE the API
// server has built the custom resource's REST handler. A caller that starts an
// informer at that moment gets a 404 and — because a watch failure is retried
// forever with backoff — a controller that appears to start and never sees an
// object. So Ensure blocks until the Established condition is true, and reports
// a NamesAccepted failure immediately rather than waiting out the timeout: a
// name conflict is not a race that resolves.
package crdensure

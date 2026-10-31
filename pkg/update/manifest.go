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

package update

// The Node annotations that deliver a release's signed payload manifest
// (certs.PayloadManifest) beside the archive. The controller writes them in
// its handover patch with the payload; the node's updater checks the
// manifest with certs.VerifySignedPayload, under the same signer certificate
// as the payload (AnnotationUpdateSigner).
const (
	// AnnotationUpdateManifest is the manifest JSON, exactly the bytes the
	// signature covers.
	AnnotationUpdateManifest = "k3sm.io/update-manifest"
	// AnnotationUpdateManifestSig is the base64 (standard encoding) of the
	// DER ECDSA signature over SHA-256 of the exact manifest bytes.
	AnnotationUpdateManifestSig = "k3sm.io/update-manifest-sig"
)

// The reason codes a node puts first in its k3sm.io/update-phase message
// ("<phase>: <code>[: <detail>]") when its update stopped in a way that must
// halt the roll. The controller fails the node and stops at the first one,
// whatever phase it reports.
const (
	// NodeReasonRolledBack is a node that activated the release, failed its
	// health check and went back to the previous one.
	NodeReasonRolledBack = "rolled-back"
	// NodeReasonRefused is a node whose updater refused the payload (a
	// signature, digest, manifest or window check).
	NodeReasonRefused = "refused"
	// NodeReasonDataRootUnmounted is a node whose data root is not mounted:
	// nothing was rolled back, and the node needs its data root mounted and
	// its daemons restarted, never a reinstall.
	NodeReasonDataRootUnmounted = "data-root-unmounted"
)

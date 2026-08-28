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

// Package images is the single home for the digest-pinned OCI image references
// k3sm depends on, plus the two checks that keep those pins honest.
//
// # What lives here
//
//   - The pins themselves: exported constants in the pkg/executor DefaultKubeVersion
//     pattern (a doc-commented constant, bumped only by a human-merged PR), and the
//     Pins registry that enumerates them so a test can iterate.
//   - Lockstep: constants <-> the committed mirror manifest at hack/images/mirror.yaml.
//     Offline, no network, and it rides "go test ./..." — so drift between the code and
//     the record fails every CI run with no extra wiring.
//   - VerifyLive: manifest <-> the real registry. Opt-in, never on the default test
//     path, and deliberately ANONYMOUS: an authenticated fetch would still succeed on a
//     private package, so only the anonymous fetch proves what the release needs proven.
//
// Together the two bind constants -> registry: lockstep proves the code names what the
// record names, --live proves the record names something that exists.
//
// # What does not live here
//
// This package holds pins and their verification. It is NOT a place for image helper
// code to accumulate:
//
//   - pkg/oci is the build/ingest plumbing (assembling and writing image content).
//   - The runtimed image package owns the content store and the pull path.
//
// A helper that manipulates image content belongs in one of those; a bare reference
// that must be reproducible across releases belongs here.
//
// # Placement
//
// The constants live in this repo while every consumer is in this repo. A consumer in a
// sibling repo re-homes them to the shared contracts module — never a sideways import,
// and never a second copy of a pin.
//
// # The paired record
//
// hack/images/mirror.yaml is the auditable record behind every constant: upstream ref,
// mirror ref, the durable mirror tag, and the per-platform digests inside the index. Its
// header states the one-PR bump procedure and the reviewer merge-precondition (the
// reviewer independently re-resolves the upstream digest; nothing mechanical here can do
// that, because every check in this package proves self-consistency only).
package images

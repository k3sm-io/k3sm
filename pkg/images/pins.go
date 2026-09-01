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

package images

// Pinned upstream images — every one consumed from the k3sm GHCR mirror, by DIGEST.
//
// The digest is an INDEX (manifest-list) digest: platform selection happens in the
// puller at runtime, so a pin must never name a single-platform manifest. The
// per-platform digests inside each index are recorded in hack/images/mirror.yaml, not
// here — this file holds exactly the reference product code passes to a puller.
//
// Bumping one of these is a human-merged PR that also updates hack/images/mirror.yaml;
// the lockstep test below fails until BOTH move. See that file's header for the full
// procedure and the reviewer merge-precondition.
const (
	// Buildkitd is the BuildKit daemon image. It is the mirror of the upstream
	// moby/buildkit v0.32.2 release index; the mirrored copy is byte-identical, so
	// this digest is upstream's own and can be re-resolved against the upstream
	// registry by anyone. The index carries linux/arm64 and linux/amd64, the two
	// platforms k3sm needs.
	//
	// A registry outage does not strand a build: the same digest is servable from
	// upstream, so pulling it from there and side-loading the result is a complete
	// recovery path.
	Buildkitd = "ghcr.io/k3sm-io/mirror/buildkit@sha256:28a898719c18a33f4e8000685287fa36fd0dd9560c6440227d3a732d79bb41d8"
)

// Pin is one digest-pinned image constant, named so it can be matched against the
// mirror manifest entry that records where the digest came from.
type Pin struct {
	// Name is the manifest key. It matches the "name" of exactly one manifest entry.
	Name string
	// Ref is the constant's value: a fully digest-pinned mirror reference.
	Ref string
}

// Pins returns every digest-pinned constant this package declares.
//
// Go cannot enumerate a package's constants at run time, so this list is written by
// hand. Both directions of the resulting drift hazard are closed mechanically:
//
//   - a manifest entry with no Pin is an orphan and fails Lockstep;
//   - a pinned CONSTANT with no Pin entry fails TestEveryPinnedConstantIsRegistered,
//     which walks this package's own syntax tree and requires every digest-pinned
//     string constant to appear here.
//
// Adding a pin therefore means touching all three of: the constant, this list, and
// hack/images/mirror.yaml.
func Pins() []Pin {
	return []Pin{
		{Name: "buildkit", Ref: Buildkitd},
	}
}

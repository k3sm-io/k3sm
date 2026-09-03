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

package builder

import (
	"fmt"
	"regexp"
)

// The pinned buildx release the engine stages into its cache and verifies on
// every start. buildx is a SEPARATE release from the buildkit image, so its
// version and hash are pinned here, in ONE place, and injected into the Pod as
// env (see spec.go) — the entrypoint never hard-codes them.
//
// The digest is a HARD PIN, taken from the release's own checksums.txt:
//
//	https://github.com/docker/buildx/releases/download/v0.17.1/checksums.txt
//
// It is verified in-pod on EVERY run, not only on download: the binary lives on
// a PVC that outlives any single pod, so "we fetched it correctly once" is not
// the property that matters. This exact pin was proven live on the k3sm vm path
// on 2026-09-02.
//
// The asset is the linux-arm64 build because buildx must match the GUEST arch —
// a different axis from the --platform an image targets. The Linux guest that
// runs the buildkit image is arm64 (amd64 build TARGETS run under Rosetta inside
// buildkitd, they do not change the daemon's or buildx's own arch), so only the
// arm64 asset is pinned; the entrypoint refuses any other guest arch rather than
// run an unverifiable one.
//
// TODO(release packaging): the release build ships buildx
// SOURCE-BUILT at this pinned tag as a goreleaser builds entry (the
// cp-payload/vmhost provenance precedent — never re-sign Docker's prebuilt
// binary), with its LICENSE run through go-licenses against the checkout. That
// packaging follow-up REPLACES the in-pod fetch below with a bundled binary; the
// pin (version + tag) stays the single source of truth for both.
const (
	// BuildxVersion is the pinned buildx release tag.
	BuildxVersion = "v0.17.1"
	// BuildxAsset is the pinned buildx asset name (the guest is linux/arm64).
	BuildxAsset = "buildx-" + BuildxVersion + "." + guestBuildxPlatform
	// BuildxSHA256 is the pinned asset's sha256, from the release checksums.txt.
	BuildxSHA256 = "de05dccd47932eb9fd6e63781ab29d2b0b2c834bbdd19b51d7ea452b1fe378d3"

	// guestBuildxPlatform is the in-pod asset's platform suffix (the guest arch).
	guestBuildxPlatform = "linux-arm64"
)

// BuildxURL is the download URL for the pinned buildx asset.
func BuildxURL() string {
	return fmt.Sprintf("https://github.com/docker/buildx/releases/download/%s/%s", BuildxVersion, BuildxAsset)
}

// sha256Hex matches a lowercase 64-hex-char sha256 digest.
var sha256Hex = regexp.MustCompile(`^[0-9a-f]{64}$`)

// The HOST-side asset (the darwin/arm64 buildx the Mac runs to drive this engine)
// is pinned beside these constants in buildxhost.go, against the same release tag.

// ValidateBuildxPin fails if the compiled-in buildx pin is malformed. It is a
// build-time contract check, not a network fetch: it proves the constants are
// internally consistent (the asset names the version, the sha256 is a well-formed
// digest) so a bad bump is caught by `go test` rather than by a pod that fetches
// an unverifiable binary an hour into a build. The actual byte verification is
// the entrypoint's `sha256sum -c` against the pinned hash.
func ValidateBuildxPin() error {
	return validatePin(BuildxVersion, BuildxAsset, BuildxSHA256, guestBuildxPlatform)
}

// validatePin is the pure core of ValidateBuildxPin and ValidateHostBuildxPin,
// split out so both the happy path and the malformed-bump cases are
// table-testable without mutating package constants. platform is the asset's
// expected os-arch suffix — the check that a pin cannot name one arch's asset
// while carrying another's, which is the bump mistake that would otherwise reach
// a running guest.
func validatePin(version, asset, sha, platform string) error {
	if version == "" {
		return fmt.Errorf("buildx pin: empty version")
	}
	if !sha256Hex.MatchString(sha) {
		return fmt.Errorf("buildx pin: sha256 %q is not a 64-char lowercase hex digest", sha)
	}
	want := "buildx-" + version + "." + platform
	if asset != want {
		return fmt.Errorf("buildx pin: asset %q does not match version %q (want %q)", asset, version, want)
	}
	return nil
}

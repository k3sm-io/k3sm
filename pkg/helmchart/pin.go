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

package helmchart

import (
	"fmt"
	"path/filepath"
	"regexp"
)

// The helm pin. The Job's command[0] is this exact helm, shipped in the k3sm
// payload beside kubectl and seeded into the work dir's bin at boot.
//
// PROVENANCE. helm publishes one tarball per platform on get.helm.sh together
// with a <asset>.sha256sum file; HelmSHA256 is the digest that file names for
// the darwin-arm64 tarball, recorded 2026-09-26 from
//
//	https://get.helm.sh/helm-v4.3.0-darwin-arm64.tar.gz.sha256sum
//
// and cross-checked by downloading the tarball and hashing it. The tarball holds
// darwin-arm64/helm, a Mach-O arm64 binary that is only linker-signed (ad hoc):
// helm ships no Developer ID signature for macOS, so k3sm re-signs it ad hoc at
// staging like every other payload binary, and a node that requires notarized
// binaries cannot run it.
//
// Helm 4 rather than 3: the HelmChart contract carries forceConflicts, and
// --force-conflicts exists only in Helm 4's server-side apply.
//
// Re-pin with hack/verify-helm-pin.sh after editing the constants: it
// re-derives the digest from helm's published checksum file and exits non-zero
// on any mismatch.
const (
	// HelmVersion is the pinned helm release.
	HelmVersion = "v4.3.0"
	// HelmAsset is the pinned release tarball's name.
	HelmAsset = "helm-" + HelmVersion + "-" + helmPlatform + ".tar.gz"
	// HelmSHA256 is the sha256 helm publishes for HelmAsset.
	HelmSHA256 = "d3870437e1e95b67f8edbde964156c84a26503f560821d40c542441658934fba"
	// HelmBinaryName is the staged binary's basename (in an install payload and
	// in the work dir's bin). The version is in the name so a bump stages beside
	// the old copy instead of silently reusing it.
	HelmBinaryName = "helm-" + HelmVersion
	// HelmTarballMember is the path of the helm binary inside HelmAsset.
	HelmTarballMember = helmPlatform + "/helm"

	// helmPlatform is the asset's platform suffix. k3sm is arm64-only, so there
	// is deliberately no darwin-amd64 pin.
	helmPlatform = "darwin-arm64"
	// helmDownloadBase is where helm publishes its release tarballs.
	helmDownloadBase = "https://get.helm.sh/"
)

// sha256Hex matches a lowercase hex sha256 digest.
var sha256Hex = regexp.MustCompile(`^[0-9a-f]{64}$`)

// helmVersionShape matches a helm release tag (vMAJOR.MINOR.PATCH).
var helmVersionShape = regexp.MustCompile(`^v[0-9]+\.[0-9]+\.[0-9]+$`)

// HelmURL is the download URL of the pinned tarball.
func HelmURL() string { return helmDownloadBase + HelmAsset }

// HelmChecksumURL is the URL of the checksum file helm publishes beside the
// pinned tarball.
func HelmChecksumURL() string { return HelmURL() + ".sha256sum" }

// HelmPath names the staged helm binary in binDir (the work dir's bin, or a
// payload dir). The controller's Job command[0] is this path under
// executor.BinDir.
func HelmPath(binDir string) string { return filepath.Join(binDir, HelmBinaryName) }

// ValidateHelmPin fails if the compiled-in pin is malformed. It is a build-time
// contract check, so a bad bump fails `go test` instead of a download nobody can
// verify.
func ValidateHelmPin() error {
	return validateHelmPin(HelmVersion, HelmAsset, HelmSHA256, HelmBinaryName)
}

// validateHelmPin is ValidateHelmPin over explicit values, so a test can feed it
// malformed pins.
func validateHelmPin(version, asset, sum, binary string) error {
	if !helmVersionShape.MatchString(version) {
		return fmt.Errorf("helm pin: version %q is not vMAJOR.MINOR.PATCH", version)
	}
	if want := "helm-" + version + "-" + helmPlatform + ".tar.gz"; asset != want {
		return fmt.Errorf("helm pin: asset %q does not match version %q (want %q)", asset, version, want)
	}
	if !sha256Hex.MatchString(sum) {
		return fmt.Errorf("helm pin: sha256 %q is not a 64-char lowercase hex digest", sum)
	}
	if want := "helm-" + version; binary != want {
		return fmt.Errorf("helm pin: binary name %q does not carry version %q (want %q)", binary, version, want)
	}
	return nil
}

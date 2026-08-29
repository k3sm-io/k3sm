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

package executor

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
)

// Digest pinning for the downloaded control-plane payload.
//
// The four kube-* binaries are fetched from a THIRD-PARTY GitHub org
// (kwok-ci/k8s — upstream ships no darwin/arm64 apiserver, k/k#118359) by tag,
// and a GitHub release tag is re-pointable and its assets replaceable in place.
// Those bytes become the apiserver a packaged install runs as a root-owned
// LaunchDaemon, i.e. the cluster's entire authentication, authorization and
// secret-custody authority. Fetching them by mutable name alone would leave the
// trust root of every k3sm cluster equal to whatever that tag resolves to at
// build time, with no anchor a reviewer or an incident responder can compare
// against — the same defect the image CAS closed by verifying blobs at commit.
//
// So each binary is pinned to the sha256 the release published, verified after
// download, and the pipeline FAILS CLOSED on a mismatch or an unknown file.
//
// kine is deliberately absent: it is not downloaded but built from source by
// `go install github.com/k3s-io/kine@<version>`, whose bytes the Go module
// checksum database already authenticates. Pinning a digest for a locally
// compiled binary would pin the toolchain, not the source.
//
// Refreshing a pin (a DefaultKubeVersion bump) means recording the digests the
// new release publishes. They are readable without downloading the assets:
//
//	gh api repos/kwok-ci/k8s/releases/tags/<ver>-kwok.0-darwin-arm64 \
//	  --jq '.assets[] | "\(.name) \(.digest)"'
//
// A version bump that forgets this file fails closed at staging rather than
// shipping unverified bytes, because an absent pin is an error, never a skip.

// payloadDigests maps DefaultKubeVersion to each downloaded binary's sha256.
// Keyed by version so a bump cannot silently reuse the previous release's pins.
var payloadDigests = map[string]map[string]string{
	"v1.36.2": {
		"kube-apiserver":          "1afff09280a70553c72561e4c2d55ec95f8c979fa5933dba770aade5a3a93ca5",
		"kube-controller-manager": "a2ad45b40d8a367022cd545d390469913aeef3c3b83300477e629c6af1bd2dad",
		"kube-scheduler":          "c46f96dd961607a325482bd46f7e53fd78cf6106fcbac48315506f37a417f6ba",
		"kubectl":                 "112ed6605c8a68d5d3e6abef5f1beb5c087309e3979dc18d7c38b018cd7758a9",
	},
}

// ErrPayloadDigestMismatch is returned when a downloaded control-plane binary
// does not match its pinned sha256. It is fatal by design: a mismatch means the
// bytes are not the reviewed bytes, and no partial-trust fallback is correct.
var ErrPayloadDigestMismatch = errors.New("control-plane payload digest mismatch")

// ErrPayloadDigestUnpinned is returned when no digest is recorded for the
// requested version. Unpinned is an error rather than a skip so that bumping
// DefaultKubeVersion without recording digests cannot silently downgrade the
// pipeline to unverified downloads.
var ErrPayloadDigestUnpinned = errors.New("control-plane payload digests not pinned for this version")

// PinnedPayloadDigests returns the pinned sha256 set for a kube version, and
// whether the version is pinned at all.
func PinnedPayloadDigests(kubeVersion string) (map[string]string, bool) {
	d, ok := payloadDigests[kubeVersion]
	return d, ok
}

// sha256File returns the lowercase hex sha256 of the file at path.
func sha256File(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", fmt.Errorf("read %s: %w", path, err)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// VerifyDownloadedDigests checks every pinned control-plane binary in dir
// against its recorded sha256.
//
// TIMING IS PART OF THE CONTRACT: this must run on the bytes as downloaded, and
// BEFORE they are ad-hoc signed. `codesign` rewrites a Mach-O to embed the
// signature, so a hash taken afterwards can never equal the digest the upstream
// release published — verifying too late does not merely weaken the check, it
// makes it permanently, confusingly red.
func VerifyDownloadedDigests(dir, kubeVersion string) error {
	want, ok := PinnedPayloadDigests(kubeVersion)
	if !ok {
		return fmt.Errorf("%w: %s (record them in pkg/executor/payload_digests.go)", ErrPayloadDigestUnpinned, kubeVersion)
	}

	for _, name := range cpBinaries {
		wantSum, pinned := want[name]
		if !pinned {
			return fmt.Errorf("%w: %s for %s", ErrPayloadDigestUnpinned, name, kubeVersion)
		}
		got, err := sha256File(filepath.Join(dir, name))
		if err != nil {
			return fmt.Errorf("verify %s: %w", name, err)
		}
		if got != wantSum {
			return fmt.Errorf("%w: %s has sha256 %s, want %s", ErrPayloadDigestMismatch, name, got, wantSum)
		}
	}
	return nil
}

// VerifyPayloadSet rejects any file in dir that is not part of the expected
// payload.
//
// This matters as much as the digest check: the download pulls whatever assets
// the third-party release happens to carry, so a presence-only or subset check
// would let an extra executable ride along inside a k3sm-published,
// k3sm-checksummed archive that a reader reasonably takes as k3sm-provenanced.
func VerifyPayloadSet(dir string) error {
	// Set-equality: nothing beyond the expected payload may sit in the tree.
	allowed := map[string]bool{}
	for _, b := range PayloadBinaries() {
		allowed[b] = true
	}
	// The kine version marker rides beside the kine binary it describes (see
	// KineMarkerName): it is what tells a seeded workdir which pin+variant it got, so
	// the payload must be allowed to carry it. It is ALLOWED, not required — archives
	// produced before markers existed still verify, and pkg/install stages it
	// best-effort for the same reason.
	allowed[KineMarkerName] = true
	entries, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("read payload dir %s: %w", dir, err)
	}
	var extra []string
	for _, e := range entries {
		if !allowed[e.Name()] {
			extra = append(extra, e.Name())
		}
	}
	if len(extra) > 0 {
		sort.Strings(extra)
		return fmt.Errorf("%w: unexpected files in payload dir %s: %v (the download pulls every release asset; the archive ships only the pinned set)",
			ErrPayloadDigestMismatch, dir, extra)
	}
	return nil
}

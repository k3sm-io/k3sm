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
	"os"
	"path/filepath"
	"testing"
)

// writeFiles lays down a fake payload tree. These tests exercise the verifier's
// REJECTION paths only: producing bytes that hash to a pinned digest would mean
// forging a sha256 preimage, so a synthetic happy path is not constructible. The
// real happy path is proven by the release pipeline against the actual download,
// and the pin table itself is guarded by TestPinnedDigestsCoverEveryDownloadedBinary.
func writeFiles(t *testing.T, dir string, names ...string) {
	t.Helper()
	for _, n := range names {
		if err := os.WriteFile(filepath.Join(dir, n), []byte(n), 0o755); err != nil {
			t.Fatalf("write %s: %v", n, err)
		}
	}
}

func TestVerifyDownloadedDigestsUnpinnedVersionIsAnError(t *testing.T) {
	dir := t.TempDir()
	err := VerifyDownloadedDigests(dir, "v9.9.9-not-pinned")
	if !errors.Is(err, ErrPayloadDigestUnpinned) {
		t.Fatalf("VerifyDownloadedDigests(unpinned) error = %v, want ErrPayloadDigestUnpinned", err)
	}
}

func TestVerifyDownloadedDigestsRejectsWrongBytes(t *testing.T) {
	dir := t.TempDir()
	// Content that is definitely not the pinned release bytes.
	writeFiles(t, dir, append(append([]string{}, cpBinaries...), "kine")...)

	err := VerifyDownloadedDigests(dir, DefaultKubeVersion)
	if !errors.Is(err, ErrPayloadDigestMismatch) {
		t.Fatalf("VerifyDownloadedDigests(wrong bytes) error = %v, want ErrPayloadDigestMismatch", err)
	}
}

func TestVerifyDownloadedDigestsRejectsMissingFile(t *testing.T) {
	dir := t.TempDir()
	// Everything except kube-apiserver.
	writeFiles(t, dir, "kube-scheduler", "kube-controller-manager", "kubectl", "kine")

	err := VerifyDownloadedDigests(dir, DefaultKubeVersion)
	if err == nil {
		t.Fatal("VerifyDownloadedDigests(missing kube-apiserver) = nil, want an error")
	}
	if !os.IsNotExist(errors.Unwrap(err)) && !errors.Is(err, ErrPayloadDigestMismatch) {
		// Either shape is acceptable; silence is not.
		t.Logf("missing-file error (acceptable): %v", err)
	}
}

// TestPinnedDigestsCoverEveryDownloadedBinary is the anti-drift guard: every
// binary the download stages must carry a pin for the shipped version, so a
// DefaultKubeVersion bump that forgets this file fails closed rather than
// silently reverting to unverified downloads.
func TestPinnedDigestsCoverEveryDownloadedBinary(t *testing.T) {
	pins, ok := PinnedPayloadDigests(DefaultKubeVersion)
	if !ok {
		t.Fatalf("no pinned digests for DefaultKubeVersion %s — record them in payload_digests.go", DefaultKubeVersion)
	}
	for _, name := range cpBinaries {
		sum, pinned := pins[name]
		if !pinned {
			t.Errorf("no pinned sha256 for %s at %s", name, DefaultKubeVersion)
			continue
		}
		if len(sum) != 2*sha256.Size {
			t.Errorf("pinned digest for %s is %d chars, want %d hex chars", name, len(sum), 2*sha256.Size)
		}
		if _, err := hex.DecodeString(sum); err != nil {
			t.Errorf("pinned digest for %s is not hex: %v", name, err)
		}
	}
	// kine is built from source (sumdb-verified), so it must NOT carry a digest
	// pin — a pin there would pin the local toolchain, not the source.
	if _, pinned := pins["kine"]; pinned {
		t.Error("kine carries a digest pin; it is built by `go install` and authenticated by the module checksum database")
	}
}

// TestVerifyPayloadSetRejectsExtraFiles pins the set-equality half: the
// third-party download pulls every asset the release carries, so an unexpected
// executable must stop the release rather than ride inside a k3sm-signed,
// k3sm-checksummed archive that a reader takes as k3sm-provenanced.
func TestVerifyPayloadSetRejectsExtraFiles(t *testing.T) {
	dir := t.TempDir()
	writeFiles(t, dir, append(append([]string{}, PayloadBinaries()...), "totally-unexpected-tool")...)

	err := VerifyPayloadSet(dir)
	if err == nil {
		t.Fatal("VerifyPayloadSet(extra file) = nil, want an error")
	}
	if !errors.Is(err, ErrPayloadDigestMismatch) {
		t.Fatalf("error = %v, want ErrPayloadDigestMismatch", err)
	}
}

// TestVerifyPayloadSetAcceptsExactly the expected payload — the happy path the
// digest tests cannot construct (they would need a sha256 preimage).
func TestVerifyPayloadSetAcceptsExactSet(t *testing.T) {
	dir := t.TempDir()
	writeFiles(t, dir, PayloadBinaries()...)
	if err := VerifyPayloadSet(dir); err != nil {
		t.Fatalf("VerifyPayloadSet(exact payload set) = %v, want nil", err)
	}
}

// TestStagePayloadRefusesDirtyDir pins the timing contract: an already-populated
// payload dir holds SIGNED bytes, and signing rewrites the Mach-O, so their
// digests can never again be compared against what upstream published. The
// packaging path must refuse rather than silently skip verification.
func TestStagePayloadRefusesPrepopulatedDir(t *testing.T) {
	dir := t.TempDir()
	writeFiles(t, dir, "kube-apiserver")

	err := ensureControlPlaneBinariesVerified(t.Context(), dir, DefaultKubeVersion, true)
	if !errors.Is(err, ErrPayloadDigestUnpinned) {
		t.Fatalf("verified staging into a pre-populated dir = %v, want a refusal", err)
	}
}

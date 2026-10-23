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
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"k3sm.io/k3sm/internal/atomicfile"
	"k3sm.io/k3sm/internal/binsign"
)

// failTempSigner is fakeCodeSigner with one injected fault: the first time an
// atomicfile temp of failName is evaluated against a requirement, it does not
// satisfy it. The payload copy itself still verifies, so the fault lands mid-way
// through a whole-set replacement, after the marker is cleared.
type failTempSigner struct {
	*fakeCodeSigner
	failName string
	fired    bool
}

func (f *failTempSigner) Satisfies(ctx context.Context, path, requirement string) (bool, error) {
	if !f.fired && strings.HasPrefix(filepath.Base(path), "."+f.failName+".tmp-") {
		f.fired = true
		return false, nil
	}
	return f.fakeCodeSigner.Satisfies(ctx, path, requirement)
}

// TestReleaseReplacesDifferingControlPlaneSet pins this contract. On the release
// path, when the work dir's kube marker is valid and names the version the payload
// vouches for but the control-plane set there is missing a binary or differs in
// content from the payload's (an earlier dev install's ad-hoc build of the same
// pin), the WHOLE set is replaced from the payload: every payload copy verified
// first, the marker cleared, each binary installed on a new inode and verified
// before it takes its name, the marker written last. Everything else keeps its
// behaviour: an identical set is used in place, an older payload and a malformed
// marker are refused, a payload copy that fails verification refuses with the work
// dir untouched, an untrusted bin dir is refused, and the dev path never compares
// or replaces.
func TestReleaseReplacesDifferingControlPlaneSet(t *testing.T) {
	const team = "ABCDE12345"
	devID := fakeDevIDPrefix + team
	payloadBytes := func(n string) string { return "payload-" + n + devID }

	// stagePayload writes a payload whose own marker vouches for DefaultKubeVersion,
	// every copy Developer ID signed unless bad names one that is not.
	stagePayload := func(t *testing.T, bad, badTrailer string) string {
		t.Helper()
		payload := t.TempDir()
		for _, n := range cpBinaries {
			content := payloadBytes(n)
			if n == bad {
				content = "payload-" + n + badTrailer
			}
			writeBin(t, filepath.Join(payload, n), content)
		}
		if err := writeKubeMarker(payload, DefaultKubeVersion); err != nil {
			t.Fatal(err)
		}
		return payload
	}
	// stageWork writes the work dir's set (content per binary) and its marker.
	stageWork := func(t *testing.T, content func(n string) string, marker string) (work, bd string) {
		t.Helper()
		work = t.TempDir()
		bd = binDir(work)
		if err := os.MkdirAll(bd, 0o755); err != nil {
			t.Fatal(err)
		}
		for _, n := range cpBinaries {
			writeBin(t, filepath.Join(bd, n), content(n))
		}
		if err := os.WriteFile(kubeMarkerPath(bd), []byte(marker), 0o644); err != nil {
			t.Fatal(err)
		}
		return work, bd
	}
	// devCopy is a dev install's ad-hoc build of the same pin.
	devCopy := func(n string) string { return "dev-" + n + fakeAdHoc }
	// oneDiffers is the payload's set with kube-scheduler replaced by a dev copy.
	oneDiffers := func(n string) string {
		if n == "kube-scheduler" {
			return devCopy(n)
		}
		return payloadBytes(n)
	}
	boot := func(t *testing.T, work, payload string) error {
		t.Helper()
		if err := seedBinDir(t.Context(), discardLogger(), work, payload, DefaultKineVersion, DefaultKubeVersion, false); err != nil {
			return err
		}
		return ensureControlPlaneBinariesVerified(t.Context(), discardLogger(), binDir(work), DefaultKubeVersion, false)
	}
	assertPayloadSet := func(t *testing.T, bd string) {
		t.Helper()
		for _, n := range cpBinaries {
			got, err := os.ReadFile(filepath.Join(bd, n))
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != payloadBytes(n) {
				t.Errorf("%s = %q, want the payload's bytes", n, got)
			}
		}
		if v := readKubeMarker(bd); v != DefaultKubeVersion {
			t.Errorf("marker = %q, want %q written last", v, DefaultKubeVersion)
		}
	}
	markerContent := func(t *testing.T, bd string) string {
		t.Helper()
		b, err := os.ReadFile(kubeMarkerPath(bd))
		if err != nil {
			t.Fatalf("the marker is gone: %v", err)
		}
		return string(b)
	}

	t.Run("release, same-version marker, one differing binary: the whole set is replaced", func(t *testing.T) {
		s := &fakeCodeSigner{}
		useFakeSigning(t, s, devID)
		forbidDownload(t)
		payload := stagePayload(t, "", "")
		work, bd := stageWork(t, oneDiffers, kubeMarkerContent(DefaultKubeVersion))
		stamp := healStamp(kubeMarkerPath(bd))
		markHealed(t, bd, stamp, cpBinaries...) // a dev boot's heal lines at the same stamp
		before := ids(t, bd)
		if err := boot(t, work, payload); err != nil {
			t.Fatalf("boot refused: %v", err)
		}
		assertPayloadSet(t, bd)
		for _, n := range cpBinaries {
			if inode(t, filepath.Join(bd, n)) == before[n].ino {
				t.Errorf("%s kept its inode: the set must be replaced whole, each on a new inode", n)
			}
		}
		if len(s.signed) != 0 {
			t.Errorf("signed %v on the release path", s.signed)
		}
		healed, err := os.ReadFile(filepath.Join(bd, binsign.HealMarkerName))
		if err != nil {
			t.Fatal(err)
		}
		for _, n := range cpBinaries {
			if !strings.Contains(string(healed), n+"\t"+stamp+"\n") {
				t.Errorf("heal marker %q does not record %s at %q", healed, n, stamp)
			}
		}
		// A second boot finds the set identical and leaves it alone.
		after := ids(t, bd)
		if err := boot(t, work, payload); err != nil {
			t.Fatal(err)
		}
		assertUntouched(t, bd, after)
	})

	t.Run("release, identical set: no writes", func(t *testing.T) {
		s := &fakeCodeSigner{}
		useFakeSigning(t, s, devID)
		forbidDownload(t)
		payload := stagePayload(t, "", "")
		work, bd := stageWork(t, payloadBytes, kubeMarkerContent(DefaultKubeVersion))
		before := ids(t, bd)
		markerIno := inode(t, kubeMarkerPath(bd))
		if err := boot(t, work, payload); err != nil {
			t.Fatal(err)
		}
		assertUntouched(t, bd, before)
		if inode(t, kubeMarkerPath(bd)) != markerIno {
			t.Error("the marker was rewritten over an identical set")
		}
		if len(s.signed) != 0 {
			t.Errorf("signed %v", s.signed)
		}
	})

	t.Run("release, missing binary: the set is replaced", func(t *testing.T) {
		useFakeSigning(t, &fakeCodeSigner{}, devID)
		forbidDownload(t)
		payload := stagePayload(t, "", "")
		work, bd := stageWork(t, payloadBytes, kubeMarkerContent(DefaultKubeVersion))
		if err := os.Remove(filepath.Join(bd, "kubectl")); err != nil {
			t.Fatal(err)
		}
		if err := boot(t, work, payload); err != nil {
			t.Fatalf("boot refused: %v", err)
		}
		assertPayloadSet(t, bd)
	})

	t.Run("release, a symlinked binary with the payload's bytes: replaced, never followed", func(t *testing.T) {
		useFakeSigning(t, &fakeCodeSigner{}, devID)
		forbidDownload(t)
		payload := stagePayload(t, "", "")
		work, bd := stageWork(t, payloadBytes, kubeMarkerContent(DefaultKubeVersion))
		target := filepath.Join(t.TempDir(), "elsewhere-kube-apiserver")
		writeBin(t, target, payloadBytes("kube-apiserver")) // same bytes, Developer ID signed
		link := filepath.Join(bd, "kube-apiserver")
		if err := os.Remove(link); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, link); err != nil {
			t.Fatal(err)
		}
		linkIno := inode(t, link)
		targetBefore := idOf(t, target)
		if err := boot(t, work, payload); err != nil {
			t.Fatalf("boot refused: %v", err)
		}
		fi, err := os.Lstat(link)
		if err != nil {
			t.Fatal(err)
		}
		if !fi.Mode().IsRegular() {
			t.Fatalf("kube-apiserver is %v after the boot, want a regular file: a symlink is never trusted as the payload's bytes", fi.Mode())
		}
		if inode(t, link) == linkIno {
			t.Error("kube-apiserver kept the symlink's inode")
		}
		assertPayloadSet(t, bd)
		if got := idOf(t, target); got != targetBefore {
			t.Error("the symlink's target was written through")
		}
	})

	for _, tc := range []struct {
		name, marker string
	}{
		{"release, payload older than the marker: refused, untouched", kubeMarkerContent("v99.0.0")},
		{"release, malformed marker: refused, untouched", "not a version\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := &fakeCodeSigner{}
			useFakeSigning(t, s, devID)
			forbidDownload(t)
			payload := stagePayload(t, "", "")
			work, bd := stageWork(t, oneDiffers, tc.marker)
			before := ids(t, bd)
			if err := boot(t, work, payload); !errors.Is(err, ErrPayloadSignature) {
				t.Fatalf("boot err = %v, want the in-place refusal (ErrPayloadSignature)", err)
			}
			assertUntouched(t, bd, before)
			if got := markerContent(t, bd); got != tc.marker {
				t.Errorf("marker = %q, want %q untouched", got, tc.marker)
			}
			if len(s.signed) != 0 {
				t.Errorf("signed %v", s.signed)
			}
		})
	}

	t.Run("release, a payload copy fails verification: refused before anything moves", func(t *testing.T) {
		useFakeSigning(t, &fakeCodeSigner{}, devID)
		forbidDownload(t)
		payload := stagePayload(t, "kube-controller-manager", fakeAdHoc)
		work, bd := stageWork(t, oneDiffers, kubeMarkerContent(DefaultKubeVersion))
		before := ids(t, bd)
		err := boot(t, work, payload)
		if !errors.Is(err, ErrPayloadSignature) {
			t.Fatalf("boot err = %v, want ErrPayloadSignature", err)
		}
		if !strings.Contains(err.Error(), "kube-controller-manager") {
			t.Errorf("the refusal %q does not name the failing copy", err)
		}
		assertUntouched(t, bd, before)
		if got := markerContent(t, bd); got != kubeMarkerContent(DefaultKubeVersion) {
			t.Errorf("marker = %q, want it still present", got)
		}
	})

	t.Run("release, the third copy fails mid-way: no marker, and the next boot completes", func(t *testing.T) {
		s := &failTempSigner{fakeCodeSigner: &fakeCodeSigner{}, failName: cpBinaries[2]}
		exe := filepath.Join(t.TempDir(), "k3sm")
		writeBin(t, exe, "k3sm-daemon"+devID)
		origSigner, origExe := bootCodeSigner, selfExecutable
		t.Cleanup(func() { bootCodeSigner, selfExecutable = origSigner, origExe; resetSigningMemo() })
		bootCodeSigner, selfExecutable = s, func() (string, error) { return exe, nil }
		resetSigningMemo()
		forbidDownload(t)
		payload := stagePayload(t, "", "")
		work, bd := stageWork(t, oneDiffers, kubeMarkerContent(DefaultKubeVersion))
		if err := boot(t, work, payload); !errors.Is(err, ErrPayloadSignature) {
			t.Fatalf("boot err = %v, want the third copy's ErrPayloadSignature", err)
		}
		if _, err := os.Stat(kubeMarkerPath(bd)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("the marker survived a torn replacement (stat err %v): it would vouch for a mixed set", err)
		}
		if err := boot(t, work, payload); err != nil {
			t.Fatalf("second boot: %v", err)
		}
		assertPayloadSet(t, bd)
	})

	t.Run("release, untrusted (group-writable) bin dir: refused", func(t *testing.T) {
		useFakeSigning(t, &fakeCodeSigner{}, devID)
		forbidDownload(t)
		payload := stagePayload(t, "", "")
		for _, set := range []struct {
			name    string
			content func(string) string
		}{{"identical", payloadBytes}, {"differing", oneDiffers}} {
			t.Run(set.name, func(t *testing.T) {
				work, bd := stageWork(t, set.content, kubeMarkerContent(DefaultKubeVersion))
				if err := os.Chmod(bd, 0o775); err != nil {
					t.Fatal(err)
				}
				before := ids(t, bd)
				if err := boot(t, work, payload); !errors.Is(err, atomicfile.ErrUnsafeDir) {
					t.Fatalf("boot err = %v, want ErrUnsafeDir", err)
				}
				assertUntouched(t, bd, before)
				if got := markerContent(t, bd); got != kubeMarkerContent(DefaultKubeVersion) {
					t.Errorf("marker = %q, want it untouched", got)
				}
			})
		}
	})

	t.Run("dev path, same-version differing set: untouched", func(t *testing.T) {
		s := &fakeCodeSigner{}
		useFakeSigning(t, s, fakeAdHoc)
		forbidDownload(t)
		payload := stagePayload(t, "", "")
		work, bd := stageWork(t, devCopy, kubeMarkerContent(DefaultKubeVersion))
		markHealed(t, bd, healStamp(kubeMarkerPath(bd)), cpBinaries...)
		before := ids(t, bd)
		if err := boot(t, work, payload); err != nil {
			t.Fatal(err)
		}
		assertUntouched(t, bd, before)
		for _, p := range s.satisfiesOn {
			if filepath.Dir(p) == payload {
				t.Errorf("the dev path verified the payload's %s", filepath.Base(p))
			}
		}
		if len(s.signed) != 0 {
			t.Errorf("signed %v", s.signed)
		}
	})
}

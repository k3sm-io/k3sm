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
	"errors"
	"os"
	"path/filepath"
	"testing"

	"k3sm.io/k3sm/pkg/helmchart"
)

// TestReleaseInstallNeverResignsHelm is the gate for helm on a release install:
// the daemon's own Developer ID signature selects the release path
// (resolveSigningPolicy), and on it helm is the signed payload's bytes, verified
// against the Developer ID requirement and never signed:
//
//   - a Developer ID helm is left on the same inode with the same bytes, and the
//     boot's signer does not sign;
//   - a payload copy that differs from the work dir's is installed verified, not
//     signed;
//   - an ad-hoc, unsigned, other-team, same-team non-Developer ID or missing helm
//     is an ErrPayloadSignature, with nothing signed or replaced;
//   - on the dev path the same staging DOES sign, so a hard-wired "never sign"
//     fails this test.
func TestReleaseInstallNeverResignsHelm(t *testing.T) {
	const team, otherTeam = "ABCDE12345", "ZZZZZ99999"
	helm := helmchart.HelmBinaryName
	devID := fakeDevIDPrefix + team

	t.Run("release: Developer ID helm is used byte-identical, nothing signed", func(t *testing.T) {
		s := &fakeCodeSigner{}
		useFakeSigning(t, s, devID)
		bd := t.TempDir()
		writeBin(t, helmchart.HelmPath(bd), "helm"+devID)
		helmBefore := idOf(t, helmchart.HelmPath(bd))

		p, err := resolveSigningPolicy(t.Context(), discardLogger())
		if err != nil || !p.release {
			t.Fatalf("policy = %+v, %v; want the release path", p, err)
		}
		if err := signHelm(t.Context(), p, bd); err != nil {
			t.Fatalf("signHelm: %v", err)
		}
		if got, err := EnsureHelm(t.Context(), bd); err != nil || got != helmchart.HelmPath(bd) {
			t.Fatalf("EnsureHelm = %q, %v", got, err)
		}
		if got := idOf(t, helmchart.HelmPath(bd)); got != helmBefore {
			t.Errorf("helm changed (inode %d -> %d, or its bytes)", helmBefore.ino, got.ino)
		}
		if len(s.signed) != 0 {
			t.Errorf("the boot signer signed %v on the release path", s.signed)
		}
	})

	t.Run("release: a differing payload copy is installed verified, not signed", func(t *testing.T) {
		s := &fakeCodeSigner{}
		useFakeSigning(t, s, devID)
		work, payload := t.TempDir(), t.TempDir()
		bd := binDir(work)
		if err := os.MkdirAll(bd, 0o755); err != nil {
			t.Fatal(err)
		}
		writeBin(t, helmchart.HelmPath(bd), "old-helm"+fakeAdHoc)
		// The seed reads the payload helm's build stamp (ensureShipped); the
		// fake stamp reader reads the line writeChildBin writes.
		useChildSeams(t)
		writeChildBin(t, helmchart.HelmPath(payload), helmchart.HelmVersion, helmchart.HelmBuildVariant, "helm", devID)
		if err := seedBinDir(t.Context(), discardLogger(), work, payload, DefaultKineVersion, DefaultKubeVersion, false); err != nil {
			t.Fatalf("seedBinDir: %v", err)
		}
		p, err := resolveSigningPolicy(t.Context(), discardLogger())
		if err != nil {
			t.Fatal(err)
		}
		if err := signHelm(t.Context(), p, bd); err != nil {
			t.Fatalf("signHelm after the seed: %v", err)
		}
		if idOf(t, filepath.Join(bd, helm)).sum != idOf(t, filepath.Join(payload, helm)).sum {
			t.Errorf("%s in the work dir is not the payload's bytes", helm)
		}
		if len(s.signed) != 0 {
			t.Errorf("the boot signer signed %v on the release path", s.signed)
		}
	})

	t.Run("release: a helm that fails verification is refused, never signed", func(t *testing.T) {
		for _, tc := range []struct {
			name    string
			trailer string
			remove  bool
		}{
			{"ad hoc", fakeAdHoc, false},
			{"unsigned", "", false},
			{"another team", fakeDevIDPrefix + otherTeam, false},
			{"a development certificate of the same team", fakeAppleDevPrefix + team, false},
			{"missing", "", true},
		} {
			t.Run(tc.name, func(t *testing.T) {
				s := &fakeCodeSigner{}
				useFakeSigning(t, s, devID)
				bd := t.TempDir()
				var helmBefore fileID
				if !tc.remove {
					writeBin(t, helmchart.HelmPath(bd), "helm"+tc.trailer)
					helmBefore = idOf(t, helmchart.HelmPath(bd))
				}
				p, err := resolveSigningPolicy(t.Context(), discardLogger())
				if err != nil {
					t.Fatal(err)
				}
				if !tc.remove {
					if err := signHelm(t.Context(), p, bd); !errors.Is(err, ErrPayloadSignature) {
						t.Errorf("signHelm err = %v, want ErrPayloadSignature", err)
					}
				}
				if _, err := EnsureHelm(t.Context(), bd); !errors.Is(err, ErrPayloadSignature) {
					t.Errorf("EnsureHelm err = %v, want ErrPayloadSignature", err)
				}
				if len(s.signed) != 0 {
					t.Errorf("the boot signer signed %v while refusing", s.signed)
				}
				if tc.remove {
					if _, err := os.Lstat(helmchart.HelmPath(bd)); !os.IsNotExist(err) {
						t.Errorf("%s was staged while refusing (err %v)", helmchart.HelmPath(bd), err)
					}
					return
				}
				if got := idOf(t, helmchart.HelmPath(bd)); got != helmBefore {
					t.Errorf("helm changed while refusing (inode %d -> %d, or its bytes)", helmBefore.ino, got.ino)
				}
			})
		}
	})

	t.Run("dev: the same staging signs", func(t *testing.T) {
		s := &fakeCodeSigner{}
		useFakeSigning(t, s, fakeAdHoc)
		bd := t.TempDir()
		writeBin(t, helmchart.HelmPath(bd), "helm")
		p, err := resolveSigningPolicy(t.Context(), discardLogger())
		if err != nil || p.release {
			t.Fatalf("policy = %+v, %v; want the dev path", p, err)
		}
		if err := signHelm(t.Context(), p, bd); err != nil {
			t.Fatalf("signHelm: %v", err)
		}
		if len(s.signed) == 0 {
			t.Error("the dev path did not sign an unsigned helm")
		}
	})
}

// TestSigningPolicyResolvedOncePerProcess pins the memo behind
// resolveSigningPolicy: every caller in the process (the boot steps, EnsureHelm)
// sees the decision the first clean probe
// made, and a probe error is returned to each caller and never remembered as the
// dev path.
func TestSigningPolicyResolvedOncePerProcess(t *testing.T) {
	const team = "ABCDE12345"

	t.Run("every caller sees the first clean decision", func(t *testing.T) {
		s := &fakeCodeSigner{}
		useFakeSigning(t, s, fakeDevIDPrefix+team)
		first, err := resolveSigningPolicy(t.Context(), discardLogger())
		if err != nil || !first.release {
			t.Fatalf("first = %+v, %v; want the release path", first, err)
		}
		// The executable now reads as ad hoc; a second probe would pick dev.
		adhoc := filepath.Join(t.TempDir(), "k3sm")
		writeBin(t, adhoc, "k3sm"+fakeAdHoc)
		selfExecutable = func() (string, error) { return adhoc, nil }
		again, err := resolveSigningPolicy(t.Context(), discardLogger())
		if err != nil || again.release != first.release || again.teamID != first.teamID {
			t.Errorf("second caller = %+v, %v; want the memoised %+v", again, err, first)
		}
		if len(s.satisfiesOn) != 1 {
			t.Errorf("the daemon's signature was evaluated %d times, want once per process", len(s.satisfiesOn))
		}
	})

	t.Run("a probe error is not memoised as dev", func(t *testing.T) {
		s := &fakeCodeSigner{inspectErr: errors.New("codesign could not run")}
		useFakeSigning(t, s, fakeDevIDPrefix+team)
		for i := range 2 {
			logger, errorLines := countingLogger()
			if p, err := resolveSigningPolicy(t.Context(), logger); !errors.Is(err, ErrSelfSignatureUnreadable) {
				t.Fatalf("call %d = %+v, %v; want ErrSelfSignatureUnreadable every time", i, p, err)
			}
			if errorLines() != 1 {
				t.Errorf("call %d logged %d error lines, want its own refusal", i, errorLines())
			}
		}
		s.inspectErr = nil
		p, err := resolveSigningPolicy(t.Context(), discardLogger())
		if err != nil || !p.release {
			t.Errorf("after the error cleared = %+v, %v; want a fresh probe choosing release", p, err)
		}
	})
}

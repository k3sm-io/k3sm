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
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"k3sm.io/k3sm/internal/binsign"
)

// The fake signature trailers fakeCodeSigner reads from a file's last line. A
// file with none of them is unsigned.
const (
	// fakeAdHoc is a valid ad-hoc signature. Sign appends it in place, as codesign
	// rewrites a file in place.
	fakeAdHoc = "\n#adhoc"
	// fakeDevIDPrefix + team is a valid Developer ID Application signature.
	fakeDevIDPrefix = "\n#devid:"
	// fakeAppleDevPrefix + team is a valid certificate signature with a Team ID
	// that is NOT a Developer ID Application certificate (an Apple Development
	// certificate, say): it satisfies TeamRequirement but not
	// DeveloperIDRequirement.
	fakeAppleDevPrefix = "\n#appledev:"
)

// fakeCodeSigner is the codeSigner seam with no codesign behind it: it reads the
// signature from the file's trailer and records every sign.
type fakeCodeSigner struct {
	signed      []string // paths passed to Sign, in order
	inspectErr  error    // returned by Inspect when set
	satisfiesOn []string // paths passed to Satisfies, in order
}

// fakeSignatureOf returns the kind and Team ID the file at path carries.
func fakeSignatureOf(path string) (kind, team string) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", ""
	}
	s := string(b)
	switch {
	case strings.HasSuffix(s, fakeAdHoc):
		return "adhoc", ""
	case strings.Contains(s, fakeDevIDPrefix):
		return "devid", s[strings.LastIndex(s, fakeDevIDPrefix)+len(fakeDevIDPrefix):]
	case strings.Contains(s, fakeAppleDevPrefix):
		return "appledev", s[strings.LastIndex(s, fakeAppleDevPrefix)+len(fakeAppleDevPrefix):]
	}
	return "", ""
}

func (f *fakeCodeSigner) Verify(_ context.Context, path string) (bool, error) {
	kind, _ := fakeSignatureOf(path)
	return kind == "adhoc", nil
}

func (f *fakeCodeSigner) Sign(_ context.Context, path, _ string) error {
	f.signed = append(f.signed, path)
	fh, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		return err
	}
	_, _ = fh.WriteString(fakeAdHoc)
	return fh.Close()
}

func (f *fakeCodeSigner) Inspect(_ context.Context, path string) (binsign.Signature, error) {
	if f.inspectErr != nil {
		return binsign.Signature{}, f.inspectErr
	}
	switch kind, team := fakeSignatureOf(path); kind {
	case "adhoc":
		return binsign.Signature{Valid: true, AdHoc: true}, nil
	case "devid", "appledev":
		return binsign.Signature{Valid: true, TeamID: team}, nil
	}
	return binsign.Signature{}, nil
}

// Satisfies evaluates exactly the two requirement texts binsign builds: the
// team clause binds the leaf's team, and the Developer ID clause (the leaf
// marker OID) admits only a Developer ID Application signature.
func (f *fakeCodeSigner) Satisfies(_ context.Context, path, requirement string) (bool, error) {
	f.satisfiesOn = append(f.satisfiesOn, path)
	kind, team := fakeSignatureOf(path)
	if kind != "devid" && kind != "appledev" {
		return false, nil
	}
	if !strings.HasSuffix(requirement, `certificate leaf[subject.OU] = "`+team+`"`) {
		return false, nil
	}
	if strings.Contains(requirement, "field.1.2.840.113635.100.6.1.13") && kind != "devid" {
		return false, nil
	}
	return true, nil
}

// useFakeSigning installs s as the boot's signer and a k3sm executable carrying
// selfTrailer as the daemon's own binary, for the duration of the test. It mutates
// package seams, so a test that calls it must never be t.Parallel.
func useFakeSigning(t *testing.T, s *fakeCodeSigner, selfTrailer string) {
	t.Helper()
	exe := filepath.Join(t.TempDir(), "k3sm")
	if err := os.WriteFile(exe, []byte("k3sm-daemon"+selfTrailer), 0o755); err != nil {
		t.Fatal(err)
	}
	origSigner, origExe := bootCodeSigner, selfExecutable
	t.Cleanup(func() { bootCodeSigner, selfExecutable = origSigner, origExe })
	bootCodeSigner = s
	selfExecutable = func() (string, error) { return exe, nil }
}

// forbidDownload fails the test if anything tries to fetch the control plane.
func forbidDownload(t *testing.T) {
	t.Helper()
	orig := runControlPlaneDownload
	t.Cleanup(func() { runControlPlaneDownload = orig })
	runControlPlaneDownload = func(context.Context, string, string) ([]byte, error) {
		t.Error("the control plane was downloaded")
		return nil, errors.New("no download in this test")
	}
}

// fileID is a binary's inode and content checksum: equal before and after means
// the binary was left byte-identical on the same inode.
type fileID struct {
	ino uint64
	sum [32]byte
}

func idOf(t *testing.T, path string) fileID {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return fileID{ino: inode(t, path), sum: sha256.Sum256(b)}
}

// stageSet writes the control-plane set into a fresh bin dir, each file ending
// with trailer, plus the kube marker, and returns the dir.
func stageSet(t *testing.T, trailer func(name string) string) string {
	t.Helper()
	bd := t.TempDir()
	for _, n := range cpBinaries {
		writeBin(t, filepath.Join(bd, n), n+"-bytes"+trailer(n))
	}
	if err := writeKubeMarker(bd, DefaultKubeVersion); err != nil {
		t.Fatal(err)
	}
	return bd
}

func ids(t *testing.T, bd string) map[string]fileID {
	t.Helper()
	m := map[string]fileID{}
	for _, n := range cpBinaries {
		m[n] = idOf(t, filepath.Join(bd, n))
	}
	return m
}

func assertUntouched(t *testing.T, bd string, before map[string]fileID) {
	t.Helper()
	for n, id := range ids(t, bd) {
		if id != before[n] {
			t.Errorf("%s changed (inode %d -> %d, or its bytes): a verified binary must stay byte-identical", n, before[n].ino, id.ino)
		}
	}
}

// TestBootVerifiesPayloadWithoutResigning is the B480 gate. A boot verifies the
// payload's signatures in place and never ad-hoc re-signs a validly signed binary:
//
//   - the signing path is chosen from the daemon's own signature, with no flag:
//     a Developer ID Application signature selects the release path and names its
//     Team ID; ad hoc, unsigned, another certificate, or an unreadable signature
//     selects the dev path;
//   - release path, control-plane binaries signed by that team: left byte-identical
//     (same inode, same checksum), no heal and no sign, the heal stamp recorded;
//   - release path, an ad-hoc, unsigned, other-team or missing binary: the boot is
//     refused naming it, nothing is downloaded, signed or replaced; a payload copy
//     is verified before it takes its name in the work dir;
//   - dev path, unsigned: re-signed on a new inode, through a temp;
//   - a heal marker without the stamp never touches a Developer ID binary, on
//     either path.
func TestBootVerifiesPayloadWithoutResigning(t *testing.T) {
	const team, otherTeam = "ABCDE12345", "ZZZZZ99999"
	devID := func(string) string { return fakeDevIDPrefix + team }

	t.Run("mode detection reads the daemon's own signature", func(t *testing.T) {
		for _, tc := range []struct {
			name        string
			self        string
			inspectErr  error
			exeErr      bool
			wantRelease bool
		}{
			{"Developer ID Application", fakeDevIDPrefix + team, nil, false, true},
			{"ad hoc", fakeAdHoc, nil, false, false},
			{"unsigned", "", nil, false, false},
			{"a team certificate that is not Developer ID", fakeAppleDevPrefix + team, nil, false, false},
			{"Developer ID with a malformed Team ID", fakeDevIDPrefix + "bad team", nil, false, false},
			{"the signature cannot be read", fakeDevIDPrefix + team, errors.New("codesign missing"), false, false},
			{"the executable cannot be resolved", fakeDevIDPrefix + team, nil, true, false},
		} {
			t.Run(tc.name, func(t *testing.T) {
				useFakeSigning(t, &fakeCodeSigner{inspectErr: tc.inspectErr}, tc.self)
				if tc.exeErr {
					selfExecutable = func() (string, error) { return "", errors.New("no executable") }
				}
				p := resolveSigningPolicy(t.Context())
				if p.release != tc.wantRelease {
					t.Fatalf("release = %v, want %v", p.release, tc.wantRelease)
				}
				if tc.wantRelease && p.teamID != team {
					t.Errorf("team = %q, want %q read from the daemon's signature", p.teamID, team)
				}
				if !tc.wantRelease && p.teamID != "" {
					t.Errorf("the dev path carries team %q", p.teamID)
				}
			})
		}
	})

	t.Run("release path: a valid Developer ID set is used byte-identical, no heal", func(t *testing.T) {
		s := &fakeCodeSigner{}
		useFakeSigning(t, s, fakeDevIDPrefix+team)
		forbidDownload(t)
		bd := stageSet(t, devID)
		before := ids(t, bd)
		if err := ensureControlPlaneBinariesVerified(t.Context(), discardLogger(), bd, DefaultKubeVersion, false); err != nil {
			t.Fatal(err)
		}
		assertUntouched(t, bd, before)
		if len(s.signed) != 0 {
			t.Errorf("signed %v on the release path", s.signed)
		}
		marker, err := os.ReadFile(filepath.Join(bd, binsign.HealMarkerName))
		if err != nil {
			t.Fatalf("the heal stamp was not recorded: %v", err)
		}
		stamp := healStamp(kubeMarkerPath(bd))
		for _, n := range cpBinaries {
			if !strings.Contains(string(marker), n+"\t"+stamp+"\n") {
				t.Errorf("heal marker %q does not record %s at %q", marker, n, stamp)
			}
		}
		// A second boot, and a later dev heal at the same stamp, still touch nothing.
		if err := ensureControlPlaneBinariesVerified(t.Context(), discardLogger(), bd, DefaultKubeVersion, false); err != nil {
			t.Fatal(err)
		}
		if err := binsign.HealOnce(t.Context(), s, bd, stamp, cpBinaries...); err != nil {
			t.Fatal(err)
		}
		assertUntouched(t, bd, before)
		if len(s.signed) != 0 {
			t.Errorf("signed %v after the release path recorded the stamp", s.signed)
		}
	})

	t.Run("release path refuses a binary that fails verification", func(t *testing.T) {
		for _, tc := range []struct {
			name    string
			bad     string // the cp binary given trailer instead of the team's
			trailer string
			remove  bool
		}{
			{"ad hoc", "kube-scheduler", fakeAdHoc, false},
			{"unsigned", "kubectl", "", false},
			{"another team", "kube-controller-manager", fakeDevIDPrefix + otherTeam, false},
			{"missing", "kube-apiserver", "", true},
		} {
			t.Run(tc.name, func(t *testing.T) {
				s := &fakeCodeSigner{}
				useFakeSigning(t, s, fakeDevIDPrefix+team)
				forbidDownload(t)
				bd := stageSet(t, func(n string) string {
					if n == tc.bad {
						return tc.trailer
					}
					return fakeDevIDPrefix + team
				})
				if tc.remove {
					if err := os.Remove(filepath.Join(bd, tc.bad)); err != nil {
						t.Fatal(err)
					}
				}
				var before map[string]fileID
				if !tc.remove {
					before = ids(t, bd)
				}
				err := ensureControlPlaneBinariesVerified(t.Context(), discardLogger(), bd, DefaultKubeVersion, false)
				if !errors.Is(err, ErrPayloadSignature) {
					t.Fatalf("err = %v, want ErrPayloadSignature", err)
				}
				if !strings.Contains(err.Error(), tc.bad) {
					t.Errorf("the refusal %q does not name %s", err, tc.bad)
				}
				if len(s.signed) != 0 {
					t.Errorf("signed %v while refusing", s.signed)
				}
				if before != nil {
					assertUntouched(t, bd, before)
				}
			})
		}
	})

	t.Run("release path: a payload copy is verified, not signed, before it takes its name", func(t *testing.T) {
		for _, tc := range []struct {
			name    string
			trailer string
			wantErr bool
		}{
			{"Developer ID copy is seeded as is", fakeDevIDPrefix + team, false},
			{"ad-hoc copy is refused", fakeAdHoc, true},
		} {
			t.Run(tc.name, func(t *testing.T) {
				s := &fakeCodeSigner{}
				useFakeSigning(t, s, fakeDevIDPrefix+team)
				payload, work := t.TempDir(), t.TempDir()
				for _, n := range cpBinaries {
					writeBin(t, filepath.Join(payload, n), "payload-"+n+tc.trailer)
				}
				if err := writeKubeMarker(payload, DefaultKubeVersion); err != nil {
					t.Fatal(err)
				}
				err := seedBinDir(t.Context(), discardLogger(), work, payload, DefaultKineVersion, DefaultKubeVersion, false)
				if len(s.signed) != 0 {
					t.Errorf("signed %v while seeding on the release path", s.signed)
				}
				if tc.wantErr {
					if !errors.Is(err, ErrPayloadSignature) {
						t.Fatalf("err = %v, want ErrPayloadSignature", err)
					}
					if _, statErr := os.Stat(filepath.Join(binDir(work), "kube-apiserver")); statErr == nil {
						t.Error("a refused copy took its name in the work dir")
					}
					return
				}
				if err != nil {
					t.Fatal(err)
				}
				for _, n := range cpBinaries {
					got, _ := os.ReadFile(filepath.Join(binDir(work), n))
					if string(got) != "payload-"+n+tc.trailer {
						t.Errorf("seeded %s = %q, want the payload's bytes unchanged", n, got)
					}
				}
				if len(s.satisfiesOn) == 0 {
					t.Error("the copies were never verified")
				}
			})
		}
	})

	t.Run("dev path: an unsigned binary is re-signed on a new inode", func(t *testing.T) {
		s := &fakeCodeSigner{}
		useFakeSigning(t, s, fakeAdHoc)
		forbidDownload(t)
		bd := stageSet(t, func(string) string { return "" })
		markHealed(t, bd, healStamp(kubeMarkerPath(bd)), cpBinaries...) // only the signature check acts
		before := ids(t, bd)
		if err := ensureControlPlaneBinariesVerified(t.Context(), discardLogger(), bd, DefaultKubeVersion, false); err != nil {
			t.Fatal(err)
		}
		for _, n := range cpBinaries {
			p := filepath.Join(bd, n)
			if got := inode(t, p); got == before[n].ino {
				t.Errorf("%s was re-signed on its old inode", n)
			}
			if kind, _ := fakeSignatureOf(p); kind != "adhoc" {
				t.Errorf("%s is not ad-hoc signed after the dev boot", n)
			}
		}
		if len(s.signed) != len(cpBinaries) {
			t.Fatalf("signed %v, want one temp per binary", s.signed)
		}
		for _, p := range s.signed {
			if _, ok := tempTarget(p, filepath.Join(bd, "kube-apiserver"), filepath.Join(bd, "kube-scheduler"),
				filepath.Join(bd, "kube-controller-manager"), filepath.Join(bd, "kubectl")); !ok {
				t.Errorf("signed %s: only a temp beside its target may be signed", p)
			}
		}
	})

	t.Run("a heal marker without the stamp never touches a Developer ID binary", func(t *testing.T) {
		for _, tc := range []struct {
			name, self string
		}{
			{"dev path", fakeAdHoc},
			{"release path", fakeDevIDPrefix + team},
		} {
			for _, marker := range []string{"absent", "another stamp"} {
				t.Run(tc.name+", marker "+marker, func(t *testing.T) {
					s := &fakeCodeSigner{}
					useFakeSigning(t, s, tc.self)
					forbidDownload(t)
					bd := stageSet(t, devID)
					if marker == "another stamp" {
						markHealed(t, bd, "v0.0.1-older", cpBinaries...)
					}
					before := ids(t, bd)
					if err := ensureControlPlaneBinariesVerified(t.Context(), discardLogger(), bd, DefaultKubeVersion, false); err != nil {
						t.Fatal(err)
					}
					if err := signBinaries(t.Context(), bd, healStamp(kubeMarkerPath(bd)), cpBinaries); err != nil {
						t.Fatal(err)
					}
					assertUntouched(t, bd, before)
					if len(s.signed) != 0 {
						t.Errorf("signed %v: a Developer ID binary was healed or re-signed", s.signed)
					}
				})
			}
		}
	})
}

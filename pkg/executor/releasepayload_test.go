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
	"strings"
	"testing"

	"k3sm.io/k3sm/pkg/helmchart"
	"k3sm.io/k3sm/pkg/registrysvc"
)

// fakeZotCodesign puts a fake `codesign` first on PATH, the tool zot's dev
// signing runs (binsign.Codesign), and returns a func reporting how many signs
// it performed. It answers --verify and -dv as unsigned for anything it did not
// sign itself, so the dev path always has something to sign.
func fakeZotCodesign(t *testing.T) func() int {
	t.Helper()
	dir := t.TempDir()
	log := filepath.Join(dir, "codesign.log")
	script := `#!/bin/sh
for a in "$@"; do last=$a; done
case "$1" in
--verify|-dv)
	[ "$(/usr/bin/tail -c 6 "$last" 2>/dev/null)" = "SIGNED" ] && { echo "Signature=adhoc" >&2; exit 0; }
	exit 1
	;;
-s)
	printf 'sign %s\n' "$last" >> "` + log + `"
	printf SIGNED >> "$last"
	exit 0
	;;
esac
exit 2
`
	if err := os.WriteFile(filepath.Join(dir, "codesign"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	return func() int {
		b, err := os.ReadFile(log)
		if err != nil {
			return 0
		}
		return strings.Count(string(b), "sign ")
	}
}

// writeZotPayload stages zot with content and its version marker in dir, the
// shape `k3sm payload` leaves.
func writeZotPayload(t *testing.T, dir, content string) {
	t.Helper()
	writeBin(t, registrysvc.ZotPath(dir), content)
	marker := registrysvc.DefaultZotVersion + " minimal+r1\n"
	if err := os.WriteFile(filepath.Join(dir, registrysvc.ZotMarkerName), []byte(marker), 0o644); err != nil {
		t.Fatal(err)
	}
}

// TestReleaseInstallNeverResignsHelmOrZot is the gate for helm and zot on a
// release install: the daemon's own Developer ID signature selects the release
// path (resolveSigningPolicy), and on it helm and the registry's zot are the
// signed payload's bytes, verified against the Developer ID requirement and
// never signed:
//
//   - Developer ID helm and zot are left on the same inode with the same bytes,
//     and neither signer (the boot's, and the codesign zot's dev path runs) signs;
//   - a payload copy that differs from the work dir's is installed verified, not
//     signed;
//   - an ad-hoc, unsigned, other-team, same-team non-Developer ID or missing helm
//     or zot is an ErrPayloadSignature, with nothing signed or replaced;
//   - on the dev path the same staging DOES sign, so a hard-wired "never sign"
//     fails this test.
func TestReleaseInstallNeverResignsHelmOrZot(t *testing.T) {
	const team, otherTeam = "ABCDE12345", "ZZZZZ99999"
	helm := helmchart.HelmBinaryName
	devID := fakeDevIDPrefix + team

	t.Run("release: Developer ID helm and zot are used byte-identical, nothing signed", func(t *testing.T) {
		s := &fakeCodeSigner{}
		useFakeSigning(t, s, devID)
		zotSigns := fakeZotCodesign(t)
		bd, payload := t.TempDir(), t.TempDir()
		writeBin(t, helmchart.HelmPath(bd), "helm"+devID)
		writeZotPayload(t, payload, "zot"+devID)
		writeZotPayload(t, bd, "zot"+devID)
		helmBefore, zotBefore := idOf(t, helmchart.HelmPath(bd)), idOf(t, registrysvc.ZotPath(bd))

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
		v, release, err := ResolveReleaseVerifier(t.Context(), discardLogger())
		if err != nil || !release {
			t.Fatalf("ResolveReleaseVerifier = %v, %v; want the release path", release, err)
		}
		if err := registrysvc.EnsureZotWith(t.Context(), v, bd, payload, ""); err != nil {
			t.Fatalf("EnsureZotWith: %v", err)
		}
		if got := idOf(t, helmchart.HelmPath(bd)); got != helmBefore {
			t.Errorf("helm changed (inode %d -> %d, or its bytes)", helmBefore.ino, got.ino)
		}
		if got := idOf(t, registrysvc.ZotPath(bd)); got != zotBefore {
			t.Errorf("zot changed (inode %d -> %d, or its bytes)", zotBefore.ino, got.ino)
		}
		if len(s.signed) != 0 {
			t.Errorf("the boot signer signed %v on the release path", s.signed)
		}
		if n := zotSigns(); n != 0 {
			t.Errorf("codesign signed %d time(s) on the release path", n)
		}
	})

	t.Run("release: a differing payload copy is installed verified, not signed", func(t *testing.T) {
		s := &fakeCodeSigner{}
		useFakeSigning(t, s, devID)
		zotSigns := fakeZotCodesign(t)
		work, payload := t.TempDir(), t.TempDir()
		bd := binDir(work)
		if err := os.MkdirAll(bd, 0o755); err != nil {
			t.Fatal(err)
		}
		writeBin(t, helmchart.HelmPath(bd), "old-helm"+fakeAdHoc)
		writeBin(t, helmchart.HelmPath(payload), "helm"+devID)
		writeZotPayload(t, payload, "zot"+devID)
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
		v, _, err := ResolveReleaseVerifier(t.Context(), discardLogger())
		if err != nil {
			t.Fatal(err)
		}
		if err := registrysvc.EnsureZotWith(t.Context(), v, bd, payload, ""); err != nil {
			t.Fatalf("EnsureZotWith: %v", err)
		}
		for _, n := range []string{helm, registrysvc.ZotBinaryName} {
			if idOf(t, filepath.Join(bd, n)).sum != idOf(t, filepath.Join(payload, n)).sum {
				t.Errorf("%s in the work dir is not the payload's bytes", n)
			}
		}
		if len(s.signed) != 0 {
			t.Errorf("the boot signer signed %v on the release path", s.signed)
		}
		if n := zotSigns(); n != 0 {
			t.Errorf("codesign signed %d time(s) on the release path", n)
		}
	})

	t.Run("release: a helm or zot that fails verification is refused, never signed", func(t *testing.T) {
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
				zotSigns := fakeZotCodesign(t)
				bd, payload := t.TempDir(), t.TempDir()
				var helmBefore, zotBefore fileID
				if !tc.remove {
					writeBin(t, helmchart.HelmPath(bd), "helm"+tc.trailer)
					writeZotPayload(t, payload, "zot"+tc.trailer)
					writeZotPayload(t, bd, "zot"+tc.trailer)
					helmBefore, zotBefore = idOf(t, helmchart.HelmPath(bd)), idOf(t, registrysvc.ZotPath(bd))
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
				v, _, err := ResolveReleaseVerifier(t.Context(), discardLogger())
				if err != nil {
					t.Fatal(err)
				}
				err = registrysvc.EnsureZotWith(t.Context(), v, bd, payload, "")
				if !errors.Is(err, ErrPayloadSignature) {
					t.Errorf("EnsureZotWith err = %v, want ErrPayloadSignature", err)
				}
				if len(s.signed) != 0 {
					t.Errorf("the boot signer signed %v while refusing", s.signed)
				}
				if n := zotSigns(); n != 0 {
					t.Errorf("codesign signed %d time(s) while refusing", n)
				}
				if tc.remove {
					for _, p := range []string{helmchart.HelmPath(bd), registrysvc.ZotPath(bd)} {
						if _, err := os.Lstat(p); !os.IsNotExist(err) {
							t.Errorf("%s was staged while refusing (err %v)", p, err)
						}
					}
					return
				}
				if got := idOf(t, helmchart.HelmPath(bd)); got != helmBefore {
					t.Errorf("helm changed while refusing (inode %d -> %d, or its bytes)", helmBefore.ino, got.ino)
				}
				if got := idOf(t, registrysvc.ZotPath(bd)); got != zotBefore {
					t.Errorf("zot changed while refusing (inode %d -> %d, or its bytes)", zotBefore.ino, got.ino)
				}
			})
		}
	})

	t.Run("dev: the same staging signs", func(t *testing.T) {
		s := &fakeCodeSigner{}
		useFakeSigning(t, s, fakeAdHoc)
		zotSigns := fakeZotCodesign(t)
		bd, payload := t.TempDir(), t.TempDir()
		writeBin(t, helmchart.HelmPath(bd), "helm")
		writeZotPayload(t, payload, "zot")
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
		if _, release, err := ResolveReleaseVerifier(t.Context(), discardLogger()); err != nil || release {
			t.Fatalf("ResolveReleaseVerifier = %v, %v; want the dev path", release, err)
		}
		if err := registrysvc.EnsureZotWith(t.Context(), nil, bd, payload, ""); err != nil {
			t.Fatalf("EnsureZotWith: %v", err)
		}
		if n := zotSigns(); n == 0 {
			t.Error("the dev path did not sign an unsigned zot")
		}
	})
}

// TestSigningPolicyResolvedOncePerProcess pins the memo behind
// resolveSigningPolicy: every caller in the process (the boot steps, EnsureHelm,
// the registry's ResolveReleaseVerifier) sees the decision the first clean probe
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
		if _, release, err := ResolveReleaseVerifier(t.Context(), discardLogger()); err != nil || !release {
			t.Errorf("ResolveReleaseVerifier = %v, %v; want the memoised release path", release, err)
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
		if _, _, err := ResolveReleaseVerifier(t.Context(), discardLogger()); !errors.Is(err, ErrSelfSignatureUnreadable) {
			t.Errorf("ResolveReleaseVerifier err = %v, want ErrSelfSignatureUnreadable", err)
		}
		s.inspectErr = nil
		p, err := resolveSigningPolicy(t.Context(), discardLogger())
		if err != nil || !p.release {
			t.Errorf("after the error cleared = %+v, %v; want a fresh probe choosing release", p, err)
		}
	})
}

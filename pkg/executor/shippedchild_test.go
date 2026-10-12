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
	"os/exec"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"slices"
	"strings"
	"testing"
)

// fakeStampLine is the first line of a fake child binary: the (version, variant) the
// fake stamp reader reports for it, standing in for the stamp a real build carries in
// its bytes.
const fakeStampLine = "stamp:"

// writeChildBin writes a fake child binary at path: its stamp line, a body, then the
// fake signature trailer.
func writeChildBin(t *testing.T, path, version, variant, body, trailer string) string {
	t.Helper()
	content := fakeStampLine + version + " " + variant + "\n" + body + trailer
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	writeBin(t, path, content)
	return content
}

// childSeams installs fakes for every seam a child staging touches and returns
// counters: builds run, and lookPathGo calls. The fake stamp reader reads the
// stamp line writeChildBin wrote.
type childSeams struct {
	kineBuilds, etcdBuilds, goLookups int
}

func useChildSeams(t *testing.T) *childSeams {
	t.Helper()
	c := &childSeams{}
	origStamp, origLook, origCache, origKine, origEtcd := shippedStamp, lookPathGo, kineModuleCacheDir, runKineBuild, runEtcdBuild
	t.Cleanup(func() {
		shippedStamp, lookPathGo, kineModuleCacheDir, runKineBuild, runEtcdBuild = origStamp, origLook, origCache, origKine, origEtcd
	})
	shippedStamp = func(_ stagedChild, path string) (string, string, error) {
		b, err := os.ReadFile(path)
		if err != nil {
			return "", "", err
		}
		line, _, _ := strings.Cut(string(b), "\n")
		rest, ok := strings.CutPrefix(line, fakeStampLine)
		if !ok {
			return "", "", errors.New("no stamp in the bytes")
		}
		v, variant, _ := strings.Cut(rest, " ")
		return v, variant, nil
	}
	lookPathGo = func() (string, error) {
		c.goLookups++
		return "/fake/go", nil
	}
	cache := t.TempDir()
	kineModuleCacheDir = func(context.Context) (string, error) { return cache, nil }
	runKineBuild = func(_ context.Context, version, gopath, _ string) ([]byte, error) {
		c.kineBuilds++
		if err := os.MkdirAll(filepath.Join(gopath, "bin"), 0o755); err != nil {
			return nil, err
		}
		return nil, os.WriteFile(filepath.Join(gopath, "bin", kineBinaryName), []byte("built-kine"+fakeAdHoc), 0o755)
	}
	runEtcdBuild = func(cmd *exec.Cmd) ([]byte, error) {
		c.etcdBuilds++
		out := cmd.Args[slices.Index(cmd.Args, "-o")+1]
		return nil, os.WriteFile(out, []byte("built-"+filepath.Base(out)+fakeAdHoc), 0o755)
	}
	return c
}

// bootKine runs the kine half of a boot's provisioning, in the order the
// supervisor runs it: the payload seed, then ensureKine.
func bootKine(t *testing.T, work, payload string) error {
	t.Helper()
	if err := seedBinDir(t.Context(), discardLogger(), work, payload, DefaultKineVersion, DefaultKubeVersion, false); err != nil {
		return err
	}
	return ensureKine(t.Context(), discardLogger(), work, payload, DefaultKineVersion)
}

// bootEtcd is bootKine for the etcd posture.
func bootEtcd(t *testing.T, work, payload string) error {
	t.Helper()
	if err := seedBinDir(t.Context(), discardLogger(), work, payload, DefaultKineVersion, DefaultKubeVersion, true); err != nil {
		return err
	}
	return ensureEtcd(t.Context(), discardLogger(), work, payload)
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// TestShippedKinePreferredOnlyWhenStampMatches is the B475 gate. The executor runs
// the kine and etcd the payload ships, and builds on demand only on the dev path:
//
//   - dev path: a payload kine whose stamp (version and patch-set id) matches the pins
//     is used, and nothing is built; a version or patch-set mismatch builds on demand;
//     an earlier on-demand build in the work dir does not shadow a matching payload;
//   - release path (a Developer ID-signed daemon): the payload kine is verified in
//     place against the daemon's team, its stamp read from the verified bytes, and on
//     a match it is used byte-identical with no sign call; a stamp mismatch, a missing
//     binary, or an ad-hoc signature refuses the boot with a named error, and neither
//     a build nor lookPath("go") is ever reached; a work-dir on-demand kine is ignored
//     and replaced by the shipped bytes on a new inode;
//   - etcd and etcdutl follow the same rules (etcd's patch set is "none");
//   - the install contract ships all three (RequiredSiblings derives from
//     PayloadBinaries; pkg/install's anti-drift test names them too).
func TestShippedKinePreferredOnlyWhenStampMatches(t *testing.T) {
	const team = "ABCDE12345"
	devID := fakeDevIDPrefix + team
	kineV, kineVar := DefaultKineVersion, kineBuildVariant

	t.Run("install contract ships kine, etcd and etcdutl", func(t *testing.T) {
		for _, want := range []string{kineBinaryName, etcdBinaryName, etcdutlBinaryName} {
			if !slices.Contains(PayloadBinaries(), want) {
				t.Errorf("PayloadBinaries() = %v omits %s, so RequiredSiblings does not require it", PayloadBinaries(), want)
			}
		}
	})

	t.Run("dev", func(t *testing.T) {
		for _, tc := range []struct {
			name      string
			marker    string // the payload's kine marker; "" for none
			workKine  bool   // an earlier on-demand build vouched for in the work dir
			wantBuild bool
		}{
			{name: "stamp matches: the shipped kine is used", marker: kineMarkerContent(kineV)},
			{name: "version mismatch: built on demand", marker: "v0.16.0 " + kineVar + "\n", wantBuild: true},
			{name: "patch-set mismatch: built on demand", marker: kineV + " nocgo+p0\n", wantBuild: true},
			{name: "unmarked payload: built on demand", wantBuild: true},
			{name: "a work-dir on-demand kine does not shadow the shipped one", marker: kineMarkerContent(kineV), workKine: true},
		} {
			t.Run(tc.name, func(t *testing.T) {
				s := &fakeCodeSigner{}
				useFakeSigning(t, s, fakeAdHoc)
				seams := useChildSeams(t)
				payload, work := t.TempDir(), t.TempDir()
				if err := os.MkdirAll(binDir(work), 0o755); err != nil {
					t.Fatal(err)
				}
				shipped := writeChildBin(t, kinePath(payload), kineV, kineVar, "shipped-kine", fakeAdHoc)
				if tc.marker != "" {
					writeBin(t, kineMarkerPath(payload), tc.marker)
				}
				if tc.workKine {
					writeBin(t, kinePath(binDir(work)), "on-demand-kine"+fakeAdHoc)
					if err := writeKineMarker(binDir(work), kineV); err != nil {
						t.Fatal(err)
					}
				}
				if err := bootKine(t, work, payload); err != nil {
					t.Fatal(err)
				}
				got := readFile(t, kinePath(binDir(work)))
				if tc.wantBuild {
					if seams.kineBuilds != 1 || !strings.HasPrefix(got, "built-kine") {
						t.Errorf("builds = %d, work kine = %q: a mismatched payload must be rebuilt on demand", seams.kineBuilds, got)
					}
				} else {
					if seams.kineBuilds != 0 {
						t.Errorf("built kine %d times with a matching shipped kine", seams.kineBuilds)
					}
					// The dev heal may re-sign a copy once per stamp; the body is the payload's.
					if !strings.HasPrefix(got, strings.TrimSuffix(shipped, fakeAdHoc)) {
						t.Errorf("work kine = %q, want the shipped bytes", got)
					}
				}
				if !kineStaged(binDir(work), kineV) {
					t.Error("the work-dir marker does not vouch for the pins after the boot")
				}
			})
		}
	})

	t.Run("release", func(t *testing.T) {
		for _, tc := range []struct {
			name             string
			version, variant string
			trailer          string
			noBinary         bool
			noPayload        bool
			workKine         bool
			wantErr          error
		}{
			{name: "stamp matches and verifies: shipped byte-identical", version: kineV, variant: kineVar, trailer: devID},
			{name: "a work-dir on-demand kine does not shadow the shipped one", version: kineV, variant: kineVar, trailer: devID, workKine: true},
			{name: "version mismatch refuses", version: "v0.16.0", variant: kineVar, trailer: devID, wantErr: ErrPayloadStamp},
			{name: "patch-set mismatch refuses", version: kineV, variant: "nocgo+p0", trailer: devID, wantErr: ErrPayloadStamp},
			{name: "cgo build refuses", version: kineV, variant: "cgo+p1", trailer: devID, wantErr: ErrPayloadStamp},
			{name: "ad-hoc signature refuses", version: kineV, variant: kineVar, trailer: fakeAdHoc, wantErr: ErrPayloadSignature},
			{name: "another team refuses", version: kineV, variant: kineVar, trailer: fakeDevIDPrefix + "ZZZZZ99999", wantErr: ErrPayloadSignature},
			{name: "missing binary refuses", noBinary: true, wantErr: ErrPayloadSignature},
			{name: "no payload refuses", noPayload: true, workKine: true, wantErr: ErrPayloadSignature},
		} {
			t.Run(tc.name, func(t *testing.T) {
				s := &fakeCodeSigner{}
				useFakeSigning(t, s, devID)
				seams := useChildSeams(t)
				payload, work := t.TempDir(), t.TempDir()
				if err := os.MkdirAll(binDir(work), 0o755); err != nil {
					t.Fatal(err)
				}
				var shipped string
				if !tc.noBinary {
					shipped = writeChildBin(t, kinePath(payload), tc.version, tc.variant, "shipped-kine", tc.trailer)
					writeBin(t, kineMarkerPath(payload), kineMarkerContent(kineV)) // a marker never vouches on this path
				}
				if tc.workKine {
					writeChildBin(t, kinePath(binDir(work)), kineV, kineVar, "on-demand-kine", fakeAdHoc)
					if err := writeKineMarker(binDir(work), kineV); err != nil {
						t.Fatal(err)
					}
				}
				var before fileID
				if tc.workKine {
					before = idOf(t, kinePath(binDir(work)))
				}
				payloadArg := payload
				if tc.noPayload {
					payloadArg = ""
				}
				err := bootKine(t, work, payloadArg)
				if seams.goLookups != 0 || seams.kineBuilds != 0 {
					t.Errorf("lookPath(go) called %d times, kine built %d times on the release path", seams.goLookups, seams.kineBuilds)
				}
				if len(s.signed) != 0 {
					t.Errorf("signed %v on the release path", s.signed)
				}
				if tc.wantErr != nil {
					if !errors.Is(err, tc.wantErr) {
						t.Fatalf("err = %v, want %v", err, tc.wantErr)
					}
					if !strings.Contains(err.Error(), kineBinaryName) {
						t.Errorf("the refusal %q does not name kine", err)
					}
					if tc.workKine {
						if after := idOf(t, kinePath(binDir(work))); after != before {
							t.Error("a refused boot replaced the work-dir kine")
						}
					} else if _, statErr := os.Stat(kinePath(binDir(work))); statErr == nil {
						t.Error("a refused shipped kine took its name in the work dir")
					}
					return
				}
				if err != nil {
					t.Fatal(err)
				}
				if got := readFile(t, kinePath(binDir(work))); got != shipped {
					t.Fatalf("work kine = %q, want the shipped bytes unchanged %q", got, shipped)
				}
				if got := readFile(t, kinePath(payload)); got != shipped {
					t.Errorf("the payload kine changed: %q", got)
				}
				if tc.workKine && idOf(t, kinePath(binDir(work))).ino == before.ino {
					t.Error("the on-demand kine was overwritten in place, not replaced on a new inode")
				}
				if !kineStaged(binDir(work), kineV) {
					t.Error("the work-dir marker does not vouch for the pins")
				}
				// A second boot verifies the identical copy in place and leaves it alone.
				id := idOf(t, kinePath(binDir(work)))
				if err := bootKine(t, work, payload); err != nil {
					t.Fatal(err)
				}
				if idOf(t, kinePath(binDir(work))) != id {
					t.Error("the second boot replaced an identical verified kine")
				}
				if len(s.signed) != 0 || seams.goLookups != 0 {
					t.Errorf("second boot signed %v / looked up go %d times", s.signed, seams.goLookups)
				}
			})
		}
	})

	t.Run("etcd", func(t *testing.T) {
		etcdV, etcdVar := DefaultEtcdVersion, etcdBuildVariant
		c := etcdChild(etcdV)
		for _, tc := range []struct {
			name             string
			self             string
			version, variant string
			trailer          string
			marker           string
			wantBuild        bool
			wantErr          error
		}{
			{name: "dev: stamp matches, shipped", self: fakeAdHoc, version: etcdV, variant: etcdVar, trailer: fakeAdHoc, marker: etcdV + " nocgo\n"},
			{name: "dev: version mismatch, built", self: fakeAdHoc, version: etcdV, variant: etcdVar, trailer: fakeAdHoc, marker: "v3.5.0 nocgo\n", wantBuild: true},
			{name: "dev: a patch set etcd does not carry, built", self: fakeAdHoc, version: etcdV, variant: etcdVar, trailer: fakeAdHoc, marker: etcdV + " nocgo+p1\n", wantBuild: true},
			{name: "release: match, shipped byte-identical", self: devID, version: etcdV, variant: etcdVar, trailer: devID},
			{name: "release: version mismatch refuses", self: devID, version: "v3.5.0", variant: etcdVar, trailer: devID, wantErr: ErrPayloadStamp},
			{name: "release: patch set refuses", self: devID, version: etcdV, variant: "nocgo+p1", trailer: devID, wantErr: ErrPayloadStamp},
			{name: "release: ad hoc refuses", self: devID, version: etcdV, variant: etcdVar, trailer: fakeAdHoc, wantErr: ErrPayloadSignature},
		} {
			t.Run(tc.name, func(t *testing.T) {
				s := &fakeCodeSigner{}
				useFakeSigning(t, s, tc.self)
				seams := useChildSeams(t)
				payload, work := t.TempDir(), t.TempDir()
				if err := os.MkdirAll(binDir(work), 0o755); err != nil {
					t.Fatal(err)
				}
				shipped := writeChildBin(t, c.binPath(payload), tc.version, tc.variant, "shipped-etcd", tc.trailer)
				if tc.marker != "" {
					writeBin(t, c.markerPath(payload), tc.marker)
				}
				// An earlier on-demand build in the work dir never shadows a payload that
				// qualifies (with a mismatched payload it would be kept, so no build would
				// be needed; those cases start from an empty work dir).
				if !tc.wantBuild {
					writeBin(t, c.binPath(binDir(work)), "on-demand-etcd"+fakeAdHoc)
					if err := c.writeMarker(binDir(work)); err != nil {
						t.Fatal(err)
					}
				}
				release := tc.self == devID
				err := bootEtcd(t, work, payload)
				if release && (seams.goLookups != 0 || seams.etcdBuilds != 0 || len(s.signed) != 0) {
					t.Errorf("release path: lookPath(go) %d, builds %d, signed %v", seams.goLookups, seams.etcdBuilds, s.signed)
				}
				if tc.wantErr != nil {
					if !errors.Is(err, tc.wantErr) {
						t.Fatalf("err = %v, want %v", err, tc.wantErr)
					}
					if got := readFile(t, c.binPath(binDir(work))); got != "on-demand-etcd"+fakeAdHoc {
						t.Errorf("a refused boot replaced the work-dir etcd with %q", got)
					}
					return
				}
				if err != nil {
					t.Fatal(err)
				}
				got := readFile(t, c.binPath(binDir(work)))
				switch {
				case tc.wantBuild:
					if seams.etcdBuilds != 1 || !strings.HasPrefix(got, "built-etcd") {
						t.Errorf("builds = %d, work etcd = %q, want an on-demand build", seams.etcdBuilds, got)
					}
				case release:
					if got != shipped {
						t.Errorf("work etcd = %q, want the shipped bytes unchanged", got)
					}
				default:
					if seams.etcdBuilds != 0 || !strings.HasPrefix(got, strings.TrimSuffix(shipped, fakeAdHoc)) {
						t.Errorf("builds = %d, work etcd = %q, want the shipped bytes", seams.etcdBuilds, got)
					}
				}
				if !etcdChild(etcdV).staged(binDir(work)) {
					t.Error("the work-dir etcd marker does not vouch for the pin")
				}
			})
		}
	})

	t.Run("etcdutl", func(t *testing.T) {
		etcdV := DefaultEtcdVersion
		c := etcdutlChild(etcdV)
		for _, tc := range []struct {
			name             string
			self             string
			version, variant string
			trailer          string
			noBinary         bool
			wantPayload      bool
			wantErr          error
		}{
			{name: "dev: a vouching payload etcdutl is used", self: fakeAdHoc, version: etcdV, variant: etcdBuildVariant, trailer: fakeAdHoc, wantPayload: true},
			{name: "release: match, run in place from the payload", self: devID, version: etcdV, variant: etcdBuildVariant, trailer: devID, wantPayload: true},
			{name: "release: version mismatch refuses", self: devID, version: "v3.5.0", variant: etcdBuildVariant, trailer: devID, wantErr: ErrPayloadStamp},
			{name: "release: ad hoc refuses", self: devID, version: etcdV, variant: etcdBuildVariant, trailer: fakeAdHoc, wantErr: ErrPayloadSignature},
			{name: "release: missing refuses, the work dir's is ignored", self: devID, noBinary: true, wantErr: ErrPayloadSignature},
		} {
			t.Run(tc.name, func(t *testing.T) {
				s := &fakeCodeSigner{}
				useFakeSigning(t, s, tc.self)
				seams := useChildSeams(t)
				payload, work := t.TempDir(), t.TempDir()
				if err := os.MkdirAll(binDir(work), 0o755); err != nil {
					t.Fatal(err)
				}
				if !tc.noBinary {
					writeChildBin(t, c.binPath(payload), tc.version, tc.variant, "shipped-etcdutl", tc.trailer)
					if err := c.writeMarker(payload); err != nil {
						t.Fatal(err)
					}
				}
				writeChildBin(t, c.binPath(binDir(work)), etcdV, etcdBuildVariant, "on-demand-etcdutl", fakeAdHoc)
				if err := c.writeMarker(binDir(work)); err != nil {
					t.Fatal(err)
				}
				got, err := resolveEtcdutl(t.Context(), work, payload)
				if tc.self == devID && (seams.goLookups != 0 || seams.etcdBuilds != 0 || len(s.signed) != 0) {
					t.Errorf("release path: lookPath(go) %d, builds %d, signed %v", seams.goLookups, seams.etcdBuilds, s.signed)
				}
				if tc.wantErr != nil {
					if !errors.Is(err, tc.wantErr) {
						t.Fatalf("resolveEtcdutl = %q, %v; want %v", got, err, tc.wantErr)
					}
					return
				}
				if err != nil {
					t.Fatal(err)
				}
				if tc.wantPayload && got != c.binPath(payload) {
					t.Errorf("resolveEtcdutl = %q, want the payload's %q", got, c.binPath(payload))
				}
			})
		}
	})
}

// TestShippedStampReaders proves the production stamp readers: kine's from its build
// info and the version stamped into its version package, etcd's and etcdutl's from
// the module versions their build info records (build info text as the real staged
// binaries carry it), and machoStringVar over a real -X stamped stand-in build.
func TestShippedStampReaders(t *testing.T) {
	parse := func(t *testing.T, text string) *debug.BuildInfo {
		t.Helper()
		bi, err := debug.ParseBuildInfo(text)
		if err != nil {
			t.Fatal(err)
		}
		return bi
	}
	const kineInfo = "go\tgo1.27.2\npath\tgithub.com/k3s-io/kine\nmod\tgithub.com/k3s-io/kine\t(devel)\t\nbuild\t-trimpath=true\nbuild\tCGO_ENABLED=0\nbuild\tGOOS=darwin\n"
	const etcdInfo = "go\tgo1.27.2\npath\tk3sm.io/etcd-child\nmod\tk3sm.io/etcd-child\t(devel)\t\n" +
		"dep\tgo.etcd.io/etcd/server/v3\tv3.6.15\th1:x=\nbuild\tCGO_ENABLED=0\n"
	const etcdutlInfo = "go\tgo1.27.2\npath\tgo.etcd.io/etcd/etcdutl/v3\nmod\tgo.etcd.io/etcd/etcdutl/v3\tv3.6.15\th1:y=\n" +
		"dep\tgo.etcd.io/etcd/server/v3\tv3.6.15\th1:x=\nbuild\tCGO_ENABLED=0\n"

	t.Run("kine", func(t *testing.T) {
		v, variant, err := kineStampOf(parse(t, kineInfo), kineStampedVersion(DefaultKineVersion))
		if err != nil || v != DefaultKineVersion || variant != kineBuildVariant {
			t.Errorf("kineStampOf = %q %q %v, want %q %q (the marker's pair)", v, variant, err, DefaultKineVersion, kineBuildVariant)
		}
		if _, variant, _ := kineStampOf(parse(t, strings.Replace(kineInfo, "CGO_ENABLED=0", "CGO_ENABLED=1", 1)), "v0.17.2+p1"); variant != "cgo+p1" {
			t.Errorf("a cgo build reads as %q", variant)
		}
		for name, tc := range map[string]struct{ info, stamped string }{
			"no stamp":        {kineInfo, ""},
			"another program": {strings.Replace(kineInfo, "path\tgithub.com/k3s-io/kine", "path\texample.com/kine", 1), "v0.17.2+p1"},
			"no CGO_ENABLED":  {strings.Replace(kineInfo, "build\tCGO_ENABLED=0\n", "", 1), "v0.17.2+p1"},
			"odd CGO_ENABLED": {strings.Replace(kineInfo, "CGO_ENABLED=0", "CGO_ENABLED=x", 1), "v0.17.2+p1"},
		} {
			if v, variant, err := kineStampOf(parse(t, tc.info), tc.stamped); err == nil {
				t.Errorf("%s: kineStampOf = %q %q, want an error", name, v, variant)
			}
		}
	})

	t.Run("etcd and etcdutl", func(t *testing.T) {
		if v, variant, err := etcdStampOf(parse(t, etcdInfo), etcdWrapperModule, etcdServerModule); err != nil || v != DefaultEtcdVersion || variant != etcdBuildVariant {
			t.Errorf("etcd stamp = %q %q %v", v, variant, err)
		}
		if v, variant, err := etcdStampOf(parse(t, etcdutlInfo), etcdutlPackage, etcdutlPackage); err != nil || v != DefaultEtcdVersion || variant != etcdBuildVariant {
			t.Errorf("etcdutl stamp = %q %q %v", v, variant, err)
		}
		// etcdutl depends on the server module too, so the main-package check is
		// what keeps it from passing for etcd.
		if _, _, err := etcdStampOf(parse(t, etcdutlInfo), etcdWrapperModule, etcdServerModule); err == nil {
			t.Error("etcdutl passed as the etcd server")
		}
		replaced := strings.Replace(etcdInfo, "h1:x=\n", "h1:x=\n=>\texample.com/fork\tv0.0.1\th1:z=\n", 1)
		if _, _, err := etcdStampOf(parse(t, replaced), etcdWrapperModule, etcdServerModule); err == nil {
			t.Error("a replaced etcd server module was accepted")
		}
		missing := strings.Replace(etcdInfo, "dep\tgo.etcd.io/etcd/server/v3\tv3.6.15\th1:x=\n", "", 1)
		if _, _, err := etcdStampOf(parse(t, missing), etcdWrapperModule, etcdServerModule); err == nil {
			t.Error("build info without the etcd server module was accepted")
		}
	})

	t.Run("a real -X stamped build reads back through kineStampFromBinary", func(t *testing.T) {
		// A stand-in kine: a module named like kine whose version package is stamped
		// with -X exactly as buildPatchedKine stamps it, built CGO_ENABLED=0 and
		// -trimpath (which keeps -ldflags out of the build info, so the stamp can
		// only be read from the linked variable). Stdlib only: nothing is fetched.
		if runtime.GOOS != "darwin" {
			t.Skip("Mach-O only")
		}
		goBin, err := exec.LookPath("go")
		if err != nil {
			t.Skip("no Go toolchain on PATH to build the stand-in")
		}
		src, bin := t.TempDir(), filepath.Join(t.TempDir(), "kine")
		for name, data := range map[string]string{
			"go.mod":                 "module " + kineModulePath + "\n\ngo 1.26\n",
			"main.go":                "package main\n\nimport \"" + kineModulePath + "/pkg/version\"\n\nfunc main() { println(version.Version) }\n",
			"pkg/version/version.go": "package version\n\nvar Version = \"dev\"\n",
		} {
			if err := os.MkdirAll(filepath.Dir(filepath.Join(src, name)), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(src, name), []byte(data), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		cmd := exec.CommandContext(t.Context(), goBin, kineBuildArgs(DefaultKineVersion, bin)...)
		cmd.Dir = src
		cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOWORK=off", "GOTOOLCHAIN=local", "GOOS=darwin", "GOARCH=arm64")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("build the stand-in kine: %v\n%s", err, out)
		}
		v, variant, err := kineStampFromBinary(bin)
		if err != nil || v != DefaultKineVersion || variant != kineBuildVariant {
			t.Errorf("kineStampFromBinary = %q %q %v, want %q %q", v, variant, err, DefaultKineVersion, kineBuildVariant)
		}
		if got, err := machoStringVar(bin, kineModulePath+"/pkg/version.Version"); err != nil || got != kineStampedVersion(DefaultKineVersion) {
			t.Errorf("machoStringVar = %q, %v", got, err)
		}
		if _, err := machoStringVar(bin, "main.noSuchSymbol"); err == nil {
			t.Error("an absent symbol read as a stamp")
		}
		notMachO := filepath.Join(t.TempDir(), "kine")
		writeBin(t, notMachO, "not a Mach-O")
		if _, _, err := kineStampFromBinary(notMachO); err == nil {
			t.Error("a non-Mach-O file read as a stamp")
		}
	})
}

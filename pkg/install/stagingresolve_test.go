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

package install

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// linkSigner is a fakeSigner that follows the fixture's links before it looks a
// path up, as codesign does, and records the path it was asked about.
type linkSigner struct {
	fakeSigner
	sfs *fakeStagingFS
}

func (s linkSigner) TeamID(ctx context.Context, path string) (string, error) {
	s.sfs.calls = append(s.sfs.calls, "TeamID:"+path)
	if target, ok := s.sfs.links[path]; ok {
		path = target
	}
	return s.fakeSigner.TeamID(ctx, path)
}

func (s linkSigner) DeveloperID(ctx context.Context, path, team string) (bool, error) {
	s.sfs.calls = append(s.sfs.calls, "DeveloperID:"+path)
	if target, ok := s.sfs.links[path]; ok {
		path = target
	}
	return s.fakeSigner.DeveloperID(ctx, path, team)
}

// TestStagingChecksResolveTheInstallOnce is the gate for resolving the installed
// k3sm once in the --from-staging checks: the signing continuity check and the
// downgrade check read the one file the installed entry point resolved to, so
// the signature and the version they compare belong to the same binary. In the
// versioned layout the entry point is a compatibility link, and neither check
// may follow it again on its own.
func TestStagingChecksResolveTheInstallOnce(t *testing.T) {
	t.Parallel()
	flat := Config{}.withDefaults().installedBinary()
	versioned := filepath.Join(filepath.Dir(flat), "versions", "v0.3.9", "k3sm")
	cases := []struct {
		name    string
		link    bool   // the entry point is a link to versioned
		version string // what the installed file reports
		devMode bool
		resolve error // ResolveInstalled refuses the entry point
		want    error // nil = accepted
		wantMsg string
	}{
		{name: "a versioned install", link: true, version: "v0.3.9"},
		{name: "a versioned install in developer mode", link: true, version: "v0.3.9", devMode: true},
		{name: "a flat install", version: "v0.3.9"},
		{name: "a downgrade read through the link is refused", link: true, version: "v0.5.0", want: ErrDowngrade},
		{name: "an entry point that resolves outside the tree is refused", link: true, version: "v0.3.9",
			resolve: errors.New("the installed k3sm resolves outside its install tree"), wantMsg: "outside its install tree"},
		{name: "an entry point that resolves outside the tree is refused in developer mode", link: true, version: "v0.3.9",
			devMode: true, resolve: errors.New("the installed k3sm resolves outside its install tree"), wantMsg: "outside its install tree"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			sfs, cfg := stagedFixture()
			file := flat
			if tc.link {
				file = versioned
				sfs.links = map[string]string{flat: versioned}
			}
			if tc.resolve != nil {
				sfs.resolveErr = map[string]error{flat: tc.resolve}
			}
			sfs.versions[file] = tc.version
			cfg.Signer = linkSigner{fakeSigner: fakeSigner{ids: signedTree(map[string]string{file: testTeamID})}, sfs: sfs}
			if tc.devMode {
				cfg.DeveloperMode = DeveloperModeOn
			}
			sfs.calls = nil
			err := preflightFromStaging(context.Background(), &cfg)
			switch {
			case tc.want != nil:
				if !errors.Is(err, tc.want) {
					t.Fatalf("preflightFromStaging = %v, want %v", err, tc.want)
				}
			case tc.wantMsg != "":
				if err == nil || !strings.Contains(err.Error(), tc.wantMsg) {
					t.Fatalf("preflightFromStaging = %v, want a refusal naming %q", err, tc.wantMsg)
				}
			default:
				if err != nil {
					t.Fatalf("preflightFromStaging = %v, want accepted", err)
				}
			}
			var resolves int
			var reads []string
			for _, c := range sfs.calls {
				op, path, _ := strings.Cut(c, ":")
				if op == "ResolveInstalled" {
					resolves++
					if path != flat {
						t.Errorf("ResolveInstalled(%s), want the entry point %s", path, flat)
					}
					continue
				}
				if path == flat || path == versioned {
					reads = append(reads, c)
				}
			}
			if resolves != 1 {
				t.Fatalf("the installed k3sm was resolved %d times, want once (calls %v)", resolves, sfs.calls)
			}
			if tc.resolve != nil {
				if len(reads) != 0 {
					t.Fatalf("a refused entry point was still read: %v", reads)
				}
				return
			}
			var sawVersion, sawTeam bool
			for _, c := range reads {
				op, path, _ := strings.Cut(c, ":")
				if path != file {
					t.Errorf("%s read %s, want only the resolved %s", op, path, file)
				}
				sawVersion = sawVersion || op == "BinaryVersion"
				sawTeam = sawTeam || op == "TeamID"
			}
			if !sawVersion {
				t.Errorf("the downgrade check never read the installed version (reads %v)", reads)
			}
			if !tc.devMode && !sawTeam {
				t.Errorf("the signing continuity check never read the installed signature (reads %v)", reads)
			}
		})
	}
}

// TestResolveInstalledBinary pins the one resolution the staging checks read
// the installed k3sm through, over a real tree: the flat file and a missing one
// are themselves, the compatibility link and the link through current lead into
// a version directory, and every other link fails closed, never as "no install".
func TestResolveInstalledBinary(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name  string
		setup func(t *testing.T, root string)
		want  string // relative to root; "" = refused
	}{
		{name: "a flat install is the file itself", want: "k3sm",
			setup: func(t *testing.T, root string) { putInstalledFile(t, filepath.Join(root, "k3sm")) }},
		{name: "no install is the entry point itself", want: "k3sm", setup: func(*testing.T, string) {}},
		{name: "the compatibility link through current", want: "versions/v0.3.9/k3sm",
			setup: func(t *testing.T, root string) {
				putInstalledFile(t, filepath.Join(root, "versions", "v0.3.9", "k3sm"))
				putInstalledLink(t, "versions/v0.3.9", filepath.Join(root, "current"))
				putInstalledLink(t, "current/k3sm", filepath.Join(root, "k3sm"))
			}},
		{name: "a link straight into a version directory", want: "versions/v0.3.9/k3sm",
			setup: func(t *testing.T, root string) {
				putInstalledFile(t, filepath.Join(root, "versions", "v0.3.9", "k3sm"))
				putInstalledLink(t, "versions/v0.3.9/k3sm", filepath.Join(root, "k3sm"))
			}},
		{name: "a dangling link",
			setup: func(t *testing.T, root string) { putInstalledLink(t, "current/k3sm", filepath.Join(root, "k3sm")) }},
		{name: "a link out of the install tree",
			setup: func(t *testing.T, root string) {
				out := filepath.Join(t.TempDir(), "k3sm")
				putInstalledFile(t, out)
				putInstalledLink(t, out, filepath.Join(root, "k3sm"))
			}},
		{name: "a link to another name in a version directory",
			setup: func(t *testing.T, root string) {
				putInstalledFile(t, filepath.Join(root, "versions", "v0.3.9", "k3sm-netd"))
				putInstalledLink(t, "versions/v0.3.9/k3sm-netd", filepath.Join(root, "k3sm"))
			}},
		{name: "a link into a directory that is not a version",
			setup: func(t *testing.T, root string) {
				putInstalledFile(t, filepath.Join(root, "versions", ".tmp-v0.3.9", "k3sm"))
				putInstalledLink(t, "versions/.tmp-v0.3.9/k3sm", filepath.Join(root, "k3sm"))
			}},
		{name: "a version directory that is a link out of the tree",
			setup: func(t *testing.T, root string) {
				out := t.TempDir()
				putInstalledFile(t, filepath.Join(out, "k3sm"))
				if err := os.MkdirAll(filepath.Join(root, "versions"), 0o755); err != nil {
					t.Fatal(err)
				}
				putInstalledLink(t, out, filepath.Join(root, "versions", "v0.3.9"))
				putInstalledLink(t, "versions/v0.3.9", filepath.Join(root, "current"))
				putInstalledLink(t, "current/k3sm", filepath.Join(root, "k3sm"))
			}},
		{name: "a version directory that is a link to another version resolves to that one", want: "versions/v0.4.0/k3sm",
			setup: func(t *testing.T, root string) {
				putInstalledFile(t, filepath.Join(root, "versions", "v0.4.0", "k3sm"))
				putInstalledLink(t, "v0.4.0", filepath.Join(root, "versions", "v0.3.9"))
				putInstalledLink(t, "versions/v0.3.9", filepath.Join(root, "current"))
				putInstalledLink(t, "current/k3sm", filepath.Join(root, "k3sm"))
			}},
		{name: "a link to a directory",
			setup: func(t *testing.T, root string) {
				if err := os.MkdirAll(filepath.Join(root, "versions", "v0.3.9", "k3sm"), 0o755); err != nil {
					t.Fatal(err)
				}
				putInstalledLink(t, "versions/v0.3.9/k3sm", filepath.Join(root, "k3sm"))
			}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			root, err := filepath.EvalSymlinks(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			tc.setup(t, root)
			entry := filepath.Join(root, "k3sm")
			got, err := resolveInstalledBinary(entry, os.Lstat, filepath.EvalSymlinks)
			if tc.want == "" {
				if !errors.Is(err, errInstalledUnresolvable) || errors.Is(err, fs.ErrNotExist) {
					t.Fatalf("resolveInstalledBinary = %q, %v; want errInstalledUnresolvable and not fs.ErrNotExist", got, err)
				}
				return
			}
			if err != nil || got != filepath.Join(root, tc.want) {
				t.Fatalf("resolveInstalledBinary = %q, %v; want %s", got, err, filepath.Join(root, tc.want))
			}
		})
	}
}

// TestResolveInstalledBinaryUnderALinkedRoot pins the resolution when the
// install root itself (the directory holding the entry point) is a symlink. A
// link entry point resolves into the real root's version directory, every
// component evaluated. A flat file is not a link and is returned as named,
// the root link still in it.
func TestResolveInstalledBinaryUnderALinkedRoot(t *testing.T) {
	t.Parallel()
	linkedRoot := func(t *testing.T) (real, linked string) {
		t.Helper()
		base, err := filepath.EvalSymlinks(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		real, linked = filepath.Join(base, "real"), filepath.Join(base, "k3sm-root")
		if err := os.Mkdir(real, 0o755); err != nil {
			t.Fatal(err)
		}
		putInstalledLink(t, real, linked)
		return real, linked
	}
	t.Run("a versioned install resolves into the real root", func(t *testing.T) {
		t.Parallel()
		real, linked := linkedRoot(t)
		putInstalledFile(t, filepath.Join(real, "versions", "v0.3.9", "k3sm"))
		putInstalledLink(t, "versions/v0.3.9", filepath.Join(real, "current"))
		putInstalledLink(t, "current/k3sm", filepath.Join(real, "k3sm"))
		got, err := resolveInstalledBinary(filepath.Join(linked, "k3sm"), os.Lstat, filepath.EvalSymlinks)
		if want := filepath.Join(real, "versions", "v0.3.9", "k3sm"); err != nil || got != want {
			t.Fatalf("resolveInstalledBinary = %q, %v; want %s", got, err, want)
		}
	})
	t.Run("a flat install is returned as named", func(t *testing.T) {
		t.Parallel()
		real, linked := linkedRoot(t)
		putInstalledFile(t, filepath.Join(real, "k3sm"))
		entry := filepath.Join(linked, "k3sm")
		got, err := resolveInstalledBinary(entry, os.Lstat, filepath.EvalSymlinks)
		if err != nil || got != entry {
			t.Fatalf("resolveInstalledBinary = %q, %v; want %s", got, err, entry)
		}
	})
}

// TestDeveloperModeOffJudgesTheResolvedInstall pins that the decision to turn
// developer mode off reads the installed k3sm preflightFromStaging resolved,
// never the entry point again, and that a developer-mode install (a marker,
// no flag) whose entry point resolves outside the tree is refused.
func TestDeveloperModeOffJudgesTheResolvedInstall(t *testing.T) {
	t.Parallel()
	flat := Config{}.withDefaults().installedBinary()
	versioned := filepath.Join(filepath.Dir(flat), "versions", "v0.3.9", "k3sm")
	setup := func(t *testing.T) (*fakeStagingFS, Config) {
		t.Helper()
		sfs, cfg := stagedFixture()
		sfs.links = map[string]string{flat: versioned}
		sfs.versions[versioned] = "v0.3.9"
		cfg.Signer = linkSigner{fakeSigner: fakeSigner{ids: signedTree(map[string]string{versioned: testTeamID})}, sfs: sfs}
		f := &fakeSystem{owners: map[string]OwnedEntry{}}
		f.owners[DeveloperModeMarkerPath] = OwnedEntry{Path: DeveloperModeMarkerPath, Kind: EntryRegular, Mode: 0o644}
		f.putFile(DeveloperModeMarkerPath, []byte("developer mode enabled by k3sm install on 2026-10-31T00:00:00Z\n"))
		if err := resolveDeveloperMode(f, &cfg); err != nil {
			t.Fatal(err)
		}
		sfs.calls = nil
		return sfs, cfg
	}
	t.Run("the resolved binary decides", func(t *testing.T) {
		t.Parallel()
		sfs, cfg := setup(t)
		if err := preflightFromStaging(context.Background(), &cfg); err != nil {
			t.Fatalf("preflightFromStaging = %v, want accepted", err)
		}
		if cfg.offTeam != testTeamID {
			t.Fatalf("offTeam = %q (keep: %q), want %s", cfg.offTeam, cfg.keepReason, testTeamID)
		}
		var sawResolved bool
		for _, c := range sfs.calls {
			op, path, _ := strings.Cut(c, ":")
			if op == "ResolveInstalled" {
				continue
			}
			if path == flat {
				t.Errorf("%s read the entry point %s again", op, flat)
			}
			sawResolved = sawResolved || (op == "TeamID" && path == versioned)
		}
		if !sawResolved {
			t.Errorf("the installed signature was never read from %s (calls %v)", versioned, sfs.calls)
		}
	})
	t.Run("an entry point outside the tree is refused", func(t *testing.T) {
		t.Parallel()
		sfs, cfg := setup(t)
		sfs.resolveErr = map[string]error{flat: errInstalledUnresolvable}
		if err := preflightFromStaging(context.Background(), &cfg); !errors.Is(err, errInstalledUnresolvable) {
			t.Fatalf("preflightFromStaging = %v, want %v", err, errInstalledUnresolvable)
		}
		for _, c := range sfs.calls {
			if _, path, _ := strings.Cut(c, ":"); path == flat || path == versioned {
				if !strings.HasPrefix(c, "ResolveInstalled:") {
					t.Errorf("a refused entry point was still read: %s", c)
				}
			}
		}
	})
}

func putInstalledFile(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("k3sm"), 0o755); err != nil {
		t.Fatal(err)
	}
}

func putInstalledLink(t *testing.T, target, link string) {
	t.Helper()
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
}

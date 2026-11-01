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
	"fmt"
	"io/fs"
	"log/slog"
	"path/filepath"
	"runtime/debug"
	"slices"
	"sort"
	"strings"
	"testing"
)

// fakeStagingFS is a StagingFS over an in-memory table of lstat facts, file
// contents and binary versions. It records every call.
type fakeStagingFS struct {
	entries  map[string]StagedEntry
	content  map[string][]byte
	versions map[string]string
	verErr   map[string]error
	macho    map[string]bool
	// links maps an installed entry point that is a symlink to the file it
	// resolves to, and resolveErr to a refusal; ResolveInstalled answers from
	// them, any other path resolving to itself. BinaryVersion refuses a path in
	// links, as the real O_NOFOLLOW open does.
	links      map[string]string
	resolveErr map[string]error
	calls      []string
}

func (f *fakeStagingFS) put(path string, uid, gid uint32, mode fs.FileMode) {
	if f.entries == nil {
		f.entries = map[string]StagedEntry{}
	}
	f.entries[path] = StagedEntry{Path: path, Mode: mode, UID: uid, GID: gid, Dev: 1, Nlink: 1}
}

func (f *fakeStagingFS) Lstat(path string) (StagedEntry, error) {
	f.calls = append(f.calls, "Lstat:"+path)
	if e, ok := f.entries[path]; ok {
		return e, nil
	}
	return StagedEntry{}, fmt.Errorf("lstat %s: %w", path, fs.ErrNotExist)
}

// WalkNoFollow lists every entry under dir, but never under an entry that is
// a symlink, which is what the real walk does.
func (f *fakeStagingFS) WalkNoFollow(dir string) ([]StagedEntry, error) {
	f.calls = append(f.calls, "WalkNoFollow:"+dir)
	var paths []string
	for p := range f.entries {
		if strings.HasPrefix(p, dir+"/") {
			paths = append(paths, p)
		}
	}
	sort.Strings(paths)
	var out []StagedEntry
	for _, p := range paths {
		viaLink := false
		for q := filepath.Dir(p); q != dir && q != "/"; q = filepath.Dir(q) {
			if f.entries[q].Mode&fs.ModeSymlink != 0 {
				viaLink = true
			}
		}
		if !viaLink {
			out = append(out, f.entries[p])
		}
	}
	return out, nil
}

func (f *fakeStagingFS) ReadTokenFile(path string) ([]byte, StagedEntry, error) {
	f.calls = append(f.calls, "ReadTokenFile:"+path)
	e, ok := f.entries[path]
	if !ok {
		return nil, StagedEntry{}, fmt.Errorf("open %s: %w", path, fs.ErrNotExist)
	}
	if !e.Mode.IsRegular() {
		return nil, e, fmt.Errorf("open %s: %w", path, ErrNotRegularFile)
	}
	return f.content[path], e, nil
}

func (f *fakeStagingFS) RemoveFile(path string) error {
	f.calls = append(f.calls, "RemoveFile:"+path)
	delete(f.entries, path)
	delete(f.content, path)
	return nil
}

func (f *fakeStagingFS) BinaryVersion(path string) (string, error) {
	f.calls = append(f.calls, "BinaryVersion:"+path)
	if _, ok := f.links[path]; ok {
		return "", fmt.Errorf("%s is a symbolic link; refusing to run it", path)
	}
	if err := f.verErr[path]; err != nil {
		return "", err
	}
	if v, ok := f.versions[path]; ok {
		return v, nil
	}
	return "", fmt.Errorf("open %s: %w", path, fs.ErrNotExist)
}

func (f *fakeStagingFS) ResolveInstalled(path string) (string, error) {
	f.calls = append(f.calls, "ResolveInstalled:"+path)
	if err := f.resolveErr[path]; err != nil {
		return "", err
	}
	if target, ok := f.links[path]; ok {
		return target, nil
	}
	return path, nil
}

func (f *fakeStagingFS) MachO(path string) (bool, error) {
	f.calls = append(f.calls, "MachO:"+path)
	return f.macho[path], nil
}

// fakeSigner answers TeamID from a table (a path with no entry is absent) and
// DeveloperID true unless the path is in notDevID.
type fakeSigner struct {
	ids      map[string]string
	errs     map[string]error
	notDevID map[string]bool
	rec      *fakeStagingFS // when set, TeamID calls are logged in rec.calls
}

func (s fakeSigner) DeveloperID(_ context.Context, path, _ string) (bool, error) {
	return !s.notDevID[path], nil
}

func (s fakeSigner) TeamID(_ context.Context, path string) (string, error) {
	if s.rec != nil {
		s.rec.calls = append(s.rec.calls, "TeamID:"+path)
	}
	if err := s.errs[path]; err != nil {
		return "", err
	}
	if id, ok := s.ids[path]; ok {
		return id, nil
	}
	return "", fmt.Errorf("lstat %s: %w", path, fs.ErrNotExist)
}

const (
	testStagingRoot = DefaultStagingRoot
	testStagedDir   = testStagingRoot + "/0.4.0.AbCdEfGh"
	testStagedApp   = testStagedDir + "/k3sm.app"
	testPayloadDir  = testStagedApp + "/Contents/Resources/payload"
	testStagedExe   = testPayloadDir + "/k3sm"
	testTeamID      = "ABCDE12345"
	testTokenPath   = testStagedDir + "/join-token"
	// testTokenText carries a marker no error may ever echo.
	testTokenText = "K10" + "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" + "::node:SECRETMARKER"
)

// stagedMachOs are the Mach-O files of the fixture tree: the staged k3sm, its
// helpers, a payload binary, and the app's own executable.
func stagedMachOs() []string {
	var out []string
	for _, f := range []string{"k3sm", ExecShimName, PathShimName, DNSShimName, VMHostName, "bin/kine"} {
		out = append(out, filepath.Join(testPayloadDir, f))
	}
	return append(out, testStagedApp+"/Contents/MacOS/k3sm")
}

// signedTree maps every fixture Mach-O to testTeamID, then applies over.
func signedTree(over map[string]string) map[string]string {
	ids := map[string]string{}
	for _, f := range stagedMachOs() {
		ids[f] = testTeamID
	}
	for k, v := range over {
		ids[k] = v
	}
	return ids
}

// stagedFixture is a staging tree that passes the predicate, and the Config
// that installs from it. Each test case breaks one thing.
func stagedFixture() (*fakeStagingFS, Config) {
	sfs := &fakeStagingFS{content: map[string][]byte{}, versions: map[string]string{}, verErr: map[string]error{}}
	sfs.put("/Library", 0, 0, fs.ModeDir|0o755)
	sfs.put(testStagingRoot, 0, 0, fs.ModeDir|0o700)
	sfs.put(testStagedDir, 0, 0, fs.ModeDir|0o700)
	for _, d := range []string{testStagedApp, testStagedApp + "/Contents", testStagedApp + "/Contents/MacOS", testStagedApp + "/Contents/Resources", testPayloadDir, testPayloadDir + "/bin"} {
		sfs.put(d, 0, 0, fs.ModeDir|0o755)
	}
	sfs.macho = map[string]bool{}
	for _, f := range stagedMachOs() {
		sfs.put(f, 0, 0, 0o755)
		sfs.macho[f] = true
	}
	// A plain file in the bundle is not a Mach-O and needs no signature.
	sfs.put(testStagedApp+"/Contents/Info.plist", 0, 0, 0o644)
	cfg := Config{
		BinarySource: testStagedExe,
		TargetUser:   "admin",
		StagingOptions: StagingOptions{
			FromStagingDir: testStagedDir,
			Executable:     testStagedExe,
			StagedVersion:  "v0.4.0",
			StagingFS:      sfs,
			Signer:         fakeSigner{ids: signedTree(nil)},
		},
	}
	return sfs, cfg.withDefaults()
}

// TestFromStagingRefusesOutsideStagingRoot is the gate for `install
// --from-staging`: every way the staged directory, its tree or the running
// binary can sit outside a trusted direct child of the staging root is refused
// before anything is written, and the untouched fixture is accepted (so each
// refusal is the one thing the case broke).
func TestFromStagingRefusesOutsideStagingRoot(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name   string
		break_ func(*fakeStagingFS, *Config)
		want   string // "" = accepted
	}{
		{name: "the untouched fixture is accepted", break_: func(*fakeStagingFS, *Config) {}},
		{name: "a directory outside the staging root", want: "not a directory directly inside",
			break_: func(s *fakeStagingFS, c *Config) {
				c.FromStagingDir = "/Library/Caches/0.4.0.AbCdEfGh"
				s.put("/Library/Caches", 0, 0, fs.ModeDir|0o755)
				s.put(c.FromStagingDir, 0, 0, fs.ModeDir|0o700)
			}},
		{name: "the staging root itself", want: "not a directory directly inside",
			break_: func(_ *fakeStagingFS, c *Config) { c.FromStagingDir = testStagingRoot }},
		{name: "nested deeper than a direct child", want: "not a directory directly inside",
			break_: func(_ *fakeStagingFS, c *Config) { c.FromStagingDir = testStagedApp }},
		{name: "a relative path", want: "not a clean absolute path",
			break_: func(_ *fakeStagingFS, c *Config) { c.FromStagingDir = "k3sm.staging/0.4.0.AbCdEfGh" }},
		{name: "a path with a dot-dot component", want: "not a clean absolute path",
			break_: func(_ *fakeStagingFS, c *Config) { c.FromStagingDir = testStagingRoot + "/x/../0.4.0.AbCdEfGh" }},
		{name: "the staged directory is a symlink", want: "is a symlink",
			break_: func(s *fakeStagingFS, _ *Config) { s.put(testStagedDir, 0, 0, fs.ModeSymlink|0o755) }},
		{name: "the staging root is a symlink", want: testStagingRoot + " is a symlink",
			break_: func(s *fakeStagingFS, _ *Config) { s.put(testStagingRoot, 0, 0, fs.ModeSymlink|0o755) }},
		{name: "a parent component is a symlink", want: "/Library is a symlink",
			break_: func(s *fakeStagingFS, _ *Config) { s.put("/Library", 0, 0, fs.ModeSymlink|0o755) }},
		{name: "the staged directory is owned by a user", want: "owned by 501:0",
			break_: func(s *fakeStagingFS, _ *Config) { s.put(testStagedDir, 501, 0, fs.ModeDir|0o700) }},
		{name: "the staging root has a non-wheel group", want: "owned by 0:20",
			break_: func(s *fakeStagingFS, _ *Config) { s.put(testStagingRoot, 0, 20, fs.ModeDir|0o700) }},
		{name: "the staged directory is 0755", want: "mode 0755, not 0700",
			break_: func(s *fakeStagingFS, _ *Config) { s.put(testStagedDir, 0, 0, fs.ModeDir|0o755) }},
		{name: "the staging root is 0750", want: "mode 0750, not 0700",
			break_: func(s *fakeStagingFS, _ *Config) { s.put(testStagingRoot, 0, 0, fs.ModeDir|0o750) }},
		{name: "the root and the directory are on different devices", want: "different devices",
			break_: func(s *fakeStagingFS, _ *Config) {
				e := s.entries[testStagedDir]
				e.Dev = 2
				s.entries[testStagedDir] = e
			}},
		{name: "a symlink inside the tree", want: "/bin/kine is a symlink",
			break_: func(s *fakeStagingFS, _ *Config) { s.put(testPayloadDir+"/bin/kine", 0, 0, fs.ModeSymlink|0o755) }},
		{name: "a special file inside the tree", want: "is a special file",
			break_: func(s *fakeStagingFS, _ *Config) { s.put(testPayloadDir+"/fifo", 0, 0, fs.ModeNamedPipe|0o600) }},
		{name: "a file inside the tree owned by a user", want: "owned by uid 501",
			break_: func(s *fakeStagingFS, _ *Config) { s.put(testPayloadDir+"/"+ExecShimName, 501, 0, 0o755) }},
		{name: "a setuid file inside the tree", want: "setuid or setgid",
			break_: func(s *fakeStagingFS, _ *Config) { s.put(testPayloadDir+"/"+VMHostName, 0, 0, fs.ModeSetuid|0o755) }},
		{name: "a group-writable directory inside the tree", want: "writable by its group or by others",
			break_: func(s *fakeStagingFS, _ *Config) { s.put(testPayloadDir+"/bin", 0, 0, fs.ModeDir|0o775) }},
		{name: "a world-writable file inside the tree", want: "writable by its group or by others",
			break_: func(s *fakeStagingFS, _ *Config) { s.put(testPayloadDir+"/"+DNSShimName, 0, 0, 0o757) }},
		{name: "a file inside the tree on another device", want: "different device",
			break_: func(s *fakeStagingFS, _ *Config) {
				e := s.entries[testPayloadDir+"/k3sm"]
				e.Dev = 9
				s.entries[testPayloadDir+"/k3sm"] = e
			}},
		{name: "the running executable is outside the directory", want: "this k3sm runs from /Library/k3sm/k3sm",
			break_: func(_ *fakeStagingFS, c *Config) { c.Executable = "/Library/k3sm/k3sm" }},
		{name: "the running executable is in a sibling staged directory", want: "is not inside " + testStagedDir,
			break_: func(_ *fakeStagingFS, c *Config) { c.Executable = testStagingRoot + "/0.3.0.ZzZzZzZz/k3sm" }},
		{name: "an installed file is sourced from outside the directory", want: "copies nothing from anywhere else",
			break_: func(_ *fakeStagingFS, c *Config) { c.PayloadSource = "/tmp/payload" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			sfs, cfg := stagedFixture()
			tc.break_(sfs, &cfg)
			err := preflightFromStaging(context.Background(), &cfg)
			if tc.want == "" {
				if err != nil {
					t.Fatalf("preflightFromStaging = %v, want the fixture accepted", err)
				}
				return
			}
			if !errors.Is(err, ErrStagingUntrusted) {
				t.Fatalf("preflightFromStaging = %v, want ErrStagingUntrusted", err)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("preflightFromStaging = %v, want it to name %q", err, tc.want)
			}
		})
	}

	// And through Install itself: the refusal comes before the first system
	// call of any kind, so nothing was read, locked or written.
	t.Run("install refuses before any system call", func(t *testing.T) {
		t.Parallel()
		sfs, cfg := stagedFixture()
		sfs.put(testStagedDir, 0, 0, fs.ModeSymlink|0o755)
		f := &fakeSystem{}
		if err := Install(context.Background(), f, cfg); !errors.Is(err, ErrStagingUntrusted) {
			t.Fatalf("Install = %v, want ErrStagingUntrusted", err)
		}
		if len(f.calls) != 0 {
			t.Errorf("Install made system calls before refusing: %v", f.calls)
		}
	})
	t.Run("missing seams refuse", func(t *testing.T) {
		t.Parallel()
		_, cfg := stagedFixture()
		cfg.StagingFS = nil
		if err := preflightFromStaging(context.Background(), &cfg); err == nil {
			t.Fatal("preflightFromStaging accepted a Config with no StagingFS")
		}
	})
}

// TestFromStagingTokenFileRules pins the strict --token-file rules under
// --from-staging: a direct child of the staged directory, root-owned, mode
// exactly 0600, a regular file with one link, read once and unlinked whatever
// the read found, and never echoed.
func TestFromStagingTokenFileRules(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name       string
		path       string
		seed       func(*fakeStagingFS)
		want       string // "" = accepted
		wantRemove bool
	}{
		{name: "a root 0600 regular file with one link is read and unlinked", path: testTokenPath,
			seed: func(s *fakeStagingFS) { s.put(testTokenPath, 0, 0, 0o600) }, wantRemove: true},
		{name: "a file in a subdirectory of the staged directory", path: testStagedApp + "/join-token", want: "not a file directly inside",
			seed: func(s *fakeStagingFS) { s.put(testStagedApp+"/join-token", 0, 0, 0o600) }},
		{name: "a file outside the staged directory", path: "/var/root/join-token", want: "not a file directly inside",
			seed: func(s *fakeStagingFS) { s.put("/var/root/join-token", 0, 0, 0o600) }},
		{name: "a symlink", path: testTokenPath, want: "not a regular file", wantRemove: true,
			seed: func(s *fakeStagingFS) { s.put(testTokenPath, 0, 0, fs.ModeSymlink|0o777) }},
		{name: "owned by a user", path: testTokenPath, want: "owned by uid 501", wantRemove: true,
			seed: func(s *fakeStagingFS) { s.put(testTokenPath, 501, 0, 0o600) }},
		{name: "mode 0640", path: testTokenPath, want: "mode 0640, not 0600", wantRemove: true,
			seed: func(s *fakeStagingFS) { s.put(testTokenPath, 0, 0, 0o640) }},
		{name: "mode 0400 is not exactly 0600", path: testTokenPath, want: "mode 0400, not 0600", wantRemove: true,
			seed: func(s *fakeStagingFS) { s.put(testTokenPath, 0, 0, 0o400) }},
		{name: "two links", path: testTokenPath, want: "2 links, not 1", wantRemove: true,
			seed: func(s *fakeStagingFS) {
				s.put(testTokenPath, 0, 0, 0o600)
				e := s.entries[testTokenPath]
				e.Nlink = 2
				s.entries[testTokenPath] = e
			}},
		{name: "empty", path: testTokenPath, want: "is empty", wantRemove: true,
			seed: func(s *fakeStagingFS) { s.put(testTokenPath, 0, 0, 0o600); s.content[testTokenPath] = []byte("\n") }},
		{name: "absent", path: testTokenPath, want: "read " + testTokenPath, wantRemove: true,
			seed: func(*fakeStagingFS) {}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			sfs, cfg := stagedFixture()
			tc.seed(sfs)
			if _, ok := sfs.content[tc.path]; !ok && sfs.entries[tc.path].Mode.IsRegular() {
				sfs.content[tc.path] = []byte(testTokenText + "\n")
			}
			cfg.TokenFile = tc.path
			err := preflightFromStaging(context.Background(), &cfg)
			removed := slices.Contains(sfs.calls, "RemoveFile:"+tc.path)
			if removed != tc.wantRemove {
				t.Errorf("token file removed = %v, want %v (calls %v)", removed, tc.wantRemove, sfs.calls)
			}
			if tc.want == "" {
				if err != nil {
					t.Fatalf("preflightFromStaging = %v, want accepted", err)
				}
				if cfg.stagedToken == nil || cfg.stagedToken.value != testTokenText {
					t.Fatalf("staged token not carried on the Config")
				}
				read := idx(sfs.calls, "ReadTokenFile:"+tc.path)
				if n := strings.Count(strings.Join(sfs.calls, ","), "ReadTokenFile:"); n != 1 || read > idx(sfs.calls, "RemoveFile:"+tc.path) {
					t.Errorf("want exactly one read, before the unlink: %v", sfs.calls)
				}
				return
			}
			if !errors.Is(err, ErrStagedTokenUntrusted) {
				t.Fatalf("preflightFromStaging = %v, want ErrStagedTokenUntrusted", err)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("preflightFromStaging = %v, want it to name %q", err, tc.want)
			}
			if strings.Contains(err.Error(), "SECRETMARKER") {
				t.Errorf("the error echoes the token: %v", err)
			}
		})
	}

	// A later refusal (here the Team ID) still finds the token already gone.
	t.Run("unlinked even when a later check refuses", func(t *testing.T) {
		t.Parallel()
		sfs, cfg := stagedFixture()
		sfs.put(testTokenPath, 0, 0, 0o600)
		sfs.content[testTokenPath] = []byte(testTokenText)
		cfg.TokenFile = testTokenPath
		cfg.Signer = fakeSigner{ids: signedTree(map[string]string{cfg.installedBinary(): "ZZZZZ99999"})}
		if err := preflightFromStaging(context.Background(), &cfg); !errors.Is(err, ErrTeamIDMismatch) {
			t.Fatalf("preflightFromStaging = %v, want ErrTeamIDMismatch", err)
		}
		if _, ok := sfs.entries[testTokenPath]; ok {
			t.Error("the token file survived a refusal")
		}
	})
}

// TestOperatorJoinTokenUsesTheStagedRead pins the hand-off: with a staged
// token the operator's file is not read again (it is already unlinked), and
// without one a plain --token-file keeps today's read and mode rule.
func TestOperatorJoinTokenUsesTheStagedRead(t *testing.T) {
	t.Parallel()
	token := testTokenText
	cfg := Config{TokenFile: testTokenPath, Role: RoleAgent}.withDefaults()
	cfg.stagedToken = &secretToken{value: token}
	f := &fakeSystem{}
	text, _, err := operatorJoinToken(f, cfg)
	if err != nil {
		t.Fatalf("operatorJoinToken with a staged token: %v", err)
	}
	if text != testTokenText {
		t.Errorf("token text not carried through")
	}
	if len(f.calls) != 0 {
		t.Errorf("the staged path re-read the operator's file: %v", f.calls)
	}

	plain := Config{TokenFile: "/var/root/join-token", Role: RoleAgent}.withDefaults()
	f = &fakeSystem{}
	f.putFile("/var/root/join-token", []byte(testTokenText))
	f.putFileMode("/var/root/join-token", 0o644)
	if _, _, err := operatorJoinToken(f, plain); err == nil || !strings.Contains(err.Error(), "must not be readable by its group") {
		t.Errorf("plain --token-file at 0644 = %v, want today's mode refusal", err)
	}
	if !slices.Contains(f.calls, "ReadRegularFileWithMode:/var/root/join-token") {
		t.Errorf("plain --token-file was not read through the existing seam: %v", f.calls)
	}
}

// TestFromStagingDowngradeRefusal pins the version rule: an unversioned
// staged build is refused outright, a lower version is refused unless
// AllowDowngrade, and an installed version that cannot be read or compared
// counts as a downgrade.
func TestFromStagingDowngradeRefusal(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name      string
		staged    string
		installed string // "" = no installed binary
		readErr   error
		allow     bool
		want      error
	}{
		{name: "first install", staged: "v0.4.0"},
		{name: "upgrade", staged: "v0.4.0", installed: "v0.3.9"},
		{name: "reinstall of the same version", staged: "v0.4.0", installed: "0.4.0"},
		{name: "release over its release candidate", staged: "v0.4.0", installed: "v0.4.0-rc.2"},
		{name: "downgrade refused", staged: "v0.3.0", installed: "v0.4.0", want: ErrDowngrade},
		{name: "release candidate over its release refused", staged: "v0.4.0-rc.1", installed: "v0.4.0", want: ErrDowngrade},
		{name: "downgrade allowed with the flag", staged: "v0.3.0", installed: "v0.4.0", allow: true},
		{name: "unversioned staged build refused", staged: "dev", want: ErrUnversioned},
		{name: "unversioned staged build refused even with the flag", staged: "dev", installed: "v0.4.0", allow: true, want: ErrUnversioned},
		{name: "pseudo-version staged build refused", staged: "v0.0.0-20261013101010-abcdefabcdef", want: ErrUnversioned},
		{name: "empty staged version refused", staged: "", want: ErrUnversioned},
		{name: "unversioned installed build refused", staged: "v0.4.0", installed: "dev", want: ErrDowngrade},
		{name: "unversioned installed build allowed with the flag", staged: "v0.4.0", installed: "dev", allow: true},
		{name: "unreadable installed version refused", staged: "v0.4.0", readErr: errors.New("not a Go binary"), want: ErrDowngrade},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			sfs, cfg := stagedFixture()
			cfg.StagedVersion, cfg.AllowDowngrade = tc.staged, tc.allow
			if tc.installed != "" {
				sfs.versions[cfg.installedBinary()] = tc.installed
				cfg.Signer = fakeSigner{ids: signedTree(map[string]string{cfg.installedBinary(): testTeamID})}
			}
			if tc.readErr != nil {
				sfs.verErr[cfg.installedBinary()] = tc.readErr
			}
			err := preflightFromStaging(context.Background(), &cfg)
			if tc.want == nil {
				if err != nil {
					t.Fatalf("preflightFromStaging = %v, want accepted", err)
				}
				return
			}
			if !errors.Is(err, tc.want) {
				t.Fatalf("preflightFromStaging = %v, want %v", err, tc.want)
			}
		})
	}
}

// TestReleaseVersionOrder pins the semver precedence the downgrade rule uses.
func TestReleaseVersionOrder(t *testing.T) {
	t.Parallel()
	ordered := []string{"v0.1.0-alpha", "v0.1.0-alpha.1", "v0.1.0-alpha.beta", "v0.1.0-beta.2", "v0.1.0-beta.11", "v0.1.0-rc.1", "v0.1.0", "0.1.1", "v0.2.0+build.5", "v1.0.0", "v10.0.0"}
	for i := range ordered {
		for j := range ordered {
			a, aok := parseReleaseVersion(ordered[i])
			b, bok := parseReleaseVersion(ordered[j])
			if !aok || !bok {
				t.Fatalf("parse %q or %q failed", ordered[i], ordered[j])
			}
			want := 0
			switch {
			case i < j:
				want = -1
			case i > j:
				want = 1
			}
			if got := a.compare(b); got != want {
				t.Errorf("compare(%s, %s) = %d, want %d", ordered[i], ordered[j], got, want)
			}
		}
	}
	for _, bad := range []string{"", "dev", "(devel)", "1.2", "v01.2.3", "v1.2.3-", "v1.2.0-0.20261013101010-abcdefabcdef", "v1.2.3-pre.0.20261013101010-abcdefabcdef"} {
		if _, ok := parseReleaseVersion(bad); ok {
			t.Errorf("parseReleaseVersion(%q) accepted a non-release version", bad)
		}
	}
}

// devPosture is the developer-mode column of TestDeveloperModeSigningContinuity:
// what the flag says and what the marker on disk is.
type devPosture int

const (
	// devNone is neither the flag nor a marker: today's install.
	devNone devPosture = iota
	// devFlagOn is --developer-mode on.
	devFlagOn
	// devMarkerOn is no flag and a valid marker on disk.
	devMarkerOn
	// devFlagOffMarkerOn is --developer-mode off over a valid marker: off wins.
	devFlagOffMarkerOn
	// devMarkerSymlink is no flag and a symlink at the marker path.
	devMarkerSymlink
	// devMarkerWorldWritable is no flag and a 0666 marker.
	devMarkerWorldWritable
)

func (d devPosture) String() string {
	return [...]string{"no developer mode", "--developer-mode on", "a valid marker", "--developer-mode off over a valid marker",
		"a symlinked marker", "a 0666 marker"}[d]
}

// on reports whether the posture turns developer mode on.
func (d devPosture) on() bool { return d == devFlagOn || d == devMarkerOn }

// apply sets the posture on cfg: the flag, and a fake system whose marker is
// the posture's, read through the production reader (resolveDeveloperMode).
func (d devPosture) apply(t *testing.T, cfg *Config) {
	t.Helper()
	f := &fakeSystem{owners: map[string]OwnedEntry{}}
	marker := OwnedEntry{Path: DeveloperModeMarkerPath, Kind: EntryRegular, Mode: 0o644}
	switch d {
	case devFlagOn:
		cfg.DeveloperMode = DeveloperModeOn
	case devMarkerOn:
		f.owners[DeveloperModeMarkerPath] = marker
	case devFlagOffMarkerOn:
		cfg.DeveloperMode = DeveloperModeOff
		f.owners[DeveloperModeMarkerPath] = marker
	case devMarkerSymlink:
		marker.Kind, marker.Mode = EntrySymlink, 0o755
		f.owners[DeveloperModeMarkerPath] = marker
	case devMarkerWorldWritable:
		marker.Mode = 0o666
		f.owners[DeveloperModeMarkerPath] = marker
	}
	if err := resolveDeveloperMode(f, cfg); err != nil {
		t.Fatal(err)
	}
}

// TestDeveloperModeSigningContinuity pins the signing continuity check, which
// follows the installed build: a first install and a team-signed install take
// only a tree whose every Mach-O carries one Developer ID team's signature (the
// installed team on an update), so an ad-hoc tree never replaces a team-signed
// install; an ad-hoc install takes an ad-hoc tree or a team-signed one, but not
// a tree mixing the two. A non-Mach-O file needs no signature.
//
// Developer mode (the flag on, or a valid marker with no flag) skips that check
// and logs a Warn saying so; every other --from-staging check still refuses.
// Every row without a developer-mode posture keeps today's verdict, and is run
// again under --developer-mode off over a valid marker and under each invalid
// marker, which must change nothing.
func TestDeveloperModeSigningContinuity(t *testing.T) {
	t.Parallel()
	installed := Config{}.withDefaults().installedBinary()
	helper := filepath.Join(testPayloadDir, VMHostName)
	appExe := testStagedApp + "/Contents/MacOS/k3sm"
	teamOverAdHocTree := fakeSigner{ids: map[string]string{installed: testTeamID}, errs: adHocTree()}
	cases := []struct {
		name   string
		signer fakeSigner
		dev    devPosture
		tweak  func(*fakeStagingFS, *Config)
		want   error
	}{
		{name: "first install", signer: fakeSigner{ids: signedTree(nil)}},
		{name: "update by the same team", signer: fakeSigner{ids: signedTree(map[string]string{installed: testTeamID})}},
		{name: "update over another team refused", want: ErrTeamIDMismatch,
			signer: fakeSigner{ids: signedTree(map[string]string{installed: "ZZZZZ99999"})}},
		{name: "an ad-hoc install takes a team-signed tree",
			signer: fakeSigner{ids: signedTree(nil), errs: map[string]error{installed: ErrNoTeamID}}},
		{name: "an ad-hoc install takes an ad-hoc tree",
			signer: fakeSigner{errs: adHocTree(installed)}},
		{name: "an ad-hoc install refuses a tree mixing ad-hoc and team signatures", want: ErrTeamIDMismatch,
			signer: fakeSigner{ids: map[string]string{helper: testTeamID}, errs: without(adHocTree(installed), helper)}},
		{name: "a team-signed install refuses an ad-hoc tree", want: ErrTeamIDMismatch, signer: teamOverAdHocTree},
		{name: "installed binary signed Apple Development by the same team refused", want: ErrNotDeveloperID,
			signer: fakeSigner{ids: signedTree(map[string]string{installed: testTeamID}), notDevID: map[string]bool{installed: true}}},
		{name: "ad-hoc staged k3sm refused", want: ErrNoTeamID,
			signer: fakeSigner{ids: signedTree(nil), errs: map[string]error{testStagedExe: ErrNoTeamID}}},
		{name: "staged k3sm signed Apple Development by the same team refused", want: ErrNotDeveloperID,
			signer: fakeSigner{ids: signedTree(nil), notDevID: map[string]bool{testStagedExe: true}}},
		{name: "a helper signed by another team refused", want: ErrTeamIDMismatch,
			signer: fakeSigner{ids: signedTree(map[string]string{helper: "ZZZZZ99999"})}},
		{name: "an ad-hoc helper refused", want: ErrTeamIDMismatch,
			signer: fakeSigner{ids: signedTree(nil), errs: map[string]error{helper: ErrNoTeamID}}},
		{name: "a helper signed Apple Development by the same team refused", want: ErrNotDeveloperID,
			signer: fakeSigner{ids: signedTree(nil), notDevID: map[string]bool{helper: true}}},
		{name: "an unsigned Mach-O anywhere in the tree refused", want: ErrTeamIDMismatch,
			signer: fakeSigner{ids: signedTree(nil), errs: map[string]error{appExe: ErrNoTeamID}}},
		{name: "unreadable installed signature refused", want: errSignatureUnreadable,
			signer: fakeSigner{ids: signedTree(nil), errs: map[string]error{installed: errSignatureUnreadable}}},

		// Developer mode.
		{name: "an ad-hoc tree over a team-signed install", dev: devFlagOn, signer: teamOverAdHocTree},
		{name: "an ad-hoc tree over a team-signed install, by the marker", dev: devMarkerOn, signer: teamOverAdHocTree},
		{name: "a team-signed tree over an ad-hoc install", dev: devFlagOn,
			signer: fakeSigner{ids: signedTree(nil), errs: map[string]error{installed: ErrNoTeamID}}},
		{name: "a tree of another team over a team-signed install", dev: devFlagOn,
			signer: fakeSigner{ids: signedTree(map[string]string{installed: "ZZZZZ99999"})}},
		{name: "a first install of an ad-hoc tree", dev: devFlagOn, signer: fakeSigner{errs: adHocTree()}},
		{name: "--require-team-signature still refuses an ad-hoc tree", dev: devFlagOn, want: ErrNoTeamID,
			signer: fakeSigner{errs: adHocTree()}, tweak: func(_ *fakeStagingFS, c *Config) { c.RequireTeamSignature = true }},
		{name: "a downgrade is still refused", dev: devFlagOn, want: ErrDowngrade, signer: teamOverAdHocTree,
			tweak: func(s *fakeStagingFS, _ *Config) { s.versions[installed] = "v0.5.0" }},
		{name: "a staging directory not owned by root is still refused", dev: devFlagOn, want: ErrStagingUntrusted,
			signer: teamOverAdHocTree, tweak: func(s *fakeStagingFS, _ *Config) { s.put(testStagedDir, 501, 0, fs.ModeDir|0o700) }},
	}
	type run struct {
		name string
		dev  devPosture
	}
	for _, tc := range cases {
		runs := []run{{tc.name, tc.dev}}
		if tc.dev == devNone {
			for _, d := range []devPosture{devFlagOffMarkerOn, devMarkerSymlink, devMarkerWorldWritable} {
				runs = append(runs, run{tc.name + " (" + d.String() + ")", d})
			}
		}
		for _, r := range runs {
			t.Run(r.name, func(t *testing.T) {
				t.Parallel()
				sfs, cfg := stagedFixture()
				cfg.Signer = tc.signer
				var logs strings.Builder
				cfg.Logger = slog.New(slog.NewTextHandler(&logs, nil))
				r.dev.apply(t, &cfg)
				if tc.tweak != nil {
					tc.tweak(sfs, &cfg)
				}
				err := preflightFromStaging(context.Background(), &cfg)
				warned := strings.Contains(logs.String(), "level=WARN") && strings.Contains(logs.String(), `"`+developerModeContinuityWarning+`"`)
				if tc.want != nil {
					if !errors.Is(err, tc.want) {
						t.Fatalf("preflightFromStaging = %v, want %v", err, tc.want)
					}
					return
				}
				if err != nil {
					t.Fatalf("preflightFromStaging = %v, want accepted", err)
				}
				if warned != r.dev.on() {
					t.Errorf("developer-mode Warn logged = %v, want %v; logs:\n%s", warned, r.dev.on(), logs.String())
				}
				if r.dev.on() {
					return
				}
				for _, f := range stagedMachOs() {
					if f != testStagedExe && !slices.Contains(sfs.calls, "MachO:"+f) {
						t.Errorf("%s was never checked for a Mach-O header", f)
					}
				}
			})
		}
	}
}

var errSignatureUnreadable = errors.New("codesign failed")

// without returns m less key.
func without(m map[string]error, key string) map[string]error {
	delete(m, key)
	return m
}

// adHocTree reports every fixture Mach-O, and each extra path, as carrying no
// Team ID: an ad-hoc signed tree.
func adHocTree(extra ...string) map[string]error {
	errs := map[string]error{}
	for _, f := range append(stagedMachOs(), extra...) {
		errs[f] = ErrNoTeamID
	}
	return errs
}

// TestStampedVersion pins how a binary's version is read from its build info.
func TestStampedVersion(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		bi   debug.BuildInfo
		want string
	}{
		{name: "goreleaser stamp", want: "0.4.0", bi: debug.BuildInfo{Main: debug.Module{Version: "(devel)"},
			Settings: []debug.BuildSetting{{Key: "-ldflags", Value: "-s -w -X k3sm.io/k3sm/pkg/version.Version=0.4.0 -X k3sm.io/k3sm/pkg/version.Commit=abc"}}}},
		{name: "-X= form", want: "v0.5.0", bi: debug.BuildInfo{
			Settings: []debug.BuildSetting{{Key: "-ldflags", Value: "-X=k3sm.io/k3sm/pkg/version.Version=v0.5.0"}}}},
		{name: "module version fallback", want: "v0.0.0-20261013101010-abcdefabcdef", bi: debug.BuildInfo{Main: debug.Module{Version: "v0.0.0-20261013101010-abcdefabcdef"}}},
		{name: "nothing stamped", want: "dev", bi: debug.BuildInfo{Main: debug.Module{Version: "(devel)"}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := stampedVersion(&tc.bi); got != tc.want {
				t.Errorf("stampedVersion = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestStagingLockOrder pins the two-lock order: the staging lock (outer)
// before the install lock (inner), released in reverse, and how each caller
// answers a staging lock the copy-out already holds.
func TestStagingLockOrder(t *testing.T) {
	t.Parallel()
	stagingLock, installLock := StagingLockPath(DefaultStagingRoot), Config{}.withDefaults().installLockPath()
	if stagingLock != "/Library/k3sm.staging.lock" {
		t.Fatalf("StagingLockPath = %s, want the copy-out's /Library/k3sm.staging.lock", stagingLock)
	}

	t.Run("install from staging takes staging then install, releases in reverse", func(t *testing.T) {
		t.Parallel()
		_, cfg := stagedFixture()
		f := &fakeSystem{}
		release, err := lockForInstall(f, cfg)
		if err != nil {
			t.Fatalf("lockForInstall: %v", err)
		}
		release()
		want := []string{"LockStaging:" + stagingLock, "LockInstall:" + installLock, "UnlockInstall:" + installLock, "UnlockStaging:" + stagingLock}
		if !slices.Equal(f.calls, want) {
			t.Errorf("calls = %v, want %v", f.calls, want)
		}
	})
	t.Run("a plain install takes only the install lock", func(t *testing.T) {
		t.Parallel()
		f := &fakeSystem{}
		release, err := lockForInstall(f, Config{}.withDefaults())
		if err != nil {
			t.Fatalf("lockForInstall: %v", err)
		}
		release()
		if want := []string{"LockInstall:" + installLock, "UnlockInstall:" + installLock}; !slices.Equal(f.calls, want) {
			t.Errorf("calls = %v, want %v", f.calls, want)
		}
	})
	t.Run("install from staging under the copy-out's held lock proceeds", func(t *testing.T) {
		t.Parallel()
		_, cfg := stagedFixture()
		f := &fakeSystem{locked: map[string]bool{stagingLock: true}}
		release, err := lockForInstall(f, cfg)
		if err != nil {
			t.Fatalf("lockForInstall: %v", err)
		}
		release()
		if want := []string{"LockStaging:" + stagingLock, "LockInstall:" + installLock, "UnlockInstall:" + installLock}; !slices.Equal(f.calls, want) {
			t.Errorf("calls = %v, want %v", f.calls, want)
		}
	})
	t.Run("a busy install lock releases the staging lock", func(t *testing.T) {
		t.Parallel()
		_, cfg := stagedFixture()
		f := &fakeSystem{locked: map[string]bool{installLock: true}}
		if _, err := lockForInstall(f, cfg); !errors.Is(err, ErrInstallInProgress) {
			t.Fatalf("lockForInstall = %v, want ErrInstallInProgress", err)
		}
		if want := []string{"LockStaging:" + stagingLock, "LockInstall:" + installLock, "UnlockStaging:" + stagingLock}; !slices.Equal(f.calls, want) {
			t.Errorf("calls = %v, want %v", f.calls, want)
		}
	})
	t.Run("uninstall refuses while a copy-out holds the staging lock", func(t *testing.T) {
		t.Parallel()
		f := &fakeSystem{locked: map[string]bool{stagingLock: true}}
		err := Uninstall(context.Background(), f, Config{StagingOptions: StagingOptions{Executable: "/Library/k3sm/k3sm"}})
		if !errors.Is(err, ErrStagingBusy) {
			t.Fatalf("Uninstall = %v, want ErrStagingBusy", err)
		}
		if want := []string{"LockStaging:" + stagingLock}; !slices.Equal(f.calls, want) {
			t.Errorf("a refused uninstall went on to %v", f.calls)
		}
	})
	t.Run("the app's own uninstall step proceeds under its copy-out's lock", func(t *testing.T) {
		t.Parallel()
		sfs, _ := stagedFixture()
		f := &fakeSystem{locked: map[string]bool{stagingLock: true}}
		cfg := Config{StagingOptions: StagingOptions{Executable: testStagedExe, StagingFS: sfs}}.withDefaults()
		release, err := lockStagingThenInstall(f, cfg, lockUninstall)
		if err != nil {
			t.Fatalf("lockStagingThenInstall: %v", err)
		}
		release()
		if !slices.Contains(f.calls, "LockInstall:"+installLock) {
			t.Errorf("the install lock was not taken: %v", f.calls)
		}
	})
	t.Run("a staged uninstall from an untrusted directory is refused", func(t *testing.T) {
		t.Parallel()
		sfs, _ := stagedFixture()
		sfs.put(testStagedDir, 501, 0, fs.ModeDir|0o700)
		f := &fakeSystem{locked: map[string]bool{stagingLock: true}}
		cfg := Config{StagingOptions: StagingOptions{Executable: testStagedExe, StagingFS: sfs}}.withDefaults()
		if _, err := lockStagingThenInstall(f, cfg, lockUninstall); !errors.Is(err, ErrStagingBusy) {
			t.Fatalf("lockStagingThenInstall = %v, want ErrStagingBusy", err)
		}
	})
	t.Run("an unconfirmed purge touches no lock", func(t *testing.T) {
		t.Parallel()
		f := &fakeSystem{}
		if err := Uninstall(context.Background(), f, Config{Purge: true}); !errors.Is(err, ErrPurgeNotConfirmed) {
			t.Fatalf("Uninstall = %v, want ErrPurgeNotConfirmed", err)
		}
		if len(f.calls) != 0 {
			t.Errorf("calls = %v, want none", f.calls)
		}
	})
}

// TestSwapDirIsNotTheStagingRoot pins the rename: install builds its new root
// at <InstallDir>.swap, never at the k3sm.app staging root, so neither can
// remove or publish the other's tree.
func TestSwapDirIsNotTheStagingRoot(t *testing.T) {
	t.Parallel()
	cfg := Config{}.withDefaults()
	if got := cfg.swapDir(); got != "/Library/k3sm.swap" {
		t.Errorf("swapDir = %s, want /Library/k3sm.swap", got)
	}
	if cfg.swapDir() == DefaultStagingRoot || strings.HasPrefix(cfg.swapDir(), DefaultStagingRoot+"/") {
		t.Errorf("swapDir %s collides with the staging root %s", cfg.swapDir(), DefaultStagingRoot)
	}
	if got := cfg.stagedBinary(); got != "/Library/k3sm.swap/k3sm" {
		t.Errorf("stagedBinary = %s, want /Library/k3sm.swap/k3sm", got)
	}
	// A tree an older build left at the old swap name is not touched by an
	// install: prepareStagingDir judges and empties only the swap dir.
	f := &fakeSystem{}
	f.putOwned(DefaultStagingRoot, 0, 0, fs.ModeDir|0o755, EntryDir)
	if err := prepareStagingDir(f, cfg); err != nil {
		t.Fatalf("prepareStagingDir: %v", err)
	}
	for _, c := range f.calls {
		if strings.Contains(c, DefaultStagingRoot) {
			t.Errorf("an install touched the staging root: %s", c)
		}
	}
	if !slices.Contains(f.calls, "EnsureRootDir:/Library/k3sm.swap") {
		t.Errorf("the swap dir was not prepared: %v", f.calls)
	}
}

// TestSweepStaging pins uninstall's staging sweep: the staging root (and a
// leftover swap tree) is removed when it is a root-owned real directory, and a
// symlink or a user-owned tree is refused and left alone.
func TestSweepStaging(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name       string
		entry      OwnedEntry
		wantRemove bool
		wantErr    string
	}{
		{name: "a root-owned staging root is removed", entry: OwnedEntry{Mode: fs.ModeDir | 0o700, Kind: EntryDir}, wantRemove: true},
		{name: "a leftover old-name swap tree (0755) is removed", entry: OwnedEntry{Mode: fs.ModeDir | 0o755, Kind: EntryDir}, wantRemove: true},
		{name: "a symlink is refused, never followed", entry: OwnedEntry{Mode: fs.ModeSymlink | 0o755, Kind: EntrySymlink}, wantErr: "is a symlink"},
		{name: "a user-owned directory is refused", entry: OwnedEntry{UID: 501, Mode: fs.ModeDir | 0o700, Kind: EntryDir}, wantErr: "owned by uid 501"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			tmp := t.TempDir()
			cfg := Config{InstallDir: filepath.Join(tmp, "k3sm"), StagingOptions: StagingOptions{StagingRoot: filepath.Join(tmp, "k3sm.staging")}}.withDefaults()
			f := &fakeSystem{}
			f.putOwnedEntry(cfg.stagingRoot(), tc.entry)
			f.putOwned(cfg.swapDir(), 0, 0, fs.ModeDir|0o755, EntryDir)
			err := sweepStaging(f, cfg)
			removed := slices.Contains(f.calls, "RemoveTree:"+cfg.stagingRoot())
			if removed != tc.wantRemove {
				t.Errorf("staging root removed = %v, want %v (calls %v)", removed, tc.wantRemove, f.calls)
			}
			if !slices.Contains(f.calls, "RemoveTree:"+cfg.swapDir()) {
				t.Errorf("the leftover swap dir was not swept: %v", f.calls)
			}
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("sweepStaging = %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("sweepStaging = %v, want it to name %q", err, tc.wantErr)
			}
		})
	}
}

// TestFromStagingEarlyRefusalUnlinksToken pins the token on the refusals that
// come before it can be read: the staged directory failing its own checks,
// and a --token-file that is not a direct child of the staged directory. The
// file is unlinked, and never read, whenever it is a regular file inside a
// direct child of the staging root.
func TestFromStagingEarlyRefusalUnlinksToken(t *testing.T) {
	t.Parallel()
	other := testStagingRoot + "/0.3.0.ZzZzZzZz"
	cases := []struct {
		name       string
		token      string
		seed       func(*fakeStagingFS, *Config)
		want       error
		wantRemove bool
	}{
		{name: "the staged directory fails its own checks", token: testTokenPath, want: ErrStagingUntrusted, wantRemove: true,
			seed: func(s *fakeStagingFS, _ *Config) { s.put(testStagedDir, 0, 0, fs.ModeDir|0o755) }},
		{name: "the staged directory is outside the root", token: testTokenPath, want: ErrStagingUntrusted, wantRemove: true,
			seed: func(_ *fakeStagingFS, c *Config) { c.FromStagingDir = "/Library/k3sm" }},
		{name: "a token in another staged directory", token: other + "/join-token", want: ErrStagedTokenUntrusted, wantRemove: true,
			seed: func(s *fakeStagingFS, _ *Config) { s.put(other, 0, 0, fs.ModeDir|0o700) }},
		{name: "a token nested deeper is left alone", token: testStagedApp + "/join-token", want: ErrStagedTokenUntrusted},
		{name: "a token outside the staging root is left alone", token: "/var/root/join-token", want: ErrStagedTokenUntrusted,
			seed: func(s *fakeStagingFS, _ *Config) {
				s.put("/var", 0, 0, fs.ModeDir|0o755)
				s.put("/var/root", 0, 0, fs.ModeDir|0o750)
			}},
		{name: "a symlink at the token path is left alone", token: testTokenPath, want: ErrStagingUntrusted,
			seed: func(s *fakeStagingFS, _ *Config) {
				s.put(testStagedDir, 0, 0, fs.ModeDir|0o755)
				s.put(testTokenPath, 0, 0, fs.ModeSymlink|0o777)
			}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			sfs, cfg := stagedFixture()
			sfs.put(tc.token, 0, 0, 0o600)
			sfs.content[tc.token] = []byte(testTokenText)
			if tc.seed != nil {
				tc.seed(sfs, &cfg)
			}
			cfg.TokenFile = tc.token
			err := preflightFromStaging(context.Background(), &cfg)
			if !errors.Is(err, tc.want) {
				t.Fatalf("preflightFromStaging = %v, want %v", err, tc.want)
			}
			if slices.Contains(sfs.calls, "ReadTokenFile:"+tc.token) {
				t.Errorf("an early refusal read the token: %v", sfs.calls)
			}
			removed := slices.Contains(sfs.calls, "RemoveFile:"+tc.token)
			if removed != tc.wantRemove {
				t.Errorf("token removed = %v, want %v (calls %v)", removed, tc.wantRemove, sfs.calls)
			}
		})
	}
}

// TestSecretTokenRedacts pins that no print or log of the staged token, or of
// a Config holding it, carries the token.
func TestSecretTokenRedacts(t *testing.T) {
	t.Parallel()
	tok := &secretToken{value: testTokenText}
	cfg := Config{StagingOptions: StagingOptions{stagedToken: tok}}
	var buf strings.Builder
	logger := slog.New(slog.NewJSONHandler(&buf, nil))
	logger.Info("dump", "token", tok, "value", *tok, "cfg", cfg)
	logger.Info("text", "cfg", fmt.Sprintf("%+v", cfg))
	outs := []string{
		fmt.Sprint(tok), fmt.Sprintf("%v %+v %#v %s %q %x", *tok, *tok, *tok, *tok, *tok, *tok),
		fmt.Sprintf("%v %+v %#v", cfg, cfg, cfg), buf.String(),
	}
	for _, out := range outs {
		if strings.Contains(out, "SECRETMARKER") {
			t.Errorf("the token leaked: %s", out)
		}
	}
	if !strings.Contains(fmt.Sprint(*tok), redacted) {
		t.Errorf("the token does not print as the redaction")
	}
}

// TestOldNameSwapTreeIsOnlyRemovedByUninstall pins the rename's migration: a
// tree an older build left at <InstallDir>.staging is neither trusted, reused
// nor removed by an install or an update, and uninstall's staging sweep is
// what removes it.
func TestOldNameSwapTreeIsOnlyRemovedByUninstall(t *testing.T) {
	shrinkRestartBudgets(t)
	tmp := t.TempDir()
	cfg := Config{BinarySource: "/tmp/k3sm", TargetUser: "alice", InstallDir: filepath.Join(tmp, "k3sm")}
	old := cfg.InstallDir + ".staging"
	f := &fakeSystem{}
	f.putOwned(old, 0, 0, fs.ModeDir|0o755, EntryDir)
	f.putFile(old+"/k3sm", []byte("an older build"))
	for _, run := range []string{"install", "update"} {
		f.calls = nil
		if err := Install(context.Background(), f, cfg); err != nil {
			t.Fatalf("%s: %v", run, err)
		}
		for _, c := range f.calls {
			if strings.Contains(c, old) {
				t.Errorf("%s touched the old-name swap tree: %s", run, c)
			}
		}
		if _, ok := f.owners[old]; !ok {
			t.Fatalf("%s removed the old-name swap tree", run)
		}
	}
	f.calls = nil
	if err := Uninstall(context.Background(), f, cfg); err != nil {
		t.Fatalf("Uninstall: %v", err)
	}
	if !slices.Contains(f.calls, "RemoveTree:"+old) {
		t.Errorf("uninstall did not sweep the old-name swap tree: %v", f.calls)
	}
}

// TestDiscardStagedToken pins where the best-effort unlink acts: only on a
// regular file inside a direct child of the staging root, with no symlink on
// the way, and never by reading it.
func TestDiscardStagedToken(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name       string
		path       string
		seed       func(*fakeStagingFS)
		wantRemove bool
	}{
		{name: "a regular file in a staged directory", path: testTokenPath, wantRemove: true,
			seed: func(s *fakeStagingFS) { s.put(testTokenPath, 0, 0, 0o600) }},
		{name: "a symlink", path: testTokenPath, seed: func(s *fakeStagingFS) { s.put(testTokenPath, 0, 0, fs.ModeSymlink|0o777) }},
		{name: "a directory", path: testTokenPath, seed: func(s *fakeStagingFS) { s.put(testTokenPath, 0, 0, fs.ModeDir|0o700) }},
		{name: "absent", path: testTokenPath, seed: func(*fakeStagingFS) {}},
		{name: "nested deeper", path: testStagedApp + "/join-token", seed: func(s *fakeStagingFS) { s.put(testStagedApp+"/join-token", 0, 0, 0o600) }},
		{name: "directly in the root", path: testStagingRoot + "/join-token", seed: func(s *fakeStagingFS) { s.put(testStagingRoot+"/join-token", 0, 0, 0o600) }},
		{name: "outside the root", path: "/Library/join-token", seed: func(s *fakeStagingFS) { s.put("/Library/join-token", 0, 0, 0o600) }},
		{name: "a relative path", path: "join-token", seed: func(*fakeStagingFS) {}},
		{name: "the staging root is a symlink", path: testTokenPath, seed: func(s *fakeStagingFS) {
			s.put(testTokenPath, 0, 0, 0o600)
			s.put(testStagingRoot, 0, 0, fs.ModeSymlink|0o755)
		}},
		{name: "the staged directory is a symlink", path: testTokenPath, seed: func(s *fakeStagingFS) {
			s.put(testTokenPath, 0, 0, 0o600)
			s.put(testStagedDir, 0, 0, fs.ModeSymlink|0o755)
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			sfs, _ := stagedFixture()
			tc.seed(sfs)
			DiscardStagedToken(sfs, testStagingRoot, tc.path)
			removed := slices.Contains(sfs.calls, "RemoveFile:"+tc.path)
			if removed != tc.wantRemove {
				t.Errorf("removed = %v, want %v (calls %v)", removed, tc.wantRemove, sfs.calls)
			}
			for _, c := range sfs.calls {
				if strings.HasPrefix(c, "ReadTokenFile:") {
					t.Errorf("the discard read the file: %s", c)
				}
			}
		})
	}
}

// TestRequireTeamSignature pins --require-team-signature: every Mach-O in the
// staged tree, the staged k3sm included, must carry a Developer ID team
// signature of its own; the installed binary is never consulted for it; and
// the flag is refused on a plain install.
func TestRequireTeamSignature(t *testing.T) {
	t.Parallel()
	helper := filepath.Join(testPayloadDir, VMHostName)
	cases := []struct {
		name   string
		signer fakeSigner
		want   error
	}{
		{name: "a fully signed tree is accepted", signer: fakeSigner{ids: signedTree(nil)}},
		{name: "an ad-hoc staged k3sm is refused", want: ErrNoTeamID,
			signer: fakeSigner{ids: signedTree(nil), errs: map[string]error{testStagedExe: ErrNoTeamID}}},
		{name: "an ad-hoc helper is refused", want: ErrNoTeamID,
			signer: fakeSigner{ids: signedTree(nil), errs: map[string]error{helper: ErrNoTeamID}}},
		{name: "a helper signed Apple Development is refused", want: ErrNotDeveloperID,
			signer: fakeSigner{ids: signedTree(nil), notDevID: map[string]bool{helper: true}}},
		{name: "an ad-hoc tree over an ad-hoc install is refused", want: ErrNoTeamID,
			signer: fakeSigner{errs: adHocTree(Config{}.withDefaults().installedBinary())}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, cfg := stagedFixture()
			cfg.RequireTeamSignature = true
			cfg.Signer = tc.signer
			entries, err := checkStagingTree(cfg.StagingFS, cfg.FromStagingDir)
			if err != nil {
				t.Fatalf("checkStagingTree = %v", err)
			}
			err = requireTeamSignatures(context.Background(), cfg, entries)
			if tc.want != nil {
				if !errors.Is(err, tc.want) || !strings.Contains(err.Error(), "--require-team-signature") {
					t.Fatalf("requireTeamSignatures = %v, want %v naming the flag", err, tc.want)
				}
				if err := preflightFromStaging(context.Background(), &cfg); !errors.Is(err, tc.want) {
					t.Fatalf("preflightFromStaging = %v, want %v", err, tc.want)
				}
				return
			}
			if err != nil {
				t.Fatalf("requireTeamSignatures = %v, want accepted", err)
			}
			if err := preflightFromStaging(context.Background(), &cfg); err != nil {
				t.Fatalf("preflightFromStaging = %v, want accepted", err)
			}
		})
	}
	t.Run("refused on a plain install", func(t *testing.T) {
		t.Parallel()
		cfg := Config{StagingOptions: StagingOptions{RequireTeamSignature: true}}.withDefaults()
		if err := preflightFromStaging(context.Background(), &cfg); err == nil {
			t.Fatal("preflightFromStaging accepted RequireTeamSignature without a staging directory")
		}
	})
}

// TestCompareReleaseVersions pins the exported comparator the managed update
// uses for its downgrade check.
func TestCompareReleaseVersions(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		a, b string
		cmp  int
		ok   bool
	}{
		{"v0.2.0", "0.2.0", 0, true},
		{"v0.1.9", "v0.2.0", -1, true},
		{"v0.2.0", "v0.2.0-rc.1", 1, true},
		{"dev", "v0.2.0", 0, false},
	} {
		cmp, ok := CompareReleaseVersions(tc.a, tc.b)
		if cmp != tc.cmp || ok != tc.ok {
			t.Errorf("CompareReleaseVersions(%q, %q) = %d, %v; want %d, %v", tc.a, tc.b, cmp, ok, tc.cmp, tc.ok)
		}
	}
}

// TestReadBinaryVersion pins how the installed binary's version is read: the
// binary's own `version --short` answer wins, so a -trimpath release build
// (no recorded -ldflags, so the module pseudo-version in its build info)
// reports its real release version; an older binary that prints the full
// report is read from its first line; and only a run that gives no answer
// falls back to the build information.
func TestReadBinaryVersion(t *testing.T) {
	t.Parallel()
	trimpath := &debug.BuildInfo{Main: debug.Module{Path: "k3sm.io/k3sm", Version: "v0.1.8-0.20261016044636-182e77c2731a"},
		Settings: []debug.BuildSetting{{Key: "-trimpath", Value: "true"}}}
	readBI := func(string) (*debug.BuildInfo, error) { return trimpath, nil }
	answer := func(out string, err error) versionRunner {
		return func(_ context.Context, path string) ([]byte, error) {
			if path != "/Library/k3sm/k3sm" {
				t.Errorf("ran %s", path)
			}
			return []byte(out), err
		}
	}
	for _, tc := range []struct {
		name string
		run  versionRunner
		want string
	}{
		{"the binary's --short answer", answer("0.1.8-rc.0\n", nil), "0.1.8-rc.0"},
		{"an older binary's full report", answer("k3sm 0.1.8-rc.0\n  commit:        182e77c\n  go:            go1.27.2\n", nil), "0.1.8-rc.0"},
		{"a failed run falls back to the build info", answer("", errors.New("exit status 2")), "v0.1.8-0.20261016044636-182e77c2731a"},
		{"empty output falls back", answer("", nil), "v0.1.8-0.20261016044636-182e77c2731a"},
		{"output over the cap falls back", answer(strings.Repeat("a", maxVersionOutput+1), nil), "v0.1.8-0.20261016044636-182e77c2731a"},
		{"no runner reads the build info", nil, "v0.1.8-0.20261016044636-182e77c2731a"},
	} {
		got, err := readBinaryVersion("/Library/k3sm/k3sm", tc.run, readBI)
		if err != nil || got != tc.want {
			t.Errorf("%s: readBinaryVersion = %q, %v; want %q", tc.name, got, err, tc.want)
		}
	}
	for _, bad := range []string{"0.1.8\nnoise\n", "version 0.1.8\n"} {
		if _, err := readBinaryVersion("/Library/k3sm/k3sm", answer(bad, nil), readBI); !errors.Is(err, ErrMalformedVersion) {
			t.Errorf("answer %q: err = %v, want ErrMalformedVersion", bad, err)
		}
	}
	if _, ok := parseReleaseVersion("v0.1.8-0.20261016044636-182e77c2731a"); ok {
		t.Error("the pseudo-version parsed as a release, so the fallback test proves nothing")
	}
	if _, ok := parseReleaseVersion("0.1.8-rc.0"); !ok {
		t.Error("the --short answer is not a release version")
	}
	failing := func(string) (*debug.BuildInfo, error) { return nil, errors.New("not a Go binary") }
	if _, err := readBinaryVersion("/Library/k3sm/k3sm", answer("", errors.New("exec format error")), failing); err == nil {
		t.Error("no run answer and no build info returned no error")
	}
}

// TestPreflightChecksSignaturesBeforeRunningTheInstalledBinary pins the
// order: the installed binary is executed (BinaryVersion) only after every
// signing check has run, and a tree the signing checks refuse never gets
// that far.
func TestPreflightChecksSignaturesBeforeRunningTheInstalledBinary(t *testing.T) {
	t.Parallel()
	t.Run("every TeamID call precedes BinaryVersion", func(t *testing.T) {
		t.Parallel()
		sfs, cfg := stagedFixture()
		installed := cfg.installedBinary()
		sfs.versions[installed] = "0.3.0"
		cfg.Signer = fakeSigner{ids: signedTree(map[string]string{installed: testTeamID}), rec: sfs}
		cfg.RequireTeamSignature = true
		if err := preflightFromStaging(context.Background(), &cfg); err != nil {
			t.Fatal(err)
		}
		lastTeam, version := -1, -1
		for i, c := range sfs.calls {
			switch {
			case strings.HasPrefix(c, "TeamID:"):
				lastTeam = i
			case c == "BinaryVersion:"+installed && version < 0:
				version = i
			}
		}
		if lastTeam < 0 || version < 0 || lastTeam > version {
			t.Errorf("TeamID last at %d, BinaryVersion at %d; calls = %v", lastTeam, version, sfs.calls)
		}
	})
	t.Run("a refused signature never runs the installed binary", func(t *testing.T) {
		t.Parallel()
		sfs, cfg := stagedFixture()
		installed := cfg.installedBinary()
		sfs.versions[installed] = "0.3.0"
		cfg.Signer = fakeSigner{ids: signedTree(nil), errs: map[string]error{testStagedExe: ErrNoTeamID}, rec: sfs}
		cfg.RequireTeamSignature = true
		if err := preflightFromStaging(context.Background(), &cfg); err == nil {
			t.Fatal("an unsigned staged k3sm was accepted")
		}
		for _, c := range sfs.calls {
			if strings.HasPrefix(c, "BinaryVersion:") {
				t.Errorf("the installed binary was run after a refused signature; calls = %v", sfs.calls)
			}
		}
	})
}

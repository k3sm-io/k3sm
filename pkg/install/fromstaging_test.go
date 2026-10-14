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
	calls    []string
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
	if err := f.verErr[path]; err != nil {
		return "", err
	}
	if v, ok := f.versions[path]; ok {
		return v, nil
	}
	return "", fmt.Errorf("open %s: %w", path, fs.ErrNotExist)
}

// fakeSigner answers TeamID from a table; a path with no entry is absent.
type fakeSigner struct {
	ids  map[string]string
	errs map[string]error
}

func (s fakeSigner) TeamID(path string) (string, error) {
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

// stagedFixture is a staging tree that passes the predicate, and the Config
// that installs from it. Each test case breaks one thing.
func stagedFixture() (*fakeStagingFS, Config) {
	sfs := &fakeStagingFS{content: map[string][]byte{}, versions: map[string]string{}, verErr: map[string]error{}}
	sfs.put("/Library", 0, 0, fs.ModeDir|0o755)
	sfs.put(testStagingRoot, 0, 0, fs.ModeDir|0o700)
	sfs.put(testStagedDir, 0, 0, fs.ModeDir|0o700)
	for _, d := range []string{testStagedApp, testStagedApp + "/Contents", testStagedApp + "/Contents/Resources", testPayloadDir, testPayloadDir + "/bin"} {
		sfs.put(d, 0, 0, fs.ModeDir|0o755)
	}
	for _, f := range []string{"k3sm", ExecShimName, PathShimName, DNSShimName, VMHostName, "bin/kine"} {
		sfs.put(filepath.Join(testPayloadDir, f), 0, 0, 0o755)
	}
	cfg := Config{
		BinarySource: testStagedExe,
		TargetUser:   "admin",
		StagingOptions: StagingOptions{
			FromStagingDir: testStagedDir,
			Executable:     testStagedExe,
			StagedVersion:  "v0.4.0",
			StagingFS:      sfs,
			Signer:         fakeSigner{ids: map[string]string{testStagedExe: testTeamID}},
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
			err := preflightFromStaging(&cfg)
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
		if err := preflightFromStaging(&cfg); err == nil {
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
			err := preflightFromStaging(&cfg)
			removed := slices.Contains(sfs.calls, "RemoveFile:"+tc.path)
			if removed != tc.wantRemove {
				t.Errorf("token file removed = %v, want %v (calls %v)", removed, tc.wantRemove, sfs.calls)
			}
			if tc.want == "" {
				if err != nil {
					t.Fatalf("preflightFromStaging = %v, want accepted", err)
				}
				if cfg.stagedToken == nil || *cfg.stagedToken != testTokenText {
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
		cfg.Signer = fakeSigner{ids: map[string]string{testStagedExe: testTeamID, cfg.installedBinary(): "ZZZZZ99999"}}
		if err := preflightFromStaging(&cfg); !errors.Is(err, ErrTeamIDMismatch) {
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
	cfg.stagedToken = &token
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
				cfg.Signer = fakeSigner{ids: map[string]string{testStagedExe: testTeamID, cfg.installedBinary(): testTeamID}}
			}
			if tc.readErr != nil {
				sfs.verErr[cfg.installedBinary()] = tc.readErr
			}
			err := preflightFromStaging(&cfg)
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

// TestFromStagingTeamIDContinuity pins the signing continuity check: a first
// install records the staged Team ID, an update needs the installed binary's
// Team ID to match, and an ad-hoc or unsigned binary on either side refuses.
func TestFromStagingTeamIDContinuity(t *testing.T) {
	t.Parallel()
	installed := Config{}.withDefaults().installedBinary()
	cases := []struct {
		name   string
		signer fakeSigner
		want   error
	}{
		{name: "first install records the Team ID", signer: fakeSigner{ids: map[string]string{testStagedExe: testTeamID}}},
		{name: "update by the same team", signer: fakeSigner{ids: map[string]string{testStagedExe: testTeamID, installed: testTeamID}}},
		{name: "update by another team refused", want: ErrTeamIDMismatch,
			signer: fakeSigner{ids: map[string]string{testStagedExe: testTeamID, installed: "ZZZZZ99999"}}},
		{name: "ad-hoc installed binary refused", want: ErrTeamIDMismatch,
			signer: fakeSigner{ids: map[string]string{testStagedExe: testTeamID}, errs: map[string]error{installed: ErrNoTeamID}}},
		{name: "ad-hoc staged binary refused", want: ErrNoTeamID,
			signer: fakeSigner{errs: map[string]error{testStagedExe: ErrNoTeamID}}},
		{name: "unreadable installed signature refused", want: errSignatureUnreadable,
			signer: fakeSigner{ids: map[string]string{testStagedExe: testTeamID}, errs: map[string]error{installed: errSignatureUnreadable}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, cfg := stagedFixture()
			cfg.Signer = tc.signer
			err := preflightFromStaging(&cfg)
			if tc.want != nil {
				if !errors.Is(err, tc.want) {
					t.Fatalf("preflightFromStaging = %v, want %v", err, tc.want)
				}
				if cfg.stagedTeamID != "" {
					t.Errorf("a refused install carried Team ID %q forward", cfg.stagedTeamID)
				}
				return
			}
			if err != nil {
				t.Fatalf("preflightFromStaging = %v, want accepted", err)
			}
			if cfg.stagedTeamID != testTeamID {
				t.Fatalf("stagedTeamID = %q, want %q", cfg.stagedTeamID, testTeamID)
			}
			f := &fakeSystem{}
			if err := recordTeamID(f, cfg); err != nil {
				t.Fatalf("recordTeamID: %v", err)
			}
			want := fmt.Sprintf("WriteRootOnlyFile:%s:%#o", cfg.swapDir()+"/"+TeamIDRecordName, teamIDRecordMode)
			if !slices.Contains(f.calls, want) {
				t.Errorf("record not staged into the swap tree: %v, want %s", f.calls, want)
			}
		})
	}
	t.Run("a plain install records nothing", func(t *testing.T) {
		t.Parallel()
		f := &fakeSystem{}
		if err := recordTeamID(f, Config{}.withDefaults()); err != nil || len(f.calls) != 0 {
			t.Errorf("recordTeamID on a plain install = %v, calls %v", err, f.calls)
		}
	})
}

var errSignatureUnreadable = errors.New("codesign failed")

// TestParseTeamIdentifier pins the codesign output parsing.
func TestParseTeamIdentifier(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name, out, want string
		wantErr         error
	}{
		{name: "developer id", out: "Executable=/x/k3sm\nIdentifier=io.k3sm.k3sm\nAuthority=Developer ID Application: k3sm (ABCDE12345)\nTeamIdentifier=ABCDE12345\n", want: "ABCDE12345"},
		{name: "ad-hoc", out: "Executable=/x/k3sm\nSignature=adhoc\nTeamIdentifier=not set\n", wantErr: ErrNoTeamID},
		{name: "no line", out: "Executable=/x/k3sm\n", wantErr: ErrNoTeamID},
		{name: "malformed", out: "TeamIdentifier=abc\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := parseTeamIdentifier(tc.out)
			switch {
			case tc.want != "":
				if err != nil || got != tc.want {
					t.Fatalf("parseTeamIdentifier = %q, %v, want %q", got, err, tc.want)
				}
			case tc.wantErr != nil:
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("parseTeamIdentifier = %q, %v, want %v", got, err, tc.wantErr)
				}
			default:
				if err == nil {
					t.Fatalf("parseTeamIdentifier accepted %q", tc.out)
				}
			}
		})
	}
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

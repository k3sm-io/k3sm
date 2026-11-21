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

package main

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"k3sm.io/runtimed/pkg/hostshare"
)

// exposeFixture runs the expose verb against a node file held in memory, a
// real exposure tree under the test's temp dir, and a recording ACL seam.
type exposeFixture struct {
	stored         []byte
	writes         int
	euid           int
	dataRoot       string
	revoked        []string
	revokeErr      error
	stdout, stderr bytes.Buffer
}

var exposeAccounts = map[string]account{
	"miko":   {name: "miko", uid: 501, gid: 20},
	"ana":    {name: "ana", uid: 502, gid: 20},
	"_k3sm":  {name: "_k3sm", uid: 271, gid: 20},
	"daemon": {name: "daemon", uid: 1, gid: 1},
}

func newExposeFixture(t *testing.T, file string) *exposeFixture {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return &exposeFixture{stored: []byte(file), dataRoot: root}
}

func (f *exposeFixture) env() exposeEnv {
	return exposeEnv{
		file:     "/node/k3sm.host-shares",
		dataRoot: f.dataRoot,
		euid:     func() int { return f.euid },
		readFile: func(string) (hostshare.File, error) { return hostshare.ParseFile(bytes.NewReader(f.stored)) },
		write: func(_ string, b []byte) error {
			f.writes++
			f.stored = b
			return nil
		},
		lookup: func(name string) (account, error) {
			if a, ok := exposeAccounts[name]; ok {
				return a, nil
			}
			return account{}, fmt.Errorf("user: unknown user %s", name)
		},
		leaves: exposureLeaves,
		revoke: func(dir string, uid uint32) error {
			f.revoked = append(f.revoked, fmt.Sprintf("%s uid=%d", strings.TrimPrefix(dir, f.dataRoot), uid))
			return f.revokeErr
		},
		stdout: &f.stdout,
		stderr: &f.stderr,
	}
}

func (f *exposeFixture) run(args ...string) int { return runExposeWith(args, f.env()) }

// grants is the stored file's grant lines.
func (f *exposeFixture) grants(t *testing.T) []string {
	t.Helper()
	nf, err := hostshare.ParseFile(bytes.NewReader(f.stored))
	if err != nil {
		t.Fatalf("stored file does not parse: %v\n%s", err, f.stored)
	}
	var out []string
	for _, g := range nf.Exposes {
		out = append(out, g.String())
	}
	slices.Sort(out)
	return out
}

func (f *exposeFixture) mkdir(t *testing.T, rel string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(f.dataRoot, rel), 0o755); err != nil {
		t.Fatal(err)
	}
}

const exposeSeed = "rw /private/tmp/code\nexpose uid=501 user=miko namespaces=apps access=read\n"

// TestExposeAllow pins `k3sm expose allow`: it writes a grant line, merges
// namespaces into the account's existing grant, sets the access only when
// asked, keeps the file's other lines, and refuses a system account, an
// unknown account and a caller that is not root.
func TestExposeAllow(t *testing.T) {
	for _, tc := range []struct {
		name   string
		seed   string
		euid   int
		args   []string
		code   int
		want   []string
		stderr string
	}{
		{"new_grant_is_read", "", 0, []string{"--user", "ana", "--namespace", "tools"}, 0,
			[]string{"expose uid=502 user=ana namespaces=tools access=read"}, ""},
		{"merges_namespaces_keeps_access", exposeSeed, 0, []string{"--user", "miko", "--namespace", "yurei-system,apps"}, 0,
			[]string{"expose uid=501 user=miko namespaces=apps,yurei-system access=read"}, ""},
		{"sets_access", exposeSeed, 0, []string{"--user", "miko", "--namespace", "apps", "--access", "read-write"}, 0,
			[]string{"expose uid=501 user=miko namespaces=apps access=read-write"}, ""},
		{"bad_access", exposeSeed, 0, []string{"--user", "miko", "--namespace", "apps", "--access", "write"}, 1,
			[]string{"expose uid=501 user=miko namespaces=apps access=read"}, "not read or read-write"},
		{"bad_namespace", "", 0, []string{"--user", "miko", "--namespace", "Apps"}, 1, nil, "not a namespace name"},
		{"system_uid", "", 0, []string{"--user", "daemon", "--namespace", "apps"}, 1, nil, "system account (uid 1)"},
		{"service_user", "", 0, []string{"--user", "_k3sm", "--namespace", "apps"}, 1, nil, "system account (uid 271)"},
		{"unknown_user", "", 0, []string{"--user", "ghost", "--namespace", "apps"}, 1, nil, "unknown user ghost"},
		{"not_root", exposeSeed, 501, []string{"--user", "miko", "--namespace", "tools"}, 3,
			[]string{"expose uid=501 user=miko namespaces=apps access=read"}, "run as root"},
		{"no_namespace", "", 0, []string{"--user", "miko"}, 2, nil, "--namespace is required"},
		{"no_user", "", 0, []string{"--namespace", "apps"}, 2, nil, "--user is required"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newExposeFixture(t, tc.seed)
			f.euid = tc.euid
			if code := f.run(append([]string{"allow"}, tc.args...)...); code != tc.code {
				t.Fatalf("exit = %d, want %d; stderr %q", code, tc.code, f.stderr.String())
			}
			if got := f.grants(t); !slices.Equal(got, tc.want) {
				t.Errorf("grants = %q, want %q", got, tc.want)
			}
			if !strings.Contains(f.stderr.String(), tc.stderr) {
				t.Errorf("stderr %q lacks %q", f.stderr.String(), tc.stderr)
			}
			if tc.code != 0 && f.writes != 0 {
				t.Errorf("a refused allow wrote the file %d times", f.writes)
			}
			if tc.code == 0 {
				if !strings.Contains(f.stdout.String(), tc.want[0]) {
					t.Errorf("stdout %q does not print the line it wrote", f.stdout.String())
				}
				if tc.seed != "" && !strings.Contains(string(f.stored), "rw /private/tmp/code") {
					t.Errorf("the share line was lost:\n%s", f.stored)
				}
			}
		})
	}
}

// TestExposeRevoke pins `k3sm expose revoke`: it removes the named
// namespaces (or the whole grant), then strips the account's entries from
// every live exposure directory in the affected namespaces and from nothing
// else; a failure there is an error exit.
func TestExposeRevoke(t *testing.T) {
	seed := "expose uid=501 user=miko namespaces=apps,tools access=read-write\nexpose uid=502 user=ana namespaces=apps access=read\n"
	layout := func(t *testing.T, f *exposeFixture) {
		f.mkdir(t, "expose/apps/web-0/sockets")
		f.mkdir(t, "expose/apps/web-0/sockets/deeper")
		f.mkdir(t, "expose/apps/web-1/state")
		f.mkdir(t, "expose/tools/cli-0/out")
		f.mkdir(t, "expose/other/x-0/v")
		if err := os.Symlink("/etc", filepath.Join(f.dataRoot, "expose/apps/link")); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(f.dataRoot, "expose/apps/web-0/file"), nil, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	for _, tc := range []struct {
		name      string
		euid      int
		args      []string
		revokeErr error
		code      int
		want      []string
		revoked   []string
		stderr    string
	}{
		{"one_namespace", 0, []string{"--user", "miko", "--namespace", "apps"}, nil, 0,
			[]string{"expose uid=501 user=miko namespaces=tools access=read-write", "expose uid=502 user=ana namespaces=apps access=read"},
			[]string{"/expose/apps/web-0/sockets uid=501", "/expose/apps/web-1/state uid=501"}, ""},
		{"whole_grant", 0, []string{"--user", "miko"}, nil, 0,
			[]string{"expose uid=502 user=ana namespaces=apps access=read"},
			[]string{"/expose/apps/web-0/sockets uid=501", "/expose/apps/web-1/state uid=501", "/expose/tools/cli-0/out uid=501"}, ""},
		{"namespace_with_no_exposures", 0, []string{"--user", "ana", "--namespace", "apps"}, nil, 0,
			[]string{"expose uid=501 user=miko namespaces=apps,tools access=read-write"},
			[]string{"/expose/apps/web-0/sockets uid=502", "/expose/apps/web-1/state uid=502"}, ""},
		// With no grant left, revoke still sweeps the account's entries, so a
		// revoke that failed half-way can be run again to finish.
		{"no_grant_left_sweeps", 0, []string{"--user", "ana", "--namespace", "tools"}, nil, 0,
			[]string{"expose uid=501 user=miko namespaces=apps,tools access=read-write", "expose uid=502 user=ana namespaces=apps access=read"},
			[]string{"/expose/tools/cli-0/out uid=502"}, ""},
		{"no_grant_no_account", 0, []string{"--user", "nosuch", "--namespace", "tools"}, nil, 1,
			[]string{"expose uid=501 user=miko namespaces=apps,tools access=read-write", "expose uid=502 user=ana namespaces=apps access=read"},
			nil, "no exposure grant to nosuch"},
		{"acl_failure_is_an_error", 0, []string{"--user", "miko", "--namespace", "tools"}, errors.New("EPERM"), 1,
			[]string{"expose uid=501 user=miko namespaces=apps access=read-write", "expose uid=502 user=ana namespaces=apps access=read"},
			[]string{"/expose/tools/cli-0/out uid=501"}, "removing miko's access"},
		// A failure on one leaf never stops the others: every live exposure
		// is attempted, and the failure is the exit status.
		{"acl_failure_attempts_every_leaf", 0, []string{"--user", "miko"}, errors.New("EPERM"), 1,
			[]string{"expose uid=502 user=ana namespaces=apps access=read"},
			[]string{"/expose/apps/web-0/sockets uid=501", "/expose/apps/web-1/state uid=501", "/expose/tools/cli-0/out uid=501"}, "run the same revoke again"},
		{"not_root", 501, []string{"--user", "miko"}, nil, 3,
			[]string{"expose uid=501 user=miko namespaces=apps,tools access=read-write", "expose uid=502 user=ana namespaces=apps access=read"},
			nil, "run as root"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newExposeFixture(t, seed)
			layout(t, f)
			f.euid = tc.euid
			f.revokeErr = tc.revokeErr
			if code := f.run(append([]string{"revoke"}, tc.args...)...); code != tc.code {
				t.Fatalf("exit = %d, want %d; stderr %q", code, tc.code, f.stderr.String())
			}
			if got := f.grants(t); !slices.Equal(got, tc.want) {
				t.Errorf("grants = %q, want %q", got, tc.want)
			}
			if !slices.Equal(f.revoked, tc.revoked) {
				t.Errorf("revoked = %q, want %q", f.revoked, tc.revoked)
			}
			if !strings.Contains(f.stderr.String(), tc.stderr) {
				t.Errorf("stderr %q lacks %q", f.stderr.String(), tc.stderr)
			}
		})
	}
	t.Run("removed_account_by_recorded_name", func(t *testing.T) {
		f := newExposeFixture(t, "expose uid=503 user=gone namespaces=apps access=read\n")
		f.mkdir(t, "expose/apps/web-0/sockets")
		if code := f.run("revoke", "--user", "gone"); code != 0 {
			t.Fatalf("exit = %d; stderr %q", code, f.stderr.String())
		}
		if got := f.grants(t); len(got) != 0 {
			t.Errorf("grants = %q, want none", got)
		}
		if want := []string{"/expose/apps/web-0/sockets uid=503"}; !slices.Equal(f.revoked, want) {
			t.Errorf("revoked = %q, want %q", f.revoked, want)
		}
	})
}

// TestExposeList pins `k3sm expose list`: the grants, with no root needed.
func TestExposeList(t *testing.T) {
	for _, tc := range []struct {
		name, seed, want string
	}{
		{"grants", exposeSeed, "expose uid=501 user=miko namespaces=apps access=read\n"},
		{"none", "rw /private/tmp/code\n", "no exposure grants"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newExposeFixture(t, tc.seed)
			f.euid = 501
			if code := f.run("list"); code != 0 {
				t.Fatalf("exit = %d; stderr %q", code, f.stderr.String())
			}
			if !strings.Contains(f.stdout.String(), tc.want) {
				t.Errorf("stdout %q lacks %q", f.stdout.String(), tc.want)
			}
			if f.writes != 0 {
				t.Errorf("list wrote the file")
			}
		})
	}
	t.Run("usage", func(t *testing.T) {
		f := newExposeFixture(t, "")
		if code := f.run("--help"); code != 0 || !strings.Contains(f.stdout.String(), "sudo k3sm expose allow --user <name>") {
			t.Fatalf("help exit %d, stdout %q", code, f.stdout.String())
		}
		if code := f.run("frob"); code != 2 {
			t.Fatalf("unknown verb exit = %d, want 2", code)
		}
	})
}

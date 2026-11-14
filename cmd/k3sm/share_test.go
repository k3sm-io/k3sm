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
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"k3sm.io/k3sm/internal/hostacl"
	"k3sm.io/runtimed/pkg/hostshare"
)

// fakeACL records what the share verb asked of the permission half.
type fakeACL struct{ calls []string }

func (f *fakeACL) GrantTree(r string, a hostacl.Access, p, o uint32) (hostacl.Report, error) {
	f.calls = append(f.calls, fmt.Sprintf("grant-tree %s %d pod=%d owner=%d", r, a, p, o))
	return hostacl.Report{Dirs: 1, Files: 2}, nil
}
func (f *fakeACL) RevokeTree(r string, p, o uint32) (hostacl.Report, error) {
	f.calls = append(f.calls, fmt.Sprintf("revoke-tree %s pod=%d owner=%d", r, p, o))
	return hostacl.Report{Dirs: 1}, nil
}
func (f *fakeACL) GrantSocket(p string, u uint32) (bool, error) {
	f.calls = append(f.calls, "grant-socket "+p)
	return true, nil
}
func (f *fakeACL) RevokeSocket(p string, u uint32) (bool, error) {
	f.calls = append(f.calls, "revoke-socket "+p)
	return true, nil
}
func (f *fakeACL) GrantSearch(d string, u uint32) (bool, error) {
	f.calls = append(f.calls, "grant-search "+d)
	return true, nil
}
func (f *fakeACL) RevokeSearch(d string, u uint32) (bool, error) {
	f.calls = append(f.calls, "revoke-search "+d)
	return true, nil
}
func (f *fakeACL) Allowed(string, uint32) (hostacl.Perm, error) { return hostacl.Search, nil }

func (f *fakeACL) did(prefix string) bool {
	for _, c := range f.calls {
		if strings.HasPrefix(c, prefix) {
			return true
		}
	}
	return false
}

// shareFixture runs the verb against a node file held in memory and real
// directories under /private/tmp (which the share rules allow), owned by the
// test user, who is also the delegated user.
type shareFixture struct {
	base, nodeFile, prefix string
	me                     account
	stored                 []byte
	acl                    *fakeACL
	removedDirs            []string
}

func newShareFixture(t *testing.T) *shareFixture {
	t.Helper()
	if os.Getuid() < hostshare.MinDelegateUID {
		t.Skip("needs an ordinary user account")
	}
	base, err := os.MkdirTemp("/private/tmp", "k3sm-share-")
	if err != nil {
		t.Skip(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(base) })
	f := &shareFixture{
		base: base, nodeFile: filepath.Join(base, "k3sm.host-shares"), prefix: filepath.Join(base, "Code"),
		me:  account{name: "dev", uid: uint32(os.Getuid()), gid: uint32(os.Getgid())},
		acl: &fakeACL{},
	}
	for _, d := range []string{filepath.Join(f.prefix, "app"), filepath.Join(base, "Other")} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	return f
}

func (f *shareFixture) readUser(_ string, uid uint32) ([]hostshare.Entry, error) {
	b, err := os.ReadFile(hostshare.UserFile(f.nodeFile, uid))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return hostshare.Parse(bytes.NewReader(b))
}

// effective is hostshare.LoadEffective without the root-ownership checks the
// test cannot meet: the delegated entries pass only CheckDelegated.
func (f *shareFixture) effective(string) (hostshare.Effective, error) {
	nf, err := hostshare.ParseFile(bytes.NewReader(f.stored))
	if err != nil {
		return hostshare.Effective{}, err
	}
	eff := hostshare.Effective{Entries: nf.Entries, Delegations: nf.Delegations, Owners: map[hostshare.Entry]uint32{}}
	for _, d := range nf.Delegations {
		entries, err := f.readUser("", d.UID)
		if err != nil {
			eff.Dropped = append(eff.Dropped, hostshare.Dropped{UID: d.UID, Reason: err.Error()})
			continue
		}
		for _, e := range entries {
			if err := hostshare.CheckDelegated(d, e); err != nil {
				eff.Dropped = append(eff.Dropped, hostshare.Dropped{UID: d.UID, Entry: e, Reason: err.Error()})
				continue
			}
			eff.Owners[e] = d.UID
			eff.Entries = append(eff.Entries, e)
		}
	}
	return eff, nil
}

func (f *shareFixture) env(euid int) (shareEnv, *bytes.Buffer, *bytes.Buffer) {
	var out, errb bytes.Buffer
	return shareEnv{
		file: f.nodeFile,
		euid: func() int { return euid },
		uid:  func() int { return int(f.me.uid) },
		readFile: func(string) (hostshare.File, error) {
			return hostshare.ParseFile(bytes.NewReader(f.stored))
		},
		effective:      f.effective,
		readUser:       f.readUser,
		checkDelegated: hostshare.CheckDelegated,
		write: func(p string, b []byte) error {
			if p == f.nodeFile {
				f.stored = append([]byte(nil), b...)
				return nil
			}
			return writeShareFile(p, b)
		},
		makeUserDir: func(file string, a account) error {
			return os.MkdirAll(hostshare.UserDir(file, a.uid), 0o755)
		},
		removeUserDir: func(file string, uid uint32) error {
			f.removedDirs = append(f.removedDirs, hostshare.UserDir(file, uid))
			return os.RemoveAll(hostshare.UserDir(file, uid))
		},
		lookup: func(name string) (account, error) {
			if name == "_k3sm" {
				return account{name: "_k3sm", uid: 250, gid: 20, gids: []uint32{20, 12}}, nil
			}
			if name == f.me.name {
				return f.me, nil
			}
			return account{}, fmt.Errorf("no user %q", name)
		},
		lookupUID: func(uint32) (account, error) { return f.me, nil },
		acl:       f.acl,
		stdout:    &out, stderr: &errb,
	}, &out, &errb
}

func TestShareVerb(t *testing.T) {
	t.Parallel()
	f := newShareFixture(t)
	dir := filepath.Join(f.prefix, "app")

	env, _, errb := f.env(501)
	if code := runShareWith([]string{"add", dir}, env); code != 3 {
		t.Fatalf("add as non-root with no delegation = %d (%s), want 3", code, errb)
	}
	env, out, errb := f.env(0)
	if code := runShareWith([]string{"add", dir}, env); code != 0 {
		t.Fatalf("add = %d (%s), want 0", code, errb)
	}
	if !f.acl.did("grant-tree "+dir) || !strings.Contains(out.String(), `"user:_k3sm allow list,add_file,search`) {
		t.Errorf("add did not set and print the ACL:\n%s\ncalls %v", out, f.acl.calls)
	}
	// MkdirTemp makes base 0700: the pods' user cannot pass it, and it is
	// the owner's, so add gives it search and says so.
	if !f.acl.did("grant-search "+f.base) || !strings.Contains(out.String(), "acl: "+f.base+": added \"user:_k3sm allow search\"") {
		t.Errorf("add did not give search on the owner's 0700 parent:\n%s", out)
	}
	if !strings.Contains(string(f.stored), "rw "+dir+"\n") {
		t.Errorf("stored list = %q, want an rw line for %s", f.stored, dir)
	}
	env, _, _ = f.env(0)
	if code := runShareWith([]string{"add", "--read-only", "--no-acl", dir}, env); code != 0 {
		t.Fatal("re-add as read-only failed")
	}
	if strings.Contains(string(f.stored), "rw "+dir) || !strings.Contains(string(f.stored), "ro "+dir) {
		t.Errorf("re-add did not replace the entry: %q", f.stored)
	}
	env, out, _ = f.env(501)
	if code := runShareWith([]string{"ls"}, env); code != 0 || !strings.Contains(out.String(), "ro "+dir+"\t(root)") {
		t.Errorf("ls = %d %q", code, out)
	}
	for _, args := range [][]string{
		{"add", "/Users"},
		{"add", filepath.Join(f.base, "missing")},
		{"add", "--socket", dir},
		{"remove", filepath.Join(f.base, "never")},
	} {
		env, _, _ = f.env(0)
		if code := runShareWith(args, env); code != 1 {
			t.Errorf("share %v = %d, want 1", args, code)
		}
	}
	env, _, _ = f.env(0)
	if code := runShareWith([]string{"add", "--read-only", "--socket", dir}, env); code != 2 {
		t.Errorf("conflicting flags = %d, want 2", code)
	}
	f.acl.calls = nil
	env, _, _ = f.env(0)
	if code := runShareWith([]string{"remove", dir}, env); code != 0 {
		t.Fatal("remove failed")
	}
	if !f.acl.did("revoke-tree " + dir) {
		t.Errorf("remove did not revoke the ACL: %v", f.acl.calls)
	}
	if got, _ := hostshare.ParseFile(bytes.NewReader(f.stored)); len(got.Entries) != 0 {
		t.Errorf("after remove the list holds %v", got)
	}
}

func TestShareDelegation(t *testing.T) {
	t.Parallel()
	f := newShareFixture(t)
	app := filepath.Join(f.prefix, "app")

	// Only root delegates.
	env, _, _ := f.env(int(f.me.uid))
	if code := runShareWith([]string{"delegate", "--user", "dev", f.prefix}, env); code != 3 {
		t.Errorf("delegate as non-root = %d, want 3", code)
	}
	for _, args := range [][]string{
		{"delegate", f.prefix}, // no --user
		{"delegate", "--user", "dev", "--modes", "rwx", f.prefix}, // bad mode
	} {
		env, _, _ = f.env(0)
		if code := runShareWith(args, env); code == 0 {
			t.Errorf("share %v = 0, want a refusal", args)
		}
	}
	// A prefix the user does not own is refused: they could share only
	// what they own anyway.
	env, _, _ = f.env(0)
	if code := runShareWith([]string{"delegate", "--user", "dev", "/private/tmp"}, env); code != 1 {
		t.Errorf("delegate of a root-owned prefix = %d, want 1", code)
	}
	env, out, errb := f.env(0)
	if code := runShareWith([]string{"delegate", "--user", "dev", "--modes", "rw,socket", f.prefix}, env); code != 0 {
		t.Fatalf("delegate = %d (%s)", code, errb)
	}
	if !strings.Contains(string(f.stored), fmt.Sprintf("delegate uid=%d user=dev modes=rw,socket %s\n", f.me.uid, f.prefix)) {
		t.Errorf("stored = %q, want the delegate line", f.stored)
	}
	if !strings.Contains(out.String(), "no sudo") {
		t.Errorf("delegate output = %q", out)
	}

	// The delegated user adds under the prefix, as themselves.
	user := func() (shareEnv, *bytes.Buffer, *bytes.Buffer) { return f.env(int(f.me.uid)) }
	f.acl.calls = nil
	env, out, errb = user()
	if code := runShareWith([]string{"add", app}, env); code != 0 {
		t.Fatalf("delegated add = %d (%s)", code, errb)
	}
	if got, _ := f.readUser("", f.me.uid); len(got) != 1 || got[0] != (hostshare.Entry{Mode: hostshare.ModeReadWrite, Path: app}) {
		t.Errorf("user file = %v, want rw %s", got, app)
	}
	if !strings.Contains(string(f.stored), "delegate") || strings.Contains(string(f.stored), "rw "+app) {
		t.Errorf("a delegated add wrote the root-owned file: %q", f.stored)
	}
	if !f.acl.did(fmt.Sprintf("grant-tree %s 0 pod=250 owner=%d", app, f.me.uid)) {
		t.Errorf("delegated add did not set the ACL as the owner: %v", f.acl.calls)
	}
	sock := filepath.Join(f.prefix, "q.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	env, _, errb = user()
	if code := runShareWith([]string{"add", "--socket", sock}, env); code != 0 || !f.acl.did("grant-socket "+sock) {
		t.Errorf("delegated socket add = %d (%s), calls %v", code, errb, f.acl.calls)
	}
	if err := os.Symlink(filepath.Join(f.base, "Other"), filepath.Join(f.prefix, "out")); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		args []string
		want int
	}{
		{[]string{"add", filepath.Join(f.base, "Other")}, 3},  // outside the prefix
		{[]string{"add", filepath.Join(f.prefix, "out")}, 3},  // a symlink resolving outside
		{[]string{"add", filepath.Join(f.prefix, ".git")}, 1}, // a dot directory inside
		{[]string{"add", "--read-only", app}, 1},              // ro is not a delegated mode
		{[]string{"undelegate", "--user", "dev"}, 3},          // root only
		{[]string{"remove", filepath.Join(f.prefix, "nope")}, 1},
	} {
		env, _, _ = user()
		if code := runShareWith(tc.args, env); code != tc.want {
			t.Errorf("delegated share %v = %d, want %d", tc.args, code, tc.want)
		}
	}

	// Editing the user file by hand admits nothing outside the prefix.
	body := hostshare.FormatUser([]hostshare.Entry{{Mode: hostshare.ModeReadWrite, Path: app}, {Mode: hostshare.ModeReadWrite, Path: filepath.Join(f.base, "Other")}})
	if err := writeShareFile(hostshare.UserFile(f.nodeFile, f.me.uid), body); err != nil {
		t.Fatal(err)
	}
	env, out, _ = user()
	if code := runShareWith([]string{"list"}, env); code != 0 {
		t.Fatal("list failed")
	}
	if !strings.Contains(out.String(), "rw "+app+"\t(added by dev") || !strings.Contains(out.String(), "not admitted (uid") ||
		strings.Contains(out.String(), "rw "+filepath.Join(f.base, "Other")+"\t") {
		t.Errorf("list after tampering =\n%s", out)
	}

	f.acl.calls = nil
	env, _, errb = user()
	if code := runShareWith([]string{"remove", app}, env); code != 0 || !f.acl.did("revoke-tree "+app) {
		t.Errorf("delegated remove = %d (%s), calls %v", code, errb, f.acl.calls)
	}

	// Root takes the delegation back: the user's file goes, and the user's
	// remaining shares are revoked.
	env, _, _ = user()
	if code := runShareWith([]string{"add", "--no-acl", app}, env); code != 0 {
		t.Fatal("re-add failed")
	}
	f.acl.calls = nil
	env, out, errb = f.env(0)
	if code := runShareWith([]string{"undelegate", "--user", "dev"}, env); code != 0 {
		t.Fatalf("undelegate = %d (%s)", code, errb)
	}
	if strings.Contains(string(f.stored), "delegate") || len(f.removedDirs) != 1 {
		t.Errorf("after undelegate: stored %q, removed %v", f.stored, f.removedDirs)
	}
	if !f.acl.did("revoke-tree " + app) {
		t.Errorf("undelegate did not revoke the user's shares: %v\n%s", f.acl.calls, out)
	}
	env, _, _ = user()
	if code := runShareWith([]string{"add", app}, env); code != 3 {
		t.Errorf("add after undelegate = %d, want 3", code)
	}
}

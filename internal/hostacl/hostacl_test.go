//go:build darwin && cgo

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

package hostacl

import (
	"net"
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

// podUID stands in for _k3sm: nobody (-2), which every Mac resolves.
const podUID = 4294967294

func tree(t *testing.T) (root, outside string) {
	t.Helper()
	base, err := os.MkdirTemp("/tmp", "acl")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(base) })
	base, _ = filepath.EvalSymlinks(base)
	root = filepath.Join(base, "share")
	outside = filepath.Join(base, "outside")
	for _, d := range []string{filepath.Join(root, "sub"), outside} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for _, f := range []string{filepath.Join(root, "f"), filepath.Join(root, "sub", "g"), filepath.Join(outside, "secret")} {
		if err := os.WriteFile(f, nil, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root, outside
}

func has(t *testing.T, path string, bit Perm) bool {
	t.Helper()
	p, err := Allowed(path, podUID)
	if err != nil {
		t.Fatal(err)
	}
	return p&bit != 0
}

func TestGrantTreeNeverFollowsSymlinks(t *testing.T) {
	root, outside := tree(t)
	// What a pod with write access could leave behind before a re-grant.
	if err := os.Symlink(outside, filepath.Join(root, "evil")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(outside, "secret"), filepath.Join(root, "evilf")); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(filepath.Join(outside, "secret"), filepath.Join(root, "hard")); err != nil {
		t.Fatal(err)
	}
	r, err := GrantTree(root, ReadWrite, podUID, uint32(os.Getuid()))
	if err != nil {
		t.Fatal(err)
	}
	if r.Dirs != 2 || r.Files != 2 || r.Skipped["symlink"] != 2 || r.Skipped["hard-linked file"] != 1 {
		t.Errorf("report = %+v, want 2 dirs, 2 files, 2 symlinks and 1 hard link skipped", r)
	}
	for _, p := range []string{root, filepath.Join(root, "sub"), filepath.Join(root, "f"), filepath.Join(root, "sub", "g")} {
		if !has(t, p, Write) {
			t.Errorf("%s: no write entry for the pods' user", p)
		}
	}
	for _, p := range []string{outside, filepath.Join(outside, "secret")} {
		if has(t, p, permRead) {
			t.Errorf("%s: the grant reached a symlink or hard-link target outside the share", p)
		}
	}
	again, err := GrantTree(root, ReadWrite, podUID, uint32(os.Getuid()))
	if err != nil || again.Dirs+again.Files != 0 || again.Unchanged != 4 {
		t.Errorf("second grant = %+v, %v; want everything unchanged (no duplicate entries)", again, err)
	}

	// A file created after the grant inherits the entry; a revoke removes
	// it with the explicit ones.
	newer := filepath.Join(root, "sub", "new")
	if err := os.WriteFile(newer, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if !has(t, newer, Write) {
		t.Errorf("%s did not inherit the entry", newer)
	}
	rv, err := RevokeTree(root, podUID, uint32(os.Getuid()))
	if err != nil {
		t.Fatal(err)
	}
	if rv.Dirs != 2 || rv.Files < 3 {
		t.Errorf("revoke report = %+v, want 2 dirs and the files", rv)
	}
	for _, p := range []string{root, filepath.Join(root, "f"), newer} {
		if has(t, p, permRead) {
			t.Errorf("%s: entry left after revoke", p)
		}
	}
	// The owner's own entry stays: revoking pods' access never takes the
	// owner's away.
	if p, _ := Allowed(root, uint32(os.Getuid())); p&Write == 0 {
		t.Error("revoke removed the owner's entry")
	}
}

func TestGrantTreeReadOnly(t *testing.T) {
	root, _ := tree(t)
	if _, err := GrantTree(root, ReadOnly, podUID, uint32(os.Getuid())); err != nil {
		t.Fatal(err)
	}
	if !has(t, root, permRead) || has(t, root, Write) || has(t, filepath.Join(root, "f"), Write) {
		t.Error("read-only grant: want read and no write")
	}
	if p, _ := Allowed(root, uint32(os.Getuid())); p != 0 {
		t.Errorf("read-only grant added an owner entry %v", p)
	}
}

func TestGrantTreeSkipsWhatTheOwnerDoesNotOwn(t *testing.T) {
	root, _ := tree(t)
	r, err := GrantTree(root, ReadWrite, podUID, uint32(os.Getuid())+1)
	if err != nil {
		t.Fatal(err)
	}
	if r.Dirs+r.Files != 0 || r.Skipped["not owned by uid "+strconv.Itoa(os.Getuid()+1)] != 1 {
		t.Errorf("report = %+v, want nothing changed", r)
	}
}

func TestSearchAndSocket(t *testing.T) {
	root, _ := tree(t)
	if changed, err := GrantSearch(root, podUID); err != nil || !changed {
		t.Fatalf("GrantSearch = %v, %v", changed, err)
	}
	if changed, _ := GrantSearch(root, podUID); changed {
		t.Error("GrantSearch twice changed the ACL twice")
	}
	if !has(t, root, Search) || has(t, root, permRead) {
		t.Error("search grant: want search only")
	}
	if changed, err := RevokeSearch(root, podUID); err != nil || !changed || has(t, root, Search) {
		t.Errorf("RevokeSearch = %v, %v", changed, err)
	}
	sock := filepath.Join(root, "q.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	if changed, err := GrantSocket(sock, podUID); err != nil || !changed || !has(t, sock, Write) {
		t.Errorf("GrantSocket = %v, %v", changed, err)
	}
	if _, err := GrantSocket(filepath.Join(root, "f"), podUID); err == nil {
		t.Error("GrantSocket on a regular file = nil, want an error")
	}
	if changed, err := RevokeSocket(sock, podUID); err != nil || !changed || has(t, sock, Write) {
		t.Errorf("RevokeSocket = %v, %v", changed, err)
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(filepath.Join(root, "sub"), link); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenNoFollow(link); err == nil {
		t.Error("OpenNoFollow(symlink) = nil, want an error")
	}
}

func TestEntryWords(t *testing.T) {
	if got := ReadOnly.DirEntry("_k3sm"); got != "user:_k3sm allow list,search,readattr,readextattr,readsecurity,file_inherit,directory_inherit" {
		t.Errorf("DirEntry = %q", got)
	}
	if got := ReadWrite.FileEntry("_k3sm"); got != "user:_k3sm allow read,write,execute,delete,append,readattr,writeattr,readextattr,writeextattr,readsecurity" {
		t.Errorf("FileEntry = %q", got)
	}
}

func TestCanonicalDir(t *testing.T) {
	root, _ := tree(t)
	odd := filepath.Join(filepath.Dir(root), "SHARE", "SUB")
	if _, err := os.Lstat(odd); err != nil {
		t.Skip("case-sensitive volume")
	}
	got, err := CanonicalDir(odd)
	if err != nil || got != filepath.Join(root, "sub") {
		t.Errorf("CanonicalDir(%s) = %q, %v, want %s", odd, got, err, filepath.Join(root, "sub"))
	}
}

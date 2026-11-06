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
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"k3sm.io/k3sm/pkg/executor"
	"k3sm.io/k3sm/pkg/install"
)

// fakeNode is one path in a described tree.
type fakeNode struct {
	uid  uint32
	mode fs.FileMode
}

// fakeExecCheck describes a tree as a map and resolves links through aliases.
func fakeExecCheck(tree map[string]fakeNode, aliases map[string]string) rootExecCheck {
	return rootExecCheck{
		lstat: func(p string) (uint32, fs.FileMode, error) {
			n, ok := tree[p]
			if !ok {
				return 0, 0, &fs.PathError{Op: "lstat", Path: p, Err: fs.ErrNotExist}
			}
			return n.uid, n.mode, nil
		},
		evalSymlinks: func(p string) (string, error) {
			for from, to := range aliases {
				if p == from || strings.HasPrefix(p, from+"/") {
					p = to + strings.TrimPrefix(p, from)
				}
			}
			if _, ok := tree[p]; !ok {
				return "", &fs.PathError{Op: "lstat", Path: p, Err: fs.ErrNotExist}
			}
			return p, nil
		},
	}
}

// rootTree is a tree of root-owned 0755 directories holding the named binary.
func rootTree(bin string) map[string]fakeNode {
	tree := map[string]fakeNode{bin: {0, 0o755}}
	for d := filepath.Dir(bin); ; d = filepath.Dir(d) {
		tree[d] = fakeNode{0, fs.ModeDir | 0o755}
		if d == filepath.Dir(d) {
			return tree
		}
	}
}

func TestRootExecCheckResolve(t *testing.T) {
	const bin = "/Library/k3sm/bin/kubectl"
	with := func(path string, n fakeNode) map[string]fakeNode {
		tree := rootTree(bin)
		tree[path] = n
		return tree
	}
	tests := []struct {
		name    string
		path    string
		tree    map[string]fakeNode
		aliases map[string]string
		want    string
		wantErr string
	}{
		{name: "root-owned file in a root-owned tree", path: bin, tree: rootTree(bin), want: bin},
		{name: "a root-owned link above the tree is resolved and checked", path: "/var/k3sm/bin/kubectl", tree: rootTree("/private/var/k3sm/bin/kubectl"), aliases: map[string]string{"/var": "/private/var"}, want: "/private/var/k3sm/bin/kubectl"},
		{name: "wrong owner", path: bin, tree: with(bin, fakeNode{501, 0o755}), wantErr: bin + " is owned by uid 501, not root"},
		{name: "group-writable binary", path: bin, tree: with(bin, fakeNode{0, 0o775}), wantErr: bin + " is group- or world-writable (mode 0775)"},
		{name: "world-writable binary", path: bin, tree: with(bin, fakeNode{0, 0o757}), wantErr: "group- or world-writable (mode 0757)"},
		{name: "symlink binary", path: bin, tree: with(bin, fakeNode{0, fs.ModeSymlink | 0o755}), wantErr: bin + " is a symlink"},
		{name: "directory where the binary should be", path: bin, tree: with(bin, fakeNode{0, fs.ModeDir | 0o755}), wantErr: "is not a regular file"},
		{name: "not executable", path: bin, tree: with(bin, fakeNode{0, 0o644}), wantErr: "is not executable"},
		{name: "immediate parent has another owner", path: bin, tree: with("/Library/k3sm/bin", fakeNode{501, fs.ModeDir | 0o755}), wantErr: "/Library/k3sm/bin is owned by uid 501, not root"},
		{name: "a higher parent is group-writable", path: bin, tree: with("/Library", fakeNode{0, fs.ModeDir | 0o775}), wantErr: "/Library is group- or world-writable (mode 0775)"},
		{name: "the root directory is checked too", path: bin, tree: with("/", fakeNode{501, fs.ModeDir | 0o755}), wantErr: "/ is owned by uid 501, not root"},
		{name: "a sticky world-writable parent still fails", path: bin, tree: with("/Library/k3sm", fakeNode{0, fs.ModeDir | fs.ModeSticky | 0o777}), wantErr: "group- or world-writable"},
		{name: "absent", path: "/nowhere/kubectl", tree: rootTree(bin), wantErr: "does not exist"},
		{name: "relative", path: "bin/kubectl", tree: rootTree(bin), wantErr: "is not an absolute path"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := fakeExecCheck(tt.tree, tt.aliases).resolve(tt.path)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("resolve = %q, %v; want an error containing %q", got, err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("resolve: %v", err)
			}
			if got != tt.want {
				t.Errorf("resolve = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestRootExecCheckOnTheRealFilesystem runs the production lstat: a system
// binary passes, and a file this test account owns does not.
func TestRootExecCheckOnTheRealFilesystem(t *testing.T) {
	if _, err := kubectlExecCheck.resolve("/bin/sh"); err != nil {
		t.Errorf("/bin/sh: %v", err)
	}
	if os.Geteuid() == 0 {
		return
	}
	own := filepath.Join(t.TempDir(), "kubectl")
	if err := os.WriteFile(own, nil, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := kubectlExecCheck.resolve(own); err == nil || !strings.Contains(err.Error(), "not root") {
		t.Errorf("own file: err = %v, want an owner refusal", err)
	}
}

// TestResolveKubectlAsRootDefaultInstall walks a default install: the service
// user owns the work dir and its kubectl, and root owns the install dir.
func TestResolveKubectlAsRootDefaultInstall(t *testing.T) {
	const workDir = "/var/lib/k3sm/server"
	installed := installedKubectl(install.DefaultInstallDir)
	tree := rootTree(installed)
	for p, n := range rootTree("/private/var/lib/k3sm/server/bin/kubectl") {
		tree[p] = n
	}
	const serviceUID = 299
	tree["/private/var/lib/k3sm/server"] = fakeNode{serviceUID, fs.ModeDir | 0o700}
	tree["/private/var/lib/k3sm/server/bin"] = fakeNode{serviceUID, fs.ModeDir | 0o755}
	tree["/private/var/lib/k3sm/server/bin/kubectl"] = fakeNode{serviceUID, 0o755}
	check := fakeExecCheck(tree, map[string]string{"/var": "/private/var"})

	noPath := func(string) (string, error) { return "", errors.New("not on PATH") }
	got, err := resolveKubectlAsRoot(workDir, install.DefaultInstallDir, check, noPath)
	if err != nil {
		t.Fatalf("resolveKubectlAsRoot: %v", err)
	}
	if got != installed {
		t.Errorf("kubectl = %q, want the installed %q", got, installed)
	}
}

func TestResolveKubectlAsRootCandidates(t *testing.T) {
	const (
		workDir    = "/custom/work"
		installDir = "/Library/k3sm"
		pathBin    = "/usr/local/bin/kubectl"
	)
	workBin := executor.KubectlPath(workDir)
	installedBin := installedKubectl(installDir)
	merge := func(trees ...map[string]fakeNode) map[string]fakeNode {
		out := map[string]fakeNode{}
		for _, tr := range trees {
			for p, n := range tr {
				out[p] = n
			}
		}
		return out
	}
	owned := func(bin string) map[string]fakeNode {
		tree := rootTree(bin)
		tree[bin] = fakeNode{501, 0o755}
		return tree
	}
	onPath := func(string) (string, error) { return pathBin, nil }
	noPath := func(string) (string, error) { return "", errors.New("not on PATH") }

	tests := []struct {
		name     string
		tree     map[string]fakeNode
		lookPath func(string) (string, error)
		want     string
		wantErr  []string
	}{
		{name: "a root-owned work dir kubectl comes first", tree: merge(rootTree(workBin), rootTree(installedBin)), lookPath: noPath, want: workBin},
		{name: "a work dir kubectl with another owner falls to the installed one", tree: merge(owned(workBin), rootTree(installedBin)), lookPath: noPath, want: installedBin},
		{name: "PATH is the last candidate and is checked", tree: merge(owned(workBin), rootTree(pathBin)), lookPath: onPath, want: pathBin},
		{
			name:     "no candidate passes: each reason and what to do",
			tree:     merge(owned(workBin), owned(pathBin)),
			lookPath: onPath,
			wantErr: []string{
				"no kubectl to run as root",
				workBin + " is owned by uid 501, not root",
				installedBin + ": does not exist",
				pathBin + " is owned by uid 501, not root",
				"run `sudo k3sm install` to restore " + installedBin,
				"or run `k3sm kubectl` without sudo",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := resolveKubectlAsRoot(workDir, installDir, fakeExecCheck(tt.tree, nil), tt.lookPath)
			if tt.wantErr != nil {
				if err == nil {
					t.Fatalf("resolveKubectlAsRoot = %q, want an error", got)
				}
				for _, want := range tt.wantErr {
					if !strings.Contains(err.Error(), want) {
						t.Errorf("error %q does not contain %q", err, want)
					}
				}
				return
			}
			if err != nil {
				t.Fatalf("resolveKubectlAsRoot: %v", err)
			}
			if got != tt.want {
				t.Errorf("kubectl = %q, want %q", got, tt.want)
			}
		})
	}
}

// asRoot makes the process read as root for the length of a test.
func asRoot(t *testing.T) {
	t.Helper()
	prev := processEuid
	processEuid = func() int { return 0 }
	t.Cleanup(func() { processEuid = prev })
}

// TestKubectlAsRootNeverExecsAWrongOwnerBinary runs the whole verb as root over
// a work dir this test account owns, whose kubectl fails the check on its owner.
func TestKubectlAsRootNeverExecsAWrongOwnerBinary(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("the fixture's owner is the test account, which must not be root")
	}
	asRoot(t)
	workDir := t.TempDir()
	writeInlineKubeconfig(t, executor.KubeconfigPath(workDir))
	bin := executor.KubectlPath(workDir)
	if err := os.MkdirAll(filepath.Dir(bin), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bin, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("K3SM_WORK_DIR", workDir)
	t.Setenv("PATH", "")
	t.Setenv("SUDO_USER", "")

	prevCheck := kubectlExecCheck
	installed := installedKubectl(install.DefaultInstallDir)
	t.Cleanup(func() { kubectlExecCheck = prevCheck })
	prevExec := kubectlExec
	t.Cleanup(func() { kubectlExec = prevExec })
	var execed []string
	kubectlExec = func(bin string, _, _ []string) error {
		execed = append(execed, bin)
		return nil
	}

	t.Run("falls to the installed kubectl", func(t *testing.T) {
		execed = nil
		tree := rootTree(installed)
		fake := fakeExecCheck(tree, nil)
		kubectlExecCheck = rootExecCheck{
			lstat: func(p string) (uint32, fs.FileMode, error) {
				if _, ok := tree[p]; ok {
					return fake.lstat(p)
				}
				return prevCheck.lstat(p)
			},
			evalSymlinks: prevCheck.evalSymlinks,
		}
		if err := runKubectl([]string{"get", "pods"}); err != nil {
			t.Fatalf("runKubectl: %v", err)
		}
		if len(execed) != 1 || execed[0] != installed {
			t.Errorf("exec'd %q, want only %q", execed, installed)
		}
	})
	t.Run("refuses when nothing passes", func(t *testing.T) {
		execed = nil
		kubectlExecCheck = fakeExecCheck(map[string]fakeNode{}, nil)
		err := runKubectl([]string{"get", "pods"})
		if err == nil || !strings.Contains(err.Error(), "no kubectl to run as root") {
			t.Fatalf("runKubectl = %v, want the refusal", err)
		}
		if len(execed) != 0 {
			t.Errorf("exec'd %q, want nothing", execed)
		}
	})
}

// writeInlineKubeconfig writes a kubeconfig whose only credential is inline.
func writeInlineKubeconfig(t *testing.T, path string) {
	t.Helper()
	body := `apiVersion: v1
kind: Config
clusters:
- name: c
  cluster:
    server: https://127.0.0.1:6443
contexts:
- name: admin
  context:
    cluster: c
    user: u
current-context: admin
users:
- name: u
  user:
    token: inline
`
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

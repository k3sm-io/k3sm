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

package dev

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// isTempBeside reports whether p is an atomicfile temp for target: in target's
// directory and named ".<base>.tmp-<digits>".
func isTempBeside(p, target string) bool {
	if filepath.Dir(p) != filepath.Dir(target) {
		return false
	}
	rest, ok := strings.CutPrefix(filepath.Base(p), "."+filepath.Base(target)+".tmp-")
	if !ok || rest == "" {
		return false
	}
	return strings.Trim(rest, "0123456789") == ""
}

// inodeOf returns path's inode number.
func inodeOf(t *testing.T, path string) uint64 {
	t.Helper()
	fi, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	return fi.Sys().(*syscall.Stat_t).Ino
}

// mutatingSign appends to path, so a fake signature changes the bytes as codesign
// does: a sign at the live path would then show through an fd held on the old file.
func mutatingSign(t *testing.T, path string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		t.Errorf("sign %s: %v", path, err)
		return
	}
	_, _ = f.WriteString("+signed")
	_ = f.Close()
}

type mutatingExecBuilder struct {
	*fakeBuilder
	t *testing.T
}

func (b mutatingExecBuilder) Sign(ctx context.Context, path, identifier string) error {
	mutatingSign(b.t, path)
	return b.fakeBuilder.Sign(ctx, path, identifier)
}

type mutatingPodShimBuilder struct {
	*fakePodShimBuilder
	t *testing.T
}

func (b mutatingPodShimBuilder) Sign(ctx context.Context, path, identifier string) error {
	mutatingSign(b.t, path)
	return b.fakePodShimBuilder.Sign(ctx, path, identifier)
}

// TestCachedShimResignNeverRewritesALiveInode is the pkg/dev half of the B544
// rule: a cached shim reused after a failed rebuild may be mapped by running pods
// (the DYLD shims) or launchers (k3sm-execshim), and macOS kills every NEW process
// that maps a signed Mach-O rewritten in place. So the re-sign is skipped when the
// signature verifies, and otherwise signs a temp copy renamed over the shim:
//
//   - an unverified shim lands on a new inode, the signer only ever sees the temp,
//     and an fd held on the old file still reads the old bytes;
//   - a verified shim is not touched: same inode, no sign call.
//
// Covered for the rootless and root exec-shim paths and the pod shim.
func TestCachedShimResignNeverRewritesALiveInode(t *testing.T) {
	const cached = "cached"
	type fixture struct {
		shim      string
		provision func() error
		signed    func() []string
		ids       func() []string
	}
	setups := map[string]func(t *testing.T, valid bool) fixture{
		"execshim/rootless": func(t *testing.T, valid bool) fixture {
			fb := &fakeBuilder{buildErr: errors.New("no workspace source"), valid: valid}
			m := newTestManagerWithBuilder(t, mutatingExecBuilder{fb, t}, testEUID(t))
			if err := os.MkdirAll(m.devBinDir(), 0o755); err != nil {
				t.Fatal(err)
			}
			shim := filepath.Join(m.devBinDir(), execShimName)
			if err := os.WriteFile(shim, []byte(cached), 0o755); err != nil {
				t.Fatal(err)
			}
			return fixture{shim, func() error {
				_, ok, err := m.provisionExecShim(t.Context())
				if err == nil && !ok {
					err = errors.New("the cached helper was not kept")
				}
				return err
			}, func() []string { return fb.signed }, func() []string { return fb.signedIDs }}
		},
		"execshim/root": func(t *testing.T, valid bool) fixture {
			fb := &fakeBuilder{buildErr: errors.New("no workspace source"), valid: valid}
			m := newTestManagerWithBuilder(t, mutatingExecBuilder{fb, t}, 0)
			m.rootBinDir = filepath.Join(rootBase(t), "k3sm-dev", rootExecShimSubdir)
			m.lstat = rootOwnedExcept()
			if err := os.MkdirAll(m.rootBinDir, 0o700); err != nil {
				t.Fatal(err)
			}
			shim := filepath.Join(m.rootBinDir, execShimName)
			if err := os.WriteFile(shim, []byte(cached), 0o755); err != nil {
				t.Fatal(err)
			}
			return fixture{shim, func() error {
				_, ok, err := m.provisionExecShim(t.Context())
				if err == nil && !ok {
					err = errors.New("the cached helper was not kept")
				}
				return err
			}, func() []string { return fb.signed }, func() []string { return fb.signedIDs }}
		},
		"podshim": func(t *testing.T, valid bool) fixture {
			fb := &fakePodShimBuilder{buildErr: errors.New("no clang"), valid: valid}
			m := newTestManagerWithShimBuilder(t, mutatingPodShimBuilder{fb, t})
			if err := os.MkdirAll(m.podShimDir("dev"), 0o755); err != nil {
				t.Fatal(err)
			}
			shim := filepath.Join(m.podShimDir("dev"), pathShimName)
			// At the mode podReadable leaves, so the kept-mode check is the copy's.
			if err := os.WriteFile(shim, []byte(cached), podShimMode); err != nil {
				t.Fatal(err)
			}
			return fixture{shim, func() error {
				got, err := m.provisionPodShim(t.Context(), "dev", pathShimName)
				if err == nil && got != shim {
					err = errors.New("the cached shim was not kept")
				}
				return err
			}, func() []string { return fb.signed }, func() []string { return fb.ids }}
		},
	}

	for name, setup := range setups {
		t.Run(name+"/unverified: re-signed on a new inode", func(t *testing.T) {
			fx := setup(t, false)
			before := inodeOf(t, fx.shim)
			mode := mustMode(t, fx.shim)
			old, err := os.Open(fx.shim)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = old.Close() }()

			if err := fx.provision(); err != nil {
				t.Fatal(err)
			}
			if after := inodeOf(t, fx.shim); after == before {
				t.Errorf("the re-sign kept inode %d: the live shim was rewritten in place", before)
			}
			signed := fx.signed()
			if len(signed) != 1 || !isTempBeside(signed[0], fx.shim) {
				t.Errorf("signed %v; want exactly one temp copy beside %s, never the live path", signed, fx.shim)
			}
			if ids := fx.ids(); len(ids) != 1 || ids[0] != filepath.Base(fx.shim) {
				t.Errorf("signed as %v, want the shim's own name %q as the identifier", ids, filepath.Base(fx.shim))
			}
			if got, _ := os.ReadFile(fx.shim); string(got) != cached+"+signed" {
				t.Errorf("shim = %q, want the signed copy", got)
			}
			if got := mustMode(t, fx.shim); got != mode {
				t.Errorf("shim mode %v, want the cached shim's %v kept", got, mode)
			}
			buf := make([]byte, 64)
			n, _ := old.ReadAt(buf, 0)
			if string(buf[:n]) != cached {
				t.Errorf("the old inode now reads %q, want %q untouched", buf[:n], cached)
			}
		})
		t.Run(name+"/verified: untouched", func(t *testing.T) {
			fx := setup(t, true)
			before := inodeOf(t, fx.shim)
			if err := fx.provision(); err != nil {
				t.Fatal(err)
			}
			if after := inodeOf(t, fx.shim); after != before {
				t.Errorf("a validly signed shim was replaced (inode %d -> %d)", before, after)
			}
			if signed := fx.signed(); len(signed) != 0 {
				t.Errorf("signed %v, want no sign call for a valid signature", signed)
			}
		})
	}
}

// mustMode returns path's permission bits.
func mustMode(t *testing.T, path string) os.FileMode {
	t.Helper()
	fi, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	return fi.Mode().Perm()
}

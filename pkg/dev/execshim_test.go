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
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// fakeBuilder is an in-memory ExecShimBuilder — no real `go build` / `codesign`.
// It records what it was asked to do and can inject a build failure so the
// hostprocess-fallback path is exercised without a toolchain.
type fakeBuilder struct {
	buildErr   error    // when non-nil, Build fails (drives the hostprocess fallback)
	built      []string // outPaths passed to Build
	signed     []string // paths passed to Sign
	writeBytes string   // stub Mach-O content Build writes on success
}

func (f *fakeBuilder) Build(_ context.Context, outPath string) error {
	f.built = append(f.built, outPath)
	if f.buildErr != nil {
		return f.buildErr
	}
	content := f.writeBytes
	if content == "" {
		content = "stub-execshim"
	}
	return os.WriteFile(outPath, []byte(content), 0o755)
}

func (f *fakeBuilder) Sign(_ context.Context, path string) error {
	f.signed = append(f.signed, path)
	return nil
}

// newTestManagerWithBuilder builds a Manager over a fake System + fake builder.
func newTestManagerWithBuilder(t *testing.T, b ExecShimBuilder, euid int) *Manager {
	t.Helper()
	m := newTestManager(t, newFakeSystem(), euid)
	m.builder = b
	return m
}

func TestProvisionExecShimBuildsWhenAbsent(t *testing.T) {
	b := &fakeBuilder{}
	m := newTestManagerWithBuilder(t, b, 501)

	dir, ok, err := m.provisionExecShim(context.Background())
	if err != nil {
		t.Fatalf("provisionExecShim: %v", err)
	}
	if !ok {
		t.Fatal("provisionExecShim ok = false, want true (build succeeded)")
	}
	if dir != m.devBinDir() {
		t.Errorf("dir = %q, want the dev-bin cache %q", dir, m.devBinDir())
	}
	shim := filepath.Join(dir, execShimName)
	if len(b.built) != 1 || filepath.Base(b.built[0]) != execShimName {
		t.Errorf("built = %v, want one build of %s", b.built, execShimName)
	}
	// Signed where it was built (before the rename), never at the cache path.
	if len(b.signed) != 1 || b.signed[0] != b.built[0] {
		t.Errorf("signed = %v, want the staged build %v signed once", b.signed, b.built)
	}
	if got, readErr := os.ReadFile(shim); readErr != nil || string(got) != "stub-execshim" {
		t.Errorf("helper at %s = %q, %v; want the fresh build installed", shim, got, readErr)
	}
}

// TestProvisionExecShimRebuildsOverCached pins the anti-staleness contract: a
// cached helper is REBUILT, never trusted on existence alone.
//
// The shim's argv is a versioned contract with sandbox.ExecShimBackend, and it
// has changed (the rlimit + qos tokens were inserted before the profile path).
// Reusing a helper cached before that change silently skews every pod launch —
// the caller's rlimit sentinel lands in the old shim's profile slot and each
// confined pod dies with `read profile -`. This test previously asserted the
// reuse it is now the guard against.
func TestProvisionExecShimRebuildsOverCached(t *testing.T) {
	b := &fakeBuilder{}
	m := newTestManagerWithBuilder(t, b, 501)
	// Seed a cached helper — stand-in for one left by an earlier session.
	if err := os.MkdirAll(m.devBinDir(), 0o755); err != nil {
		t.Fatal(err)
	}
	shim := filepath.Join(m.devBinDir(), execShimName)
	if err := os.WriteFile(shim, []byte("cached"), 0o755); err != nil {
		t.Fatal(err)
	}

	dir, ok, err := m.provisionExecShim(context.Background())
	if err != nil {
		t.Fatalf("provisionExecShim: %v", err)
	}
	if !ok || dir != m.devBinDir() {
		t.Fatalf("provisionExecShim = (%q,%v), want the cache dir + ok", dir, ok)
	}
	// The cached helper is rebuilt from source, not reused.
	if len(b.built) != 1 {
		t.Errorf("built = %v, want the helper rebuilt once", b.built)
	}
	if got, _ := os.ReadFile(shim); string(got) != "stub-execshim" {
		t.Errorf("cached helper = %q, want it replaced by the rebuild", got)
	}
	// ...and signed, so a stale signature can't wedge exec.
	if len(b.signed) != 1 || b.signed[0] != b.built[0] {
		t.Errorf("signed = %v, want the rebuilt helper signed once", b.signed)
	}
}

// TestExecShimUnwritableCacheIsNotReused is the B461 gate.
//
// provisionExecShim always rebuilds the helper, and reuses a cached one only
// when the host cannot build. On 2026-10-07 the source was present and only the
// destination was unwritable (a root-owned cached helper left by an earlier sudo
// run): the failed copy was taken for "cannot build", the stale helper, which
// predated the current shim argv contract, was reused, and every confined pod
// failed. A fresh build that cannot be installed must never fall back to the
// cache; it is used from a path this user owns, with a note naming the file.
//
// The no-source rows pin what stays: a cached helper is reused only when it is
// the only option AND the invoking user owns it.
func TestExecShimUnwritableCacheIsNotReused(t *testing.T) {
	const stale = "stale-predates-argv-contract"
	tests := []struct {
		name     string
		buildErr error
		cached   bool
		lock     bool // make the cached file 0444 inside a 0555 cache dir
		foreign  bool // the Manager's euid is not the cached file's owner
		wantOK   bool
		wantDir  func(m *Manager) string
		wantNote string // substring the output must carry ("" = none checked)
	}{
		{
			name: "built but the cache is unwritable: the fresh build is used, not the cache",
			lock: true, cached: true, wantOK: true,
			wantDir:  (*Manager).freshBinDir,
			wantNote: execShimName + " is not writable by you",
		},
		{
			name:     "no source, cached helper owned by the user: reused",
			buildErr: errors.New("no workspace source"), cached: true, wantOK: true,
			wantDir:  (*Manager).devBinDir,
			wantNote: "reusing the cached helper",
		},
		{
			name:     "no source, cached helper owned by someone else: hostprocess, never the cache",
			buildErr: errors.New("no workspace source"), cached: true, foreign: true,
			wantDir:  func(*Manager) string { return "" },
			wantNote: "not by you; not reusing it",
		},
		{
			name:     "no source, nothing cached: hostprocess",
			buildErr: errors.New("no workspace source"),
			wantDir:  func(*Manager) string { return "" },
			wantNote: "could not build " + execShimName,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			b := &fakeBuilder{buildErr: tc.buildErr}
			m := newTestManagerWithBuilder(t, b, os.Geteuid())
			out := &bytes.Buffer{}
			m.out = out
			bin := m.devBinDir()
			shim := filepath.Join(bin, execShimName)
			if tc.cached {
				if err := os.MkdirAll(bin, 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(shim, []byte(stale), 0o755); err != nil {
					t.Fatal(err)
				}
			}
			if tc.lock {
				if err := os.Chmod(shim, 0o444); err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(bin, 0o555); err != nil {
					t.Fatal(err)
				}
				// Restore so t.TempDir's cleanup can remove the tree.
				t.Cleanup(func() { _ = os.Chmod(bin, 0o755) })
			}
			if tc.foreign {
				m.euid = os.Geteuid() + 4242
			}

			dir, ok, err := m.provisionExecShim(context.Background())
			if err != nil {
				t.Fatalf("provisionExecShim: %v", err)
			}
			if ok != tc.wantOK || dir != tc.wantDir(m) {
				t.Fatalf("provisionExecShim = (%q, %v), want (%q, %v)\noutput: %s", dir, ok, tc.wantDir(m), tc.wantOK, out)
			}
			if ok {
				got, readErr := os.ReadFile(filepath.Join(dir, execShimName))
				if readErr != nil {
					t.Fatalf("returned helper: %v", readErr)
				}
				wantContent := "stub-execshim"
				if tc.buildErr != nil {
					wantContent = stale
				}
				if string(got) != wantContent {
					t.Errorf("helper in %s = %q, want %q", dir, got, wantContent)
				}
			}
			if tc.lock {
				// The note names the file that blocked the install and the remedy.
				if !strings.Contains(out.String(), shim) || !strings.Contains(out.String(), "sudo rm") {
					t.Errorf("output %q must name %s and the remedy", out, shim)
				}
				// The locked cache is left exactly as found.
				if got, _ := os.ReadFile(shim); string(got) != stale {
					t.Errorf("cached file = %q, want it untouched", got)
				}
			}
			if !strings.Contains(out.String(), tc.wantNote) {
				t.Errorf("output %q, want it to contain %q", out, tc.wantNote)
			}
		})
	}
}

// rootOwnedExcept returns an lstat seam that reports every path as owned by uid
// 0 except those in userOwned, so a test running unprivileged can drive the
// root-run checks. Mode and type come from the real file.
func rootOwnedExcept(userOwned ...string) func(string, *unix.Stat_t) error {
	return func(path string, st *unix.Stat_t) error {
		if err := unix.Lstat(path, st); err != nil {
			return err
		}
		if !slices.Contains(userOwned, path) {
			st.Uid = 0
		}
		return nil
	}
}

// rootBase returns a temp dir with no symlink in its path (t.TempDir sits under
// /var, a link to /private/var), so the root chain check sees real dirs only.
func rootBase(t *testing.T) string {
	t.Helper()
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return base
}

// TestExecShimRootRunUsesPrivateDir pins the root-run half of B461. A
// `sudo k3sm dev up --datapath` server runs as root and execs the helper as its
// Seatbelt launcher, so it must never execute a helper the unprivileged user can
// replace: not the user's .bin, and not one under any directory the user could
// write or swap. The root helper lives under the root-owned dev tree
// (/Library/k3sm-dev/bin), and the whole ancestor chain is checked.
func TestExecShimRootRunUsesPrivateDir(t *testing.T) {
	const userHelper = "user-owned-helper"
	tests := []struct {
		name       string
		buildErr   error
		userCached bool   // a user-owned helper sits in the user's .bin
		userOwned  string // the base-relative ancestor presented as user-owned ("" = none; "." = the base)
		groupWrite string // the base-relative ancestor pre-created with mode 0775
		rootHelper bool   // a helper already sits in the root helper dir
		wantUsed   bool   // want the root helper dir returned (else hostprocess)
		wantFresh  bool   // the returned helper is the fresh build
		wantNote   string
	}{
		{
			name:       "a valid root-owned chain is used; the user's .bin helper is not",
			userCached: true, wantUsed: true, wantFresh: true,
		},
		{
			name:       "an ancestor not owned by root: refused",
			userCached: true, userOwned: ".", wantNote: "is owned by uid",
		},
		{
			name:       "a group-writable ancestor: refused",
			userCached: true, groupWrite: "k3sm-dev", wantNote: "group- or other-writable",
		},
		{
			name:       "no source: the user's .bin helper is never reused under root",
			buildErr:   errors.New("no workspace source"),
			userCached: true, wantNote: "could not build " + execShimName,
		},
		{
			name:       "no source: a helper already in the root-owned dir is reused",
			buildErr:   errors.New("no workspace source"),
			userCached: true, rootHelper: true, wantUsed: true,
			wantNote: "reusing the cached helper",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			b := &fakeBuilder{buildErr: tc.buildErr}
			m := newTestManagerWithBuilder(t, b, 0)
			out := &bytes.Buffer{}
			m.out = out
			base := rootBase(t)
			m.rootBinDir = filepath.Join(base, "k3sm-dev", rootExecShimSubdir)
			var userOwned []string
			if tc.userOwned != "" {
				userOwned = append(userOwned, filepath.Join(base, tc.userOwned))
			}
			m.lstat = rootOwnedExcept(userOwned...)
			if tc.groupWrite != "" {
				gw := filepath.Join(base, tc.groupWrite)
				if err := os.Mkdir(gw, 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(gw, 0o775); err != nil {
					t.Fatal(err)
				}
			}
			if tc.rootHelper {
				if err := os.MkdirAll(m.rootBinDir, 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(m.rootBinDir, execShimName), []byte("root-cached"), 0o755); err != nil {
					t.Fatal(err)
				}
			}
			userShim := filepath.Join(m.devBinDir(), execShimName)
			if tc.userCached {
				if err := os.MkdirAll(m.devBinDir(), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(userShim, []byte(userHelper), 0o755); err != nil {
					t.Fatal(err)
				}
			}

			dir, ok, err := m.provisionExecShim(context.Background())
			if err != nil {
				t.Fatalf("provisionExecShim: %v", err)
			}
			if tc.wantUsed {
				if !ok || dir != m.rootBinDir {
					t.Fatalf("provisionExecShim = (%q, %v), want (%q, true)\noutput: %s", dir, ok, m.rootBinDir, out)
				}
				got, _ := os.ReadFile(filepath.Join(dir, execShimName))
				if tc.wantFresh && string(got) != "stub-execshim" {
					t.Errorf("root helper = %q, want the fresh build", got)
				}
			} else if ok || dir != "" {
				t.Fatalf("provisionExecShim = (%q, %v), want the hostprocess fallback\noutput: %s", dir, ok, out)
			}
			if tc.userCached {
				if got, _ := os.ReadFile(userShim); string(got) != userHelper {
					t.Errorf("user's .bin helper = %q, want it untouched", got)
				}
			}
			if !strings.Contains(out.String(), tc.wantNote) {
				t.Errorf("output %q, want it to contain %q", out, tc.wantNote)
			}
		})
	}
}

// TestExecShimSudoRunHandsCacheBack pins what a sudo run gives back to the
// invoking human: the registry dirs it had to create (so the next rootless run
// can write its registry), and nothing else. The helper stays in the root-owned
// dev tree, and the user's .bin is not created, so a sudo run leaves nothing
// root-owned there.
func TestExecShimSudoRunHandsCacheBack(t *testing.T) {
	b := &fakeBuilder{}
	m := newTestManagerWithBuilder(t, b, 0)
	base := rootBase(t)
	home := filepath.Join(base, "home")
	m.reg = NewRegistry(filepath.Join(home, ".k3sm", "dev"))
	m.rootBinDir = filepath.Join(base, "k3sm-dev", rootExecShimSubdir)
	// Everything is root-owned, as under a real sudo.
	m.lstat = rootOwnedExcept()
	m.kubeMg.chownUser, m.kubeMg.chownUID, m.kubeMg.chownGID = "human", 4242, 4243
	var chowned []string
	m.lchown = func(path string, uid, gid int) error {
		if uid != 4242 || gid != 4243 {
			t.Errorf("lchown(%s, %d, %d), want the invoking human 4242:4243", path, uid, gid)
		}
		chowned = append(chowned, path)
		return nil
	}

	dir, ok, err := m.provisionExecShim(context.Background())
	if err != nil || !ok || dir != m.rootBinDir {
		t.Fatalf("provisionExecShim = (%q, %v, %v), want %s", dir, ok, err, m.rootBinDir)
	}
	want := []string{home, filepath.Join(home, ".k3sm"), m.reg.root}
	if !slices.Equal(chowned, want) {
		t.Errorf("handed back %v, want exactly the created registry dirs %v", chowned, want)
	}
	for _, p := range chowned {
		if strings.Contains(p, execShimName) || strings.HasPrefix(p, filepath.Dir(m.rootBinDir)) {
			t.Errorf("handed back %s: a helper or the root-owned dev tree must never be chowned", p)
		}
	}
	if _, statErr := os.Lstat(m.devBinDir()); statErr == nil {
		t.Errorf("a root run created the user's %s; it must leave nothing there", m.devBinDir())
	}

	// Outside sudo nothing is chowned.
	chowned = nil
	m.kubeMg.chownUID, m.kubeMg.chownGID = -1, -1
	if _, _, err := m.provisionExecShim(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(chowned) != 0 {
		t.Errorf("not under sudo: chowned %v, want nothing", chowned)
	}
}

// TestProvisionExecShimKeepsCachedWhenRebuildFails pins the other half: a host
// that cannot build (an installed k3sm with no workspace source) still gets the
// isolation a previously-cached helper provides, rather than being dropped to
// the unconfined hostprocess fallback.
func TestProvisionExecShimKeepsCachedWhenRebuildFails(t *testing.T) {
	b := &fakeBuilder{buildErr: errors.New("no workspace source")}
	m := newTestManagerWithBuilder(t, b, 501)
	if err := os.MkdirAll(m.devBinDir(), 0o755); err != nil {
		t.Fatal(err)
	}
	shim := filepath.Join(m.devBinDir(), execShimName)
	if err := os.WriteFile(shim, []byte("cached"), 0o755); err != nil {
		t.Fatal(err)
	}

	dir, ok, err := m.provisionExecShim(context.Background())
	if err != nil {
		t.Fatalf("provisionExecShim: %v", err)
	}
	if !ok || dir != m.devBinDir() {
		t.Fatalf("provisionExecShim = (%q,%v), want the cached helper kept + ok", dir, ok)
	}
	if len(b.signed) != 1 || b.signed[0] != shim {
		t.Errorf("signed = %v, want the cached helper re-signed once", b.signed)
	}
}

func TestProvisionExecShimFallsBackWhenBuildFails(t *testing.T) {
	b := &fakeBuilder{buildErr: errors.New("no workspace source")}
	m := newTestManagerWithBuilder(t, b, 501)

	dir, ok, err := m.provisionExecShim(context.Background())
	if err != nil {
		t.Fatalf("provisionExecShim on build failure = err %v, want nil (fallback, not fatal)", err)
	}
	if ok {
		t.Fatal("provisionExecShim ok = true, want false (build failed → hostprocess fallback)")
	}
	if dir != "" {
		t.Errorf("dir = %q, want empty on the fallback (no helper to add to PATH)", dir)
	}
	// A failed build is not signed.
	if len(b.signed) != 0 {
		t.Errorf("signed = %v, want none (build failed)", b.signed)
	}
}

func TestWithExecShimPathPrepends(t *testing.T) {
	got := withExecShimPath([]string{"HOME=/h", "PATH=/usr/bin:/bin"}, "/dev/.bin")
	want := "PATH=/dev/.bin" + string(os.PathListSeparator) + "/usr/bin:/bin"
	if !containsEnv(got, want) {
		t.Errorf("withExecShimPath = %v, want PATH prepended to %q", got, want)
	}
	// HOME is untouched.
	if !containsEnv(got, "HOME=/h") {
		t.Errorf("withExecShimPath dropped an unrelated env var: %v", got)
	}
}

func TestWithExecShimPathEmptyDirNoop(t *testing.T) {
	in := []string{"PATH=/usr/bin"}
	got := withExecShimPath(in, "")
	if len(got) != 1 || got[0] != "PATH=/usr/bin" {
		t.Errorf("withExecShimPath with empty binDir = %v, want the input unchanged", got)
	}
}

func TestWithExecShimPathAlreadyLeadingNoDuplicate(t *testing.T) {
	lead := "PATH=/dev/.bin" + string(os.PathListSeparator) + "/usr/bin"
	got := withExecShimPath([]string{lead}, "/dev/.bin")
	if len(got) != 1 || got[0] != lead {
		t.Errorf("withExecShimPath = %v, want no duplicate prepend of an already-leading dir", got)
	}
}

func TestWithExecShimPathNoPathSeedsOne(t *testing.T) {
	got := withExecShimPath([]string{"HOME=/h"}, "/dev/.bin")
	if !containsEnv(got, "PATH=/dev/.bin") {
		t.Errorf("withExecShimPath with no PATH = %v, want a PATH seeded with the dev-bin dir", got)
	}
}

func containsEnv(env []string, kv string) bool {
	for _, e := range env {
		if e == kv {
			return true
		}
	}
	return false
}

// TestWithExecShimPathTrailingElementStillPrepends guards that a dev-bin dir that
// appears mid-PATH (not leading) is still prepended (LookPath resolves the first
// match, so leading placement matters).
func TestWithExecShimPathTrailingElementStillPrepends(t *testing.T) {
	sep := string(os.PathListSeparator)
	in := []string{"PATH=/usr/bin" + sep + "/dev/.bin"}
	got := withExecShimPath(in, "/dev/.bin")
	wantPrefix := "PATH=/dev/.bin" + sep
	if len(got) != 1 || !strings.HasPrefix(got[0], wantPrefix) {
		t.Errorf("withExecShimPath = %v, want /dev/.bin prepended even when it already appears later", got)
	}
}

// TestDevUpWaitsForDefaultNamespaceBootstrap is the B152 gate.
//
// `Up` used to return as soon as the apiserver was healthy and its kubeconfig
// merged, while the service-account controller and the root-ca-cert-publisher had
// not yet reconciled the default namespace. A caller that created a pod
// immediately — every acceptance/e2e suite does — then race-failed either at
// admission (`serviceaccount "default" not found`) or at volume materialisation
// (`configMap default/kube-root-ca.crt: file does not exist`). Observed on lab
// hardware 2026-08-27: both objects existed at AGE=1s, and the same criteria
// passed against a warm cluster.
//
// Scope note: `Up` itself is not unit-reachable (it fork/execs a real server), so
// this pins the WAIT's semantics — the part that was missing — plus the wiring
// that makes Up use it. The end-to-end "Up blocks" claim is the lab's to prove.
func TestDevUpWaitsForDefaultNamespaceBootstrap(t *testing.T) {
	always := func(context.Context) bool { return true }
	never := func(context.Context) bool { return false }

	t.Run("returns once BOTH objects are present", func(t *testing.T) {
		if err := awaitBootstrapObjects(context.Background(), 2*time.Second, "kc", always, always); err != nil {
			t.Fatalf("both present: err = %v, want nil", err)
		}
	})

	t.Run("blocks while either object is missing, and names it on timeout", func(t *testing.T) {
		err := awaitBootstrapObjects(context.Background(), 300*time.Millisecond, "kc", always, never)
		if err == nil {
			t.Fatal("configmap missing: err = nil, want a timeout error")
		}
		// The operator has to know WHICH object never landed.
		if !strings.Contains(err.Error(), "kube-root-ca.crt present=false") {
			t.Errorf("error %q must name the missing ConfigMap", err)
		}
		if !strings.Contains(err.Error(), "serviceaccount/default present=true") {
			t.Errorf("error %q must report the ServiceAccount as present", err)
		}

		err = awaitBootstrapObjects(context.Background(), 300*time.Millisecond, "kc", never, always)
		if err == nil || !strings.Contains(err.Error(), "serviceaccount/default present=false") {
			t.Errorf("serviceaccount missing: err = %v, must name it", err)
		}
	})

	t.Run("each probe is LATCHED — a transient failure never re-opens a settled object", func(t *testing.T) {
		// The ServiceAccount answers true exactly once, then flaps to false. Without
		// latching the wait would never converge and would time out.
		saCalls := 0
		flaky := func(context.Context) bool { saCalls++; return saCalls == 1 }
		cmCalls := 0
		lateCM := func(context.Context) bool { cmCalls++; return cmCalls >= 3 }
		if err := awaitBootstrapObjects(context.Background(), 5*time.Second, "kc", flaky, lateCM); err != nil {
			t.Fatalf("latching: err = %v, want nil (the SA was seen once and must stay settled)", err)
		}
	})

	t.Run("honors context cancellation", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if err := awaitBootstrapObjects(ctx, time.Minute, "kc", never, never); !errors.Is(err, context.Canceled) {
			t.Errorf("err = %v, want context.Canceled", err)
		}
	})

	t.Run("Up is wired to a non-nil wait by default", func(t *testing.T) {
		m := newTestManager(t, newFakeSystem(), 501)
		if m.awaitNamespaceBootstrap != nil {
			t.Fatal("a fresh Manager must leave the seam nil so Up falls back to the production wait")
		}
		// The production wait must be a real method, reachable and non-panicking.
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if err := m.awaitDefaultNamespaceBootstrap(ctx, filepath.Join(t.TempDir(), "absent.kubeconfig")); err == nil {
			t.Error("production wait on an absent kubeconfig = nil, want an error")
		}
	})
}

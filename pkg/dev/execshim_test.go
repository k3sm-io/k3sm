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
	"testing"
	"time"
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
	if len(b.built) != 1 || b.built[0] != shim {
		t.Errorf("built = %v, want one build of %q", b.built, shim)
	}
	if len(b.signed) != 1 || b.signed[0] != shim {
		t.Errorf("signed = %v, want the built helper signed once", b.signed)
	}
	if _, statErr := os.Stat(shim); statErr != nil {
		t.Errorf("helper not present after build: %v", statErr)
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
	if len(b.built) != 1 || b.built[0] != shim {
		t.Errorf("built = %v, want the cached helper rebuilt once", b.built)
	}
	// ...and signed, so a stale signature can't wedge exec.
	if len(b.signed) != 1 || b.signed[0] != shim {
		t.Errorf("signed = %v, want the rebuilt helper signed once", b.signed)
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

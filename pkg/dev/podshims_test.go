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
	"slices"
	"testing"
)

// fakePodShimBuilder is an in-memory PodShimBuilder — no real clang / codesign.
// It records what it was asked to do and can inject a build failure so the
// degrade and cached-shim paths are exercised without a toolchain.
type fakePodShimBuilder struct {
	buildErr error       // when non-nil, Build fails (drives the degrade paths)
	built    [][2]string // {name, outDir} pairs passed to Build
	signed   []string    // paths passed to Sign
}

func (f *fakePodShimBuilder) Build(_ context.Context, name, outDir string) error {
	f.built = append(f.built, [2]string{name, outDir})
	if f.buildErr != nil {
		return f.buildErr
	}
	// The real scripts name their own output; write it at the same basename, with
	// a deliberately NON-pod-readable mode so the chmod contract is load-bearing.
	return os.WriteFile(filepath.Join(outDir, name), []byte("stub-dylib"), 0o600)
}

func (f *fakePodShimBuilder) Sign(_ context.Context, path string) error {
	f.signed = append(f.signed, path)
	return nil
}

// buildNames returns the shim names Build was called with.
func (f *fakePodShimBuilder) buildNames() []string {
	var out []string
	for _, b := range f.built {
		out = append(out, b[0])
	}
	return out
}

// newTestManagerWithShimBuilder builds a Manager whose pod-support shims are
// staged into a temp dir (never /Library) and built by b.
func newTestManagerWithShimBuilder(t *testing.T, b PodShimBuilder) *Manager {
	t.Helper()
	m := newTestManager(t, newFakeSystem(), 0)
	m.shimBuilder = b
	m.shimDir = filepath.Join(t.TempDir(), "stage")
	return m
}

// TestDevProvisionsDNSShim is the B151 gate. Despite the name (B151's contract),
// it covers BOTH pod-support DYLD shims, because they are ONE defect with two
// symptoms: cmd/k3sm resolves the getaddrinfo shim and the path-rebase shim
// through the same resolveSiblingDylib call, and `k3sm dev` re-execs THIS binary
// out of a `go build` output dir, so it staged and wired NEITHER.
//
//   - No getaddrinfo shim → the spawned server logged `dyld_shim=""` and a dev
//     cluster could not resolve cluster DNS in-pod by construction (macOS
//     getaddrinfo ignores /etc/resolv.conf). Verified live on a root
//     `k3sm dev up --datapath` cluster, 2026-08-27.
//   - No path-rebase shim → runtimed injects no rebase (pkg/runtime/pod.go guards
//     on PathShimPath != ""), so every ABSOLUTE volume-mount path ENOENTs in-pod:
//     the M2 ConfigMap/Secret/emptyDir/in-pod-kubectl suites all failed on paths
//     whose files were present on disk the whole time.
//
// Scope note: `Up` is not unit-reachable (it fork/execs a real server), so this
// pins the WIRING — provisioning, pod-readability, the posture gates, and the
// argv that carries each shim to the server — NOT end-to-end DNS or end-to-end
// mounts, which are the lab's to prove.
func TestDevProvisionsDNSShim(t *testing.T) {
	shims := []string{dnsShimName, pathShimName}

	t.Run("stages BOTH shims into the pod-readable stage dir and signs them", func(t *testing.T) {
		b := &fakePodShimBuilder{}
		m := newTestManagerWithShimBuilder(t, b)

		for _, name := range shims {
			shim, err := m.provisionPodShim(context.Background(), name)
			if err != nil {
				t.Fatalf("provisionPodShim(%s): %v", name, err)
			}
			want := filepath.Join(m.podShimDir(), name)
			if shim != want {
				t.Fatalf("provisionPodShim(%s) = %q, want the staged shim %q", name, shim, want)
			}
			// dyld loads the dylib INSIDE the pod, at a different uid than the
			// staging root, and fails CLOSED on an unreadable insert — the file and
			// the dir it sits in must both be world-readable/traversable.
			fi, statErr := os.Stat(shim)
			if statErr != nil {
				t.Fatalf("staged %s not present: %v", name, statErr)
			}
			if fi.Mode().Perm()&0o004 == 0 {
				t.Errorf("staged %s mode = %v, want world-readable (dyld fails closed in-pod)", name, fi.Mode().Perm())
			}
			if !slices.Contains(b.signed, want) {
				t.Errorf("signed = %v, want %q signed", b.signed, want)
			}
		}
		if got := b.buildNames(); !slices.Equal(got, shims) {
			t.Errorf("built = %v, want both shims %v", got, shims)
		}
		di, statErr := os.Stat(m.podShimDir())
		if statErr != nil {
			t.Fatalf("stage dir not present: %v", statErr)
		}
		if di.Mode().Perm()&0o001 == 0 {
			t.Errorf("stage dir mode = %v, want world-traversable", di.Mode().Perm())
		}
	})

	t.Run("both staged shims reach the server as --path-shim / --dns-shim", func(t *testing.T) {
		wantPath := filepath.Join(DefaultPodShimDir, pathShimName)
		wantDNS := filepath.Join(DefaultPodShimDir, dnsShimName)
		args := serverArgs("dev", "/w", "/pods", 7443, 12379, "direct", runtimeRuntimed, wantPath, wantDNS)
		for _, tc := range []struct{ flag, want string }{
			{"--path-shim", wantPath},
			{"--dns-shim", wantDNS},
		} {
			i := slices.Index(args, tc.flag)
			if i < 0 {
				t.Fatalf("serverArgs = %v, want a %s flag", args, tc.flag)
			}
			if i+1 >= len(args) || args[i+1] != tc.want {
				t.Errorf("serverArgs %s value = %v, want the staged shim %q", tc.flag, args[i+1:], tc.want)
			}
		}
	})

	t.Run("an unstaged shim emits no flag at all", func(t *testing.T) {
		args := serverArgs("dev", "/w", "/pods", 7443, 12379, "none", runtimeRuntimed, "", "")
		for _, flag := range []string{"--path-shim", "--dns-shim"} {
			if slices.Contains(args, flag) {
				t.Errorf("serverArgs = %v, must not point the server at a shim that was not staged (%s)", args, flag)
			}
		}
		// Each is independent: a staged path shim must not drag in a --dns-shim.
		args = serverArgs("dev", "/w", "/pods", 7443, 12379, "none", runtimeRuntimed, "/Library/k3sm-dev/"+pathShimName, "")
		if !slices.Contains(args, "--path-shim") || slices.Contains(args, "--dns-shim") {
			t.Errorf("serverArgs = %v, want --path-shim only", args)
		}
	})

	t.Run("the posture gates: staging needs root+runtimed, the DNS shim also needs a datapath", func(t *testing.T) {
		cases := []struct {
			name              string
			euid              int
			datapath          bool
			runtime           string
			wantPath, wantDNS bool
		}{
			// Root + runtimed + datapath: both shims apply.
			{"root datapath runtimed", 0, true, runtimeRuntimed, true, true},
			// Root, no datapath: mounts still need the path shim, but no per-node
			// resolver binds the DNS VIP, so a DNS shim would point pods at nothing.
			{"root rootless-network runtimed", 0, false, runtimeRuntimed, true, false},
			// Non-root cannot stage under /Library (the pod Seatbelt read baseline).
			{"unprivileged runtimed", 501, false, runtimeRuntimed, false, false},
			{"unprivileged datapath-request runtimed", 501, true, runtimeRuntimed, false, false},
			// The hostprocess provider performs no DYLD injection at all.
			{"root datapath hostprocess", 0, true, runtimeHostProcess, false, false},
		}
		for _, tc := range cases {
			if got := wantsPathShim(tc.euid, tc.runtime); got != tc.wantPath {
				t.Errorf("wantsPathShim(%s) = %v, want %v", tc.name, got, tc.wantPath)
			}
			if got := wantsDNSShim(tc.euid, tc.datapath, tc.runtime); got != tc.wantDNS {
				t.Errorf("wantsDNSShim(%s) = %v, want %v", tc.name, got, tc.wantDNS)
			}
		}
	})

	t.Run("an unbuildable shim degrades, it does not fail the bring-up", func(t *testing.T) {
		b := &fakePodShimBuilder{buildErr: errors.New("no workspace source")}
		m := newTestManagerWithShimBuilder(t, b)

		for _, name := range shims {
			shim, err := m.provisionPodShim(context.Background(), name)
			if err != nil {
				t.Fatalf("provisionPodShim(%s) on build failure = err %v, want nil (degrade, not fatal)", name, err)
			}
			if shim != "" {
				t.Errorf("provisionPodShim(%s) = %q, want empty (nothing staged)", name, shim)
			}
		}
		if len(b.signed) != 0 {
			t.Errorf("signed = %v, want none (build failed)", b.signed)
		}
	})

	t.Run("a cached shim is REBUILT, and kept only when the rebuild fails", func(t *testing.T) {
		// Mirrors the k3sm-execshim anti-staleness policy: never trust the cache on
		// existence alone, because the re-sign refreshes the mtime and a skewed
		// artifact is invisible.
		b := &fakePodShimBuilder{}
		m := newTestManagerWithShimBuilder(t, b)
		if err := os.MkdirAll(m.podShimDir(), 0o755); err != nil {
			t.Fatal(err)
		}
		staged := filepath.Join(m.podShimDir(), pathShimName)
		if err := os.WriteFile(staged, []byte("cached"), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := m.provisionPodShim(context.Background(), pathShimName); err != nil {
			t.Fatalf("provisionPodShim: %v", err)
		}
		if got := b.buildNames(); !slices.Equal(got, []string{pathShimName}) {
			t.Errorf("built = %v, want the cached shim rebuilt once", got)
		}

		// ...and on a host that cannot rebuild, the cached shim is kept rather than
		// dropping the cluster to no absolute mounts at all.
		b2 := &fakePodShimBuilder{buildErr: errors.New("no clang")}
		m.shimBuilder = b2
		shim, err := m.provisionPodShim(context.Background(), pathShimName)
		if err != nil {
			t.Fatalf("provisionPodShim with a failed rebuild: %v", err)
		}
		if shim != staged {
			t.Errorf("provisionPodShim = %q, want the cached shim %q kept", shim, staged)
		}
		if len(b2.signed) != 1 || b2.signed[0] != staged {
			t.Errorf("signed = %v, want the cached shim re-signed once", b2.signed)
		}
	})

	t.Run("every shim has a production build recipe", func(t *testing.T) {
		for _, name := range shims {
			r, ok := shimRecipes[name]
			if !ok {
				t.Errorf("no build recipe for %s — the production builder would refuse it", name)
				continue
			}
			if r.module == "" || r.script == "" {
				t.Errorf("recipe for %s = %+v, want a module and a script", name, r)
			}
		}
	})

	t.Run("Up is wired to the production seams by default", func(t *testing.T) {
		m := newTestManager(t, newFakeSystem(), 0)
		if m.shimBuilder == nil {
			t.Fatal("a fresh Manager must carry the production PodShimBuilder")
		}
		// The default stage dir must be the pod-readable /Library location: the dev
		// registry root (~/.k3sm/dev) is OUTSIDE the pod Seatbelt read baseline
		// (/System, /usr, /bin, /Library), where dyld fails closed and every
		// confined pod dies at exec.
		if got := m.podShimDir(); got != DefaultPodShimDir {
			t.Errorf("default stage dir = %q, want %q", got, DefaultPodShimDir)
		}
		if filepath.Dir(DefaultPodShimDir) != "/Library" {
			t.Errorf("DefaultPodShimDir = %q, want a /Library path (the pod sandbox read baseline)", DefaultPodShimDir)
		}
	})
}

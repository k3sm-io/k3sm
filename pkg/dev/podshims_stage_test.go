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
	"strconv"
	"strings"
	"testing"

	"golang.org/x/sys/unix"

	runtimev1 "k3sm.io/apis/runtime/v1"
	"k3sm.io/runtimed/pkg/sandbox"
)

// TestDevStagesShimDylibsIntoAPodReadableDir pins WHERE `k3sm dev` stages the
// pod-support DYLD shims, per tier. dyld loads them inside the confined pod, so
// the path handed to the node must be one the pod's Seatbelt profile can read:
//
//   - root: /Library/k3sm-dev, inside the profile's read baseline;
//   - rootless: <runtime root>/shims, which the provider adds to the pod's
//     ExtraReadPaths — and which runtimed's profile generator must ACCEPT there,
//     so it can never sit under the pods root, a daemon-private runtime-root
//     subtree, or /Users (so never beside a home-dir binary).
//
// It also pins the staged artifact (a regular-file copy, mode 0755) and the
// symlink refusal at the stage.
func TestDevStagesShimDylibsIntoAPodReadableDir(t *testing.T) {
	t.Run("root tier stages under /Library/k3sm-dev", func(t *testing.T) {
		m := newTestManager(t, newFakeSystem(), 0)
		if got, want := m.podShimDir("dev"), DefaultPodShimDir; got != want {
			t.Fatalf("root stage dir = %q, want %q", got, want)
		}
		if DefaultPodShimDir != "/Library/k3sm-dev" {
			t.Errorf("DefaultPodShimDir = %q, want /Library/k3sm-dev (the pod read baseline)", DefaultPodShimDir)
		}
	})

	t.Run("rootless tier stages", func(t *testing.T) {
		b := &fakePodShimBuilder{}
		m := newTestManager(t, newFakeSystem(), os.Geteuid())
		m.shimBuilder = b
		m.podRootBase = filepath.Join(t.TempDir(), "k3sm-dev-501")
		const instance = "dev"

		pathShim, dnsShim, err := m.stagePodShims(context.Background(), instance, false, runtimeRuntimed)
		if err != nil {
			t.Fatalf("stagePodShims: %v", err)
		}
		podRoot := m.podRoot(instance)
		wantDir := filepath.Join(podRoot, podShimSubdir)
		if want := filepath.Join(wantDir, pathShimName); pathShim != want {
			t.Fatalf("path shim handed to the node = %q, want %q", pathShim, want)
		}
		// network=none: no resolver binds the DNS VIP, so no DNS shim.
		if dnsShim != "" {
			t.Errorf("dns shim = %q, want none on the rootless (network=none) tier", dnsShim)
		}
		// Never under the pods root (sibling pods are denied), never beside a
		// home-dir binary (the registry root and its execshim dev-bin cache).
		for _, bad := range []string{filepath.Join(podRoot, "pods"), m.reg.root, m.devBinDir()} {
			if pathShim == bad || strings.HasPrefix(pathShim, bad+"/") {
				t.Errorf("path shim %q is under %q", pathShim, bad)
			}
		}
		if home, herr := os.UserHomeDir(); herr == nil && strings.HasPrefix(pathShim, home+"/") {
			t.Errorf("path shim %q is under $HOME %q", pathShim, home)
		}
		assertStagedCopy(t, pathShim)

		// Both shims (as a root-less datapath would need) are accepted by the
		// real runtimed profile generator as the pod's extra reads, with the
		// SAME posture the dev server runs under: work-dir == the runtime root.
		dns, err := m.provisionPodShim(context.Background(), instance, dnsShimName)
		if err != nil || dns == "" {
			t.Fatalf("provisionPodShim(dns) = %q, %v", dns, err)
		}
		assertStagedCopy(t, dns)
		_, err = sandbox.Generate(&runtimev1.SandboxProfile{
			DataVolumePath: filepath.Join(podRoot, "pods", "uid-web"),
			ExtraReadPaths: []string{pathShim, dns},
		}, sandbox.GenerateOptions{Posture: sandbox.Posture{WorkDir: podRoot, PodLogsDir: devPodLogsDir(podRoot)}})
		if err != nil {
			t.Errorf("runtimed rejects the rootless shim read grant: %v", err)
		}
		// The runtime root stays 0700 even though the stage dir inside it is 0755.
		if fi, err := os.Stat(podRoot); err != nil || fi.Mode().Perm() != 0o700 {
			t.Errorf("runtime root %q mode = %v (%v), want 0700", podRoot, fi.Mode().Perm(), err)
		}
	})

	symlinkCases := []struct {
		name string
		// plant creates the attacker link given the stage dir and a victim dir.
		plant func(t *testing.T, stage, victim string)
	}{
		// The base sits under the world-writable /private/var/tmp: any local user
		// can plant it (or the instance root) as a link before `up` runs.
		{"symlinked pod-root base", func(t *testing.T, stage, victim string) {
			if err := os.Symlink(victim, filepath.Dir(filepath.Dir(stage))); err != nil {
				t.Fatal(err)
			}
		}},
		{"symlinked instance runtime root", func(t *testing.T, stage, victim string) {
			if err := os.MkdirAll(filepath.Dir(filepath.Dir(stage)), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(victim, filepath.Dir(stage)); err != nil {
				t.Fatal(err)
			}
		}},
		{"symlinked stage dir", func(t *testing.T, stage, victim string) {
			if err := os.MkdirAll(filepath.Dir(stage), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(victim, stage); err != nil {
				t.Fatal(err)
			}
		}},
		{"symlinked target file", func(t *testing.T, stage, victim string) {
			if err := os.MkdirAll(stage, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(filepath.Join(victim, pathShimName), filepath.Join(stage, pathShimName)); err != nil {
				t.Fatal(err)
			}
		}},
	}
	for _, tc := range symlinkCases {
		t.Run("refuses a "+tc.name, func(t *testing.T) {
			b := &fakePodShimBuilder{}
			m := newTestManager(t, newFakeSystem(), os.Geteuid())
			m.shimBuilder = b
			m.podRootBase = filepath.Join(t.TempDir(), "k3sm-dev-501")
			victim := t.TempDir()
			victimFile := filepath.Join(victim, pathShimName)
			if err := os.WriteFile(victimFile, []byte("victim"), 0o600); err != nil {
				t.Fatal(err)
			}
			tc.plant(t, m.podShimDir("dev"), victim)

			shim, err := m.provisionPodShim(context.Background(), "dev", pathShimName)
			if !errors.Is(err, ErrSymlinkStage) {
				t.Fatalf("provisionPodShim through a %s = %q, %v; want ErrSymlinkStage", tc.name, shim, err)
			}
			if len(b.built) != 0 {
				t.Errorf("built = %v, want nothing built through a link", b.built)
			}
			got, _ := os.ReadFile(victimFile)
			fi, _ := os.Stat(victimFile)
			if string(got) != "victim" || fi.Mode().Perm() != 0o600 {
				t.Errorf("victim %s changed: %q mode %v", victimFile, got, fi.Mode().Perm())
			}
			if entries, _ := os.ReadDir(victim); len(entries) != 1 {
				t.Errorf("victim dir = %v, want only the untouched victim file", entries)
			}
		})
	}

	t.Run("refuses a symlink planted at the cached shim before the re-sign", func(t *testing.T) {
		m := newTestManager(t, newFakeSystem(), os.Geteuid())
		m.podRootBase = filepath.Join(t.TempDir(), "k3sm-dev-501")
		// Seed a cached shim with one successful build.
		m.shimBuilder = &fakePodShimBuilder{}
		cached, err := m.provisionPodShim(context.Background(), "dev", pathShimName)
		if err != nil || cached == "" {
			t.Fatalf("seed provisionPodShim = %q, %v", cached, err)
		}
		victim := t.TempDir()
		victimFile := filepath.Join(victim, pathShimName)
		if err := os.WriteFile(victimFile, []byte("victim"), 0o600); err != nil {
			t.Fatal(err)
		}
		// The rebuild fails, and while it runs the cached shim is swapped for a
		// link: the re-sign must not follow it.
		inner := &fakePodShimBuilder{buildErr: errors.New("no clang")}
		m.shimBuilder = racingShimBuilder{fakePodShimBuilder: inner, during: func() {
			if err := os.Remove(cached); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(victimFile, cached); err != nil {
				t.Fatal(err)
			}
		}}
		shim, err := m.provisionPodShim(context.Background(), "dev", pathShimName)
		if !errors.Is(err, ErrSymlinkStage) {
			t.Fatalf("provisionPodShim with a link planted during the rebuild = %q, %v; want ErrSymlinkStage", shim, err)
		}
		if len(inner.signed) != 0 {
			t.Errorf("signed = %v, want no re-sign through the link", inner.signed)
		}
		got, _ := os.ReadFile(victimFile)
		fi, _ := os.Stat(victimFile)
		if string(got) != "victim" || fi.Mode().Perm() != 0o600 {
			t.Errorf("victim %s changed: %q mode %v", victimFile, got, fi.Mode().Perm())
		}
	})

	t.Run("the execshim dev-bin cache refuses a symlink too", func(t *testing.T) {
		m := newTestManagerWithBuilder(t, &fakeBuilder{}, 501)
		victim := t.TempDir()
		if err := os.MkdirAll(filepath.Dir(m.devBinDir()), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(victim, m.devBinDir()); err != nil {
			t.Fatal(err)
		}
		if _, _, err := m.provisionExecShim(context.Background()); !errors.Is(err, ErrSymlinkStage) {
			t.Fatalf("provisionExecShim through a symlinked cache = %v, want ErrSymlinkStage", err)
		}
		if entries, _ := os.ReadDir(victim); len(entries) != 0 {
			t.Errorf("victim dir gained %v", entries)
		}
	})
}

// racingShimBuilder runs during inside Build, before delegating, to simulate a
// concurrent change to the stage while a (slow) rebuild is in flight.
type racingShimBuilder struct {
	*fakePodShimBuilder
	during func()
}

func (r racingShimBuilder) Build(ctx context.Context, name, outDir string) error {
	r.during()
	return r.fakePodShimBuilder.Build(ctx, name, outDir)
}

// assertStagedCopy fails unless path is a regular file (a copy, never a link)
// with mode 0755.
func assertStagedCopy(t *testing.T, path string) {
	t.Helper()
	fi, err := os.Lstat(path)
	if err != nil {
		t.Fatalf("staged shim %s: %v", path, err)
	}
	if !fi.Mode().IsRegular() {
		t.Errorf("staged shim %s is %v, want a regular file", path, fi.Mode().Type())
	}
	if fi.Mode().Perm() != 0o755 {
		t.Errorf("staged shim %s mode = %v, want 0755", path, fi.Mode().Perm())
	}
}

// foreignOwned returns an lstat seam that reports each path in paths as owned
// by uid 0 (another user, for an unprivileged test) and every other path as it
// really is, so a test can plant a stage dir "someone else" created without
// being root.
func foreignOwned(paths ...string) func(string, *unix.Stat_t) error {
	return func(path string, st *unix.Stat_t) error {
		if err := unix.Lstat(path, st); err != nil {
			return err
		}
		if slices.Contains(paths, path) {
			st.Uid = 0
		}
		return nil
	}
}

// TestPodShimStageRefusesForeignOwnedBase is the B464 gate. The rootless tier
// stages the pod shims, which are DYLD-injected into every dev pod, under
// <PodRootBasePrefix>-<euid> in the world-writable, sticky /private/var/tmp. The
// symlink refusal alone let any local user create that name first as a real
// directory they own (or one everyone can write) and so control the injected
// shim. Every component from the base down must now be owned by the euid and
// writable by nobody else, a cached shim is reused after a failed build only
// under the same rule, and the root tier checks its whole chain. A refused
// stage writes nothing, and the run degrades to no shim with a note naming the
// path and the remedy.
func TestPodShimStageRefusesForeignOwnedBase(t *testing.T) {
	euid := os.Geteuid()
	if euid == 0 {
		t.Skip("the rootless tier needs an unprivileged test process")
	}
	tests := []struct {
		name string
		// setup prepares the base (and anything under it) and returns the paths
		// the lstat seam presents as foreign-owned.
		setup      func(t *testing.T, base, instRoot string) []string
		wantUsed   bool
		wantErr    error
		wantNote   []string
		untouched  string // a dir that must still be empty afterwards ("" = none)
		wantBuilds int
	}{
		{
			name:       "user-owned base is used",
			setup:      func(t *testing.T, base, _ string) []string { mkdirMode(t, base, 0o700); return nil },
			wantUsed:   true,
			wantBuilds: 1,
		},
		{
			name:      "foreign-owned base is refused",
			setup:     func(t *testing.T, base, _ string) []string { mkdirMode(t, base, 0o755); return []string{base} },
			wantNote:  []string{"is owned by uid 0", "Remedy: sudo rm -rf "},
			untouched: "base",
		},
		{
			name:      "0777 base is refused",
			setup:     func(t *testing.T, base, _ string) []string { mkdirMode(t, base, 0o777); return nil },
			wantNote:  []string{"group- or other-writable (mode 0777)", "Remedy: chmod go-w "},
			untouched: "base",
		},
		{
			name:      "group-writable base is refused",
			setup:     func(t *testing.T, base, _ string) []string { mkdirMode(t, base, 0o770); return nil },
			wantNote:  []string{"group- or other-writable (mode 0770)"},
			untouched: "base",
		},
		{
			name: "foreign-owned instance runtime root is refused",
			setup: func(t *testing.T, base, instRoot string) []string {
				mkdirMode(t, base, 0o700)
				mkdirMode(t, instRoot, 0o755)
				return []string{instRoot}
			},
			wantNote:  []string{"is owned by uid 0", "Remedy: sudo rm -rf "},
			untouched: "instance",
		},
		{
			name: "symlinked base is refused",
			setup: func(t *testing.T, base, _ string) []string {
				if err := os.Symlink(t.TempDir(), base); err != nil {
					t.Fatal(err)
				}
				return nil
			},
			wantErr: ErrSymlinkStage,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			b := &fakePodShimBuilder{}
			m := newTestManager(t, newFakeSystem(), euid)
			m.shimBuilder = b
			m.podRootBase = filepath.Join(t.TempDir(), "k3sm-dev-"+strconv.Itoa(euid))
			instRoot := m.podRoot("dev")
			m.lstat = foreignOwned(tc.setup(t, m.podRootBase, instRoot)...)

			shim, err := m.provisionPodShim(context.Background(), "dev", pathShimName)
			out := m.out.(*bytes.Buffer).String()
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("provisionPodShim = %q, %v; want %v", shim, err, tc.wantErr)
				}
			} else if err != nil {
				t.Fatalf("provisionPodShim: %v (a refused stage degrades, it is not fatal)", err)
			}
			if tc.wantUsed {
				if want := filepath.Join(instRoot, podShimSubdir, pathShimName); shim != want {
					t.Fatalf("provisionPodShim = %q, want the staged shim %q (output %q)", shim, want, out)
				}
				assertStagedCopy(t, shim)
			} else if shim != "" {
				t.Fatalf("provisionPodShim = %q, want no shim from a stage this user does not control", shim)
			}
			if len(b.built) != tc.wantBuilds {
				t.Errorf("built = %v, want %d builds", b.built, tc.wantBuilds)
			}
			for _, want := range tc.wantNote {
				if !strings.Contains(out, want) {
					t.Errorf("output %q, want it to contain %q", out, want)
				}
			}
			if len(tc.wantNote) > 0 && !strings.Contains(out, instRoot) && !strings.Contains(out, m.podRootBase) {
				t.Errorf("output %q does not name the refused path", out)
			}
			switch tc.untouched {
			case "base":
				if entries, _ := os.ReadDir(m.podRootBase); len(entries) != 0 {
					t.Errorf("refused base %s gained %v", m.podRootBase, entries)
				}
			case "instance":
				if entries, _ := os.ReadDir(instRoot); len(entries) != 0 {
					t.Errorf("refused instance root %s gained %v", instRoot, entries)
				}
			}
		})
	}

	t.Run("a foreign-owned cached shim is not reused after a failed build", func(t *testing.T) {
		m := newTestManager(t, newFakeSystem(), euid)
		m.podRootBase = filepath.Join(t.TempDir(), "k3sm-dev-"+strconv.Itoa(euid))
		m.shimBuilder = &fakePodShimBuilder{}
		cached, err := m.provisionPodShim(context.Background(), "dev", pathShimName)
		if err != nil || cached == "" {
			t.Fatalf("seed provisionPodShim = %q, %v", cached, err)
		}
		m.lstat = foreignOwned(cached)
		failing := &fakePodShimBuilder{buildErr: errors.New("no clang")}
		m.shimBuilder = failing
		shim, err := m.provisionPodShim(context.Background(), "dev", pathShimName)
		if err != nil || shim != "" {
			t.Fatalf("provisionPodShim = %q, %v; want no shim and no error", shim, err)
		}
		if len(failing.signed) != 0 {
			t.Errorf("signed = %v, want no re-sign of a shim this user does not own", failing.signed)
		}
		out := m.out.(*bytes.Buffer).String()
		if want := "the cached " + cached + " is owned by uid 0, not by you; not reusing it"; !strings.Contains(out, want) {
			t.Errorf("output %q, want %q", out, want)
		}
		if strings.Contains(out, "STALE") {
			t.Errorf("output %q, want no STALE reuse", out)
		}
	})

	t.Run("root tier refuses a stage whose chain the user controls", func(t *testing.T) {
		b := &fakePodShimBuilder{}
		m := newTestManager(t, newFakeSystem(), 0)
		m.shimBuilder = b
		parent := rootBase(t)
		m.shimDir = filepath.Join(parent, "k3sm-dev")
		// Everything is root's except the parent of the stage, which the
		// unprivileged user owns and so could swap.
		m.lstat = rootOwnedExcept(parent)
		shim, err := m.provisionPodShim(context.Background(), "dev", pathShimName)
		if err != nil || shim != "" {
			t.Fatalf("provisionPodShim = %q, %v; want no shim and no error", shim, err)
		}
		if len(b.built) != 0 {
			t.Errorf("built = %v, want nothing built into an untrusted stage", b.built)
		}
		out := m.out.(*bytes.Buffer).String()
		if want := parent + " is owned by uid " + strconv.Itoa(euid) + ", not 0"; !strings.Contains(out, want) {
			t.Errorf("output %q, want %q", out, want)
		}
	})
}

// mkdirMode creates dir with exactly mode (past the umask).
func mkdirMode(t *testing.T, dir string, mode os.FileMode) {
	t.Helper()
	if err := os.Mkdir(dir, mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, mode); err != nil {
		t.Fatal(err)
	}
}

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
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"k3sm.io/runtimed/pkg/image"
)

// pruneCalls records what the fake seams observed, so each row asserts exact
// behavior (was the executor called? with which plan? which grace reached the
// planner?) instead of merely "no error".
type pruneCalls struct {
	enumerated  int
	inUseCalls  int
	planCalls   int
	planGrace   time.Duration
	planInUse   []string
	execCalls   int
	execGrace   time.Duration
	execPlanPtr *image.PrunePlan
}

// fixedNow is the injected clock for every row (the planner never calls time.Now).
var fixedNow = time.Date(2026, 7, 30, 12, 0, 0, 0, time.UTC)

// testPruneEnv returns a fake pruneEnv plus its call recorder. The inventory is a
// two-image store: one manifest chain that is old and unreferenced (so a real
// PlanPrune yields a non-empty delete set) and one young layer. Each row builds
// its own env, so this is -race / t.Parallel safe.
func testPruneEnv(out *bytes.Buffer) (pruneEnv, *pruneCalls) {
	rec := &pruneCalls{}
	const (
		mfst = "sha256:" + "aa11223344556677889900aabbccddeeff00112233445566778899aabbccddee"
		cfg  = "sha256:" + "bb11223344556677889900aabbccddeeff00112233445566778899aabbccddee"
		lay  = "sha256:" + "cc11223344556677889900aabbccddeeff00112233445566778899aabbccddee"
		grn  = "sha256:" + "dd11223344556677889900aabbccddeeff00112233445566778899aabbccddee"
	)
	old := fixedNow.Add(-48 * time.Hour)
	young := fixedNow.Add(-time.Minute)
	rel := func(d string) string { return strings.Replace(d, ":", "/", 1) }
	nodes := []image.BlobNode{
		{Path: rel(mfst), Digest: mfst, Kind: image.BlobKindManifest, Size: 512, ModTime: old},
		{Path: rel(cfg), Digest: cfg, Kind: image.BlobKindConfig, Size: 2048, ModTime: old},
		{Path: rel(lay), Digest: lay, Kind: image.BlobKindLayer, Size: 4 << 20, ModTime: old},
		{Path: rel(grn), Digest: grn, Kind: image.BlobKindLayer, Size: 8 << 20, ModTime: young},
	}
	edges := []image.ImageEdge{{Manifest: mfst, Config: cfg, Layers: []string{lay, grn}}}

	env := pruneEnv{
		euid: func() int { return 501 },
		now:  func() time.Time { return fixedNow },
		out:  out,
		enumerate: func(root string) ([]image.BlobNode, []image.ImageEdge, error) {
			rec.enumerated++
			return nodes, edges, nil
		},
		inUse: func(root string) (inUseSet, error) {
			rec.inUseCalls++
			return inUseSet{Derivable: false, Pods: 2, Detail: "fake: no live-pod→image mapping on disk"}, nil
		},
		plan: func(n []image.BlobNode, e []image.ImageEdge, inUse []string, grace time.Duration, now time.Time) (*image.PrunePlan, error) {
			rec.planCalls++
			rec.planGrace = grace
			rec.planInUse = inUse
			return image.PlanPrune(n, e, inUse, grace, now)
		},
		execute: func(root string, plan *image.PrunePlan, grace time.Duration, now time.Time) (*image.ExecuteReport, error) {
			rec.execCalls++
			rec.execGrace = grace
			rec.execPlanPtr = plan
			return &image.ExecuteReport{
				Deleted:      len(plan.Delete),
				DeletedBytes: 512,
				Skipped:      []image.SkippedBlob{{Path: "sha256/deadbeef", Reason: "younger than grace"}},
			}, nil
		},
	}
	return env, rec
}

// mfstDigest is the manifest digest testPruneEnv's inventory describes; a row
// that needs a derivable in-use set protects exactly this chain.
const mfstDigest = "sha256:" + "aa11223344556677889900aabbccddeeff00112233445566778899aabbccddee"

func TestImagePruneCLI(t *testing.T) {
	t.Parallel()

	type want struct {
		err       bool
		errHas    []string // substrings the error must name
		outHas    []string // substrings the output must contain
		execCalls int
		planGrace time.Duration // 0 = unchecked
	}
	cases := []struct {
		name string
		args []string
		mut  func(*pruneEnv) // override the baseline for the field under test
		want want
	}{
		// DRY RUN IS THE DEFAULT: no flags ⇒ plan only, executor never called.
		{
			name: "dry-run/default-never-executes",
			args: nil,
			mut:  func(e *pruneEnv) {},
			want: want{
				outHas:    []string{"DRY RUN", "nothing will be deleted", "delete set", "delete-unreferenced", "mode=dry-run"},
				execCalls: 0,
				planGrace: defaultPruneGrace,
			},
		},
		// Reclaim figures are LOGICAL, never a promise of freed bytes.
		{
			name: "dry-run/labels-reclaim-as-logical",
			args: nil,
			mut:  func(e *pruneEnv) {},
			want: want{
				outHas:    []string{"logical", "LOGICAL blob sizes", "free-space delta", "delete_logical_bytes="},
				execCalls: 0,
			},
		},
		// An underivable in-use set must be labelled as such, not printed as "0 in use".
		{
			name: "dry-run/labels-underivable-in-use-set-provisional",
			args: nil,
			mut:  func(e *pruneEnv) {},
			want: want{
				outHas:    []string{"UNDERIVABLE", "PROVISIONAL", "inuse=underivable"},
				execCalls: 0,
			},
		},
		// --execute without root: refused before anything is touched.
		{
			name: "execute/non-root-refused",
			args: []string{"--execute"},
			mut:  func(e *pruneEnv) { e.euid = func() int { return 501 } },
			want: want{
				err:       true,
				errHas:    []string{"--execute needs root", "sudo", "root-owned"},
				execCalls: 0,
			},
		},
		// THE DELETE-THE-WORLD GUARD: root, but the in-use set cannot be proven.
		{
			name: "execute/root-with-underivable-in-use-set-refused",
			args: []string{"--execute"},
			mut:  func(e *pruneEnv) { e.euid = func() int { return 0 } },
			want: want{
				err:       true,
				errHas:    []string{"refusing to delete", "cannot prove which images are in use", "no live-pod→image mapping"},
				execCalls: 0,
			},
		},
		// The seam the M12.1-d1 image index fills: a PROVEN in-use set executes.
		{
			name: "execute/root-with-derivable-in-use-set-executes",
			args: []string{"--execute"},
			mut: func(e *pruneEnv) {
				e.euid = func() int { return 0 }
				e.inUse = func(root string) (inUseSet, error) {
					return inUseSet{Derivable: true, Digests: []string{mfstDigest}, Pods: 1, Detail: "fake: proven mapping"}, nil
				}
			},
			want: want{
				outHas:    []string{"EXECUTED", "deleted:", "skipped:", "logical", "mode=execute"},
				execCalls: 1,
			},
		},
		// --grace parses and reaches the planner (and the executor) unchanged.
		{
			name: "grace/parsed-and-passed-to-planner",
			args: []string{"--grace", "2h30m"},
			mut:  func(e *pruneEnv) {},
			want: want{
				outHas:    []string{"grace: 2h30m0s", "grace=2h30m0s"},
				planGrace: 150 * time.Minute,
			},
		},
		{
			name: "grace/negative-rejected",
			args: []string{"--grace", "-1s"},
			mut:  func(e *pruneEnv) {},
			want: want{err: true, errHas: []string{"--grace", "negative"}, execCalls: 0},
		},
		{
			name: "pod-root/empty-rejected",
			args: []string{"--pod-root", ""},
			mut:  func(e *pruneEnv) {},
			want: want{err: true, errHas: []string{"--pod-root"}, execCalls: 0},
		},
		{
			name: "flags/positional-argument-rejected",
			args: []string{"stray"},
			mut:  func(e *pruneEnv) {},
			want: want{err: true, errHas: []string{"unexpected argument"}, execCalls: 0},
		},
		{
			name: "flags/unknown-flag-rejected",
			args: []string{"--nope"},
			mut:  func(e *pruneEnv) {},
			want: want{err: true, errHas: []string{"parse flags"}, execCalls: 0},
		},
	}

	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			var out bytes.Buffer
			env, rec := testPruneEnv(&out)
			c.mut(&env)

			err := imagePruneCLI(c.args, env)
			if c.want.err && err == nil {
				t.Fatalf("want an error, got nil (output: %q)", out.String())
			}
			if !c.want.err && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			for _, s := range c.want.errHas {
				if err == nil || !strings.Contains(err.Error(), s) {
					t.Errorf("error %v does not name %q", err, s)
				}
			}
			for _, s := range c.want.outHas {
				if !strings.Contains(out.String(), s) {
					t.Errorf("output missing %q\n---\n%s---", s, out.String())
				}
			}
			if rec.execCalls != c.want.execCalls {
				t.Errorf("executor called %d time(s), want %d", rec.execCalls, c.want.execCalls)
			}
			if c.want.planGrace != 0 && rec.planGrace != c.want.planGrace {
				t.Errorf("planner got grace %v, want %v", rec.planGrace, c.want.planGrace)
			}
		})
	}

	// The executor must receive EXACTLY the plan that was printed/planned — not a
	// re-derived one — and an in-use set that reached the planner.
	t.Run("execute/passes-the-planned-plan-and-grace-through", func(t *testing.T) {
		t.Parallel()
		var out bytes.Buffer
		env, rec := testPruneEnv(&out)
		env.euid = func() int { return 0 }
		env.inUse = func(root string) (inUseSet, error) {
			return inUseSet{Derivable: true, Digests: []string{mfstDigest}, Detail: "fake"}, nil
		}
		var planned *image.PrunePlan
		inner := env.plan
		env.plan = func(n []image.BlobNode, e []image.ImageEdge, inUse []string, grace time.Duration, now time.Time) (*image.PrunePlan, error) {
			p, err := inner(n, e, inUse, grace, now)
			planned = p
			return p, err
		}
		if err := imagePruneCLI([]string{"--execute", "--grace", "45m"}, env); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if rec.execCalls != 1 {
			t.Fatalf("executor called %d time(s), want exactly 1", rec.execCalls)
		}
		if rec.execPlanPtr != planned {
			t.Errorf("executor got plan %p, want the planned plan %p", rec.execPlanPtr, planned)
		}
		if rec.execGrace != 45*time.Minute {
			t.Errorf("executor got grace %v, want 45m", rec.execGrace)
		}
		if len(rec.planInUse) != 1 || rec.planInUse[0] != mfstDigest {
			t.Errorf("planner got in-use %v, want [%s]", rec.planInUse, mfstDigest)
		}
		// The in-use manifest's chain must NOT be in the delete set.
		for _, d := range planned.Delete {
			if strings.Contains(mfstDigest, strings.Replace(d.Node.Path, "/", ":", 1)) {
				t.Errorf("in-use manifest %s planned for deletion", d.Node.Path)
			}
		}
	})

	// An UNDERIVABLE in-use set never leaks a partial digest list into the planner.
	t.Run("in-use/underivable-set-yields-no-digests", func(t *testing.T) {
		t.Parallel()
		s := inUseSet{Derivable: false, Digests: []string{mfstDigest}}
		if got := s.digests(); got != nil {
			t.Fatalf("underivable set returned digests %v, want nil", got)
		}
	})

	// The PRODUCTION derivation is UNCONDITIONALLY underivable in v1 — with pod
	// dirs present, with none, and with no pods dir at all — so `--execute` can
	// never be reached today. This is the property the refusal rests on.
	t.Run("in-use/production-derivation-is-unconditionally-underivable", func(t *testing.T) {
		t.Parallel()
		for _, tc := range []struct {
			name     string
			podDirs  []string
			makePods bool
			wantPods int
		}{
			{name: "no-pods-dir", makePods: false},
			{name: "empty-pods-dir", makePods: true},
			{name: "two-pod-dirs", makePods: true, podDirs: []string{"pod-a", "pod-b"}, wantPods: 2},
		} {
			tc := tc
			t.Run(tc.name, func(t *testing.T) {
				t.Parallel()
				root := t.TempDir()
				if tc.makePods {
					if err := os.MkdirAll(filepath.Join(root, "pods"), 0o755); err != nil {
						t.Fatalf("mkdir pods: %v", err)
					}
				}
				for _, p := range tc.podDirs {
					if err := os.MkdirAll(filepath.Join(root, "pods", p, "rootfs"), 0o755); err != nil {
						t.Fatalf("mkdir pod dir: %v", err)
					}
				}
				use, err := derivePodInUse(root)
				if err != nil {
					t.Fatalf("derivePodInUse: %v", err)
				}
				if use.Derivable {
					t.Fatal("production derivation reported Derivable=true — v1 has no live-pod→image mapping on disk, so --execute must always refuse")
				}
				if use.Pods != tc.wantPods {
					t.Errorf("pods = %d, want %d", use.Pods, tc.wantPods)
				}
				if use.Detail == "" {
					t.Error("empty Detail — the refusal message needs it")
				}
				// And the refusal it produces really does block --execute as root.
				var out bytes.Buffer
				env, rec := testPruneEnv(&out)
				env.euid = func() int { return 0 }
				env.inUse = derivePodInUse
				if err := imagePruneCLI([]string{"--execute", "--pod-root", root}, env); err == nil {
					t.Fatal("--execute as root was NOT refused with the production derivation")
				}
				if rec.execCalls != 0 {
					t.Fatalf("executor called %d time(s) despite the refusal", rec.execCalls)
				}
			})
		}
	})

	// Router: no sub-verb and an unknown sub-verb are both usage errors naming
	// the known verbs (B117/B118 add load/import/ls here additively).
	t.Run("router/usage-errors", func(t *testing.T) {
		t.Parallel()
		if err := runImage(nil); err == nil {
			t.Error("`k3sm image` with no subcommand must be a usage error")
		} else if !strings.Contains(err.Error(), "prune") {
			t.Errorf("usage error %v does not list the known verbs", err)
		}
		err := runImage([]string{"bogus"})
		if err == nil {
			t.Fatal("unknown subcommand must be a usage error")
		}
		for _, s := range []string{"bogus", "prune"} {
			if !strings.Contains(err.Error(), s) {
				t.Errorf("usage error %v does not name %q", err, s)
			}
		}
	})

	// Size rendering must name the RIGHT unit: an off-by-one here reports a 5 MB
	// layer as gigabytes and would make an operator delete on a false premise.
	t.Run("human-bytes/units", func(t *testing.T) {
		t.Parallel()
		for _, tc := range []struct {
			n    int64
			want string
		}{
			{0, "0 B"},
			{7, "7 B"},
			{1023, "1023 B"},
			{1024, "1 KiB"},
			{5_000_000, "4.8 MiB"},
			{5 << 30, "5 GiB"},
		} {
			if got := humanBytes(tc.n); got != tc.want {
				t.Errorf("humanBytes(%d) = %q, want %q", tc.n, got, tc.want)
			}
		}
	})

	// openCache must not CREATE anything: a dry-run scan is strictly read-only
	// (image.NewCache would MkdirAll the blobs dir).
	t.Run("open-cache/absent-store-creates-nothing", func(t *testing.T) {
		t.Parallel()
		root := t.TempDir()
		if _, err := openCache(root); err == nil {
			t.Fatal("openCache on a root with no blobs dir must error, not create it")
		}
		if _, err := os.Stat(filepath.Join(root, "blobs")); err == nil {
			t.Fatal("openCache created the blobs dir — the scan must be read-only")
		}
	})
}

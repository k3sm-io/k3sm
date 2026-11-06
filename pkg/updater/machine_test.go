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

package updater

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"k3sm.io/k3sm/pkg/install/order"
	"k3sm.io/k3sm/pkg/updater/layout"
)

// fakeLaunchctl is the restarter: it records the labels it kickstarts.
type fakeLaunchctl struct {
	mu     sync.Mutex
	labels []string
}

func (f *fakeLaunchctl) Kickstart(_ context.Context, label string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.labels = append(f.labels, label)
	return nil
}

// fakeHealth reports the node: mounted unless told otherwise, every probe
// green unless listed in red.
type fakeHealth struct {
	mu        sync.Mutex
	unmounted bool
	red       map[Probe]bool
	asked     []Probe
}

func (h *fakeHealth) DataRootMounted(context.Context) (bool, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return !h.unmounted, nil
}

func (h *fakeHealth) Check(_ context.Context, p Probe) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.asked = append(h.asked, p)
	if h.red[p] {
		return errors.New("red")
	}
	return nil
}

// swapRig is a stage rig with 0.1.0 (old), previous 0.2.0, current 0.3.0,
// updater/current 0.3.0 and 0.4.0 staged.
type swapRig struct {
	*stageRig
	m      *Machine
	clock  *fakeClock
	health *fakeHealth
	launch *fakeLaunchctl
}

func newSwapRig(t *testing.T) *swapRig {
	t.Helper()
	r := newStageRig(t)
	installVersion(t, r.l, "0.1.0")
	link(t, r.fs, r.l.PlanUpdaterCurrent, "0.3.0")
	r.deliver(t, newRelease("0.4.0"), goodSig)
	if _, err := r.stage(t); err != nil {
		t.Fatal(err)
	}
	clock := r.s.Clock.(*fakeClock)
	s := &swapRig{stageRig: r, clock: clock, health: &fakeHealth{red: map[Probe]bool{}}, launch: &fakeLaunchctl{}}
	s.m = &Machine{FS: r.fs, Layout: r.l, Code: r.code, Restarter: s.launch, Health: s.health,
		Clock: clock, Pods: fakePods(nil), Role: order.Agent}
	return s
}

func (s *swapRig) links(t *testing.T) (cur, prev, upd string) {
	t.Helper()
	cur, _ = s.l.ResolveActive(os.Readlink)
	prev, _ = s.l.ResolvePrevious(os.Readlink)
	upd, _ = s.l.ResolveUpdater(os.Readlink)
	return cur, prev, upd
}

func (s *swapRig) marker(t *testing.T) *Marker {
	t.Helper()
	mk, err := s.m.readMarker()
	if err != nil {
		t.Fatal(err)
	}
	return mk
}

func wantOutcome(t *testing.T, got Outcome, err error, want Outcome) {
	t.Helper()
	if got != want {
		t.Fatalf("outcome = %s (%v), want %s", got, err, want)
	}
}

func wantLinks(t *testing.T, s *swapRig, cur, prev, upd string) {
	t.Helper()
	if c, p, u := s.links(t); c != cur || p != prev || u != upd {
		t.Fatalf("current, previous, updater/current = %s, %s, %s; want %s, %s, %s", c, p, u, cur, prev, upd)
	}
}

// TestSwap is the swap state machine's table: activation, resume, health,
// commit and rollback, on a temporary root with a fake launchctl, fake health
// and a clock seam.
func TestSwap(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		name string
		run  func(t *testing.T, s *swapRig)
	}{
		{"activate flips, restarts in order and waits", func(t *testing.T, s *swapRig) {
			out, err := s.m.Activate(ctx, "0.4.0")
			wantOutcome(t, out, err, OutcomeWaiting)
			wantLinks(t, s, "0.4.0", "0.3.0", "0.3.0")
			if want := []string{order.NetdLabel, order.AgentLabel}; !slices.Equal(s.launch.labels, want) {
				t.Errorf("restarted %v, want %v", s.launch.labels, want)
			}
			if mk := s.marker(t); mk.Phase != PhaseHealthWait || mk.From != "0.3.0" || mk.To != "0.4.0" {
				t.Errorf("marker = %+v", mk)
			}
		}},
		{"resumes an unfinished flipped and restarting from the marker", func(t *testing.T, s *swapRig) {
			// Crash at every write and rename the activation makes, then
			// resume: each run ends in health-wait on the same links, and
			// previous is always the version the marker names.
			for crash := 1; ; crash++ {
				s := newSwapRig(t)
				s.fs.crashAt = s.fs.ops + crash
				_, err := s.m.Activate(ctx, "0.4.0")
				s.fs.crashAt = 0
				if err == nil {
					if crash < 4 {
						t.Fatalf("activation finished after only %d steps", crash)
					}
					break
				}
				if !errors.Is(err, errCrash) {
					t.Fatalf("crash %d: %v", crash, err)
				}
				if c, p, _ := s.links(t); c == "0.4.0" && p != "0.3.0" {
					t.Fatalf("crash %d: current moved while previous is %s, an older rollback target", crash, p)
				}
				out, err := s.m.Resume(ctx)
				if mk := s.marker(t); mk == nil {
					// The crash came before the first marker write: nothing
					// was flipped and nothing resumes.
					wantOutcome(t, out, err, OutcomeIdle)
					wantLinks(t, s, "0.3.0", "0.2.0", "0.3.0")
					continue
				}
				wantOutcome(t, out, err, OutcomeWaiting)
				wantLinks(t, s, "0.4.0", "0.3.0", "0.3.0")
				if !slices.Contains(s.launch.labels, order.AgentLabel) {
					t.Errorf("crash %d: the node daemon was never restarted", crash)
				}
			}
			for _, phase := range []Phase{PhaseFlipped, PhaseRestarting} {
				s := newSwapRig(t)
				mk := Marker{From: "0.3.0", To: "0.4.0", Phase: phase, BootID: "b1", Deadline: s.clock.Now().Add(HealthWindow)}
				if phase == PhaseRestarting {
					link(t, s.fs, s.l.PlanCurrent, "0.4.0")
					link(t, s.fs, s.l.PlanPrevious, "0.3.0")
				}
				if err := s.m.writeMarker(mk); err != nil {
					t.Fatal(err)
				}
				out, err := s.m.Resume(ctx)
				wantOutcome(t, out, err, OutcomeWaiting)
				wantLinks(t, s, "0.4.0", "0.3.0", "0.3.0")
				if want := []string{order.NetdLabel, order.AgentLabel}; !slices.Equal(s.launch.labels, want) {
					t.Errorf("%s: restarted %v, want %v", phase, s.launch.labels, want)
				}
			}
		}},
		{"rolls back a health-wait past its deadline", func(t *testing.T, s *swapRig) {
			out, err := s.m.Activate(ctx, "0.4.0")
			wantOutcome(t, out, err, OutcomeWaiting)
			s.health.red[ProbeAgentReady] = true
			out, err = s.m.Poll(ctx)
			wantOutcome(t, out, err, OutcomeWaiting)
			s.clock.advance(HealthWindow + time.Second)
			out, err = s.m.Poll(ctx)
			wantOutcome(t, out, err, OutcomeRolledBack)
			wantLinks(t, s, "0.3.0", "0.3.0", "0.3.0")
			if s.marker(t) != nil {
				t.Error("marker left after the rollback")
			}
			// The same holds at start, after the updater itself restarted.
			s2 := newSwapRig(t)
			if _, err := s2.m.Activate(ctx, "0.4.0"); err != nil {
				t.Fatal(err)
			}
			s2.health.red[ProbeNetd] = true
			s2.clock.advance(HealthWindow + time.Second)
			out, err = s2.m.Resume(ctx)
			wantOutcome(t, out, err, OutcomeRolledBack)
		}},
		{"re-arms the deadline from the marker at start and restarts the window after a reboot", func(t *testing.T, s *swapRig) {
			if _, err := s.m.Activate(ctx, "0.4.0"); err != nil {
				t.Fatal(err)
			}
			s.health.red[ProbeJobs] = true
			armed := s.marker(t).Deadline
			// Same boot: the persisted deadline stands, not a fresh one.
			s.clock.advance(HealthWindow - time.Second)
			out, err := s.m.Resume(ctx)
			wantOutcome(t, out, err, OutcomeWaiting)
			if got := s.marker(t).Deadline; !got.Equal(armed) {
				t.Errorf("deadline moved without a reboot: %v -> %v", armed, got)
			}
			// A reboot: the window restarts from now.
			s.clock.advance(time.Hour)
			s.clock.reboot("b2")
			out, err = s.m.Resume(ctx)
			wantOutcome(t, out, err, OutcomeWaiting)
			mk := s.marker(t)
			if want := s.clock.Now().Add(HealthWindow); !mk.Deadline.Equal(want) || mk.BootID != "b2" {
				t.Errorf("after reboot marker = %+v, want deadline %v in b2", mk, want)
			}
			s.clock.advance(HealthWindow + time.Second)
			out, err = s.m.Poll(ctx)
			wantOutcome(t, out, err, OutcomeRolledBack)
		}},
		{"data root unmounted gives data-root-unmounted with no rollback", func(t *testing.T, s *swapRig) {
			if _, err := s.m.Activate(ctx, "0.4.0"); err != nil {
				t.Fatal(err)
			}
			s.health.unmounted = true
			s.clock.advance(HealthWindow + time.Hour)
			for _, f := range []func(context.Context) (Outcome, error){s.m.Poll, s.m.Resume} {
				out, err := f(ctx)
				wantOutcome(t, out, err, OutcomeDataRootUnmounted)
			}
			wantLinks(t, s, "0.4.0", "0.3.0", "0.3.0")
			if len(s.health.asked) != 0 {
				t.Errorf("probes ran with the data root unmounted: %v", s.health.asked)
			}
		}},
		{"server health needs /readyz and one kine read", func(t *testing.T, s *swapRig) {
			s.m.Role = order.Server
			for _, p := range []Probe{ProbeReadyz, ProbeKineRead} {
				s := newSwapRig(t)
				s.m.Role = order.Server
				if _, err := s.m.Activate(ctx, "0.4.0"); err != nil {
					t.Fatal(err)
				}
				s.health.red[p] = true
				out, err := s.m.Poll(ctx)
				wantOutcome(t, out, err, OutcomeWaiting)
				delete(s.health.red, p)
				out, err = s.m.Poll(ctx)
				wantOutcome(t, out, err, OutcomeCommitted)
			}
			// A worker never asks for them.
			if _, err := s.m.Activate(ctx, "0.4.0"); err != nil {
				t.Fatal(err)
			}
			s.m.Role = order.Agent
			if out, err := s.m.Poll(ctx); out != OutcomeCommitted {
				t.Fatalf("agent poll = %s, %v", out, err)
			}
			if slices.Contains(s.health.asked, ProbeReadyz) || slices.Contains(s.health.asked, ProbeKineRead) {
				t.Errorf("a worker asked for server probes: %v", s.health.asked)
			}
		}},
		{"commit sets previous, raises the high-water mark and commits updater/current", func(t *testing.T, s *swapRig) {
			if err := s.m.state().fs.WriteFileAtomic(s.m.state().path(highwaterName), []byte("0.3.0\n"), stateFileMode); err != nil {
				t.Fatal(err)
			}
			if _, err := s.m.Activate(ctx, "0.4.0"); err != nil {
				t.Fatal(err)
			}
			wantLinks(t, s, "0.4.0", "0.3.0", "0.3.0")
			out, err := s.m.Poll(ctx)
			wantOutcome(t, out, err, OutcomeCommitted)
			wantLinks(t, s, "0.4.0", "0.3.0", "0.4.0")
			if hw, err := s.m.state().highwater(); hw != "0.4.0" || err != nil {
				t.Errorf("high-water = %q, %v", hw, err)
			}
			if s.marker(t) != nil {
				t.Error("marker left after commit")
			}
			if st, _ := s.m.state().staged(); st != "" {
				t.Errorf("staged record left: %s", st)
			}
			if out, err := s.m.Poll(ctx); out != OutcomeIdle || err != nil {
				t.Errorf("after commit Poll = %s, %v", out, err)
			}
		}},
		{"rollback re-runs the Apple leg on previous and refuses the flip when it fails", func(t *testing.T, s *swapRig) {
			if _, err := s.m.Activate(ctx, "0.4.0"); err != nil {
				t.Fatal(err)
			}
			s.code.checked = nil
			s.code.refuse["0.3.0"] = true
			s.health.red[ProbeJobs] = true
			s.clock.advance(HealthWindow + time.Second)
			out, err := s.m.Poll(ctx)
			wantOutcome(t, out, err, OutcomeRefused)
			if !errors.Is(err, ErrRollbackRefused) {
				t.Errorf("err = %v, want ErrRollbackRefused", err)
			}
			wantLinks(t, s, "0.4.0", "0.3.0", "0.3.0")
			if len(s.code.checked) == 0 || !strings.Contains(s.code.checked[0], "/versions/0.3.0/") {
				t.Errorf("Apple leg ran on %v, not previous", s.code.checked)
			}
			if mk := s.marker(t); mk == nil || mk.Phase != PhaseRollbackRefused {
				t.Errorf("marker = %+v, want rollback-refused", mk)
			}
			// It stays refused across a restart and does not loop.
			out, _ = s.m.Resume(ctx)
			wantOutcome(t, out, nil, OutcomeRefused)
			wantLinks(t, s, "0.4.0", "0.3.0", "0.3.0")
			// A sound previous is checked and flipped to.
			s2 := newSwapRig(t)
			if _, err := s2.m.Activate(ctx, "0.4.0"); err != nil {
				t.Fatal(err)
			}
			s2.code.checked = nil
			out, err = s2.m.Rollback(ctx)
			wantOutcome(t, out, err, OutcomeRolledBack)
			if len(s2.code.checked) != len(RequiredMembers)+1 {
				t.Errorf("Apple leg ran on %d binaries of previous, want %d", len(s2.code.checked), len(RequiredMembers)+1)
			}
		}},
		{"ad-hoc tree has no automatic rollback", func(t *testing.T, s *swapRig) {
			// A dev install's previous is ad-hoc signed, which the Apple
			// leg refuses; the health deadline then flips nothing.
			if _, err := s.m.Activate(ctx, "0.4.0"); err != nil {
				t.Fatal(err)
			}
			for _, bin := range RequiredMembers {
				s.code.refuse[bin] = true
			}
			s.health.red[ProbeAgentReady] = true
			s.clock.advance(HealthWindow + time.Second)
			out, err := s.m.Poll(ctx)
			wantOutcome(t, out, err, OutcomeRefused)
			wantLinks(t, s, "0.4.0", "0.3.0", "0.3.0")
			if bad, _ := s.m.state().badList(); len(bad) != 0 {
				t.Errorf("bad list %v after a refused rollback", bad)
			}
		}},
		{"bad version refused until repair --clear-bad", func(t *testing.T, s *swapRig) {
			if _, err := s.m.Activate(ctx, "0.4.0"); err != nil {
				t.Fatal(err)
			}
			if out, err := s.m.Rollback(ctx); out != OutcomeRolledBack {
				t.Fatalf("Rollback = %s, %v", out, err)
			}
			if err := s.s.state().writeStaged("0.4.0"); err != nil {
				t.Fatal(err)
			}
			_, err := s.m.Activate(ctx, "v0.4.0")
			if !errors.Is(err, ErrNotStaged) {
				t.Fatalf("spelling variant: err = %v", err)
			}
			_, err = s.m.Activate(ctx, "0.4.0")
			wantErr(t, err, ErrVersionBad)
			_, err = s.stage(t)
			wantErr(t, err, ErrVersionBad)
			if err := s.m.ClearBad("v0.4.0"); err != nil {
				t.Fatal(err)
			}
			out, err := s.m.Activate(ctx, "0.4.0")
			wantOutcome(t, out, err, OutcomeWaiting)
		}},
		{"downgrade refused except the rollback to previous", func(t *testing.T, s *swapRig) {
			if err := s.s.state().writeStaged("0.2.0"); err != nil {
				t.Fatal(err)
			}
			_, err := s.m.Activate(ctx, "0.2.0")
			wantErr(t, err, ErrDowngrade)
			// Below the high-water mark, even above current.
			if err := s.fs.WriteFileAtomic(s.m.state().path(highwaterName), []byte("0.5.0\n"), stateFileMode); err != nil {
				t.Fatal(err)
			}
			if err := s.s.state().writeStaged("0.4.0"); err != nil {
				t.Fatal(err)
			}
			_, err = s.m.Activate(ctx, "0.4.0")
			wantErr(t, err, ErrDowngrade)
			// The rollback to previous goes down.
			out, err := s.m.Rollback(ctx)
			wantOutcome(t, out, err, OutcomeRolledBack)
			wantLinks(t, s, "0.2.0", "0.2.0", "0.2.0")
		}},
		{"a fourth staged version refused", func(t *testing.T, s *swapRig) {
			s.deliver(t, newRelease("0.5.0"), goodSig)
			_, err := s.stage(t)
			wantErr(t, err, layout.ErrStagingFull)
		}},
		{"older versions removed after commit", func(t *testing.T, s *swapRig) {
			installVersion(t, s.l, "0.0.9")
			s.m.Pods = fakePods{"0.0.9"}
			if _, err := s.m.Activate(ctx, "0.4.0"); err != nil {
				t.Fatal(err)
			}
			if out, err := s.m.Poll(ctx); out != OutcomeCommitted {
				t.Fatalf("Poll = %s, %v", out, err)
			}
			for ver, kept := range map[string]bool{"0.0.9": true, "0.1.0": false, "0.2.0": false, "0.3.0": true, "0.4.0": true} {
				_, err := os.Lstat(filepath.Join(s.l.VersionsDir(), ver))
				if kept != (err == nil) {
					t.Errorf("%s kept = %v, want %v", ver, err == nil, kept)
				}
			}
		}},
		{"every marker write flushed with F_FULLFSYNC", func(t *testing.T, s *swapRig) {
			s.fs.events = nil
			if _, err := s.m.Activate(ctx, "0.4.0"); err != nil {
				t.Fatal(err)
			}
			if _, err := s.m.Rollback(ctx); err != nil {
				t.Fatal(err)
			}
			marker := filepath.Join(s.l.StateDir(), markerName)
			writes := 0
			for i, e := range s.fs.events {
				if e != "write "+marker && e != "unlink "+marker {
					continue
				}
				writes++
				rest := s.fs.events[i+1:]
				j := slices.Index(rest, "sync "+marker+".tmp")
				k := slices.Index(rest, "sync "+s.l.StateDir())
				if strings.HasPrefix(e, "write") && (j < 0 || k < j) {
					t.Errorf("marker write %d: the file was not flushed before its directory: %v", writes, rest)
				}
				if k < 0 {
					t.Errorf("marker write %d: updater-state not flushed", writes)
				}
			}
			// flipped, restarting, health-wait, rolling-back, removal.
			if writes != 5 {
				t.Errorf("%d marker writes, want 5", writes)
			}
			// A flush that fails stops the swap before anything flips.
			s2 := newSwapRig(t)
			s2.fs.OSFS.FullSync = func(*os.File) error { return errors.New("F_FULLFSYNC: ENOTSUP") }
			if _, err := s2.m.Activate(ctx, "0.4.0"); err == nil {
				t.Fatal("a swap ran without a durable marker")
			}
			wantLinks(t, s2, "0.3.0", "0.2.0", "0.3.0")
		}},
		{"remove-stale unlinks a link and refuses a directory", func(t *testing.T, s *swapRig) {
			tmp := s.l.Current() + layout.TempSuffix
			if err := os.Symlink("versions/0.1.0", tmp); err != nil {
				t.Fatal(err)
			}
			if err := removeStale(s.fs, tmp); err != nil {
				t.Fatal(err)
			}
			if _, err := os.Lstat(tmp); !errors.Is(err, fs.ErrNotExist) {
				t.Errorf("stale link left: %v", err)
			}
			if err := os.Mkdir(tmp, 0o755); err != nil {
				t.Fatal(err)
			}
			_, err := s.m.Activate(ctx, "0.4.0")
			wantErr(t, err, ErrStaleIsDirectory)
			if _, err := os.Stat(tmp); err != nil {
				t.Errorf("the directory was removed: %v", err)
			}
		}},
		{"activation re-verifies the version tree", func(t *testing.T, s *swapRig) {
			k := filepath.Join(s.l.VersionsDir(), "0.4.0", "k3sm")
			s.fs.uid[k] = k3smUID
			_, err := s.m.Activate(ctx, "0.4.0")
			wantErr(t, err, ErrTreeMember)
			delete(s.fs.uid, k)
			s.fs.acl[k] = true
			_, err = s.m.Activate(ctx, "0.4.0")
			wantErr(t, err, ErrTreeMember)
			wantLinks(t, s, "0.3.0", "0.2.0", "0.3.0")
		}},
	} {
		t.Run(tc.name, func(t *testing.T) { tc.run(t, newSwapRig(t)) })
	}
}

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
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"path/filepath"
	"time"

	"k3sm.io/k3sm/pkg/install/order"
	"k3sm.io/k3sm/pkg/updater/layout"
)

// HealthWindow is how long a swapped node has to report healthy before the
// updater rolls it back. It is a compiled constant.
const HealthWindow = 5 * time.Minute

// Phase is the step a swap marker records. The marker is written, and
// flushed, before the step it names is taken.
type Phase string

// The swap phases.
const (
	// PhaseFlipped is written before the links are flipped to the new version.
	PhaseFlipped Phase = "flipped"
	// PhaseRestarting is written before the jobs are restarted.
	PhaseRestarting Phase = "restarting"
	// PhaseHealthWait is written before the health window opens.
	PhaseHealthWait Phase = "health-wait"
	// PhaseRollingBack is written before the links are flipped back.
	PhaseRollingBack Phase = "rolling-back"
	// PhaseRollbackRefused records a rollback whose target failed the Apple
	// leg: the node stays on the new version for a person to repair.
	PhaseRollbackRefused Phase = "rollback-refused"
)

// Outcome is what a step of the machine left the node in: a closed code set
// the status surface and the controller read.
type Outcome string

// The outcomes.
const (
	OutcomeIdle              Outcome = "idle"
	OutcomeWaiting           Outcome = "health-wait"
	OutcomeCommitted         Outcome = "committed"
	OutcomeRolledBack        Outcome = "rolled-back"
	OutcomeRefused           Outcome = "refused"
	OutcomeDataRootUnmounted Outcome = "data-root-unmounted"
)

var (
	// ErrSwapInProgress reports an activate while a marker is present.
	ErrSwapInProgress = errors.New("a swap is in progress")
	// ErrNotStaged reports an activate of a version that is not the staged one.
	ErrNotStaged = errors.New("the version is not staged")
	// ErrRollbackRefused reports a rollback target that failed the Apple leg,
	// an ad-hoc tree among them: such a node has no automatic rollback.
	ErrRollbackRefused = errors.New("the rollback target failed the Apple code check; the flip is refused")
	// ErrNoRollbackTarget reports a rollback with no previous version.
	ErrNoRollbackTarget = errors.New("there is no previous version to roll back to")
)

// Marker is updater-state/swap.json.
type Marker struct {
	// From is the version current named before the swap; the rollback target.
	From string `json:"from"`
	// To is the version the swap moves to.
	To string `json:"to"`
	// Phase is the step being taken.
	Phase Phase `json:"phase"`
	// Deadline is when health-wait gives up.
	Deadline time.Time `json:"deadline"`
	// BootID is the boot the deadline was armed in.
	BootID string `json:"bootID"`
}

// Machine is the swap state machine over one root.
type Machine struct {
	// FS is the filesystem.
	FS FS
	// Layout is the tree.
	Layout layout.Layout
	// Code is the Apple leg, re-run on a rollback target.
	Code CodeVerifier
	// Restarter kickstarts the jobs.
	Restarter Restarter
	// Health reports the node.
	Health NodeHealth
	// Clock drives every deadline.
	Clock Clock
	// Pods reports the versions running pods hold; a nil Pods or a failed
	// report skips the prune.
	Pods PodUsage
	// Role is the node's role; a server adds /readyz and a kine read.
	Role order.Role
	// DataVolume is true when the node has a declared data volume.
	DataVolume bool
}

func (m *Machine) state() state { return state{fs: m.FS, dir: m.Layout.StateDir()} }

// readMarker returns the marker, or nil when no swap is in progress.
func (m *Machine) readMarker() (*Marker, error) {
	data, ok, err := m.state().read(markerName)
	if err != nil || !ok {
		return nil, err
	}
	var mk Marker
	if err := strictJSON(data, &mk); err != nil {
		return nil, fmt.Errorf("%w: %s: %w", ErrBadState, markerName, err)
	}
	if err := layout.ValidateVersion(mk.To); err != nil {
		return nil, fmt.Errorf("%w: %s: %w", ErrBadState, markerName, err)
	}
	if mk.From != "" {
		if err := layout.ValidateVersion(mk.From); err != nil {
			return nil, fmt.Errorf("%w: %s: %w", ErrBadState, markerName, err)
		}
	}
	switch mk.Phase {
	case PhaseFlipped, PhaseRestarting, PhaseHealthWait, PhaseRollingBack, PhaseRollbackRefused:
	default:
		return nil, fmt.Errorf("%w: %s phase %q", ErrBadState, markerName, mk.Phase)
	}
	return &mk, nil
}

// writeMarker writes the marker through WriteFileAtomic: F_FULLFSYNC of the
// file, rename, F_FULLFSYNC of updater-state.
func (m *Machine) writeMarker(mk Marker) error {
	data, err := json.Marshal(mk)
	if err != nil {
		return err
	}
	if err := m.FS.WriteFileAtomic(m.state().path(markerName), data, stateFileMode); err != nil {
		return fmt.Errorf("write the swap marker (%s): %w", mk.Phase, err)
	}
	return nil
}

func (m *Machine) arm(mk *Marker) error {
	boot, err := m.Clock.BootID()
	if err != nil {
		return fmt.Errorf("read the boot id: %w", err)
	}
	mk.BootID = boot
	mk.Deadline = m.Clock.Now().Add(HealthWindow)
	return nil
}

// Activate moves the node to the staged version to: it checks the version,
// writes the marker before each step, flips previous then current, restarts
// the jobs in order and enters health-wait.
func (m *Machine) Activate(ctx context.Context, to string) (Outcome, error) {
	if mk, err := m.readMarker(); err != nil {
		return OutcomeRefused, err
	} else if mk != nil {
		return OutcomeRefused, fmt.Errorf("activate %s: %w (%s -> %s, %s)", to, ErrSwapInProgress, mk.From, mk.To, mk.Phase)
	}
	if err := layout.ValidateVersion(to); err != nil {
		return OutcomeRefused, err
	}
	st := m.state()
	staged, err := st.staged()
	if err != nil {
		return OutcomeRefused, err
	}
	if staged != to {
		return OutcomeRefused, fmt.Errorf("activate %s: %w (staged %q)", to, ErrNotStaged, staged)
	}
	from, err := resolveOptional(m.Layout.ResolveActive, m.FS)
	if err != nil {
		return OutcomeRefused, err
	}
	if err := st.checkTarget(to, from); err != nil {
		return OutcomeRefused, err
	}
	dir, _ := m.Layout.VersionDir(to)
	if err := checkTrustedDirs(m.FS, m.Layout.Root()); err != nil {
		return OutcomeRefused, err
	}
	if _, err := verifyVersionTree(m.FS, dir, maxTreeEntries); err != nil {
		return OutcomeRefused, err
	}
	mk := Marker{From: from, To: to, Phase: PhaseFlipped}
	if err := m.arm(&mk); err != nil {
		return OutcomeRefused, err
	}
	if err := m.writeMarker(mk); err != nil {
		return OutcomeRefused, err
	}
	return m.advance(ctx, &mk)
}

// advance carries a marker from its phase to health-wait.
func (m *Machine) advance(ctx context.Context, mk *Marker) (Outcome, error) {
	if mk.Phase == PhaseFlipped {
		// previous is re-derived from the marker, never from the links a
		// crash may have left half-flipped.
		steps, err := m.Layout.PlanFlip(mk.From, mk.To)
		if err != nil {
			return OutcomeRefused, err
		}
		if err := applySteps(m.FS, steps); err != nil {
			return OutcomeRefused, err
		}
		mk.Phase = PhaseRestarting
		if err := m.writeMarker(*mk); err != nil {
			return OutcomeRefused, err
		}
	}
	if mk.Phase == PhaseRestarting {
		if err := m.restart(ctx); err != nil {
			return OutcomeRefused, err
		}
		mk.Phase = PhaseHealthWait
		if err := m.arm(mk); err != nil {
			return OutcomeRefused, err
		}
		if err := m.writeMarker(*mk); err != nil {
			return OutcomeRefused, err
		}
	}
	return OutcomeWaiting, nil
}

func (m *Machine) restart(ctx context.Context) error {
	for _, j := range order.Start(m.Role, m.DataVolume) {
		if err := m.Restarter.Kickstart(ctx, j.Label); err != nil {
			return fmt.Errorf("restart %s: %w", j.Label, err)
		}
	}
	return nil
}

// Resume runs once at start. It re-arms the deadline from the marker,
// restarting the window when the machine rebooted since it was armed,
// completes an unfinished flipped or restarting swap, rolls back a health-wait
// past its deadline and finishes an interrupted rollback.
func (m *Machine) Resume(ctx context.Context) (Outcome, error) {
	mk, err := m.readMarker()
	if err != nil || mk == nil {
		return OutcomeIdle, err
	}
	boot, err := m.Clock.BootID()
	if err != nil {
		return OutcomeRefused, err
	}
	if boot != mk.BootID && mk.Phase != PhaseRollbackRefused {
		if err := m.arm(mk); err != nil {
			return OutcomeRefused, err
		}
		if err := m.writeMarker(*mk); err != nil {
			return OutcomeRefused, err
		}
	}
	switch mk.Phase {
	case PhaseFlipped, PhaseRestarting:
		return m.advance(ctx, mk)
	case PhaseRollingBack:
		return m.finishRollback(ctx, mk)
	case PhaseRollbackRefused:
		return OutcomeRefused, ErrRollbackRefused
	}
	return m.Poll(ctx)
}

// Poll evaluates health once. Outside a swap it is OutcomeIdle. An unmounted
// data root is OutcomeDataRootUnmounted and never rolls back. All probes green
// commits; a red probe waits until the deadline and then rolls back.
func (m *Machine) Poll(ctx context.Context) (Outcome, error) {
	mk, err := m.readMarker()
	if err != nil || mk == nil {
		return OutcomeIdle, err
	}
	if mk.Phase != PhaseHealthWait {
		return m.Resume(ctx)
	}
	mounted, err := m.Health.DataRootMounted(ctx)
	if err != nil {
		return OutcomeWaiting, fmt.Errorf("read the data root: %w", err)
	}
	if !mounted {
		return OutcomeDataRootUnmounted, nil
	}
	var red error
	for _, p := range m.probes() {
		if err := m.Health.Check(ctx, p); err != nil {
			red = fmt.Errorf("%s: %w", p, err)
			break
		}
	}
	if red == nil {
		return m.commit(ctx, mk)
	}
	if m.Clock.Now().Before(mk.Deadline) {
		return OutcomeWaiting, nil
	}
	return m.rollback(ctx, mk)
}

func (m *Machine) probes() []Probe {
	ps := []Probe{ProbeJobs, ProbeNetd, ProbeAgentReady}
	if m.Role == order.Server {
		ps = append(ps, ProbeReadyz, ProbeKineRead)
	}
	return ps
}

// commit keeps the new version: previous is the old current, the updater's
// own pointer moves with the node, the high-water mark rises, the staged
// record and the marker go, and versions nothing keeps are removed.
func (m *Machine) commit(ctx context.Context, mk *Marker) (Outcome, error) {
	l := m.Layout
	var steps []layout.Step
	if mk.From != "" {
		s, err := l.PlanPrevious(mk.From)
		if err != nil {
			return OutcomeRefused, err
		}
		steps = append(steps, s...)
	}
	s, err := l.PlanUpdaterCurrent(mk.To)
	if err != nil {
		return OutcomeRefused, err
	}
	if err := applySteps(m.FS, append(steps, s...)); err != nil {
		return OutcomeRefused, err
	}
	st := m.state()
	if err := st.raiseHighwater(mk.To); err != nil {
		return OutcomeRefused, err
	}
	if err := st.remove(stagedName); err != nil {
		return OutcomeRefused, err
	}
	if err := st.remove(markerName); err != nil {
		return OutcomeRefused, err
	}
	m.prune(ctx, layout.Retained{Current: mk.To, Previous: mk.From})
	return OutcomeCommitted, nil
}

// prune removes every version directory the tree no longer keeps. A failed
// pod report keeps everything.
func (m *Machine) prune(ctx context.Context, r layout.Retained) {
	if m.Pods == nil {
		return
	}
	inUse, err := m.Pods.InUseVersions(ctx)
	if err != nil {
		return
	}
	r.InUse = inUse
	names, err := m.FS.ReadDirNames(m.Layout.VersionsDir(), maxEmptyEntries)
	if err != nil {
		return
	}
	for _, ver := range layout.PlanPrune(names, r).Remove {
		if dir, err := m.Layout.VersionDir(ver); err == nil {
			_ = m.FS.RemoveAll(dir)
		}
	}
}

// Rollback is the root verb: it flips back to previous and marks the current
// version bad, through the same Apple check as an automatic rollback.
func (m *Machine) Rollback(ctx context.Context) (Outcome, error) {
	mk, err := m.readMarker()
	if err != nil {
		return OutcomeRefused, err
	}
	if mk == nil {
		cur, err := m.Layout.ResolveActive(m.FS.Readlink)
		if err != nil {
			return OutcomeRefused, err
		}
		prev, err := resolveOptional(m.Layout.ResolvePrevious, m.FS)
		if err != nil {
			return OutcomeRefused, err
		}
		mk = &Marker{From: prev, To: cur}
	}
	return m.rollback(ctx, mk)
}

// rollback re-runs the Apple leg on the rollback target and refuses the flip
// when it fails; otherwise it marks the target of the swap bad and flips back.
func (m *Machine) rollback(ctx context.Context, mk *Marker) (Outcome, error) {
	if mk.From == "" || mk.From == mk.To {
		return OutcomeRefused, ErrNoRollbackTarget
	}
	if err := m.verifyRollbackTarget(ctx, mk.From); err != nil {
		mk.Phase = PhaseRollbackRefused
		if werr := m.writeMarker(*mk); werr != nil {
			return OutcomeRefused, errors.Join(err, werr)
		}
		return OutcomeRefused, fmt.Errorf("roll back to %s: %w: %w", mk.From, ErrRollbackRefused, err)
	}
	mk.Phase = PhaseRollingBack
	if err := m.writeMarker(*mk); err != nil {
		return OutcomeRefused, err
	}
	return m.finishRollback(ctx, mk)
}

func (m *Machine) finishRollback(ctx context.Context, mk *Marker) (Outcome, error) {
	st := m.state()
	if err := st.markBad(mk.To); err != nil {
		return OutcomeRefused, err
	}
	cur, err := m.Layout.PlanCurrent(mk.From)
	if err != nil {
		return OutcomeRefused, err
	}
	upd, err := m.Layout.PlanUpdaterCurrent(mk.From)
	if err != nil {
		return OutcomeRefused, err
	}
	if err := applySteps(m.FS, append(cur, upd...)); err != nil {
		return OutcomeRefused, err
	}
	if err := m.restart(ctx); err != nil {
		return OutcomeRefused, err
	}
	if err := st.remove(stagedName); err != nil {
		return OutcomeRefused, err
	}
	if err := st.remove(markerName); err != nil {
		return OutcomeRefused, err
	}
	return OutcomeRolledBack, nil
}

// verifyRollbackTarget re-verifies the tree of ver and runs the Apple leg on
// every Mach-O in it. An ad-hoc tree fails here.
func (m *Machine) verifyRollbackTarget(ctx context.Context, ver string) error {
	dir, err := m.Layout.VersionDir(ver)
	if err != nil {
		return err
	}
	entries, err := verifyVersionTree(m.FS, dir, maxTreeEntries)
	if err != nil {
		return err
	}
	checked := 0
	for _, e := range entries {
		if !e.info.Mode.IsRegular() {
			continue
		}
		p := filepath.Join(dir, filepath.FromSlash(e.rel))
		head, err := readHead(m.FS, p)
		if err != nil {
			return err
		}
		if !machOMagic(head) {
			continue
		}
		if err := m.Code.VerifyCode(ctx, p, path.Base(e.rel), ver); err != nil {
			return fmt.Errorf("%s: %w", e.rel, err)
		}
		checked++
	}
	if checked == 0 {
		return fmt.Errorf("%s holds no Mach-O to check", ver)
	}
	return nil
}

// ClearBad is repair --clear-bad: root takes ver off the bad list.
func (m *Machine) ClearBad(ver string) error {
	if err := layout.ValidateVersion(ver); err != nil {
		return err
	}
	return m.state().clearBad(ver)
}

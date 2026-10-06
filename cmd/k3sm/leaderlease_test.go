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
	"fmt"
	"os/exec"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"k3sm.io/k3sm/pkg/executor"
)

// fakeProbe is a controlPlaneProbe over fixed answers.
type fakeProbe struct {
	leaderElect bool
	dead        map[string]bool
}

func (p fakeProbe) LeaderElected() bool              { return p.leaderElect }
func (p fakeProbe) ComponentExited(name string) bool { return p.dead[name] }

// exitStatus is a component's cmd.Wait error carrying an exit code, the shape
// *exec.ExitError presents to errors.As.
type exitStatus int

func (e exitStatus) Error() string { return fmt.Sprintf("exit status %d", int(e)) }
func (e exitStatus) ExitCode() int { return int(e) }

// The upstream v1.36.5 lines, in klog's text format (leaseLossMessages names the
// source lines). The prefix is what a real component log carries before them.
const (
	kcmLeaseLoss   = `E1005 18:47:21.104512   61234 controllermanager.go:413] "leaderelection lost/stopped"`
	schedLeaseLoss = `E1005 18:47:21.104512   61235 server.go:328] "Leaderelection lost"`
	renewFailed    = `I1005 18:47:21.104000   61234 leaderelection.go:304] "Failed to renew lease" lock="kube-system/kube-controller-manager" err="timed out waiting for the condition"`
	watchNoise     = `W1005 18:47:21.104600   61234 reflector.go:561] "Failed to watch" err="etcdserver: no leader"`
)

func tail(lines ...string) string { return strings.Join(lines, "\n") }

// TestLeaderLeaseLossIsNotACrash pins B454: on an HA server that loses etcd
// quorum, the controller-manager or scheduler that held its lease exits as
// upstream intends. The daemon must still restart (the exit cancels the
// process), but the record must carry it as leader-lost — never as a crash, so
// repeated quorum loss cannot trip the crash threshold — and only when every
// condition holds; anything else stays a crash. Lease losses have their own,
// higher bound, so a lease that flaps forever still parks.
//
// If an upstream bump rewords either line, the first two rows go red: re-read
// cmd/kube-controller-manager/app/controllermanager.go (OnStoppedLeading) and
// cmd/kube-scheduler/app/server.go (OnStoppedLeading) at the new pin and update
// leaseLossMessages.
func TestLeaderLeaseLossIsNotACrash(t *testing.T) {
	alive := fakeProbe{leaderElect: true}
	tests := []struct {
		name       string
		component  string
		exitErr    error
		tail       string
		probe      controlPlaneProbe
		wantOrigin string
	}{
		{"controller-manager lease loss with the control plane alive is leader-lost",
			"kube-controller-manager", exitStatus(1), tail(renewFailed, kcmLeaseLoss), alive, executor.CrashOriginLeaderLost},
		{"scheduler lease loss with the control plane alive is leader-lost",
			"kube-scheduler", exitStatus(1), tail(renewFailed, schedLeaseLoss), alive, executor.CrashOriginLeaderLost},
		{"ordinary log lines after the lease-loss line do not change it",
			"kube-controller-manager", exitStatus(1), tail(kcmLeaseLoss, watchNoise), alive, executor.CrashOriginLeaderLost},
		{"the same line from a component outside the allowlist is a crash",
			"kube-apiserver", exitStatus(1), tail(renewFailed, kcmLeaseLoss), alive, executor.CrashOriginCrash},
		{"the scheduler logging the controller-manager's line is a crash",
			"kube-scheduler", exitStatus(1), tail(kcmLeaseLoss), alive, executor.CrashOriginCrash},
		{"lease-loss text while the apiserver child is dead is a crash",
			"kube-controller-manager", exitStatus(1), tail(renewFailed, kcmLeaseLoss),
			fakeProbe{leaderElect: true, dead: map[string]bool{"kube-apiserver": true}}, executor.CrashOriginCrash},
		{"lease-loss text while the etcd child is dead is a crash",
			"kube-scheduler", exitStatus(1), tail(schedLeaseLoss),
			fakeProbe{leaderElect: true, dead: map[string]bool{"etcd": true}}, executor.CrashOriginCrash},
		{"lease-loss text while the kine child is dead is a crash",
			"kube-scheduler", exitStatus(1), tail(schedLeaseLoss),
			fakeProbe{leaderElect: true, dead: map[string]bool{"kine": true}}, executor.CrashOriginCrash},
		{"a lease-loss line followed by an unrelated klog fatal is a crash",
			"kube-controller-manager", exitStatus(1),
			tail(kcmLeaseLoss, `F1005 18:47:21.200000   61234 controllermanager.go:250] "error starting controllers" err="boom"`),
			alive, executor.CrashOriginCrash},
		{"a lease-loss line followed by a Go panic is a crash",
			"kube-scheduler", exitStatus(2), tail(schedLeaseLoss, "panic: runtime error: invalid memory address", "goroutine 1 [running]:"),
			alive, executor.CrashOriginCrash},
		{"a lease-loss line with another exit code is a crash",
			"kube-controller-manager", exitStatus(255), tail(kcmLeaseLoss), alive, executor.CrashOriginCrash},
		{"a signalled exit is a crash",
			"kube-controller-manager", errors.New("signal: killed"), tail(kcmLeaseLoss), alive, executor.CrashOriginCrash},
		{"the leader-MIGRATION line is not the lease-loss line",
			"kube-controller-manager", exitStatus(1),
			tail(`E1005 18:47:21.104512   61234 controllermanager.go:444] "migration leaderelection lost/stopped"`),
			alive, executor.CrashOriginCrash},
		{"single-node (leader election off) is unchanged: a crash",
			"kube-controller-manager", exitStatus(1), tail(kcmLeaseLoss), fakeProbe{}, executor.CrashOriginCrash},
		{"an unset production probe answers single-node: a crash",
			"kube-controller-manager", exitStatus(1), tail(kcmLeaseLoss), &supervisedProbe{}, executor.CrashOriginCrash},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			b := newCrashBreaker(dir, quietLogger())
			var crashed atomic.Pointer[string]
			cancelled := false
			componentExitHandler(&crashed, b, tc.probe, func() { cancelled = true }, quietLogger())(
				tc.component, tc.exitErr, "/var/lib/k3sm/server/logs/"+tc.component+".log", tc.tail)

			if !cancelled {
				t.Error("the exit did not cancel the process; launchd would never restart the daemon")
			}
			if got := crashed.Load(); got == nil || *got != tc.component {
				t.Errorf("crashed component = %v, want %q (the restart error names it)", got, tc.component)
			}
			rec, err := executor.ReadCrashRecord(executor.CrashLoopPath(dir))
			if err != nil {
				t.Fatal(err)
			}
			if len(rec.Crashes) != 1 {
				t.Fatalf("one exit left %d record entries, want exactly 1: %+v", len(rec.Crashes), rec.Crashes)
			}
			if got := rec.Crashes[0]; got.Origin != tc.wantOrigin || got.Component != tc.component {
				t.Fatalf("recorded %q/%q, want origin %q for %q", got.Origin, got.Component, tc.wantOrigin, tc.component)
			}
			now := time.Now()
			wantCrashes, wantLost := 1, 0
			if tc.wantOrigin == executor.CrashOriginLeaderLost {
				wantCrashes, wantLost = 0, 1
			}
			if rec.Recent(now) != wantCrashes || rec.LeaderLost(now) != wantLost {
				t.Errorf("crash count %d, leader-lost count %d; want %d and %d",
					rec.Recent(now), rec.LeaderLost(now), wantCrashes, wantLost)
			}
		})
	}

	t.Run("a real exec.ExitError carries the exit code the classifier keys on", func(t *testing.T) {
		err := exec.Command("/bin/sh", "-c", "exit 1").Run()
		if !leaderLeaseLost(alive, "kube-controller-manager", err, kcmLeaseLoss) {
			t.Fatalf("an *exec.ExitError with status 1 (%v) was not read as a lease-loss exit", err)
		}
	})

	t.Run("lease loss beyond its own threshold parks, naming leader-lease loss", func(t *testing.T) {
		dir := t.TempDir()
		start := time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC)
		for i := 0; i < executor.LeaderLostThreshold; i++ {
			b := newCrashBreaker(dir, quietLogger()) // one process per lap, as in life
			at := start.Add(time.Duration(i) * 50 * time.Second)
			b.now = func() time.Time { return at }
			var crashed atomic.Pointer[string]
			componentExitHandler(&crashed, b, alive, func() {}, quietLogger())(
				"kube-controller-manager", exitStatus(1), "", tail(renewFailed, kcmLeaseLoss))
			rec := b.load()
			if i < executor.LeaderLostThreshold-1 {
				if rec.Tripped() {
					t.Fatalf("tripped on lease loss %d; lease losses must not trip before %d", i+1, executor.LeaderLostThreshold)
				}
				continue
			}
			if !rec.Tripped() {
				t.Fatalf("%d lease losses inside %s did not park the server: a flapping lease would restart it forever",
					i+1, executor.CrashLoopWindow)
			}
			last, _ := rec.Last()
			if reason := parkReason(last); !strings.Contains(reason, "leader-lease loss") {
				t.Errorf("park reason %q does not name repeated leader-lease loss", reason)
			}
		}
		if executor.LeaderLostThreshold <= executor.CrashLoopThreshold {
			t.Errorf("LeaderLostThreshold %d must be higher than CrashLoopThreshold %d", executor.LeaderLostThreshold, executor.CrashLoopThreshold)
		}
	})

	t.Run("lease losses never count toward the crash threshold", func(t *testing.T) {
		dir := t.TempDir()
		start := time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC)
		b := newCrashBreaker(dir, quietLogger())
		at := start
		b.now = func() time.Time { return at }
		for i := 0; i < executor.LeaderLostThreshold-1; i++ {
			at = start.Add(time.Duration(i) * time.Second)
			if b.recordLeaderLost("kube-scheduler", "tail") {
				t.Fatalf("lease loss %d tripped the breaker", i+1)
			}
		}
		for i := 0; i < executor.CrashLoopThreshold; i++ {
			at = start.Add(time.Minute + time.Duration(i)*time.Second)
			tripped := b.record("kube-apiserver", "tail")
			if tripped != (i == executor.CrashLoopThreshold-1) {
				t.Fatalf("crash %d after %d lease losses: tripped=%v, want a trip on crash %d exactly",
					i+1, executor.LeaderLostThreshold-1, tripped, executor.CrashLoopThreshold)
			}
		}
	})
}

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

package install

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
)

// enableOrBootstrap returns every call that could start a long-running k3sm
// daemon: an enable or a bootstrap of netd or a node daemon.
func enableOrBootstrap(calls []string) []string {
	var out []string
	for _, c := range calls {
		for _, l := range []string{NetdLabel, ServerLabel, AgentLabel} {
			if c == "Enable:"+l || c == "Bootstrap:"+l {
				out = append(out, c)
			}
		}
	}
	return out
}

// before reports whether every call in order appears in calls, in that order.
func before(t *testing.T, calls []string, order ...string) {
	t.Helper()
	last := -1
	for _, want := range order {
		i := idx(calls, want)
		if i < 0 {
			t.Errorf("%s never happened: %q", want, calls)
			return
		}
		if i < last {
			t.Errorf("%s came out of order (want %q in that order): %q", want, order, calls)
			return
		}
		last = i
	}
}

// TestInstallHonoursUserStop is the B482 gate: a user stop is one state every
// transition honours. An install (or in-app update) on a stopped node updates
// it and leaves it stopped, never enabling a label; install --start starts it;
// uninstall clears the stop's disable and its marker; start converges after a
// stop that was interrupted; and restart keeps pods running.
func TestInstallHonoursUserStop(t *testing.T) {
	ctx := context.Background()

	t.Run("an install on a stopped node stays stopped and never enables the label", func(t *testing.T) {
		f, cfg, logs := stoppableNode(t)
		if err := Stop(ctx, f, cfg, ActorUser, "test"); err != nil {
			t.Fatalf("Stop: %v", err)
		}
		f.calls = nil
		if err := Install(ctx, f, cfg); err != nil {
			t.Fatalf("Install on a stopped node: %v", err)
		}
		if got := enableOrBootstrap(f.calls); len(got) != 0 {
			t.Errorf("install on a stopped node started a daemon: %q", got)
		}
		for _, l := range []string{ServerLabel, NetdLabel} {
			if _, isLoaded := f.loaded[l]; isLoaded || !f.disabled[l] {
				t.Errorf("%s after the install: loaded %v, disabled %v; want unloaded and disabled", l, isLoaded, f.disabled[l])
			}
		}
		if m, ok := f.stopMarker(DefaultStopMarkerPath); !ok || m.Phase != StopPhaseStopped {
			t.Errorf("marker after the install = %+v (present %v), want it kept at stopped", m, ok)
		}
		if !strings.Contains(logs.String(), "updated, still stopped") {
			t.Errorf("the install does not say the node is still stopped:\n%s", logs.String())
		}
	})

	t.Run("install --start starts a stopped node", func(t *testing.T) {
		f, cfg, _ := stoppableNode(t)
		if err := Stop(ctx, f, cfg, ActorUser, "test"); err != nil {
			t.Fatalf("Stop: %v", err)
		}
		f.calls = nil
		cfg.Start = true
		if err := Install(ctx, f, cfg); err != nil {
			t.Fatalf("Install --start: %v", err)
		}
		before(t, f.calls,
			"FlushLo0Aliases:100.64.0.0/10,"+stopTestServiceCIDR, // the start precondition
			"RemoveStopMarker",
			"Enable:"+NetdLabel, "Bootstrap:"+NetdLabel,
			"Enable:"+ServerLabel, "Bootstrap:"+ServerLabel,
			"MarkNode:false:user")
		for _, l := range []string{ServerLabel, NetdLabel} {
			if _, isLoaded := f.loaded[l]; !isLoaded || f.disabled[l] {
				t.Errorf("%s after install --start: loaded %v, disabled %v", l, isLoaded, f.disabled[l])
			}
		}
		if _, ok := f.stopMarker(DefaultStopMarkerPath); ok {
			t.Error("the stop marker survived install --start")
		}
	})

	t.Run("uninstall after a stop leaves no disabled override and no marker", func(t *testing.T) {
		f, cfg, _ := stoppableNode(t)
		if err := Stop(ctx, f, cfg, ActorUser, "test"); err != nil {
			t.Fatalf("Stop: %v", err)
		}
		if err := Uninstall(ctx, f, Config{Logger: cfg.Logger}); err != nil {
			t.Fatalf("Uninstall: %v", err)
		}
		for _, l := range []string{ServerLabel, NetdLabel} {
			if f.disabled[l] {
				t.Errorf("%s is still disabled after uninstall", l)
			}
		}
		if _, ok := f.stopMarker(DefaultStopMarkerPath); ok {
			t.Error("the stop marker survived uninstall")
		}
	})

	t.Run("uninstall with no stop leaves the enabled bit alone", func(t *testing.T) {
		f, cfg, _ := stoppableNode(t)
		f.disabled = map[string]bool{NetdLabel: true} // the operator's own disable
		f.calls = nil
		if err := Uninstall(ctx, f, Config{Logger: cfg.Logger}); err != nil {
			t.Fatalf("Uninstall: %v", err)
		}
		if got := enableOrBootstrap(f.calls); len(got) != 0 {
			t.Errorf("uninstall with no stop marker enabled a label: %q", got)
		}
	})

	t.Run("start after a stop starts the node", func(t *testing.T) {
		f, cfg, logs := stoppableNode(t)
		if err := Stop(ctx, f, cfg, ActorUser, "test"); err != nil {
			t.Fatalf("Stop: %v", err)
		}
		f.calls = nil
		if err := Start(ctx, f, cfg, ActorUser, "back home"); err != nil {
			t.Fatalf("Start: %v", err)
		}
		before(t, f.calls,
			"FlushMeshPFAnchor", "FlushLo0Aliases:100.64.0.0/10,"+stopTestServiceCIDR,
			"RemoveStopMarker",
			"Enable:"+NetdLabel, "Bootstrap:"+NetdLabel, "ProbeNetd:"+DefaultNetdSocket,
			"Enable:"+ServerLabel, "Bootstrap:"+ServerLabel,
			"MarkNode:false:user")
		if slices.ContainsFunc(f.calls, func(c string) bool { return strings.HasPrefix(c, "Signal:") }) {
			t.Errorf("start after a clean stop signalled a process: %q", f.calls)
		}
		if !strings.Contains(logs.String(), "result=started") || !strings.Contains(logs.String(), "reason=\"back home\"") {
			t.Errorf("start log lacks the result and reason:\n%s", logs.String())
		}
		// Started and no marker: a second start is a no-op.
		f.calls = nil
		if err := Start(ctx, f, cfg, ActorUser, "again"); err != nil {
			t.Fatalf("second Start: %v", err)
		}
		if got := enableOrBootstrap(f.calls); len(got) != 0 {
			t.Errorf("a start on a running node restarted it: %q", got)
		}
	})

	t.Run("start after an interrupted stop converges", func(t *testing.T) {
		f, cfg, _ := stoppableNode(t)
		// The stop got as far as its intent marker and was killed: both daemons
		// are still loaded and the pod is still running.
		f.putStopMarker(DefaultStopMarkerPath, StopPhaseStopping)
		if err := Start(ctx, f, cfg, ActorUser, "test"); err != nil {
			t.Fatalf("Start after an interrupted stop: %v", err)
		}
		before(t, f.calls,
			"Bootout:"+ServerLabel, "Bootout:"+NetdLabel,
			fmt.Sprintf("Signal:%d:TERM", stopTestPodPgid),
			"FlushLo0Aliases:100.64.0.0/10,"+stopTestServiceCIDR,
			"RemoveStopMarker",
			"Bootstrap:"+NetdLabel, "Bootstrap:"+ServerLabel)
		for _, l := range []string{ServerLabel, NetdLabel} {
			if _, isLoaded := f.loaded[l]; !isLoaded {
				t.Errorf("%s is not running after start", l)
			}
		}
		if _, ok := f.stopMarker(DefaultStopMarkerPath); ok {
			t.Error("the stop marker survived start")
		}
	})

	t.Run("restart keeps pods running", func(t *testing.T) {
		f, cfg, _ := stoppableNode(t)
		if err := Restart(ctx, f, cfg, ActorUser, "test"); err != nil {
			t.Fatalf("Restart: %v", err)
		}
		before(t, f.calls, "Bootout:"+NetdLabel, "Bootstrap:"+NetdLabel, "Bootout:"+ServerLabel, "Bootstrap:"+ServerLabel)
		if slices.ContainsFunc(f.calls, func(c string) bool {
			return strings.HasPrefix(c, "Signal:") || strings.HasPrefix(c, "ReadPodReapRecords:") || strings.HasPrefix(c, "Flush")
		}) {
			t.Errorf("restart touched pods or host networking: %q", f.calls)
		}
	})

	t.Run("restart on a stopped node refuses unless --start", func(t *testing.T) {
		f, cfg, _ := stoppableNode(t)
		if err := Stop(ctx, f, cfg, ActorUser, "test"); err != nil {
			t.Fatalf("Stop: %v", err)
		}
		f.calls = nil
		if err := Restart(ctx, f, cfg, ActorUser, "test"); !errors.Is(err, ErrUserStopped) {
			t.Fatalf("Restart on a stopped node = %v, want ErrUserStopped", err)
		}
		if got := enableOrBootstrap(f.calls); len(got) != 0 {
			t.Errorf("a refused restart started a daemon: %q", got)
		}
		cfg.Start = true
		if err := Restart(ctx, f, cfg, ActorUser, "test"); err != nil {
			t.Fatalf("Restart --start: %v", err)
		}
		if _, isLoaded := f.loaded[ServerLabel]; !isLoaded {
			t.Error("restart --start did not start the node daemon")
		}
	})
}

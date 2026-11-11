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
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"k3sm.io/k3sm/pkg/executor"
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

// TestInstallHonoursUserStop is the start-side gate: a user stop is one state every
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
		for _, want := range []string{"level=WARN msg=\"updated, still stopped", "stopped-by=user", "stopped-ago="} {
			if !strings.Contains(logs.String(), want) {
				t.Errorf("the install's still-stopped warning lacks %q:\n%s", want, logs.String())
			}
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
		// The start precondition flushes the range the netd plist recorded
		// before the reinstall rewrote it to the default.
		before(t, f.calls,
			"FlushLo0Aliases:100.64.0.0/10,"+stopTestServiceCIDR,
			"Enable:"+NetdLabel, "Bootstrap:"+NetdLabel,
			"Enable:"+ServerLabel, "Bootstrap:"+ServerLabel,
			"RemoveStopMarker", // only once the daemons are up
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
		if err := Uninstall(ctx, f, Config{Logger: cfg.Logger, InstallDir: cfg.InstallDir}); err != nil {
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
		if err := Uninstall(ctx, f, Config{Logger: cfg.Logger, InstallDir: cfg.InstallDir}); err != nil {
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
			"Enable:"+NetdLabel, "Bootstrap:"+NetdLabel, "ProbeNetd:"+DefaultNetdSocket,
			"Enable:"+ServerLabel, "Bootstrap:"+ServerLabel,
			"RemoveStopMarker",
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

	t.Run("a start that fails keeps the marker", func(t *testing.T) {
		f, cfg, _ := stoppableNode(t)
		if err := Stop(ctx, f, cfg, ActorUser, "test"); err != nil {
			t.Fatalf("Stop: %v", err)
		}
		f.putBootstrapAlways(ServerLabel, errors.New("bootstrap: malformed plist"))
		f.calls = nil
		if err := Start(ctx, f, cfg, ActorUser, "test"); err == nil {
			t.Fatal("Start succeeded with a node daemon that never bootstraps")
		}
		if idx(f.calls, "RemoveStopMarker") >= 0 {
			t.Errorf("a failed start removed the stop marker: %q", f.calls)
		}
		if _, ok := f.stopMarker(DefaultStopMarkerPath); !ok {
			t.Error("the stop marker is gone after a failed start; status would say running")
		}
		// Once the fault is gone, start converges.
		delete(f.bootstrapAlways, ServerLabel)
		if err := Start(ctx, f, cfg, ActorUser, "test"); err != nil {
			t.Fatalf("Start after the fault cleared: %v", err)
		}
		if _, ok := f.stopMarker(DefaultStopMarkerPath); ok {
			t.Error("the stop marker survived a successful start")
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
			"Bootstrap:"+NetdLabel, "Bootstrap:"+ServerLabel,
			"RemoveStopMarker")
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

// TestStillCordonedMarkerIsStable pins the stderr token the k3sm app matches
// on a still-cordoned start; changing it breaks that caller.
func TestStillCordonedMarkerIsStable(t *testing.T) {
	if StillCordonedMarker != "k3sm: node is still cordoned" {
		t.Errorf("StillCordonedMarker = %q; the app matches the exact token", StillCordonedMarker)
	}
	if got, want := StartCutoff(), StartTimeBound()+LifecycleMargin; got != want {
		t.Errorf("StartCutoff = %s, want %s", got, want)
	}
}

// TestStartFlushesTheRangeTheOldPlistRecorded is the B1403 gate: install
// --start over a node whose netd plist records a non-default Service range
// (the stop fixture's, as an earlier release that took --service-cidr wrote
// it) flushes that range's lo0 aliases, not the default the reinstall renders
// into the new plist. The flush scope is read before the plist is rewritten.
func TestStartFlushesTheRangeTheOldPlistRecorded(t *testing.T) {
	f, cfg, _ := stoppableNode(t)
	if err := Stop(context.Background(), f, cfg, ActorUser, "test"); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	f.calls = nil
	cfg.Start = true
	if err := Install(context.Background(), f, cfg); err != nil {
		t.Fatalf("Install --start: %v", err)
	}
	var flushes []string
	for _, c := range f.calls {
		if strings.HasPrefix(c, "FlushLo0Aliases:") {
			flushes = append(flushes, c)
		}
	}
	want := []string{"FlushLo0Aliases:100.64.0.0/10," + stopTestServiceCIDR}
	if !slices.Equal(flushes, want) {
		t.Errorf("install --start flushed %q, want %q: the range the old netd plist recorded", flushes, want)
	}
}

// TestStartReportsBringUpBackoff is the gate for what a start on an already
// running node says about a server holding off a slow bring-up: a back-off
// still pending in the server's crash record adds the next attempt and when
// it is due to the line, printed and logged; no record, one the no-follow read
// refuses (a symlink, a non-regular file), a malformed one, a back-off that has
// elapsed, and an agent-only node leave the line as it was. The start reads the
// record only through ReadRegularFile and never writes it.
func TestStartReportsBringUpBackoff(t *testing.T) {
	const prefix = "k3sm start: already running, nothing to do"
	pinned := time.Unix(1_700_000_000, 0)
	slowRecord := func(streak int, lastSlow time.Time) []byte {
		b, err := json.Marshal(executor.CrashRecord{SlowStreak: streak, LastSlowAt: &lastSlow})
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	// A streak of 2 waits 60s from its last slow lap: 20s ago leaves 40s.
	due := pinned.Add(40 * time.Second).Format(time.RFC3339)
	wantWait := "; the server is waiting to retry a slow start (attempt 3 of 8 at " + due + ")"

	cases := []struct {
		name   string
		role   Role
		record []byte // nil: no record
		// kind makes the no-follow read refuse the record; the bytes stay in
		// the fake, so a read that followed the link would find the back-off.
		kind     fakeFileKind
		wantWait bool
	}{
		{name: "a pending back-off names the attempt and when", role: RoleServer, record: slowRecord(2, pinned.Add(-20*time.Second)), wantWait: true},
		{name: "no record", role: RoleServer},
		{name: "a symlinked record is refused", role: RoleServer, record: slowRecord(2, pinned.Add(-20*time.Second)), kind: fakeSymlink},
		{name: "a non-regular record is refused", role: RoleServer, record: slowRecord(2, pinned.Add(-20*time.Second)), kind: fakeIrregular},
		{name: "a malformed record", role: RoleServer, record: []byte("{not json")},
		{name: "an elapsed back-off", role: RoleServer, record: slowRecord(2, pinned.Add(-2*time.Minute))},
		{name: "an agent-only node", role: RoleAgent, record: slowRecord(2, pinned.Add(-20*time.Second))},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			f, cfg, _ := stoppedNodeOfRole(t, tc.role)
			f.now = func() time.Time { return pinned }
			cfg.MarkNode = func(context.Context, bool, string, string) error { return nil }
			if err := Start(ctx, f, cfg, ActorUser, "test"); err != nil {
				t.Fatalf("first Start: %v", err)
			}
			path := executor.CrashLoopPath(cfg.withDefaults().serverWorkDir())
			if tc.record != nil {
				f.putFile(path, tc.record)
			}
			if tc.kind != fakeRegular {
				f.putKind(path, tc.kind)
			}
			f.calls, f.life.oslog = nil, nil
			var out, logs bytes.Buffer
			cfg.Out = &out
			cfg.Logger = testLogger(&logs)

			if err := Start(ctx, f, cfg, ActorUser, "test"); err != nil {
				t.Fatalf("Start on a running node: %v (exit code would not be 0)", err)
			}

			var line string
			for _, l := range f.life.oslog {
				if strings.Contains(l, prefix) {
					line = l
				}
			}
			if line == "" {
				t.Fatalf("no already-running line logged: %q", f.life.oslog)
			}
			if tc.wantWait {
				if !strings.Contains(line, prefix+wantWait) {
					t.Errorf("logged line = %q, want it to carry %q", line, prefix+wantWait)
				}
				if got, want := out.String(), prefix+wantWait+"\n"; got != want {
					t.Errorf("printed %q, want %q", got, want)
				}
				if !strings.Contains(logs.String(), "attempt 3 of 8 at "+due) {
					t.Errorf("logger output lacks the wait: %s", logs.String())
				}
			} else {
				if strings.Contains(line, "waiting to retry") || !strings.Contains(line, prefix+` actor=`) {
					t.Errorf("logged line changed: %q", line)
				}
				if out.Len() != 0 {
					t.Errorf("printed %q, want nothing", out.String())
				}
			}
			for _, c := range f.calls {
				if strings.Contains(c, path) && c != "ReadRegularFile:"+path {
					t.Errorf("start touched the crash record other than through the no-follow read: %s", c)
				}
			}
			if tc.wantWait && !slices.Contains(f.calls, "ReadRegularFile:"+path) {
				t.Errorf("the record was not read through ReadRegularFile: %q", f.calls)
			}
			if tc.record != nil {
				if got, err := f.ReadFile(path); err != nil || !slices.Equal(got, tc.record) {
					t.Errorf("record changed: %q, %v", got, err)
				}
			}
		})
	}
}

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
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"testing"
	"time"

	"k3sm.io/k3sm/pkg/netdsvc"
	runtimed "k3sm.io/runtimed/pkg/runtime"
	"k3sm.io/runtimed/pkg/sandbox"
)

// The stop scenario every lifecycle test starts from: a server installed with a
// NON-default Service CIDR (so a flush of the default range would be visibly
// wrong), one recorded pod process group alive, one vm pod's k3sm-vmhost helper
// alive (spawned with a 5s grace), and this node's cluster identity on disk.
const (
	stopTestServiceCIDR = "10.96.0.0/16"
	stopTestPodPgid     = 501
	stopTestVMPgid      = 601
	// stopTestVMGrace is the grace the vm pod's helper was spawned with.
	stopTestVMGrace = 5 * time.Second
)

// stoppableNode installs a server on a fresh fake and seeds the running node
// state. The returned buffer collects the stop's slog output.
func stoppableNode(t *testing.T) (*fakeSystem, Config, *bytes.Buffer) {
	t.Helper()
	shrinkRestartBudgets(t)
	f := &fakeSystem{}
	// A pinned clock: the vm helper stop measures its waits from one start, so
	// the asserted waits are exact only on a clock that does not move.
	pinned := time.Unix(1_700_000_000, 0)
	f.now = func() time.Time { return pinned }
	var logs bytes.Buffer
	cfg := Config{
		BinarySource: "/tmp/k3sm", TargetUser: "alice", ServiceCIDR: stopTestServiceCIDR,
		Logger: slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug})),
	}
	if err := Install(context.Background(), f, cfg); err != nil {
		t.Fatalf("Install: %v", err)
	}
	f.podReap = []runtimed.PodReapRecord{{PodID: "web", Container: "app", Pgid: stopTestPodPgid, StartUnixNano: 11}}
	f.podLeaders = map[int]int64{stopTestPodPgid: 11, stopTestVMPgid: 22}
	f.life.vmhosts = []VMHostRecord{{Schema: 1, PodID: "linux", Pgid: stopTestVMPgid, StartUnixNano: 22, StopGraceNanos: int64(stopTestVMGrace)}}
	f.life.procs = map[int]fakeProc{stopTestVMPgid: {exe: DefaultInstallDir + "/" + VMHostName, uid: fakeServiceUID}}
	f.putFile(netdsvc.NodeIdentityPath(MeshKeyDir), []byte("100.64.3.0/24\n"))
	cfg.MarkNode = func(_ context.Context, stopped bool, actor, _ string) error {
		f.calls = append(f.calls, fmt.Sprintf("MarkNode:%t:%s", stopped, actor))
		return nil
	}
	cfg.RemoveMesh = func(context.Context) error {
		f.calls = append(f.calls, "RemoveMesh")
		return f.failures["RemoveMesh"]
	}
	f.calls = nil
	return f, cfg, &logs
}

// lifecycleCalls drops the read-only probes (launchd pid reads, file reads)
// from a call log, leaving the actions whose order the lifecycle tests pin.
func lifecycleCalls(calls []string) []string {
	return slices.DeleteFunc(slices.Clone(calls), func(c string) bool {
		return strings.HasPrefix(c, "ServicePID:") || strings.HasPrefix(c, "ReadFile:") || strings.HasPrefix(c, "ReadRegularFile:")
	})
}

// wantCleanStop is the whole stop, in order.
var wantCleanStop = []string{
	// 0. (A server's joined-worker count is a read; no seam call.)
	// 1. The intent marker, before anything is touched.
	"WriteStopMarker:stopping",
	// 2. Cordon + annotate, while the server's own apiserver still answers.
	"MarkNode:true:user",
	// 3. The node daemon: disable, read the disable back, bootout.
	"Disable:" + ServerLabel,
	"Disabled:" + ServerLabel,
	"Bootout:" + ServerLabel,
	// 4. The workload half of the shared teardown, while the mesh is still
	//    up: pods (SIGTERM, the grace), the vm pod's helper (SIGTERM by its
	//    recorded identity, then the wait for its recorded grace plus the
	//    helper's margin), control-plane orphans.
	"ReadPodReapRecords:" + DefaultDataRoot,
	fmt.Sprintf("Signal:%d:TERM", stopTestPodPgid),
	fmt.Sprintf("WaitGone:%d:%s", stopTestPodPgid, podGroupStopGrace),
	"ReadVMHostRecords:" + DefaultDataRoot,
	fmt.Sprintf("Signal:%d:TERM", stopTestVMPgid),
	fmt.Sprintf("WaitGone:%d:%s", stopTestVMPgid, stopTestVMGrace+sandbox.VMHelperStopMargin),
	"ReapOrphans:" + DefaultDataRoot + "/server/bin",
	// 5. RemoveMesh, while netd still serves.
	"RemoveMesh",
	// 6. The network half: the pf anchor, lo0 with the RECORDED Service
	//    CIDR, the interconnect sweep with this node's index.
	"FlushMeshPFAnchor",
	"FlushLo0Aliases:100.64.0.0/10," + stopTestServiceCIDR,
	"FlushInterconnectAliases:" + netdsvc.InterconnectStatePath(MeshKeyDir) + ":3",
	// 7. netd: disable, read back, bootout.
	"Disable:" + NetdLabel,
	"Disabled:" + NetdLabel,
	"Bootout:" + NetdLabel,
	// 8. Done, with nothing left behind.
	"WriteStopMarker:stopped",
}

// TestStopTearsDownPodsAndKeepsPlists is the stop gate: `k3sm stop` is the
// full stop, in its exact order, keeps every plist (so the node stays stopped
// across reboot) and the node identity, stops a vm pod's helper by its
// recorded identity, flushes the Service CIDR the node was installed with,
// names whatever it could not remove, and converges on a rerun.
func TestStopTearsDownPodsAndKeepsPlists(t *testing.T) {
	ctx := context.Background()

	t.Run("a clean stop runs every step in order and keeps the plists", func(t *testing.T) {
		f, cfg, logs := stoppableNode(t)
		if err := Stop(ctx, f, cfg, ActorUser, "going on a plane"); err != nil {
			t.Fatalf("Stop: %v", err)
		}
		if got := lifecycleCalls(f.calls); !slices.Equal(got, wantCleanStop) {
			t.Fatalf("stop calls:\n got %q\nwant %q", got, wantCleanStop)
		}
		for _, c := range f.calls {
			if strings.HasPrefix(c, "RemoveAll:") || strings.HasPrefix(c, "RemoveSymlink:") {
				t.Errorf("stop removed something (%s); it must keep every plist and artifact", c)
			}
		}
		for _, p := range []string{cfg.withDefaults().plistPath(ServerLabel), cfg.withDefaults().plistPath(NetdLabel), netdsvc.NodeIdentityPath(MeshKeyDir)} {
			if _, ok := f.files[p]; !ok {
				t.Errorf("%s is gone after stop; it must stay", p)
			}
		}
		for _, l := range []string{ServerLabel, NetdLabel} {
			if _, isLoaded := f.loaded[l]; isLoaded {
				t.Errorf("%s is still loaded after stop", l)
			}
			if !f.disabled[l] {
				t.Errorf("%s is not disabled after stop; it would start again at boot", l)
			}
		}
		if m, ok := f.stopMarker(DefaultStopMarkerPath); !ok || m.Phase != StopPhaseStopped || m.Actor != ActorUser || m.Reason != "going on a plane" || m.At.IsZero() {
			t.Errorf("marker after a clean stop = %+v (present %v), want phase stopped with actor, reason and time", m, ok)
		}
		for _, want := range []string{"actor=user", "reason=\"going on a plane\"", "result=stopped"} {
			if !strings.Contains(logs.String(), want) {
				t.Errorf("stop log lacks %s:\n%s", want, logs.String())
			}
		}
		if !slices.ContainsFunc(f.life.oslog, func(l string) bool {
			return strings.Contains(l, "k3sm stop: stopped") && strings.Contains(l, "actor=\"user\"") && strings.Contains(l, "result=\"stopped\"")
		}) {
			t.Errorf("no os_log line with actor and result: %q", f.life.oslog)
		}

		// A second run over the stopped node changes nothing and succeeds.
		f.calls = nil
		if err := Stop(ctx, f, cfg, ActorUser, "again"); err != nil {
			t.Fatalf("second Stop: %v", err)
		}
		if got := lifecycleCalls(f.calls); len(got) != 0 {
			t.Errorf("second stop acted: %q, want a no-op", got)
		}
	})

	t.Run("RemoveMesh is non-fatal when netd does not answer, and named", func(t *testing.T) {
		f, cfg, _ := stoppableNode(t)
		f.failOn("RemoveMesh", errors.New("dial unix /var/lib/k3sm/run/netd.sock: connection refused"))
		err := Stop(ctx, f, cfg, ActorUser, "test")
		var serr *StopIncompleteError
		if !errors.As(err, &serr) || !slices.Equal(serr.Leftovers(), []Leftover{LeftoverMesh}) {
			t.Fatalf("Stop = %v, want a StopIncompleteError naming only the mesh", err)
		}
		if got := serr.ExitCode(); got != StopExitLeftoverBase+4 {
			t.Errorf("exit code = %d, want %d", got, StopExitLeftoverBase+4)
		}
		if i, j := idx(f.calls, "RemoveMesh"), idx(f.calls, "Bootout:"+NetdLabel); i < 0 || j < 0 || i > j {
			t.Errorf("RemoveMesh (%d) must come before netd's bootout (%d), and the stop must go on to it: %q", i, j, f.calls)
		}
	})

	t.Run("a forged vm record is never signalled", func(t *testing.T) {
		for name, proc := range map[string]fakeProc{
			"wrong executable": {exe: "/usr/sbin/sshd", uid: fakeServiceUID},
			"wrong uid":        {exe: DefaultInstallDir + "/" + VMHostName, uid: 0},
		} {
			f, cfg, _ := stoppableNode(t)
			f.life.procs[stopTestVMPgid] = proc
			err := Stop(ctx, f, cfg, ActorUser, "test")
			var serr *StopIncompleteError
			if !errors.As(err, &serr) || !slices.Contains(serr.Leftovers(), LeftoverVMHelpers) {
				t.Errorf("%s: Stop = %v, want the vm record reported", name, err)
			}
			if idx(f.calls, fmt.Sprintf("Signal:%d:TERM", stopTestVMPgid)) >= 0 || idx(f.calls, fmt.Sprintf("Signal:%d:KILL", stopTestVMPgid)) >= 0 {
				t.Errorf("%s: a process the record does not prove is k3sm-vmhost was signalled", name)
			}
		}
	})

	t.Run("a server stop warns about joined workers", func(t *testing.T) {
		f, cfg, logs := stoppableNode(t)
		cfg.JoinedWorkers = func(context.Context) (int, error) { return 2, nil }
		if err := Stop(ctx, f, cfg, ActorUser, "test"); err != nil {
			t.Fatalf("Stop: %v", err)
		}
		if !strings.Contains(logs.String(), "2 joined worker(s)") {
			t.Errorf("no joined-worker warning:\n%s", logs.String())
		}
		g, gcfg, glogs := stoppableNode(t)
		gcfg.JoinedWorkers = func(context.Context) (int, error) { return 0, errors.New("apiserver unreachable") }
		if err := Stop(ctx, g, gcfg, ActorUser, "test"); err != nil {
			t.Fatalf("Stop with the count unknown: %v", err)
		}
		if !strings.Contains(glogs.String(), "could not count the workers") {
			t.Errorf("an unknown count is not warned:\n%s", glogs.String())
		}
	})

	t.Run("a cordon that times out is not fatal", func(t *testing.T) {
		f, cfg, logs := stoppableNode(t)
		orig := markNodeTimeout
		markNodeTimeout = 10 * time.Millisecond
		t.Cleanup(func() { markNodeTimeout = orig })
		cfg.MarkNode = func(ctx context.Context, _ bool, _, _ string) error {
			<-ctx.Done()
			return ctx.Err()
		}
		if err := Stop(ctx, f, cfg, ActorUser, "test"); err != nil {
			t.Fatalf("Stop with an unreachable cluster: %v", err)
		}
		if m, _ := f.stopMarker(DefaultStopMarkerPath); m.Phase != StopPhaseStopped {
			t.Errorf("marker phase = %q, want stopped", m.Phase)
		}
		if !strings.Contains(logs.String(), "could not cordon") {
			t.Errorf("the cordon failure is not logged:\n%s", logs.String())
		}
	})

	t.Run("a marker that cannot be written refuses before anything changes", func(t *testing.T) {
		f, cfg, _ := stoppableNode(t)
		f.failOn("WriteStopMarker:stopping", errors.New("read-only file system"))
		err := Stop(ctx, f, cfg, ActorUser, "test")
		var serr *StopIncompleteError
		if err == nil || errors.As(err, &serr) {
			t.Fatalf("Stop = %v, want a plain refusal", err)
		}
		if got := lifecycleCalls(f.calls); !slices.Equal(got, []string{"WriteStopMarker:stopping"}) {
			t.Errorf("a refused stop acted: %q", got)
		}
	})

	// Every step that can leave something behind: the stop goes on past it,
	// leaves the marker at stopping, names the class in the error and the exit
	// code, and a rerun once the fault is gone converges to stopped.
	netdPlist := DefaultLaunchDaemonDir + "/" + NetdLabel + ".plist"
	for _, tc := range []struct {
		name   string
		want   Leftover
		arm    func(f *fakeSystem)
		disarm func(f *fakeSystem)
	}{
		{"the node daemon disable fails", LeftoverNodeDaemon,
			func(f *fakeSystem) { f.failOn("Disable:"+ServerLabel, errors.New("disable failed")) },
			func(f *fakeSystem) { delete(f.failures, "Disable:"+ServerLabel) }},
		{"the node daemon disable does not read back", LeftoverNodeDaemon,
			func(f *fakeSystem) { f.life.disableIgnored = map[string]bool{ServerLabel: true} },
			func(f *fakeSystem) { f.life.disableIgnored = nil }},
		{"the node daemon never unloads", LeftoverNodeDaemon,
			func(f *fakeSystem) { f.purge.stuck = map[string]bool{ServerLabel: true} },
			func(f *fakeSystem) { f.purge.stuck = nil }},
		{"RemoveMesh fails", LeftoverMesh,
			func(f *fakeSystem) { f.failOn("RemoveMesh", errors.New("netd refused")) },
			func(f *fakeSystem) { delete(f.failures, "RemoveMesh") }},
		{"a pod group cannot be signalled", LeftoverPods,
			func(f *fakeSystem) { f.failOn(fmt.Sprintf("Signal:%d:TERM", stopTestPodPgid), errors.New("EPERM")) },
			func(f *fakeSystem) { delete(f.failures, fmt.Sprintf("Signal:%d:TERM", stopTestPodPgid)) }},
		{"the vm helper records cannot be read", LeftoverVMHelpers,
			func(f *fakeSystem) { f.failOn("ReadVMHostRecords", errors.New("permission denied")) },
			func(f *fakeSystem) { delete(f.failures, "ReadVMHostRecords") }},
		{"the vm helper outlives its grace and survives SIGKILL", LeftoverVMHelpers,
			func(f *fakeSystem) { f.podLingering = map[int]bool{stopTestVMPgid: true} },
			func(f *fakeSystem) { f.podLingering = nil }},
		{"a vm record names another executable", LeftoverVMHelpers,
			func(f *fakeSystem) { f.life.procs[stopTestVMPgid] = fakeProc{exe: "/usr/sbin/sshd", uid: 0} },
			func(f *fakeSystem) {
				f.life.procs[stopTestVMPgid] = fakeProc{exe: DefaultInstallDir + "/" + VMHostName, uid: fakeServiceUID}
			}},
		{"a vm record is untrusted", LeftoverVMHelpers,
			func(f *fakeSystem) { f.life.vmRejected = []string{"666.json"} },
			func(f *fakeSystem) { f.life.vmRejected = nil }},
		{"control-plane orphans cannot be reaped", LeftoverControlPlane,
			func(f *fakeSystem) { f.failOn("ReapOrphans", errors.New("kill failed")) },
			func(f *fakeSystem) { delete(f.failures, "ReapOrphans") }},
		{"the pf anchor cannot be flushed", LeftoverPFAnchor,
			func(f *fakeSystem) { f.failOn("FlushMeshPFAnchor", errors.New("pfctl failed")) },
			func(f *fakeSystem) { delete(f.failures, "FlushMeshPFAnchor") }},
		{"the lo0 flush fails", LeftoverLo0,
			func(f *fakeSystem) { f.failOn("FlushLo0Aliases", errors.New("ifconfig failed")) },
			func(f *fakeSystem) { delete(f.failures, "FlushLo0Aliases") }},
		{"the Service CIDR record is unreadable", LeftoverLo0,
			func(f *fakeSystem) {
				f.putFile(netdPlist+".orig", f.files[netdPlist])
				f.putFile(netdPlist, bytes.ReplaceAll(f.files[netdPlist], []byte("--service-cidr"), []byte("--no-such-flag")))
			},
			func(f *fakeSystem) { f.putFile(netdPlist, f.files[netdPlist+".orig"]) }},
		{"the interconnect sweep fails", LeftoverInterconnect,
			func(f *fakeSystem) { f.failOn("FlushInterconnectAliases", errors.New("ifconfig failed")) },
			func(f *fakeSystem) { delete(f.failures, "FlushInterconnectAliases") }},
		{"netd cannot be disabled", LeftoverNetd,
			func(f *fakeSystem) { f.failOn("Disable:"+NetdLabel, errors.New("disable failed")) },
			func(f *fakeSystem) { delete(f.failures, "Disable:"+NetdLabel) }},
		{"the stopped marker cannot be written", LeftoverMarker,
			func(f *fakeSystem) { f.failOn("WriteStopMarker:stopped", errors.New("disk full")) },
			func(f *fakeSystem) { delete(f.failures, "WriteStopMarker:stopped") }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f, cfg, logs := stoppableNode(t)
			tc.arm(f)
			err := Stop(ctx, f, cfg, ActorUser, "test")
			var serr *StopIncompleteError
			if !errors.As(err, &serr) {
				t.Fatalf("Stop = %v, want a StopIncompleteError", err)
			}
			if !slices.Contains(serr.Leftovers(), tc.want) || !strings.Contains(err.Error(), string(tc.want)) {
				t.Errorf("leftovers = %v (%v), want %s named", serr.Leftovers(), err, tc.want)
			}
			if code := serr.ExitCode(); code <= StopExitLeftoverBase || code > 125 || (code-StopExitLeftoverBase)&tc.want.exitBit() == 0 {
				t.Errorf("exit code %d does not carry the %s bit %d", code, tc.want, tc.want.exitBit())
			}
			if m, ok := f.stopMarker(DefaultStopMarkerPath); !ok || m.Phase != StopPhaseStopping {
				t.Errorf("marker = %+v (present %v), want it left at stopping", m, ok)
			}
			if idx(f.calls, "Bootout:"+NetdLabel) < 0 {
				t.Errorf("the stop gave up before netd: %q", f.calls)
			}
			if tc.want == LeftoverLo0 && tc.name == "the Service CIDR record is unreadable" {
				if slices.ContainsFunc(f.calls, func(c string) bool { return strings.HasPrefix(c, "FlushLo0Aliases:") }) {
					t.Errorf("lo0 was flushed with no recorded Service CIDR (a guessed range): %q", f.calls)
				}
			}
			if !strings.Contains(logs.String(), "result=incomplete") || !strings.Contains(logs.String(), string(tc.want)) {
				t.Errorf("the incomplete result is not logged with %s:\n%s", tc.want, logs.String())
			}

			tc.disarm(f)
			if err := Stop(ctx, f, cfg, ActorUser, "test"); err != nil {
				t.Fatalf("rerun after the fault cleared: %v", err)
			}
			if m, _ := f.stopMarker(DefaultStopMarkerPath); m.Phase != StopPhaseStopped {
				t.Errorf("rerun left marker phase %q, want stopped", m.Phase)
			}
		})
	}
}

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
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"testing"
	"time"

	"k3sm.io/runtimed/pkg/sandbox"
)

// TestStopVMHelpersHonoursEachRecordedGrace pins the vm half of the shared
// teardown (`k3sm stop`, `k3sm uninstall`): a vm pod's helper is stopped the
// way a native pod's group is, SIGTERM first, and each helper is waited for
// exactly the runtime's own wait for the grace it was spawned with
// (sandbox.VMHelperStopWait), capped at the runtime's bound for stopping every
// guest (sandbox.VMStopAllBound). The waits share one clock, a helper is sent
// SIGKILL only once its OWN wait is over, and a record from an earlier runtime
// (no grace recorded) gets the helper's default. Every signal, the SIGKILL
// included, is preceded by a fresh proof that the group is still the helper.
func TestStopVMHelpersHonoursEachRecordedGrace(t *testing.T) {
	const (
		quick  = 701 // 5s grace: waited 13s
		legacy = 702 // no grace recorded: the default 20s, waited 28s
		long   = 703 // 300s grace: cut at the 45s bound
	)
	vmhost := DefaultInstallDir + "/" + VMHostName
	newFake := func() (*fakeSystem, Config, *bytes.Buffer) {
		var logs bytes.Buffer
		f := &fakeSystem{}
		f.podLeaders = map[int]int64{quick: 1, legacy: 2, long: 3}
		f.life.vmhosts = []VMHostRecord{
			{Schema: 1, PodID: "long", Pgid: long, StartUnixNano: 3, StopGraceNanos: int64(300 * time.Second)},
			{Schema: 1, PodID: "quick", Pgid: quick, StartUnixNano: 1, StopGraceNanos: int64(5 * time.Second)},
			{PodID: "legacy", Pgid: legacy, StartUnixNano: 2},
		}
		f.life.procs = map[int]fakeProc{
			quick:  {exe: vmhost, uid: fakeServiceUID},
			legacy: {exe: vmhost, uid: fakeServiceUID},
			long:   {exe: vmhost, uid: fakeServiceUID},
		}
		cfg := Config{Logger: slog.New(slog.NewTextHandler(&logs, nil))}.withDefaults()
		return f, cfg, &logs
	}
	signals := func(calls []string) []string {
		return slices.DeleteFunc(slices.Clone(calls), func(c string) bool { return !strings.HasPrefix(c, "Signal:") && !strings.HasPrefix(c, "WaitGone:") })
	}

	if got := vmHelperWait(VMHostRecord{StopGraceNanos: int64(5 * time.Second)}); got != 5*time.Second+sandbox.VMHelperStopMargin {
		t.Errorf("a 5s grace waits %s, want the grace plus the helper's %s margin", got, sandbox.VMHelperStopMargin)
	}
	if got := vmHelperWait(VMHostRecord{}); got != sandbox.VMHelperStopWait(0) {
		t.Errorf("a record with no grace waits %s, want the helper default's %s", got, sandbox.VMHelperStopWait(0))
	}
	if got := vmHelperWait(VMHostRecord{StopGraceNanos: int64(300 * time.Second)}); got != sandbox.VMStopAllBound {
		t.Errorf("a 300s grace waits %s, want the %s bound", got, sandbox.VMStopAllBound)
	}

	t.Run("every helper exits inside its grace and none is killed", func(t *testing.T) {
		f, cfg, _ := newFake()
		if err := stopVMHelpers(context.Background(), f, cfg); err != nil {
			t.Fatalf("stopVMHelpers: %v", err)
		}
		want := []string{
			fmt.Sprintf("Signal:%d:TERM", long),
			fmt.Sprintf("Signal:%d:TERM", quick),
			fmt.Sprintf("Signal:%d:TERM", legacy),
			fmt.Sprintf("WaitGone:%d,%d,%d:%s", quick, legacy, long, 13*time.Second),
		}
		if got := signals(f.calls); !slices.Equal(got, want) {
			t.Errorf("calls = %q, want %q", got, want)
		}
	})

	t.Run("each straggler is killed at the end of its own wait, never earlier", func(t *testing.T) {
		f, cfg, logs := newFake()
		f.podLingering = map[int]bool{legacy: true, long: true}
		err := stopVMHelpers(context.Background(), f, cfg)
		if err == nil || !strings.Contains(err.Error(), "still alive") {
			t.Fatalf("stopVMHelpers = %v, want the helpers that survived SIGKILL named", err)
		}
		want := []string{
			fmt.Sprintf("Signal:%d:TERM", long),
			fmt.Sprintf("Signal:%d:TERM", quick),
			fmt.Sprintf("Signal:%d:TERM", legacy),
			// 0s..13s: the quick helper's wait; all three watched.
			fmt.Sprintf("WaitGone:%d,%d,%d:%s", quick, legacy, long, 13*time.Second),
			// 13s..28s: the legacy helper's default wait; it is killed at 28s.
			fmt.Sprintf("WaitGone:%d,%d:%s", legacy, long, 15*time.Second),
			fmt.Sprintf("Signal:%d:KILL", legacy),
			// 28s..45s: the long helper is cut at the bound.
			fmt.Sprintf("WaitGone:%d:%s", long, 17*time.Second),
			fmt.Sprintf("Signal:%d:KILL", long),
			fmt.Sprintf("WaitGone:%d,%d:%s", legacy, long, vmHostKillWait),
		}
		if got := signals(f.calls); !slices.Equal(got, want) {
			t.Errorf("calls = %q, want %q", got, want)
		}
		if strings.Count(logs.String(), "did not exit within its grace") != 2 {
			t.Errorf("want one kill line per straggler:\n%s", logs.String())
		}
	})

	t.Run("a straggler is re-verified before its SIGKILL", func(t *testing.T) {
		f, cfg, _ := newFake()
		f.podLingering = map[int]bool{legacy: true, long: true}
		// During the wait the legacy helper exits and its pgid is reused, and the
		// long one's pgid now leads another executable.
		f.afterWait = func() {
			f.podLeaders[legacy] = 99
			f.life.procs[long] = fakeProc{exe: "/usr/sbin/sshd", uid: 0}
		}
		err := stopVMHelpers(context.Background(), f, cfg)
		for _, pgid := range []int{legacy, long} {
			if idx(f.calls, fmt.Sprintf("Signal:%d:KILL", pgid)) >= 0 {
				t.Errorf("group %d was SIGKILLed after it stopped being the recorded helper: %q", pgid, signals(f.calls))
			}
		}
		if err == nil || !strings.Contains(err.Error(), "/usr/sbin/sshd") {
			t.Errorf("stopVMHelpers = %v, want the forged executable reported", err)
		}
	})

	t.Run("a group that cannot be inspected is never signalled", func(t *testing.T) {
		f, cfg, _ := newFake()
		delete(f.podLeaders, quick) // ProcessGroupLeaderStart reports it not inspectable
		if err := stopVMHelpers(context.Background(), f, cfg); err != nil {
			t.Fatalf("stopVMHelpers: %v", err)
		}
		if idx(f.calls, fmt.Sprintf("Signal:%d:TERM", quick)) >= 0 || idx(f.calls, fmt.Sprintf("Signal:%d:KILL", quick)) >= 0 {
			t.Errorf("an uninspectable group was signalled: %q", signals(f.calls))
		}
	})
}

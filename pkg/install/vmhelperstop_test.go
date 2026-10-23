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
	"sync"
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
		pinned := time.Unix(1_700_000_000, 0)
		f.now = func() time.Time { return pinned }
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

// TestStopVMHelpersShortensACutGrace pins the teardown half: before the
// SIGTERM of a helper whose recorded grace does not fit the stop bound, the
// teardown asks the helper on its control socket to start its stop with the
// grace the bound leaves it, and prints the cut to the command's output. A
// helper whose grace fits is not asked; a helper that predates the request, an
// error, or a record with no run dir falls back to today's SIGTERM-and-wait,
// and the cut is printed all the same.
func TestStopVMHelpersShortensACutGrace(t *testing.T) {
	const (
		quick = 801 // 5s grace: fits, never asked
		long  = 802 // 300s grace: cut at the 45s bound
	)
	vmhost := DefaultInstallDir + "/" + VMHostName
	runDir := "/var/lib/k3sm/run/vm/long"
	socket := runDir + "/" + sandbox.VMHostControlSocketName
	shortenCall := fmt.Sprintf("Shorten:%d:%s:%s", long, socket, sandbox.VMStopAllBound)
	newFake := func(runDir string) (*fakeSystem, Config, *bytes.Buffer) {
		var out bytes.Buffer
		f := &fakeSystem{}
		pinned := time.Unix(1_700_000_000, 0)
		f.now = func() time.Time { return pinned }
		f.podLeaders = map[int]int64{quick: 1, long: 2}
		f.life.vmhosts = []VMHostRecord{
			{Schema: 1, PodID: "quick", Pgid: quick, StartUnixNano: 1, StopGraceNanos: int64(5 * time.Second), RunDir: "/var/lib/k3sm/run/vm/quick"},
			{Schema: 1, PodID: "long", Pgid: long, StartUnixNano: 2, StopGraceNanos: int64(300 * time.Second), RunDir: runDir},
		}
		f.life.procs = map[int]fakeProc{
			quick: {exe: vmhost, uid: fakeServiceUID},
			long:  {exe: vmhost, uid: fakeServiceUID},
		}
		cfg := Config{Logger: slog.New(slog.DiscardHandler), Out: &out}.withDefaults()
		return f, cfg, &out
	}
	stopCalls := func(calls []string) []string {
		return slices.DeleteFunc(slices.Clone(calls), func(c string) bool {
			return !strings.HasPrefix(c, "Shorten:") && !strings.HasPrefix(c, "Signal:")
		})
	}
	cut := sandbox.VMStopAllBound - sandbox.VMHelperStopMargin

	t.Run("a cut grace is shortened before the SIGTERM and the cut is printed", func(t *testing.T) {
		f, cfg, out := newFake(runDir)
		f.life.shorten = map[int]sandbox.VMHostShortenOutcome{long: {Result: sandbox.VMHostShortened, From: 300 * time.Second, To: cut}}
		if err := stopVMHelpers(context.Background(), f, cfg); err != nil {
			t.Fatalf("stopVMHelpers: %v", err)
		}
		want := []string{
			shortenCall,
			fmt.Sprintf("Signal:%d:TERM", quick),
			fmt.Sprintf("Signal:%d:TERM", long),
		}
		if got := stopCalls(f.calls); !slices.Equal(got, want) {
			t.Errorf("calls = %q, want %q: only the cut helper is asked, and before any SIGTERM", got, want)
		}
		if line := out.String(); !strings.Contains(line, "vm pod long: grace 5m0s cut to 37s to fit the 45s stop bound") {
			t.Errorf("output = %q, want the cut printed", line)
		}
		if strings.Contains(out.String(), "quick") {
			t.Errorf("output = %q names a pod whose grace fits", out.String())
		}
	})

	for _, tc := range []struct {
		name   string
		runDir string
		setup  func(f *fakeSystem)
		reason string
		asked  bool
	}{
		{"an old helper with a banner only gets the plain SIGTERM", runDir, func(*fakeSystem) {}, "banner only", true},
		{"an error falls back to the plain SIGTERM", runDir,
			func(f *fakeSystem) { f.failOn(shortenCall, errors.New("served by pid 9, not the helper")) }, "served by pid 9", true},
		{"a record with no run dir is not asked", "", func(*fakeSystem) {}, "no run dir", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f, cfg, out := newFake(tc.runDir)
			tc.setup(f)
			if err := stopVMHelpers(context.Background(), f, cfg); err != nil {
				t.Fatalf("stopVMHelpers: %v", err)
			}
			got := stopCalls(f.calls)
			term := idx(got, fmt.Sprintf("Signal:%d:TERM", long))
			if term < 0 {
				t.Fatalf("calls = %q, want the cut helper SIGTERMed all the same", got)
			}
			if asked := slices.ContainsFunc(got, func(c string) bool { return strings.HasPrefix(c, "Shorten:") }); asked != tc.asked {
				t.Errorf("calls = %q, asked = %v, want %v", got, asked, tc.asked)
			}
			line := out.String()
			if !strings.Contains(line, "vm pod long: grace 5m0s does not fit the 45s stop bound (it would be cut to 37s)") || !strings.Contains(line, tc.reason) {
				t.Errorf("output = %q, want the cut and its reason (%q) printed", line, tc.reason)
			}
		})
	}
}

// TestStopVMHelpersShortensConcurrently pins how the teardown sends its
// shorten requests: all of them before any SIGTERM, one goroutine per helper,
// so a slow helper never delays another's request; and each with the time left
// until the shared SIGKILL deadline, not the constant bound. An
// already-stopping helper whose grace the bound cuts is a printed, warned cut;
// one whose grace fits is only logged.
func TestStopVMHelpersShortensConcurrently(t *testing.T) {
	const (
		a = 901 // 300s grace
		b = 902 // 120s grace
	)
	vmhost := DefaultInstallDir + "/" + VMHostName
	newFake := func() (*fakeSystem, Config, *bytes.Buffer, *bytes.Buffer) {
		var out, logs bytes.Buffer
		f := &fakeSystem{}
		f.podLeaders = map[int]int64{a: 1, b: 2}
		f.life.vmhosts = []VMHostRecord{
			{Schema: 1, PodID: "a", Pgid: a, StartUnixNano: 1, StopGraceNanos: int64(300 * time.Second), RunDir: "/r/a"},
			{Schema: 1, PodID: "b", Pgid: b, StartUnixNano: 2, StopGraceNanos: int64(120 * time.Second), RunDir: "/r/b"},
		}
		f.life.procs = map[int]fakeProc{a: {exe: vmhost, uid: fakeServiceUID}, b: {exe: vmhost, uid: fakeServiceUID}}
		cfg := Config{Logger: slog.New(slog.NewTextHandler(&logs, nil)), Out: &out}.withDefaults()
		return f, cfg, &out, &logs
	}

	t.Run("two slow helpers are asked at once, before any SIGTERM", func(t *testing.T) {
		f, cfg, out, _ := newFake()
		pinned := time.Unix(1_700_000_000, 0)
		f.now = func() time.Time { return pinned }
		// Each request blocks until both are in flight: sent one after the
		// other, the first would wait alone and fail.
		f.life.shortenRendezvous = 2
		cut := sandbox.VMStopAllBound - sandbox.VMHelperStopMargin
		f.life.shorten = map[int]sandbox.VMHostShortenOutcome{
			a: {Result: sandbox.VMHostShortened, From: 300 * time.Second, To: cut},
			b: {Result: sandbox.VMHostShortened, From: 120 * time.Second, To: cut},
		}
		if err := stopVMHelpers(context.Background(), f, cfg); err != nil {
			t.Fatalf("stopVMHelpers: %v", err)
		}
		for _, line := range []string{"vm pod a: grace 5m0s cut to 37s", "vm pod b: grace 2m0s cut to 37s"} {
			if !strings.Contains(out.String(), line) {
				t.Errorf("output = %q, want %q (a serial request would have waited alone and failed)", out.String(), line)
			}
		}
		firstTerm := slices.IndexFunc(f.calls, func(c string) bool { return strings.HasPrefix(c, "Signal:") })
		for i, c := range f.calls {
			if strings.HasPrefix(c, "Shorten:") && i > firstTerm {
				t.Errorf("calls = %q: a shorten request came after a SIGTERM", f.calls)
			}
		}
	})

	t.Run("each request carries the time left until the shared deadline", func(t *testing.T) {
		f, cfg, _, _ := newFake()
		start := time.Unix(1_700_000_000, 0)
		var (
			mu    sync.Mutex
			reads int
		)
		// The first read is the stop's start; every later one is 3s on.
		f.now = func() time.Time {
			mu.Lock()
			defer mu.Unlock()
			reads++
			if reads == 1 {
				return start
			}
			return start.Add(3 * time.Second)
		}
		if err := stopVMHelpers(context.Background(), f, cfg); err != nil {
			t.Fatalf("stopVMHelpers: %v", err)
		}
		left := sandbox.VMStopAllBound - 3*time.Second
		for _, pgid := range []int{a, b} {
			want := fmt.Sprintf("Shorten:%d:/r/%s/%s:%s", pgid, map[int]string{a: "a", b: "b"}[pgid], sandbox.VMHostControlSocketName, left)
			if idx(f.calls, want) < 0 {
				t.Errorf("calls = %q, want %q", f.calls, want)
			}
		}
		// The SIGKILL clock is the same one: both are cut at the bound, 3s of
		// which the requests already spent.
		if idx(f.calls, fmt.Sprintf("WaitGone:%d,%d:%s", a, b, left)) < 0 {
			t.Errorf("calls = %q, want the wait measured from the start of the stop (%s left)", f.calls, left)
		}
	})

	t.Run("an already-stopping helper is a warned cut only when the bound cuts its grace", func(t *testing.T) {
		f, cfg, out, logs := newFake()
		pinned := time.Unix(1_700_000_000, 0)
		f.now = func() time.Time { return pinned }
		f.life.shorten = map[int]sandbox.VMHostShortenOutcome{
			a: {Result: sandbox.VMHostAlreadyStopping, From: 300 * time.Second, To: 300 * time.Second},
			b: {Result: sandbox.VMHostAlreadyStopping, From: 20 * time.Second, To: 20 * time.Second},
		}
		if err := stopVMHelpers(context.Background(), f, cfg); err != nil {
			t.Fatalf("stopVMHelpers: %v", err)
		}
		if !strings.Contains(out.String(), "vm pod a: already stopping with grace 5m0s, longer than the 45s stop bound allows") {
			t.Errorf("output = %q, want pod a's cut printed", out.String())
		}
		if strings.Contains(out.String(), "vm pod b") {
			t.Errorf("output = %q prints pod b, whose running grace fits", out.String())
		}
		for _, l := range strings.Split(logs.String(), "\n") {
			switch {
			case strings.Contains(l, "pod=a") && strings.Contains(l, "already stopping") && !strings.Contains(l, "level=WARN"):
				t.Errorf("pod a's cut logged below Warn: %s", l)
			case strings.Contains(l, "pod=b") && strings.Contains(l, "already stopping") && !strings.Contains(l, "level=INFO"):
				t.Errorf("pod b's fitting grace logged above Info: %s", l)
			}
		}
	})
}

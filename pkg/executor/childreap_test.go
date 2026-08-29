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

// Child-process ownership for the fixtures in this package.
//
// A fixture that spawns a REAL server owns that child's whole lifetime, and the
// cross-pin datastore fixture spawns two. Losing one is not untidiness: an orphaned
// datastore holds a TCP port and a temp-dir database for as long as the machine stays
// up, and bring-up now REFUSES to start when the datastore port is already held
// (preflightDatastorePort) — so one run's orphan becomes the NEXT run's boot refusal,
// reported against a port nobody in that run chose.
//
// `defer stop()` does not own a lifetime. It is skipped on three paths that all
// happen in practice:
//
//	t.Fatalf before the stop call   a seed/verify failure Goexits past it
//	an interrupted run             SIGINT/SIGTERM kills the binary; no defer runs
//	`go test -timeout` expiry      testing panics from a TIMER goroutine and crashes
//	                               the binary without unwinding the test goroutine
//
// So the three mechanisms below cover them in order: t.Cleanup (runs on return,
// Fatal, and panic), a signal handler that reaps then re-raises, and a pre-timeout
// alarm armed a short lead before `go test`'s own deadline. The residual is honest
// and unclosable from inside the process: SIGKILL of the test binary leaves the
// children orphaned, which is why refuseOnFixtureOrphans exists to make the NEXT run
// say so instead of failing obscurely.

package executor

import (
	"flag"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// spawnedChildren is the package-wide registry of live fixture children. Every
// fixture that starts a long-running process registers it here, and every reaping
// path goes through it, so there is exactly one answer to "what did this run start".
var spawnedChildren = &childReaper{}

type childReaper struct {
	mu   sync.Mutex
	kids map[int]*trackedChild
}

// trackedChild is one spawned process plus the once that makes reaping it idempotent
// — stop() is reachable from the caller's own defer, from t.Cleanup, from the signal
// handler, and from the pre-timeout alarm, concurrently.
type trackedChild struct {
	reaper *childReaper
	cmd    *exec.Cmd
	what   string
	once   sync.Once
}

// track registers a STARTED child. what is a human label used only in the
// survivor report (e.g. "kine v0.17.0 on :52431").
func (r *childReaper) track(cmd *exec.Cmd, what string) *trackedChild {
	c := &trackedChild{reaper: r, cmd: cmd, what: what}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.kids == nil {
		r.kids = map[int]*trackedChild{}
	}
	r.kids[cmd.Process.Pid] = c
	return c
}

func (r *childReaper) forget(pid int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.kids, pid)
}

// pids returns the pids this run currently owns — the exclusion set for the orphan
// scan, so a fixture's own live child is never reported as somebody else's leak.
func (r *childReaper) pids() map[int]bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make(map[int]bool, len(r.kids))
	for pid := range r.kids {
		out[pid] = true
	}
	return out
}

// reapAll stops every child still registered. Safe to call repeatedly and from a
// signal handler: each child's stop is once-guarded.
func (r *childReaper) reapAll() {
	r.mu.Lock()
	kids := make([]*trackedChild, 0, len(r.kids))
	for _, c := range r.kids {
		kids = append(kids, c)
	}
	r.mu.Unlock()
	for _, c := range kids {
		c.stop()
	}
}

// outstanding names the children still registered — i.e. those nobody stopped. It is
// read at exit, BEFORE the final reapAll, so the verdict is "a child outlived the
// test that started it", not "a pid is alive" (which a reused pid could fake).
func (r *childReaper) outstanding() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]string, 0, len(r.kids))
	for pid, c := range r.kids {
		out = append(out, fmt.Sprintf("pid %d (%s)", pid, c.what))
	}
	slices.Sort(out)
	return out
}

// stop kills the child's process GROUP, waits for it, and deregisters it. Idempotent.
func (c *trackedChild) stop() {
	c.once.Do(func() {
		pid := c.cmd.Process.Pid
		killProcessGroup(pid)
		_, _ = c.cmd.Process.Wait()
		c.reaper.forget(pid)
	})
}

// killProcessGroup SIGKILLs the group led by pid — the whole subtree, so a child that
// forked before dying cannot survive its parent's death.
//
// The group is signalled ONLY when pid actually leads it (Setpgid at spawn). A child
// started without Setpgid sits in the TEST BINARY's own group, and `kill(-pgid)` there
// would kill the test run itself; that case falls back to signalling the one pid.
func killProcessGroup(pid int) {
	if pgid, err := syscall.Getpgid(pid); err == nil && pgid == pid {
		_ = syscall.Kill(-pgid, syscall.SIGKILL)
		return
	}
	_ = syscall.Kill(pid, syscall.SIGKILL)
}

// pidAlive reports whether pid still exists (signal 0 is the standard existence
// probe). A zombie counts as alive until it is waited for, which is correct here:
// this package's children are always waited for by stop().
func pidAlive(pid int) bool {
	return syscall.Kill(pid, 0) == nil
}

// ---- the interrupted and timed-out paths ------------------------------------

// installReapOnSignal reaps every tracked child on SIGINT/SIGTERM and then re-raises
// the signal with its DEFAULT disposition, so an interrupted run still dies exactly
// the way the caller asked — it just does not leave a datastore behind. This is the
// path no defer and no t.Cleanup can cover: the test binary is killed outright.
//
// SIGKILL is uncatchable and therefore NOT covered; refuseOnFixtureOrphans is the
// compensating control for it.
func installReapOnSignal() {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		s := <-ch
		spawnedChildren.reapAll()
		signal.Stop(ch)
		if sig, ok := s.(syscall.Signal); ok {
			_ = syscall.Kill(os.Getpid(), sig)
		}
		// Belt: if re-raising somehow does not take, an interrupt must still end
		// the run rather than hang it.
		time.Sleep(2 * time.Second)
		os.Exit(130)
	}()
}

// reapAlarmAt returns the delay after which the pre-timeout reap alarm should fire
// for a `go test -timeout` budget of d, or 0 to disarm.
//
// `go test`'s own timeout panics from a TIMER goroutine and crashes the binary
// without unwinding the test goroutine, so neither a defer nor a t.Cleanup runs and
// every child is orphaned. Firing our own alarm a short lead BEFORE that panic reaps
// them while the process is still ours; the real timeout then fires and reports the
// hang exactly as it would have.
//
// The lead is 5% of the budget, clamped to [1s, 15s]: proportional so a long soak
// budget does not lose a minute of runway, floored so a very short budget still gets
// a usable window, and capped so the alarm never eats a meaningful share of a long
// run. A non-positive budget (`-timeout 0`, i.e. no deadline) disarms it.
func reapAlarmAt(d time.Duration) time.Duration {
	if d <= 0 {
		return 0
	}
	lead := d / 20
	if lead < time.Second {
		lead = time.Second
	}
	if lead > 15*time.Second {
		lead = 15 * time.Second
	}
	if lead >= d {
		return 0
	}
	return d - lead
}

// testTimeout reads the effective -test.timeout. Zero when the flag is absent or
// unparseable, which disarms the alarm rather than guessing a budget.
func testTimeout() time.Duration {
	f := flag.Lookup("test.timeout")
	if f == nil {
		return 0
	}
	g, ok := f.Value.(flag.Getter)
	if !ok {
		return 0
	}
	d, _ := g.Get().(time.Duration)
	return d
}

// TestMain installs the two out-of-band reaping paths, then reports any child that
// outlived its test as a FAILURE of the run — a leaked datastore is a defect in the
// fixture, not an acceptable residue, so it must not be able to hide behind a green
// suite.
func TestMain(m *testing.M) {
	// -test.timeout is only readable once flags are parsed; m.Run parses only if we
	// have not already.
	flag.Parse()
	installReapOnSignal()
	if d := reapAlarmAt(testTimeout()); d > 0 {
		time.AfterFunc(d, spawnedChildren.reapAll)
	}

	code := m.Run()

	if left := spawnedChildren.outstanding(); len(left) > 0 {
		fmt.Fprintf(os.Stderr, "executor tests: %d fixture child process(es) outlived the test that started them: %s\n",
			len(left), strings.Join(left, ", "))
		code = 1
	}
	spawnedChildren.reapAll()
	os.Exit(code)
}

// ---- refusing to start on a previous run's orphan ----------------------------

// fixtureOrphan is a datastore process left behind by an EARLIER run of this
// package's fixtures.
type fixtureOrphan struct {
	pid  int
	port string
	line string
}

var orphanScanOnce sync.Once

// refuseOnFixtureOrphans fails the run — before spawning anything — when a datastore
// from an earlier run of these fixtures is still alive. It is the same fail-closed
// shape bring-up uses for a held datastore port, and for the same reason: after the
// spawn, the leftover is indistinguishable from an ordinary environment problem, and
// the run reports a confusing downstream error instead of the cause.
//
// It NEVER kills anything. Only the run that started a process knows it is safe to
// reap; a scan cannot tell an abandoned fixture child from one another session is
// still using, so it names what it found and hands the decision to the human.
func refuseOnFixtureOrphans(t *testing.T) {
	t.Helper()
	var found []fixtureOrphan
	orphanScanOnce.Do(func() { found = liveFixtureOrphans() })
	if len(found) == 0 {
		return
	}
	var detail, pids strings.Builder
	for i, o := range found {
		fmt.Fprintf(&detail, "\n  pid %d holding :%s — %s", o.pid, o.port, o.line)
		if i > 0 {
			pids.WriteString(" ")
		}
		fmt.Fprintf(&pids, "%d", o.pid)
	}
	t.Fatalf("REFUSING to start: %d datastore process(es) from an earlier run of these fixtures are still alive:%s\n"+
		"Each holds a TCP port and a temp-dir database, and bring-up refuses a datastore port it finds held — so a later run fails for a reason that has nothing to do with it.\n"+
		"Stop them by hand (kill %s) and re-run. Nothing is killed automatically: only the run that started a process may reap it.",
		len(found), detail.String(), pids.String())
}

// liveFixtureOrphans scans the process table for this package's leftovers. A ps that
// fails yields no finding: the refusal is a safety net, and it must not itself become
// a reason a run cannot start.
func liveFixtureOrphans() []fixtureOrphan {
	out, err := exec.Command("ps", "-Ao", "pid=,command=").Output()
	if err != nil {
		return nil
	}
	return parseFixtureOrphans(string(out), os.TempDir(), spawnedChildren.pids())
}

// parseFixtureOrphans picks this package's fixture children out of
// `ps -Ao pid=,command=` output, skipping the pids the caller already owns.
//
// The discriminator is the DATASTORE ENDPOINT, not the process name: a datastore
// served out of this host's temp directory is by construction a t.TempDir() fixture's
// child, because a real server's database lives under its workdir (~/.k3sm/... or
// /var/lib/k3sm) and never under $TMPDIR. That is what keeps the scan from ever
// naming an operator's live cluster — which matters precisely because the report
// tells a human to kill what it names.
func parseFixtureOrphans(psOut, tmpDir string, skip map[int]bool) []fixtureOrphan {
	if tmpDir == "" {
		return nil
	}
	var out []fixtureOrphan
	for _, line := range strings.Split(psOut, "\n") {
		line = strings.TrimSpace(line)
		pidStr, cmdline, ok := strings.Cut(line, " ")
		if !ok {
			continue
		}
		cmdline = strings.TrimSpace(cmdline)
		if !strings.Contains(cmdline, "--endpoint") || !strings.Contains(cmdline, "sqlite://"+tmpDir) {
			continue
		}
		pid, err := strconv.Atoi(pidStr)
		if err != nil || pid <= 0 || skip[pid] {
			continue
		}
		out = append(out, fixtureOrphan{pid: pid, port: listenPortOf(cmdline), line: cmdline})
	}
	return out
}

// listenPortOf reads the port out of a `--listen-address <host>:<port>` argv, as a
// string so an unreadable one renders as "?" in the report rather than as 0 (which a
// reader would take for a real port).
func listenPortOf(cmdline string) string {
	fields := strings.Fields(cmdline)
	for i, f := range fields {
		if f != "--listen-address" || i+1 >= len(fields) {
			continue
		}
		if _, port, err := net.SplitHostPort(fields[i+1]); err == nil {
			return port
		}
	}
	return "?"
}

// ---- tests for the reaping helper itself -------------------------------------

// spawnGroupLeader starts `sh` in its OWN process group with a `sleep` running
// underneath it, and returns the tracked leader plus the grandchild's pid. It is the
// shape the fixture spawns with (Setpgid), so a test over it is a test of the real
// path rather than of a simplified one.
func spawnGroupLeader(t *testing.T) (*trackedChild, int) {
	t.Helper()
	pidFile := filepath.Join(t.TempDir(), "grandchild.pid")
	cmd := exec.Command("/bin/sh", "-c", "sleep 300 & echo $! > "+pidFile+"; wait")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		t.Fatalf("start the group leader: %v", err)
	}
	c := spawnedChildren.track(cmd, "reap probe")
	t.Cleanup(c.stop)

	var grandchild int
	deadline := time.Now().Add(10 * time.Second)
	for {
		b, err := os.ReadFile(pidFile)
		if err == nil {
			if pid, err := strconv.Atoi(strings.TrimSpace(string(b))); err == nil && pid > 0 {
				grandchild = pid
				break
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("the group leader never reported its grandchild pid")
		}
		time.Sleep(20 * time.Millisecond)
	}
	return c, grandchild
}

// awaitGone polls until pid is gone, failing after a bounded wait. The kill is
// synchronous but the kernel's teardown of a whole group is not instantaneous.
func awaitGone(t *testing.T, pid int, what string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for pidAlive(pid) {
		if time.Now().After(deadline) {
			t.Fatalf("%s (pid %d) is still alive 10s after the reap", what, pid)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// TestTrackedChildStopReapsTheWholeGroup pins the property the fixture depends on:
// stopping a tracked child takes its process GROUP with it, so a process the child
// spawned cannot outlive the reap. Killing the leader alone would leave the
// grandchild holding whatever the leader held.
func TestTrackedChildStopReapsTheWholeGroup(t *testing.T) {
	c, grandchild := spawnGroupLeader(t)
	leader := c.cmd.Process.Pid
	if !pidAlive(grandchild) {
		t.Fatalf("the grandchild (pid %d) was never alive — the probe proves nothing", grandchild)
	}
	c.stop()
	awaitGone(t, leader, "the group leader")
	awaitGone(t, grandchild, "the grandchild")
	if left := spawnedChildren.outstanding(); len(left) != 0 {
		t.Errorf("after stop the reaper still tracks %v", left)
	}
}

// TestTrackedChildStopIsIdempotent pins that the four reaping paths can all fire.
// stop() is reachable from the caller's defer, from t.Cleanup, from the signal
// handler and from the pre-timeout alarm, so a second call must be a no-op rather
// than a second Wait on a reaped pid (or a signal to a REUSED one).
func TestTrackedChildStopIsIdempotent(t *testing.T) {
	c, _ := spawnGroupLeader(t)
	c.stop()
	c.stop()
	c.stop()
	if left := spawnedChildren.outstanding(); len(left) != 0 {
		t.Errorf("after repeated stops the reaper still tracks %v", left)
	}
}

// reapProbeEnv names the file the subprocess half writes its child's pid to. Its
// presence is also what tells that half to run instead of skipping.
const reapProbeEnv = "K3SM_EXECUTOR_REAP_PROBE"

// TestReapProbeFatalsWithALiveChild is the SUBPROCESS half of
// TestFixtureChildReapedOnFatalPath: it reproduces the exact leak — a fixture that
// spawns a server and then t.Fatalf's before any stop call, which Goexits past every
// defer the test had not reached yet. It is skipped unless its parent invokes it.
func TestReapProbeFatalsWithALiveChild(t *testing.T) {
	pidFile := os.Getenv(reapProbeEnv)
	if pidFile == "" {
		t.Skip("the subprocess half of TestFixtureChildReapedOnFatalPath")
	}
	cmd := exec.Command("/bin/sh", "-c", "exec sleep 300")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	c := spawnedChildren.track(cmd, "fatal-path probe")
	t.Cleanup(c.stop)
	if err := os.WriteFile(pidFile, []byte(strconv.Itoa(cmd.Process.Pid)), 0o600); err != nil {
		t.Fatalf("record the child pid: %v", err)
	}
	t.Fatal("deliberate: the fixture fails BEFORE reaching any stop call — the path that leaked")
}

// TestFixtureChildReapedOnFatalPath is the real regression proof, and it has to run
// out-of-process: the property under test is what survives a test binary's exit, and
// nothing in-process can observe that. It runs the subprocess half — which spawns a
// child and then Fatals before stopping it — and asserts the child is gone once that
// binary is.
func TestFixtureChildReapedOnFatalPath(t *testing.T) {
	if os.Getenv(reapProbeEnv) != "" {
		t.Skip("running as the subprocess half")
	}
	pidFile := filepath.Join(t.TempDir(), "child.pid")
	cmd := exec.Command(os.Args[0], "-test.run", "^TestReapProbeFatalsWithALiveChild$", "-test.v")
	cmd.Env = append(os.Environ(), reapProbeEnv+"="+pidFile)
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("the probe subprocess was expected to FAIL (it Fatals on purpose); output:\n%s", out)
	}

	b, readErr := os.ReadFile(pidFile)
	if readErr != nil {
		t.Fatalf("the probe never recorded its child pid (%v) — it did not reach the spawn; output:\n%s", readErr, out)
	}
	pid, convErr := strconv.Atoi(strings.TrimSpace(string(b)))
	if convErr != nil || pid <= 0 {
		t.Fatalf("unreadable probe child pid %q", b)
	}
	if pidAlive(pid) {
		// Do not leave the machine dirtier than we found it: this process is one
		// THIS test started, so reaping it here is ours to do.
		killProcessGroup(pid)
		t.Fatalf("the probe's child (pid %d) outlived the test binary that spawned it — the Fatal path is not reaped; output:\n%s", pid, out)
	}
}

func TestReapAlarmAt(t *testing.T) {
	cases := []struct {
		name    string
		timeout time.Duration
		want    time.Duration
	}{
		{"no deadline disarms", 0, 0},
		{"a negative budget disarms", -time.Second, 0},
		{"a sub-second budget cannot fit the floor", 500 * time.Millisecond, 0},
		{"the 1s floor applies below 20s", 10 * time.Second, 9 * time.Second},
		{"the default 10m budget keeps a 15s lead", 10 * time.Minute, 10*time.Minute - 15*time.Second},
		{"a 15m budget keeps the same capped lead", 15 * time.Minute, 15*time.Minute - 15*time.Second},
		{"the 5% lead applies between the clamps", 100 * time.Second, 95 * time.Second},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := reapAlarmAt(c.timeout); got != c.want {
				t.Errorf("reapAlarmAt(%v) = %v, want %v", c.timeout, got, c.want)
			}
		})
	}
}

func TestParseFixtureOrphans(t *testing.T) {
	const tmp = "/var/folders/gn/xxxx/T"
	fixture := "  4711 /tmp/gopath/bin/kine --listen-address 127.0.0.1:62649 --metrics-bind-address 0 --endpoint sqlite://" + tmp + "/TestKineCompatForward123/001/db/state.db?_journal=WAL"
	real := "  4712 /Users/x/.k3sm/dev/a/server/bin/kine --listen-address 127.0.0.1:2391 --metrics-bind-address 0 --endpoint sqlite:///Users/x/.k3sm/dev/a/server/db/state.db?_journal=WAL"
	system := "  4713 /usr/sbin/notifyd"

	cases := []struct {
		name     string
		ps       string
		skip     map[int]bool
		wantPIDs []int
		wantPort string
	}{
		{"a fixture leftover is named", fixture + "\n" + system, nil, []int{4711}, "62649"},
		{"an operator's live cluster is NEVER named", real + "\n" + system, nil, nil, ""},
		{"both together: only the fixture one", real + "\n" + fixture, nil, []int{4711}, "62649"},
		{"this run's own child is skipped", fixture, map[int]bool{4711: true}, nil, ""},
		{"an empty table finds nothing", "", nil, nil, ""},
		{"no temp dir means no verdict", fixture, nil, nil, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := tmp
			if c.name == "no temp dir means no verdict" {
				dir = ""
			}
			got := parseFixtureOrphans(c.ps, dir, c.skip)
			if len(got) != len(c.wantPIDs) {
				t.Fatalf("parseFixtureOrphans = %+v, want %d finding(s)", got, len(c.wantPIDs))
			}
			for i, want := range c.wantPIDs {
				if got[i].pid != want {
					t.Errorf("finding %d pid = %d, want %d", i, got[i].pid, want)
				}
				if got[i].port != c.wantPort {
					t.Errorf("finding %d port = %q, want %q", i, got[i].port, c.wantPort)
				}
			}
		})
	}
}

func TestListenPortOf(t *testing.T) {
	cases := []struct{ in, want string }{
		{"kine --listen-address 127.0.0.1:62649 --endpoint x", "62649"},
		{"kine --listen-address [::1]:2391", "2391"},
		{"kine --endpoint sqlite:///x", "?"},
		{"kine --listen-address", "?"},
		{"kine --listen-address not-an-address", "?"},
	}
	for _, c := range cases {
		if got := listenPortOf(c.in); got != c.want {
			t.Errorf("listenPortOf(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

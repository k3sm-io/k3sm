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

package executor

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// TestAwaitHealthyFailFast table-tests the pure bring-up select loop (M10.0
// SRE fail-fast): child-exit beats the timeout (killing the opaque 90s wedge),
// readiness returns nil, the timeout still fires when nothing happens, and ctx
// cancellation propagates. Pure channels + funcs — no real control-plane
// binaries are spawned.
func TestAwaitHealthyFailFast(t *testing.T) {
	never := func(context.Context) bool { return false }
	always := func(context.Context) bool { return true }
	detail := func() string { return "exit status 1; last log lines:\nboom" }
	closed := func() chan struct{} {
		ch := make(chan struct{})
		close(ch)
		return ch
	}

	t.Run("ready returns nil", func(t *testing.T) {
		if err := awaitHealthy(context.Background(), "c", make(chan struct{}), nil, always, time.Second, 10*time.Millisecond, detail); err != nil {
			t.Fatalf("ready component: err = %v, want nil", err)
		}
	})

	t.Run("pre-exited child fails fast with detail", func(t *testing.T) {
		start := time.Now()
		err := awaitHealthy(context.Background(), "kube-apiserver", closed(), nil, never, time.Minute, 10*time.Millisecond, detail)
		if err == nil {
			t.Fatal("exited child: want error, got nil")
		}
		for _, want := range []string{"kube-apiserver", "exited during bring-up", "boom"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("error %q must contain %q (component name + log tail)", err, want)
			}
		}
		if elapsed := time.Since(start); elapsed > 5*time.Second {
			t.Errorf("fail-fast took %s — must not wait out the timeout", elapsed)
		}
	})

	t.Run("exit during the poll wait fails fast", func(t *testing.T) {
		exited := make(chan struct{})
		go func() {
			time.Sleep(20 * time.Millisecond)
			close(exited)
		}()
		start := time.Now()
		err := awaitHealthy(context.Background(), "kine", exited, nil, never, time.Minute, 10*time.Second, detail)
		if err == nil || !strings.Contains(err.Error(), "kine exited during bring-up") {
			t.Fatalf("err = %v, want the kine early-exit error", err)
		}
		if elapsed := time.Since(start); elapsed > 5*time.Second {
			t.Errorf("fail-fast took %s — must preempt the poll sleep", elapsed)
		}
	})

	t.Run("exited wins over ready", func(t *testing.T) {
		err := awaitHealthy(context.Background(), "c", closed(), nil, always, time.Second, 10*time.Millisecond, detail)
		if err == nil || !strings.Contains(err.Error(), "exited during bring-up") {
			t.Fatalf("err = %v, want the early-exit error (a dead child is never healthy)", err)
		}
	})

	t.Run("timeout still fires", func(t *testing.T) {
		err := awaitHealthy(context.Background(), "c", make(chan struct{}), nil, never, 50*time.Millisecond, 10*time.Millisecond, detail)
		if err == nil || !strings.Contains(err.Error(), "not healthy within") {
			t.Fatalf("err = %v, want the timeout error", err)
		}
	})

	t.Run("ctx cancellation propagates", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		err := awaitHealthy(ctx, "c", make(chan struct{}), nil, never, time.Minute, 10*time.Millisecond, detail)
		if err != context.Canceled {
			t.Fatalf("err = %v, want context.Canceled", err)
		}
	})
}

// TestSpawnChildExitSurfacesLog proves the whole fail-fast seam end-to-end with
// a fake child (a shell script that prints and exits nonzero — NOT a real
// control-plane binary): spawnEnv's reaper closes exited, and the bring-up wait
// returns an error naming the component, its exit status, and the last log
// lines from its 0600 log file. The wait is handed the component's kernel exit
// probe, so the assertions below hold even when a loaded machine delays the
// reaper past the 10s deadline (B172); the constructed interleaving itself is
// pinned by TestAwaitHealthyExitBeatsExpiredDeadline.
func TestSpawnChildExitSurfacesLog(t *testing.T) {
	wd := t.TempDir()
	if err := os.MkdirAll(binDir(wd), 0o755); err != nil {
		t.Fatal(err)
	}
	script := "#!/bin/sh\necho fatal-flag-error-detail\nexit 3\n"
	if err := os.WriteFile(filepath.Join(binDir(wd), "failer"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}

	s := NewSupervised(Config{WorkDir: wd})
	c, err := s.spawnEnv(context.Background(), "failer", nil)
	if err != nil {
		t.Fatalf("spawnEnv: %v", err)
	}
	defer func() { _ = s.Stop(context.Background()) }()

	never := func(context.Context) bool { return false }
	waitErr := awaitHealthy(context.Background(), c.name, c.exited, c.exitedNow, never, 10*time.Second, 10*time.Millisecond, c.exitDetail)
	if waitErr == nil {
		t.Fatal("want an early-exit error, got nil")
	}
	for _, want := range []string{"failer", "exited during bring-up", "exit status 3", "fatal-flag-error-detail"} {
		if !strings.Contains(waitErr.Error(), want) {
			t.Errorf("error %q must contain %q", waitErr, want)
		}
	}
	if fi, err := os.Stat(filepath.Join(wd, "failer.log")); err != nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("component log must exist with mode 0600, got %v (err=%v)", fi, err)
	}
}

// TestAwaitHealthyExitBeatsExpiredDeadline constructs the interleaving that a
// real child process cannot be made to reproduce on demand (B172): the health
// deadline has ALREADY expired while the child has ALREADY exited and the reaper
// goroutine that closes exited has not been scheduled yet. The exit-shaped error
// must win regardless — the deadline may only author its "not healthy within"
// error for a child that is genuinely still alive. Pure funcs + channels: the
// lagging close is a real goroutine delay, the exit state a controllable probe.
func TestAwaitHealthyExitBeatsExpiredDeadline(t *testing.T) {
	never := func(context.Context) bool { return false }
	detail := func() string { return "exit status 3; last log lines:\nfatal-flag-error-detail" }
	alive := func() bool { return false }
	dead := func() bool { return true }
	// expired makes time.Now().After(deadline) true on the very first pass, so
	// every case below enters the deadline branch with no prior poll.
	const expired = time.Nanosecond

	t.Run("exited child wins an expired deadline despite a lagging close", func(t *testing.T) {
		exited := make(chan struct{})
		go func() {
			time.Sleep(60 * time.Millisecond)
			close(exited)
		}()
		err := awaitHealthy(context.Background(), "failer", exited, dead, never, expired, 10*time.Millisecond, detail)
		if err == nil {
			t.Fatal("want the early-exit error, got nil")
		}
		for _, want := range []string{"failer", "exited during bring-up", "exit status 3", "fatal-flag-error-detail"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("error %q must contain %q — the deadline must not outrace a dead child", err, want)
			}
		}
	})

	t.Run("a still-running child leaves the deadline intact", func(t *testing.T) {
		err := awaitHealthy(context.Background(), "c", make(chan struct{}), alive, never, expired, 10*time.Millisecond, detail)
		if err == nil || !strings.Contains(err.Error(), "not healthy within") {
			t.Fatalf("err = %v, want the timeout error (the probe must not defeat a live child's deadline)", err)
		}
	})

	t.Run("no probe leaves the deadline unqualified", func(t *testing.T) {
		err := awaitHealthy(context.Background(), "c", make(chan struct{}), nil, never, expired, 10*time.Millisecond, detail)
		if err == nil || !strings.Contains(err.Error(), "not healthy within") {
			t.Fatalf("err = %v, want the timeout error", err)
		}
	})

	t.Run("ctx cancellation escapes the wait for a lagging close", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		err := awaitHealthy(ctx, "c", make(chan struct{}), dead, never, expired, 10*time.Millisecond, detail)
		if err != context.Canceled {
			t.Fatalf("err = %v, want context.Canceled", err)
		}
	})
}

// TestComponentExitedNowTracksTheChild pins the kernel probe behind the deadline
// tie-break against real children: a running child must report false (or the
// probe would defeat every legitimate health timeout) and an exited one true.
func TestComponentExitedNowTracksTheChild(t *testing.T) {
	wd := t.TempDir()
	if err := os.MkdirAll(binDir(wd), 0o755); err != nil {
		t.Fatal(err)
	}
	for name, script := range map[string]string{
		"sleeper": "#!/bin/sh\nsleep 30\n",
		"failer":  "#!/bin/sh\necho fatal-flag-error-detail\nexit 3\n",
	} {
		if err := os.WriteFile(filepath.Join(binDir(wd), name), []byte(script), 0o755); err != nil {
			t.Fatal(err)
		}
	}

	s := NewSupervised(Config{WorkDir: wd})
	defer func() { _ = s.Stop(context.Background()) }()

	live, err := s.spawnEnv(context.Background(), "sleeper", nil)
	if err != nil {
		t.Fatalf("spawnEnv sleeper: %v", err)
	}
	if live.exitedNow() {
		t.Error("a running child must report exitedNow() == false")
	}

	gone, err := s.spawnEnv(context.Background(), "failer", nil)
	if err != nil {
		t.Fatalf("spawnEnv failer: %v", err)
	}
	<-gone.exited
	if !gone.exitedNow() {
		t.Error("an exited child must report exitedNow() == true")
	}
}

// TestLoopbackComponentWaitsForItsListener pins the bring-up stage that the
// scheduler and controller-manager did not previously have. They were started
// fire-and-forget, so a component that died after the spawn left bring-up
// reporting success, and the failure surfaced far downstream — as a namespace
// bootstrap that never completes, because nothing is running the service-account
// controller.
//
// Both directions run against a REAL child process and a REAL socket. A component
// that dies must fail with its own name and log tail; a component whose port
// starts accepting must return promptly rather than block to the timeout. The
// live listener is opened only AFTER the child is running, because the pre-spawn
// guard (see preflightComponentPort) correctly refuses a port that was already
// held — the two halves cover disjoint windows and the test must not conflate
// them.
func TestLoopbackComponentWaitsForItsListener(t *testing.T) {
	wd := t.TempDir()
	if err := os.MkdirAll(binDir(wd), 0o755); err != nil {
		t.Fatal(err)
	}
	// Stands in for kube-scheduler: prints the diagnostic a real one prints when it
	// cannot get its port, and dies.
	deadScript := "#!/bin/sh\necho 'failed to listen on 127.0.0.1: address already in use'\nexit 1\n"
	if err := os.WriteFile(filepath.Join(binDir(wd), "kube-scheduler"), []byte(deadScript), 0o755); err != nil {
		t.Fatal(err)
	}
	// Stands in for a healthy controller-manager: announces that it is running and
	// stays up. It never binds anything — the test opens the listener, so what the
	// wait observes is unambiguously the port and not the process.
	marker := filepath.Join(wd, "kcm.started")
	liveScript := "#!/bin/sh\ntouch " + marker + "\nsleep 60\n"
	if err := os.WriteFile(filepath.Join(binDir(wd), "kube-controller-manager"), []byte(liveScript), 0o755); err != nil {
		t.Fatal(err)
	}

	s := NewSupervised(Config{WorkDir: wd})
	defer func() { _ = s.Stop(context.Background()) }()

	deadPort := freePort(t)
	err := s.startAndAwaitListening(context.Background(), "scheduler", s.startScheduler, deadPort)
	if err == nil {
		t.Fatal("a component that died during bring-up must fail it, got nil")
	}
	for _, want := range []string{"kube-scheduler", "exited during bring-up", "address already in use"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q must contain %q — the fault has to name the component that has it", err, want)
		}
	}

	livePort := freePort(t)
	done := make(chan error, 1)
	go func() {
		done <- s.startAndAwaitListening(context.Background(), "controller-manager", s.startControllerManager, livePort)
	}()
	// Bind only once the child is up, so the pre-spawn guard sees a free port and
	// the wait sees a listener appear the way a real component's would.
	deadline := time.Now().Add(20 * time.Second)
	for {
		if _, statErr := os.Stat(marker); statErr == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the fake controller-manager never started")
		}
		time.Sleep(20 * time.Millisecond)
	}
	live, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(livePort)))
	if err != nil {
		t.Fatalf("open the component's listener: %v", err)
	}
	defer live.Close()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("a component whose port accepts must pass bring-up, got %v", err)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("the wait did not return once the port accepted — it must return on readiness, not on the timeout")
	}
}

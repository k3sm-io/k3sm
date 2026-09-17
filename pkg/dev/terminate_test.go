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

package dev

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// spawnGroupChild starts `sh -c script` in its OWN process group — the same shape
// executor.spawnEnv gives every supervised component, and the shape TerminateProcess
// signals with -pid. It blocks until the script has signalled readiness by creating
// $READYFILE, so a trap installed by the script is provably in place before the test
// signals it. The returned channel carries the child's cmd.Wait() result: the waiter
// runs from the start so an exited child is REAPED promptly, which is what lets
// TerminateProcess's kill(pid, 0) poll observe the death instead of a zombie.
func spawnGroupChild(t *testing.T, script string) (*exec.Cmd, <-chan error) {
	t.Helper()
	ready := filepath.Join(t.TempDir(), "ready")
	cmd := exec.Command("/bin/sh", "-c", script)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Env = append(os.Environ(), "READYFILE="+ready)
	if err := cmd.Start(); err != nil {
		t.Fatalf("start child: %v", err)
	}
	waitCh := make(chan error, 1)
	go func() { waitCh <- cmd.Wait() }()
	t.Cleanup(func() { _ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) })

	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(ready); err == nil {
			return cmd, waitCh
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("child never signalled readiness (pid %d)", cmd.Process.Pid)
	return nil, nil
}

// awaitExit reaps the child and returns the signal that killed it (0 if it exited
// normally).
func awaitExit(t *testing.T, cmd *exec.Cmd, waitCh <-chan error, within time.Duration) syscall.Signal {
	t.Helper()
	select {
	case <-waitCh:
	case <-time.After(within):
		t.Fatalf("child pid %d still running %s after TerminateProcess returned", cmd.Process.Pid, within)
	}
	ws, ok := cmd.ProcessState.Sys().(syscall.WaitStatus)
	if !ok {
		t.Fatalf("unexpected wait status type %T", cmd.ProcessState.Sys())
	}
	if !ws.Signaled() {
		return 0
	}
	return ws.Signal()
}

// TestTerminateProcessCompletesOnCancelledContext pins the asymmetry the context
// threading rests on: ctx shortens the grace WAIT, it never cancels the kill.
//
// A cleanup path that honoured cancellation by returning early would leak the very
// detached server it was asked to reap — every TerminateProcess caller in Manager is a
// cleanup path, and several of them run with a ctx that is ALREADY cancelled (a
// ctrl-C'd `dev up` tearing its half-started server down). So a cancelled ctx must
// still leave a dead process behind.
func TestTerminateProcessCompletesOnCancelledContext(t *testing.T) {
	var sys realSystem

	t.Run("CancelledCtxStillEscalatesToSIGKILL", func(t *testing.T) {
		// The child IGNORES SIGTERM, so only the escalation can kill it: if
		// TerminateProcess returned on ctx.Done() without SIGKILLing, this process
		// would outlive the test.
		cmd, waitCh := spawnGroupChild(t, `trap '' TERM; : > "$READYFILE"; while :; do sleep 1; done`)

		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		start := time.Now()
		if err := sys.TerminateProcess(ctx, cmd.Process.Pid, 30*time.Second); err != nil {
			t.Fatalf("TerminateProcess: %v", err)
		}
		if elapsed := time.Since(start); elapsed > 5*time.Second {
			t.Errorf("a cancelled ctx must SHORTEN the grace wait; took %s of a 30s grace", elapsed)
		}
		if sig := awaitExit(t, cmd, waitCh, 10*time.Second); sig != syscall.SIGKILL {
			t.Errorf("child died of %v, want SIGKILL (the escalation must still run)", sig)
		}
	})

	t.Run("LiveCtxHonoursTheGraceWait", func(t *testing.T) {
		// The child exits on SIGTERM. A live ctx must let the grace wait observe
		// that — returning as soon as the process is gone, and never escalating.
		cmd, waitCh := spawnGroupChild(t, `: > "$READYFILE"; sleep 30`)

		const grace = 10 * time.Second
		start := time.Now()
		if err := sys.TerminateProcess(t.Context(), cmd.Process.Pid, grace); err != nil {
			t.Fatalf("TerminateProcess: %v", err)
		}
		if elapsed := time.Since(start); elapsed >= grace {
			t.Errorf("waited the full grace (%s) for a child that exits on SIGTERM", elapsed)
		}
		if sig := awaitExit(t, cmd, waitCh, 10*time.Second); sig != syscall.SIGTERM {
			t.Errorf("child died of %v, want SIGTERM (SIGKILL means the grace wait was skipped)", sig)
		}
	})

	t.Run("NonPositivePIDIsANoOp", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if err := sys.TerminateProcess(ctx, 0, time.Second); err != nil {
			t.Errorf("TerminateProcess(0) = %v, want nil", err)
		}
	})
}

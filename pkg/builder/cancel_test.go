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

package builder

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// shortSocketPath is a socket path inside a fresh directory short enough for
// darwin's 104-byte sun_path, which t.TempDir() can exceed.
func shortSocketPath(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "bc")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return filepath.Join(dir, "aaaaaaaaaaaa.sock")
}

// waitAlive polls until a build listens at path.
func waitAlive(t *testing.T, path string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !BuildAlive(t.Context(), path) {
		if time.Now().After(deadline) {
			t.Fatal("the build never opened its cancel socket")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// TestCancelStopsARunningBuild pins the cancel contract: a request at the
// build's socket cancels the job's context, the build records itself
// (finish runs with cancelled=true) BEFORE the requester is answered, and the
// build returns ErrCancelled. The fake job blocks until it is cancelled, the
// shape of a buildx solve waiting on buildkitd.
func TestCancelStopsARunningBuild(t *testing.T) {
	path := shortSocketPath(t)
	jobStopped := make(chan error, 1)
	finished := make(chan bool, 1)
	runErr := make(chan error, 1)
	go func() {
		runErr <- RunCancellable(t.Context(), path, func(ctx context.Context) error {
			<-ctx.Done()
			jobStopped <- ctx.Err()
			return ctx.Err()
		}, func(cancelled bool, _ error) {
			finished <- cancelled
		})
	}()
	waitAlive(t, path)

	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	if err := RequestCancel(ctx, path); err != nil {
		t.Fatalf("RequestCancel: %v", err)
	}
	// finish ran before the answer, so its value is already there.
	select {
	case c := <-finished:
		if !c {
			t.Error("finish reported the build as not cancelled")
		}
	default:
		t.Fatal("the cancel was answered before the build recorded itself")
	}
	if err := <-jobStopped; !errors.Is(err, context.Canceled) {
		t.Errorf("the job's context ended with %v, want context.Canceled", err)
	}
	if err := <-runErr; !errors.Is(err, ErrCancelled) {
		t.Errorf("RunCancellable = %v, want ErrCancelled", err)
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the cancel socket outlived the build: %v", err)
	}
	if err := RequestCancel(t.Context(), path); !errors.Is(err, ErrNoBuildProcess) {
		t.Errorf("a cancel after the build exited = %v, want ErrNoBuildProcess", err)
	}
}

// TestCancelAfterSuccessIsNotACancellation: a job that succeeded is a success
// even if a request raced in, and a probe connection cancels nothing.
func TestCancelAfterSuccessIsNotACancellation(t *testing.T) {
	path := shortSocketPath(t)
	release := make(chan struct{})
	var gotCancelled bool
	runErr := make(chan error, 1)
	go func() {
		runErr <- RunCancellable(t.Context(), path, func(ctx context.Context) error {
			<-release
			return nil
		}, func(cancelled bool, _ error) { gotCancelled = cancelled })
	}()
	waitAlive(t, path)
	if !BuildAlive(t.Context(), path) {
		t.Fatal("a probe did not see the build")
	}
	close(release)
	if err := <-runErr; err != nil {
		t.Fatalf("RunCancellable = %v, want nil", err)
	}
	if gotCancelled {
		t.Error("a successful build was reported cancelled")
	}
}

// TestCancelRefusesANonSocketAndStillBuilds: something that is not a socket in
// the socket's place is never removed, and the build runs without a channel.
func TestCancelRefusesANonSocketAndStillBuilds(t *testing.T) {
	path := shortSocketPath(t)
	if err := os.WriteFile(path, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	ran := false
	if err := RunCancellable(t.Context(), path, func(context.Context) error { ran = true; return nil }, nil); err != nil {
		t.Fatal(err)
	}
	if !ran {
		t.Error("the job did not run")
	}
	if data, err := os.ReadFile(path); err != nil || string(data) != "keep" {
		t.Errorf("the file in the socket's place was touched: %q, %v", data, err)
	}
}

// TestRunBuildxInterruptsOnCancel: cancelling the context interrupts buildx
// (SIGINT, which buildx turns into a cancelled solve) instead of killing it.
func TestRunBuildxInterruptsOnCancel(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "interrupted")
	script := filepath.Join(t.TempDir(), "fake-buildx")
	ready := marker + ".ready"
	body := "#!/bin/sh\ntrap 'echo int > " + marker + "; exit 130' INT\n: > " + ready + "\nwhile :; do sleep 0.05; done\n"
	if err := os.WriteFile(script, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- RunBuildxTo(ctx, script, nil, nil, nil, nil) }()
	// Cancel only once the trap is set: an interrupt before it would kill the
	// shell, which proves nothing about what buildx receives.
	deadline := time.Now().Add(10 * time.Second)
	for {
		if _, err := os.Stat(ready); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the fake buildx never started")
		}
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Errorf("RunBuildxTo = %v, want context.Canceled in the chain", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("buildx was not stopped")
	}
	if data, err := os.ReadFile(marker); err != nil || string(data) != "int\n" {
		t.Errorf("buildx did not receive SIGINT: %q, %v", data, err)
	}
}

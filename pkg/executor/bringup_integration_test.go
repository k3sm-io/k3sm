//go:build integration

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
	"testing"
	"time"
)

// TestLoopbackComponentWaitsForItsListener is the live-listener direction of the
// scheduler/controller-manager bring-up stage (the dead-component direction is
// TestLoopbackComponentFailsWhenItDies, in the unit tier): a component whose port
// starts accepting must return promptly rather than block to the timeout.
//
// It runs against a REAL child process and a REAL loopback listener, which is why
// it is in the integration tier. The listener is opened only AFTER the child is
// running, because the pre-spawn guard (see preflightComponentPort) correctly
// refuses a port that was already held — the guard and the wait cover disjoint
// windows and the test must not conflate them. It needs no privilege:
//
//	CGO_ENABLED=1 go test -tags integration -run TestLoopbackComponentWaitsForItsListener ./pkg/executor/
func TestLoopbackComponentWaitsForItsListener(t *testing.T) {
	wd := t.TempDir()
	if err := os.MkdirAll(binDir(wd), 0o755); err != nil {
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

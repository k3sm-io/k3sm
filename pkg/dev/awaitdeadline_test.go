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
	"strings"
	"testing"
	"time"
)

// The two await helpers poll a client-go Get/List whose rest.Config leaves
// Timeout at zero, so each probe is bounded only by the context it receives.
// Both used to hand the probe the CALLER's context and check their own deadline
// only after it returned — so against a wedged apiserver the probe never
// returned and the deadline was never reached. `k3sm dev up` hung forever with
// nothing logged, and the 90s / 5m constants were decorative.
//
// These tests model exactly that: a probe that blocks until ITS OWN context is
// done, driven by a caller context that never expires. Before the fix both hang
// until the -timeout kills the run; after it, each returns at its deadline with
// the descriptive error the helper is supposed to produce.

// blockUntilCtxDone is a probe that never succeeds and returns only when the
// context it was handed is cancelled — the shape of a client-go call against an
// apiserver that has stopped answering.
func blockUntilCtxDone(ctx context.Context) bool {
	<-ctx.Done()
	return false
}

func TestAwaitBootstrapObjectsBoundsAWedgedProbe(t *testing.T) {
	const timeout = 200 * time.Millisecond
	done := make(chan error, 1)
	start := time.Now()
	go func() {
		// context.Background() deliberately: the caller's context carries no
		// deadline, which is the production shape and was the bug.
		done <- awaitBootstrapObjects(context.Background(), timeout, "/tmp/kubeconfig",
			blockUntilCtxDone, blockUntilCtxDone)
	}()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("want a timeout error, got nil")
		}
		if !strings.Contains(err.Error(), "not bootstrapped within") {
			t.Fatalf("want the helper's descriptive timeout error, got %v", err)
		}
		if elapsed := time.Since(start); elapsed > 5*timeout {
			t.Fatalf("returned after %s, want ~%s — the deadline is not bounding the probe", elapsed, timeout)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("awaitBootstrapObjects never returned: the probe is unbounded, so its own deadline is unreachable")
	}
}

func TestAwaitReadyNodeBoundsAWedgedProbe(t *testing.T) {
	const timeout = 200 * time.Millisecond
	done := make(chan error, 1)
	start := time.Now()
	go func() {
		done <- awaitReadyNode(context.Background(), timeout, "/tmp/kubeconfig",
			func(ctx context.Context) (int, int, error) {
				<-ctx.Done()
				return 0, 0, ctx.Err()
			})
	}()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("want a timeout error, got nil")
		}
		if !strings.Contains(err.Error(), "no node registered Ready within") {
			t.Fatalf("want the helper's descriptive timeout error, got %v", err)
		}
		// The deadline now reaches the probe, so the cause is named rather than
		// leaving the reader with registered=0 and no explanation.
		if !strings.Contains(err.Error(), "context deadline exceeded") {
			t.Fatalf("want the wedged probe's cause reported as lastErr, got %v", err)
		}
		if elapsed := time.Since(start); elapsed > 5*timeout {
			t.Fatalf("returned after %s, want ~%s — the deadline is not bounding the probe", elapsed, timeout)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("awaitReadyNode never returned: the probe is unbounded, so its own deadline is unreachable")
	}
}

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

package main

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	"k3sm.io/k3sm/pkg/hostnet"
)

// TestAgentWaitsOutALateNetdHelper is the daemon half of the 2026-09-17
// ordering: io.k3sm.netd was bootstrapped 24ms before io.k3sm.agent, the
// agent's helper probe failed with "no such file", and that start was recorded
// as a bring-up failure — the record `k3sm install` reads to decide whether
// this node joined. The probe used to return that first failure straight out of
// the start, so a helper one second late cost a recorded failure and a launchd
// respawn.
//
// The grace is bounded, so a helper that is genuinely not coming back is still
// a start failure, and the error names the last refusal rather than a timeout
// with nothing in it.
func TestAgentWaitsOutALateNetdHelper(t *testing.T) {
	discard := slog.New(slog.DiscardHandler)

	t.Run("a helper that answers on the third attempt is not a start failure", func(t *testing.T) {
		attempts := 0
		probe := func(context.Context) error {
			attempts++
			if attempts < 3 {
				return hostnet.ErrHelperUnreachable
			}
			return nil
		}
		if err := awaitNetdHelper(context.Background(), probe, time.Second, time.Millisecond, discard); err != nil {
			t.Fatalf("awaitNetdHelper must wait out a helper that is a moment late: %v", err)
		}
		if attempts != 3 {
			t.Errorf("probe attempts = %d, want 3 (two refusals then the answer)", attempts)
		}
	})

	t.Run("a helper that never answers is still a start failure, naming the last refusal", func(t *testing.T) {
		attempts := 0
		probe := func(context.Context) error {
			attempts++
			return hostnet.ErrHelperUnreachable
		}
		err := awaitNetdHelper(context.Background(), probe, 5*time.Millisecond, time.Millisecond, discard)
		if !errors.Is(err, hostnet.ErrHelperUnreachable) {
			t.Fatalf("awaitNetdHelper error = %v, want the probe's own %v", err, hostnet.ErrHelperUnreachable)
		}
		if !strings.Contains(err.Error(), "attempts") {
			t.Errorf("error %q must say how long it waited and how often it asked", err)
		}
		if attempts < 2 {
			t.Errorf("probe attempts = %d, want more than one before giving up", attempts)
		}
	})

	t.Run("the grace is shorter than the terminal backoff a recorded failure costs", func(t *testing.T) {
		if netdProbeGrace >= agentTerminalBackoff {
			t.Errorf("netdProbeGrace %s must stay below the %s terminal backoff: waiting longer than the retry costs is not a grace", netdProbeGrace, agentTerminalBackoff)
		}
	})
}

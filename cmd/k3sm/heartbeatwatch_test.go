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
	"bytes"
	"log/slog"
	"strings"
	"testing"
	"time"

	"k3sm.io/k3sm/pkg/provider/vkadapter"
	"k3sm.io/k3sm/pkg/status"
)

// TestHeartbeatWatchReportsStaleWrites walks the watchdog through an outage:
// fresh writes log nothing; a Lease renewal older than its window logs one Warn
// naming the write and its age, repeated only after heartbeatRewarn; a status
// post judged on its own (longer) window does the same; recovery logs Info once;
// and a write that never landed is aged from the node's start.
func TestHeartbeatWatchReportsStaleWrites(t *testing.T) {
	var buf bytes.Buffer
	start := time.Unix(10_000, 0)
	w := &heartbeatWatch{node: "k3sm-w", started: start, log: slog.New(slog.NewTextHandler(&buf, nil))}
	lines := func() []string {
		out := strings.Split(strings.TrimSpace(buf.String()), "\n")
		buf.Reset()
		if len(out) == 1 && out[0] == "" {
			return nil
		}
		return out
	}

	last := start.Add(time.Minute)
	hb := vkadapter.Heartbeat{StatusPosted: last, LeaseRenewed: last}
	w.check(hb, last.Add(5*time.Second))
	if got := lines(); got != nil {
		t.Fatalf("fresh heartbeat logged %v", got)
	}

	// The Lease stops renewing; the status post is still inside its window.
	at := last.Add(status.HeartbeatLeaseStaleAfter + 5*time.Second)
	w.check(hb, at)
	got := lines()
	if len(got) != 1 || !strings.Contains(got[0], "level=WARN") || !strings.Contains(got[0], `write="lease renewal"`) || !strings.Contains(got[0], "age=45s") || !strings.Contains(got[0], "node=k3sm-w") {
		t.Fatalf("stale lease logged %v, want one WARN naming the lease renewal, its age and the node", got)
	}
	w.check(hb, at.Add(heartbeatWatchInterval))
	if got := lines(); got != nil {
		t.Fatalf("a stale lease re-warned inside %s: %v", heartbeatRewarn, got)
	}
	// The status keeps posting meanwhile, so only the lease is judged stale.
	hb.StatusPosted = at
	w.check(hb, at.Add(heartbeatRewarn))
	if got := lines(); len(got) != 1 || !strings.Contains(got[0], "lease renewal") {
		t.Fatalf("after %s the stale lease logged %v, want one repeat", heartbeatRewarn, got)
	}

	// The status post stops too and crosses its own window; the lease warning
	// is not due again yet.
	at = hb.StatusPosted.Add(status.HeartbeatStatusStaleAfter + time.Second)
	w.leaseWarned = at
	w.check(hb, at)
	if got := lines(); len(got) != 1 || !strings.Contains(got[0], `write="node status post"`) {
		t.Fatalf("stale status logged %v, want one WARN for the status post", got)
	}

	// Both land again.
	hb = vkadapter.Heartbeat{StatusPosted: at, LeaseRenewed: at}
	w.check(hb, at.Add(time.Second))
	got = lines()
	if len(got) != 2 || !strings.Contains(got[0], "recovered") || !strings.Contains(got[1], "recovered") {
		t.Fatalf("recovery logged %v, want one INFO per write", got)
	}

	// A node that never managed a write is aged from its start.
	w2 := &heartbeatWatch{node: "k3sm-w", started: start, log: slog.New(slog.NewTextHandler(&buf, nil))}
	w2.check(vkadapter.Heartbeat{}, start.Add(status.HeartbeatLeaseStaleAfter+time.Second))
	if got := lines(); len(got) != 1 || !strings.Contains(got[0], "never since the node started") {
		t.Fatalf("a never-renewed lease logged %v", got)
	}
}

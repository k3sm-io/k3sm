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
	"log/slog"
	"time"

	"k3sm.io/k3sm/pkg/provider/vkadapter"
	"k3sm.io/k3sm/pkg/status"
)

// heartbeatWatchInterval is how often the watchdog checks the node's heartbeat:
// the Lease renew interval, so a stale renewal is noticed within one interval
// of crossing its window.
const heartbeatWatchInterval = 10 * time.Second

// heartbeatRewarn is how often a heartbeat that STAYS stale is reported again.
const heartbeatRewarn = time.Minute

// heartbeatWatch is the node daemon's outcome watchdog: it judges the node by
// whether its liveness writes LANDED (vkadapter.Node.Heartbeat), not by whether
// its loops are running, because in the episode that motivated it every loop
// was running and idle between ticks while no write had landed for 36 minutes.
//
// It only reports. It never restarts anything: a write that cannot land is a
// path problem a restart does not fix, and a daemon that restarts itself hides
// the evidence of why.
type heartbeatWatch struct {
	node    string
	started time.Time
	log     *slog.Logger

	// Per-kind alert state: when the current stale episode was last reported
	// (zero when the kind is healthy).
	statusWarned, leaseWarned time.Time
}

// check judges one heartbeat sample at now and logs what changed: a Warn when a
// write's age crosses its window (and again every heartbeatRewarn while it
// stays there), an Info when it recovers. A write that has never landed is aged
// from the node's start.
func (w *heartbeatWatch) check(hb vkadapter.Heartbeat, now time.Time) {
	w.statusWarned = w.judge("node status post", hb.StatusPosted, status.HeartbeatStatusStaleAfter, w.statusWarned, now)
	w.leaseWarned = w.judge("lease renewal", hb.LeaseRenewed, status.HeartbeatLeaseStaleAfter, w.leaseWarned, now)
}

func (w *heartbeatWatch) judge(kind string, last time.Time, window time.Duration, warned, now time.Time) time.Time {
	since := last
	if since.IsZero() {
		since = w.started
	}
	age := now.Sub(since).Round(time.Second)
	if age <= window {
		if !warned.IsZero() {
			w.log.Info("node heartbeat recovered", "node", w.node, "write", kind, "last_success_age", age.String())
		}
		return time.Time{}
	}
	if !warned.IsZero() && now.Sub(warned) < heartbeatRewarn {
		return warned
	}
	lastText := "never since the node started"
	if !last.IsZero() {
		lastText = last.UTC().Format(time.RFC3339)
	}
	// The virtual-kubelet Warn lines logged before this one name the failing
	// request; this line says what the failure costs.
	w.log.Warn("node heartbeat is stale: no successful "+kind+" within its window, so the control plane will mark this node NotReady",
		"node", w.node, "write", kind, "age", age.String(), "window", window.String(), "last_success", lastText)
	return now
}

// run checks hb every heartbeatWatchInterval until ctx ends.
func (w *heartbeatWatch) run(ctx context.Context, hb func() vkadapter.Heartbeat) {
	t := time.NewTicker(heartbeatWatchInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			w.check(hb(), now)
		}
	}
}

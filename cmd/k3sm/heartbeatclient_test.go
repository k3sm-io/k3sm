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
	"testing"
	"time"
)

// TestNodeHeartbeatTimingFitsTheGracePeriod pins the production numbers against
// the node lifecycle: a renewal that stalls must fail before the next one is
// due, and a half-open connection must be closed and replaced well inside the
// node-monitor grace period, counting one lost renewal.
func TestNodeHeartbeatTimingFitsTheGracePeriod(t *testing.T) {
	const (
		leaseRenewInterval = 10 * time.Second // VK: 40 s lease x 0.25
		gracePeriod        = 40 * time.Second // the stricter pre-1.32 default
	)
	tm := nodeHeartbeatTiming
	if tm.request > leaseRenewInterval {
		t.Errorf("request bound %s exceeds the %s renew interval", tm.request, leaseRenewInterval)
	}
	// The health check must have closed the dead connection by the time the
	// stalled renewal gives up, so the renewal after it dials a new one.
	if tm.readIdle+tm.ping > tm.request {
		t.Errorf("health check (%s idle + %s PING) outlasts the %s request bound", tm.readIdle, tm.ping, tm.request)
	}
	// Last success at 0; the renewal at one interval stalls and fails; the one
	// at two intervals dials and handshakes a new connection.
	if worst := 2*leaseRenewInterval + tm.dial + tm.handshake; worst >= gracePeriod {
		t.Errorf("worst-case recovery %s is not inside the %s grace period", worst, gracePeriod)
	}
	if tm.request >= nodeAPIRequestTimeout {
		t.Errorf("heartbeat request bound %s is not shorter than the general client's %s", tm.request, nodeAPIRequestTimeout)
	}
	if tm.readIdle == 0 {
		t.Error("readIdle 0 disables the HTTP/2 health check")
	}
}

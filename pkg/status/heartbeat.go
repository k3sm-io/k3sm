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

package status

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	coordinationv1 "k8s.io/api/coordination/v1"
	corev1 "k8s.io/api/core/v1"

	"k3sm.io/k3sm/pkg/dataroot"
)

// The windows a node's two liveness writes are judged against. They are shared
// by this row and by the node daemon's own heartbeat watchdog, so the log line
// and the status report call the same heartbeat stale.
const (
	// HeartbeatLeaseStaleAfter is how old the last Lease renewal may be. It is
	// the Lease duration (40 s), which was also the controller-manager's
	// node-monitor grace period before Kubernetes 1.32 (50 s since): a renewal
	// older than this means the node is about to be marked NotReady, or already
	// has been. Renewals are due every 10 s.
	HeartbeatLeaseStaleAfter = 40 * time.Second
	// HeartbeatStatusStaleAfter is how old the last node-status post may be.
	// Status is posted once a minute while the Lease carries liveness, so the
	// window is that interval plus the Lease window above.
	HeartbeatStatusStaleAfter = time.Minute + HeartbeatLeaseStaleAfter
)

// leasePath is the apiserver path of a node's Lease.
func leasePath(node string) string {
	return "/apis/coordination.k8s.io/v1/namespaces/" + corev1.NamespaceNodeLease + "/leases/" + node
}

// heartbeatRow reports how long ago THIS Mac's node last posted its status and
// renewed its Lease, read from the objects the apiserver holds: the Ready
// condition's lastHeartbeatTime and the Lease's renewTime. Those are what the
// node lifecycle controller judges the node by, so a stale value here is the
// cause of a NotReady node, seen from the node's own Mac.
//
// Both times are written with this Mac's clock and read here with the same
// clock, so the ages carry no cross-host skew.
//
// The row is omitted when there is nothing to judge: the apiserver did not
// answer (the apiserver row says so), this Mac's node could not be picked out,
// or neither time could be read.
func (c Collector) heartbeatRow(ctx context.Context, serving bool, role dataroot.Role, nodes []corev1.Node, nodesErr error, now time.Time) (Row, bool) {
	if c.Kube == nil || !serving || nodesErr != nil {
		return Row{}, false
	}
	mine, ok := PickNode(nodes, c.Hostname)
	if !ok {
		return Row{}, false
	}
	var statusAt time.Time
	for _, cond := range mine.Status.Conditions {
		if cond.Type == corev1.NodeReady {
			statusAt = cond.LastHeartbeatTime.Time
		}
	}
	var renewAt time.Time
	var leaseErr error
	if raw, err := c.Kube.RawGet(ctx, leasePath(mine.Name)); err != nil {
		leaseErr = err
	} else {
		var lease coordinationv1.Lease
		if err := json.Unmarshal(raw, &lease); err != nil {
			leaseErr = fmt.Errorf("decode lease: %w", err)
		} else if lease.Spec.RenewTime != nil {
			renewAt = lease.Spec.RenewTime.Time
		}
	}
	if statusAt.IsZero() && renewAt.IsZero() {
		return Row{}, false
	}

	row := Row{Name: RowHeartbeat, Wide: map[string]string{"node": mine.Name}}
	stale := false
	statusPart := "node status: never posted"
	if !statusAt.IsZero() {
		age := ageOf(now, statusAt)
		row.Wide["statusAgeSeconds"] = strconv.Itoa(int(age / time.Second))
		statusPart = "node status posted " + age.String() + " ago"
		if age > HeartbeatStatusStaleAfter {
			stale = true
			statusPart += " (over " + HeartbeatStatusStaleAfter.String() + ")"
		}
	}
	leasePart := "lease: never renewed"
	switch {
	case leaseErr != nil:
		leasePart = "lease could not be read: " + errText(leaseErr)
	case !renewAt.IsZero():
		age := ageOf(now, renewAt)
		row.Wide["leaseAgeSeconds"] = strconv.Itoa(int(age / time.Second))
		leasePart = "lease renewed " + age.String() + " ago"
		if age > HeartbeatLeaseStaleAfter {
			stale = true
			leasePart += " (over " + HeartbeatLeaseStaleAfter.String() + ")"
		}
	}
	row.Detail = mine.Name + ": " + statusPart + " · " + leasePart
	if stale {
		row.State, row.Severity = StateStale, SeverityWarn
		row.Remedy = c.nodeLogRemedy(role)
		return row, true
	}
	row.State, row.Severity = StateOK, SeverityOK
	return row, true
}

// ageOf is now-t rounded to the second, never negative.
func ageOf(now, t time.Time) time.Duration {
	d := now.Sub(t).Round(time.Second)
	if d < 0 {
		return 0
	}
	return d
}

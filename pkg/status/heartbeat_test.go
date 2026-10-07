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
	"errors"
	"strings"
	"testing"
	"time"

	coordinationv1 "k8s.io/api/coordination/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"k3sm.io/k3sm/pkg/dataroot"
)

// heartbeatingKube is healthyKube whose node last posted its status 20 s
// before now and renewed its Lease 5 s before now: a node in good standing.
func heartbeatingKube(now time.Time) fakeKube {
	return withHeartbeat(healthyKube(), now.Add(-20*time.Second), now.Add(-5*time.Second))
}

// withHeartbeat stamps k's first node with a Ready heartbeat at statusAt and
// serves its Lease renewed at renewAt (zero: no Lease served).
func withHeartbeat(k fakeKube, statusAt, renewAt time.Time) fakeKube {
	nodes := make([]corev1.Node, len(k.nodes))
	for i := range k.nodes {
		nodes[i] = *k.nodes[i].DeepCopy()
	}
	k.nodes = nodes
	if !statusAt.IsZero() {
		k.nodes[0].Status.Conditions[0].LastHeartbeatTime = metav1.NewTime(statusAt)
	}
	raw := make(map[string][]byte, len(k.raw)+1)
	for p, b := range k.raw {
		raw[p] = b
	}
	if !renewAt.IsZero() {
		rt := metav1.NewMicroTime(renewAt)
		b, _ := json.Marshal(coordinationv1.Lease{Spec: coordinationv1.LeaseSpec{RenewTime: &rt}})
		raw[leasePath(k.nodes[0].Name)] = b
	}
	k.raw = raw
	return k
}

// TestHeartbeatRow pins the heartbeat row: the two ages it reports, which one
// makes it stale and at which window, and when it is omitted.
func TestHeartbeatRow(t *testing.T) {
	now := goldenTime
	c := Collector{Hostname: "my-mac"}
	for _, tc := range []struct {
		name      string
		kube      fakeKube
		leaseErr  error
		serving   bool
		wantRow   bool
		wantState RowState
		wantSev   Severity
		wantIn    []string
	}{
		{
			name: "fresh", kube: heartbeatingKube(now), serving: true, wantRow: true,
			wantState: StateOK, wantSev: SeverityOK,
			wantIn: []string{"node status posted 20s ago", "lease renewed 5s ago"},
		},
		{
			name:    "lease stale",
			kube:    withHeartbeat(healthyKube(), now.Add(-20*time.Second), now.Add(-HeartbeatLeaseStaleAfter-time.Second)),
			serving: true, wantRow: true, wantState: StateStale, wantSev: SeverityWarn,
			wantIn: []string{"lease renewed 41s ago (over 40s)"},
		},
		{
			name:    "lease exactly at the window is not stale",
			kube:    withHeartbeat(healthyKube(), now.Add(-20*time.Second), now.Add(-HeartbeatLeaseStaleAfter)),
			serving: true, wantRow: true, wantState: StateOK, wantSev: SeverityOK,
		},
		{
			name:    "status stale while the lease renews",
			kube:    withHeartbeat(healthyKube(), now.Add(-HeartbeatStatusStaleAfter-time.Second), now.Add(-5*time.Second)),
			serving: true, wantRow: true, wantState: StateStale, wantSev: SeverityWarn,
			wantIn: []string{"node status posted 1m41s ago (over 1m40s)", "lease renewed 5s ago"},
		},
		{
			name: "lease unreadable", kube: withHeartbeat(healthyKube(), now.Add(-20*time.Second), time.Time{}),
			leaseErr: errors.New("forbidden"), serving: true, wantRow: true, wantState: StateOK, wantSev: SeverityOK,
			wantIn: []string{"lease could not be read: forbidden"},
		},
		{name: "nothing to judge", kube: healthyKube(), serving: true, wantRow: false},
		{name: "apiserver not serving", kube: heartbeatingKube(now), serving: false, wantRow: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			k := tc.kube
			if tc.leaseErr != nil {
				k.rawErr = map[string]error{leasePath("my-mac"): tc.leaseErr}
			}
			c := c
			c.Kube = k
			row, ok := c.heartbeatRow(context.Background(), tc.serving, dataroot.RoleAgent, k.nodes, nil, now)
			if ok != tc.wantRow {
				t.Fatalf("row present = %v, want %v (%+v)", ok, tc.wantRow, row)
			}
			if !ok {
				return
			}
			if row.Name != RowHeartbeat || row.State != tc.wantState || row.Severity != tc.wantSev {
				t.Errorf("row = %s %s/%v, want %s %s/%v", row.Name, row.State, row.Severity, RowHeartbeat, tc.wantState, tc.wantSev)
			}
			for _, w := range tc.wantIn {
				if !strings.Contains(row.Detail, w) {
					t.Errorf("detail %q does not contain %q", row.Detail, w)
				}
			}
			if tc.wantState == StateStale && row.Remedy == "" {
				t.Error("a stale heartbeat carries no remedy")
			}
		})
	}
}

// TestStaleHeartbeatDegradesAWorker pins that a stale heartbeat on a worker
// moves the verdict: it is this node's own health (its writes are not reaching
// the control plane, and the node will be marked NotReady), not a note about a
// control plane on another Mac, so it is not one of the worker-advisory rows.
func TestStaleHeartbeatDegradesAWorker(t *testing.T) {
	if advisory(dataroot.RoleAgent, RowHeartbeat) || advisory(dataroot.RoleServer, RowHeartbeat) {
		t.Fatal("the heartbeat row is advisory; a stale heartbeat would not move the verdict")
	}
}

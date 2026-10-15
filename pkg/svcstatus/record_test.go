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

package svcstatus

import (
	"slices"
	"testing"
	"time"

	"k3sm.io/darwin-net/pkg/proxy"

	"k3sm.io/k3sm/pkg/status"
)

// TestRecordConvertsTheTable pins Record: every field carries over, a nil
// backend list becomes empty, and only the pinned Service is marked static.
func TestRecordConvertsTheTable(t *testing.T) {
	now := time.Date(2026, 10, 15, 12, 0, 0, 0, time.FixedZone("x", 3600))
	rec := Record([]proxy.VIPState{
		{ClusterIP: "10.43.0.1", Port: 443, Protocol: "TCP", Namespace: "default", Name: "kubernetes", Policy: "Cluster", Backends: []string{"127.0.0.1:6443"}, LocalBackends: 1, Generation: 3},
		{ClusterIP: "10.43.0.20", Port: 80, Protocol: "UDP", Namespace: "web", Name: "front", Policy: "Local"},
	}, []string{"default/kubernetes"}, []string{"10.43.0.10"}, now)
	if !rec.UpdatedAt.Equal(now) || rec.UpdatedAt.Location() != time.UTC {
		t.Errorf("UpdatedAt = %v, want %v in UTC", rec.UpdatedAt, now)
	}
	want := []status.VIPEntry{
		{ClusterIP: "10.43.0.1", Port: 443, Protocol: "TCP", Namespace: "default", Name: "kubernetes", Policy: "Cluster", Backends: []string{"127.0.0.1:6443"}, LocalBackends: 1, Generation: 3, Static: true},
		{ClusterIP: "10.43.0.20", Port: 80, Protocol: "UDP", Namespace: "web", Name: "front", Policy: "Local", Backends: []string{}},
	}
	if len(rec.VIPs) != len(want) {
		t.Fatalf("VIPs = %+v", rec.VIPs)
	}
	for i := range want {
		g, w := rec.VIPs[i], want[i]
		if g.ClusterIP != w.ClusterIP || g.Port != w.Port || g.Protocol != w.Protocol || g.Namespace != w.Namespace ||
			g.Name != w.Name || g.Policy != w.Policy || !slices.Equal(g.Backends, w.Backends) || g.Backends == nil ||
			g.LocalBackends != w.LocalBackends || g.Generation != w.Generation || g.Static != w.Static {
			t.Errorf("VIPs[%d] = %+v, want %+v", i, g, w)
		}
	}
	if !slices.Equal(rec.Unproxied, []string{"10.43.0.10"}) {
		t.Errorf("Unproxied = %v", rec.Unproxied)
	}
}

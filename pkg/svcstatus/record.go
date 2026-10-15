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
	"maps"
	"slices"
	"strings"
	"time"

	"k3sm.io/darwin-net/pkg/proxy"

	"k3sm.io/k3sm/pkg/status"
)

// Record converts the proxy's routing table into the record the services row
// reads. pinned are the backends the server pins per "namespace/name" Service
// (netserve.Server.PinnedBackends); unproxied are the ClusterIPs the proxy leaves
// to another listener (netserve.Server.UnproxiedClusterIPs).
func Record(states []proxy.VIPState, pinned map[string][]string, unproxied []string, now time.Time) status.ServicesRecord {
	rec := status.ServicesRecord{
		UpdatedAt: now.UTC(),
		VIPs:      make([]status.VIPEntry, 0, len(states)),
		Unproxied: slices.Clone(unproxied),
	}
	for _, s := range states {
		rec.VIPs = append(rec.VIPs, vipEntry(s))
	}
	for _, key := range slices.Sorted(maps.Keys(pinned)) {
		ns, name, _ := strings.Cut(key, "/")
		backends := slices.Clone(pinned[key])
		slices.Sort(backends)
		if backends == nil {
			backends = []string{}
		}
		rec.Pinned = append(rec.Pinned, status.PinnedService{Namespace: ns, Name: name, Backends: backends})
	}
	return rec
}

// vipEntry converts one table entry to the record's type.
func vipEntry(s proxy.VIPState) status.VIPEntry {
	backends := slices.Clone(s.Backends)
	if backends == nil {
		backends = []string{}
	}
	return status.VIPEntry{
		ClusterIP:     s.ClusterIP,
		Port:          s.Port,
		Protocol:      s.Protocol,
		Namespace:     s.Namespace,
		Name:          s.Name,
		Policy:        s.Policy,
		Backends:      backends,
		LocalBackends: s.LocalBackends,
		Generation:    s.Generation,
	}
}

// vipState is the inverse of vipEntry: the proxy's own type, so the
// have side of the comparison is built by proxy.BackendSets.
func vipState(e status.VIPEntry) proxy.VIPState {
	return proxy.VIPState{
		ClusterIP:     e.ClusterIP,
		Port:          e.Port,
		Protocol:      e.Protocol,
		Namespace:     e.Namespace,
		Name:          e.Name,
		Policy:        e.Policy,
		Backends:      e.Backends,
		LocalBackends: e.LocalBackends,
		Generation:    e.Generation,
	}
}

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
	"path/filepath"
	"time"
)

// ServicesRecord is what a running server records about its Service proxy: every
// Service port the proxy routes and the Ready backends it routes each one to,
// refreshed every ServicesRecordInterval. The services row compares it with the
// API's EndpointSlices.
type ServicesRecord struct {
	UpdatedAt time.Time  `json:"updatedAt"`
	VIPs      []VIPEntry `json:"vips"`
	// Unproxied are the ClusterIPs the proxy deliberately does not route because
	// another listener on the node owns them (the cluster DNS address). Their
	// Services have no entry in VIPs, and the row does not expect one.
	Unproxied []string `json:"unproxied,omitempty"`
	// Pinned are the Services whose backends the server pins rather than
	// derives from EndpointSlices (the kubernetes Service of a single-node
	// server, whose loopback endpoint no EndpointSlice may carry), with the
	// backends pinned. They are what the proxy must route those ports to, and no
	// API object can say so.
	Pinned []PinnedService `json:"pinned,omitempty"`
}

// PinnedService is one Service the server pins to fixed backends.
type PinnedService struct {
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
	// Backends are the pinned addresses ("ip:port"), sorted.
	Backends []string `json:"backends"`
}

// VIPEntry is one routed Service port as the proxy holds it.
type VIPEntry struct {
	ClusterIP string `json:"clusterIP"`
	Port      int32  `json:"port"`
	// Protocol is "TCP" or "UDP".
	Protocol string `json:"protocol"`
	// Namespace and Name identify the owning Service.
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
	// Policy is the port's internalTrafficPolicy, "Cluster" or "Local".
	Policy string `json:"policy"`
	// Backends are the Ready backend addresses ("ip:port"), sorted; empty, never
	// nil, when the port has none.
	Backends []string `json:"backends"`
	// LocalBackends is how many of Backends run on this node.
	LocalBackends int `json:"localBackends"`
	// Generation numbers the distinct backend sets the proxy has installed for
	// the port.
	Generation uint64 `json:"generation"`
}

// ServicesRecordInterval is how often a server refreshes its ServicesRecord.
const ServicesRecordInterval = 30 * time.Second

// servicesName is the record's basename, beside the mesh claim record.
const servicesName = "services.json"

// ServicesPath is the record's path for a work dir.
func ServicesPath(workDir string) string { return filepath.Join(workDir, servicesName) }

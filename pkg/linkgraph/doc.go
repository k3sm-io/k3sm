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

// Package linkgraph is the server's direct-link resolver: it joins every node's
// DirectLink spec (each node sees only its own side of a cable) into the status of
// every port, and builds the cluster's cable graph from the ports that are up.
//
// # The up rule
//
// A port is up iff both ends list each other (each port's peerDomainUUID is the
// other's domainUUID), both report linkUp AND routeReady, neither sets
// tunnelOnly, and the peer node's Lease is fresh. The Lease term is there because
// a node that vanished cannot report its own port down; liveness demotes it. A
// port whose peer UUID belongs to no node in the cluster is peer-unknown (a cabled
// Mac that has not joined, the pairing hint); every other port is down.
// lastTransition moves only when the state changes.
//
// Resolve is that rule, pure, and the table tests drive it over fake objects. The
// Controller runs it on every DirectLink or Lease change and on a short resync,
// writes status through the status subresource (never the spec), and sets the
// advisory k3sm.io/direct-links=<up count> label on each Node.
//
// # The graph
//
// Graph holds an edge between two nodes only when BOTH nodes' statuses report the
// cable up, and Clique and Ring are the deterministic searches sharded placement
// reads (n is at most five in practice, so they are brute force).
package linkgraph

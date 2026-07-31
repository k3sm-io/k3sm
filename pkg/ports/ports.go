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

// Package ports single-sources the TCP ports k3sm's own server process binds on
// the WILDCARD address, and the reserved set derived from them.
//
// It is a LEAF: it depends on nothing else in this repo, so the apiserver argv
// (pkg/executor), the kubelet API listen addresses (cmd/k3sm), the svclb bind
// refusal (pkg/svclb) and the admission CEL (pkg/policy) all read ONE
// definition. Before B116 the NodePort range was a bare string inside the
// apiserver argv and the kubelet port had no constant at all — two bare literals
// inside listen addresses — so a range change could silently desync the guard
// from the thing it guards.
package ports

import "strconv"

// The wildcard listeners k3sm's server process owns. Go sets SO_REUSEADDR but
// NOT SO_REUSEPORT, so wildcard-vs-wildcard on the same port fails EADDRINUSE
// (wildcard-vs-specific coexists — that is why the ClusterIP/DNS VIPs, which
// bind SPECIFIC addresses, are deliberately absent from this set).
const (
	// NodePortRangeMin / NodePortRangeMax are the apiserver's
	// --service-node-port-range bounds — the standard upstream default, pinned
	// so the range k3sm's in-process Service proxy binds *:port on is explicit
	// rather than inherited from an upstream default that may move.
	NodePortRangeMin = 30000
	// NodePortRangeMax is the inclusive upper bound of the NodePort range.
	NodePortRangeMax = 32767
	// KubeletAPIPort is the kubelet HTTP API port the VK node serves logs/exec/
	// stats on (`k3sm server`/`k3sm agent` listen on *:10250). Losing it to a
	// LoadBalancer Service kills logs/exec/`kubectl top` on that node.
	KubeletAPIPort = 10250
)

// LEDGER — the fifth wildcard listener, deliberately NOT in the reserved set.
//
// The wireguard mesh binds UDP :51820 on the wildcard (darwin-net pkg/mesh). It
// is harmless today ONLY by protocol disjointness: svclb skips every non-TCP
// LoadBalancer port (UDP LoadBalancer is deferred) and the Service proxy opens
// no UDP NodePort listener, so nothing k3sm reserves here can ever contend for
// it. WHOEVER UN-DEFERS UDP LoadBalancer MUST REVISIT THIS: a UDP LB Service on
// 51820 would take the mesh's port and partition the cluster, and the guard
// below — TCP-shaped by construction — would not have considered it.

// NodePortRange renders the --service-node-port-range argv value ("30000-32767")
// from the bounds above, so the apiserver's allocation range and the reserved
// set below cannot be edited apart.
func NodePortRange() string {
	return strconv.Itoa(NodePortRangeMin) + "-" + strconv.Itoa(NodePortRangeMax)
}

// Reserved reports whether port belongs to a wildcard listener k3sm's own server
// process owns: the NodePort range, or the kubelet API port. A LoadBalancer
// Service declaring such a port would race a k3sm listener for the same wildcard
// socket, so admission rejects it (pkg/policy) and svclb refuses to bind it
// (pkg/svclb) rather than letting the race decide.
func Reserved(port int) bool {
	return port == KubeletAPIPort || (port >= NodePortRangeMin && port <= NodePortRangeMax)
}

// ReservedSet materializes Reserved as an explicit set keyed by the int32 a
// corev1.ServicePort carries — the shape svclb.Config.ReservedPorts takes, so
// the controller holds the reserved policy as DATA the assembler injected rather
// than importing this package and re-deciding it.
func ReservedSet() map[int32]bool {
	set := make(map[int32]bool, NodePortRangeMax-NodePortRangeMin+2)
	for p := NodePortRangeMin; p <= NodePortRangeMax; p++ {
		set[int32(p)] = true
	}
	set[int32(KubeletAPIPort)] = true
	return set
}

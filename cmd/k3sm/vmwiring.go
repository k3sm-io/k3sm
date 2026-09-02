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
	"k3sm.io/runtimed/pkg/sandbox"

	"k3sm.io/k3sm/pkg/hostnet"
	"k3sm.io/k3sm/pkg/netserve"
	"k3sm.io/k3sm/pkg/provider"
)

// vmBackendAvailable reports whether this host can run vm-RuntimeClass guests,
// via runtimed's OWN capability probe (sandbox.VMBackend.Available: darwin, the
// macOS floor, +[VZVirtualMachine isSupported], the k3sm-vmhost helper resolving,
// and that helper's signature carrying com.apple.security.virtualization).
//
// IT IS THE DIRECT PROBE, DELIBERATELY, not the node's advertised capability.
// netserve is constructed at datapath bring-up, several steps BEFORE the VK node
// exists, so provider.Capabilities() — which reads the same verdict back off
// runtimed's GetRuntimeInfo — is simply not answerable yet, and making the
// datapath wait on the node would invert the bring-up order for a boolean. Both
// paths terminate at this one probe on this one host, so they cannot disagree; the
// difference is only which of them is reachable at the moment of the question.
//
// It is SAFE and cheap: Available never constructs or boots a VM (see its doc). On
// a CGO_ENABLED=0 build the host probes report false, so this reports false — the
// same fail-closed answer a non-VZ Mac gives, which is the correct one for a
// binary that could not have driven a guest anyway.
func vmBackendAvailable() bool { return sandbox.NewVMBackend().Available() }

// guestNATSubnet returns the NAT segment this node's Linux guests attach to, or
// "" when this node cannot host one.
//
// It exists so the two consumers of that segment — the ingest registry's relay,
// whose gateway bind is the only address a guest can reach a host listener at,
// and the NetworkPolicy table's fail-closed unknown-vm-source branch — make the
// SAME decision from the same probe. A node with no vm backend names no segment,
// so nothing is bound and nothing is scoped for guests that cannot exist.
func guestNATSubnet(vmCapable bool) string {
	if !vmCapable {
		return ""
	}
	return netserve.DefaultVMNetSubnet
}

// nodeTransportOverrides returns the sink the in-process node feeds vm-pod
// transport overrides into: the node-local datapath's Server, which forwards to
// the Service proxy's routing table (netserve.Server.SetTransportOverrides).
//
// It returns nil — the inert feed, which installs no override and holds no lease
// state — for the two postures with no proxy to feed: `--network none`, where the
// Server exists but runs no datapath, and any bring-up that stood up no Server at
// all. Returning a live Server there would push generations into a table nothing
// routes on, which is harmless but reads in the logs as a working datapath.
//
// The nil return is an untyped nil interface, not a typed-nil *netserve.Server, so
// provider's newTransportFeed(nil) sees the nil it is documented to test for.
func nodeTransportOverrides(srv *netserve.Server, mode hostnet.Mode) provider.TransportOverrideSink {
	if srv == nil || !mode.DataPath() {
		return nil
	}
	return srv
}

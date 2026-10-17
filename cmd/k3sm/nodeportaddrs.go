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
	"fmt"
	"net/netip"
	"strings"

	"k3sm.io/darwin-net/pkg/proxy"

	"k3sm.io/k3sm/pkg/dataroot"
	"k3sm.io/k3sm/pkg/install"
)

// nodePortAddressesFlag is the k3s-style flag (`--nodeport-addresses`, kube-proxy's
// name) shared by `k3sm server`, `k3sm agent` and `k3sm install`.
const nodePortAddressesFlag = "nodeport-addresses"

// nodePortAddressesUsage is that flag's help text, one string for all three commands.
const nodePortAddressesUsage = "the addresses NodePort listeners bind, as a comma-separated IPv4 CIDR list (the kube-proxy --nodeport-addresses shape) and/or the preset \"local\" (127.0.0.1 plus this node's own address: its mesh address when joined). Empty, the default, binds every interface. It applies while LAN access is on; with LAN access off (k3sm network lan off) NodePorts bind \"local\" whatever this says. Resolved against this Mac's addresses when the daemon starts and again at every LAN access change"

// nodePortHostAddrs is the host-address seam the resolution reads
// (proxy.HostAddrs). A package var so a test can name the host's addresses.
var nodePortHostAddrs = proxy.HostAddrs

// validatedLBPorts is the parsed --lb-privileged-ports of a daemon whose
// entry check already refused a bad value (`k3sm server` and `k3sm agent`
// both parse it before anything starts), so a failure cannot reach here; it
// would yield no brokered port, the narrower posture.
func validatedLBPorts(value string) []uint16 {
	ports, err := dataroot.ParseLBPrivilegedPorts(value)
	if err != nil {
		return nil
	}
	return ports
}

// ingressListenerPorts are the ingress host's enabled listener ports.
func ingressListenerPorts(httpPort, httpsPort int) []int32 {
	var out []int32
	for _, p := range []int{httpPort, httpsPort} {
		if p > 0 && p < 65536 {
			out = append(out, int32(p))
		}
	}
	return out
}

// lbPrivilegedPortsUsage is the --lb-privileged-ports help, shared by `k3sm
// server` and `k3sm agent`.
const lbPrivilegedPortsUsage = "LoadBalancer ports below 1024 (comma-separated, 1-1023) served through the root network helper on this node's own address and 127.0.0.1 while LAN access is off; any other LoadBalancer port below 1024 is not served on this node then. Recorded with the install arguments and handed to the helper by the installer; empty allows none"

// resolveNodePortAddresses resolves a --nodeport-addresses spec for this node,
// at datapath start and at every LAN access change (lanSwitch.resolve),
// against this Mac's addresses (hostAddrs, normally nodePortHostAddrs) and
// node (the address the node advertises, which the preset names). An empty
// spec is the wildcard (nil). An unusable spec, or one that selects nothing,
// is an error, so the node refuses rather than serving NodePorts nowhere.
func resolveNodePortAddresses(spec string, node netip.Addr, hostAddrs func() ([]netip.Addr, error)) ([]netip.Addr, error) {
	if strings.TrimSpace(spec) == "" {
		return nil, nil
	}
	host, err := hostAddrs()
	if err != nil {
		return nil, fmt.Errorf("--%s: %w", nodePortAddressesFlag, err)
	}
	addrs, err := proxy.ResolveNodePortAddresses(spec, node, host)
	if err != nil {
		return nil, fmt.Errorf("--%s: %w", nodePortAddressesFlag, err)
	}
	return addrs, nil
}

// checkNodePortAddresses is the `k3sm server` and `k3sm agent` entry check:
// it normalises *spec in place (trimmed, so whitespace-only is unset), checks
// its syntax, and refuses a non-empty value beside --network none
// (install.ErrNodePortAddressesWithoutDatapath), where no Service proxy runs
// and the setting would be silently ignored.
func checkNodePortAddresses(spec *string, network string) error {
	*spec = strings.TrimSpace(*spec)
	if err := validateNodePortAddresses(*spec); err != nil {
		return err
	}
	return install.CheckNodePortPosture(network, *spec)
}

// validateNodePortAddresses checks a --nodeport-addresses spec's syntax at flag
// parse, before anything starts or is recorded.
func validateNodePortAddresses(spec string) error {
	if err := proxy.ValidateNodePortAddresses(spec); err != nil {
		return fmt.Errorf("--%s: %w", nodePortAddressesFlag, err)
	}
	return nil
}

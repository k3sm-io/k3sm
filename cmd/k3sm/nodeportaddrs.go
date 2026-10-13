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

	"k3sm.io/k3sm/pkg/install"
)

// nodePortAddressesFlag is the k3s-style flag (`--nodeport-addresses`, kube-proxy's
// name) shared by `k3sm server`, `k3sm agent` and `k3sm install`.
const nodePortAddressesFlag = "nodeport-addresses"

// nodePortAddressesUsage is that flag's help text, one string for all three commands.
const nodePortAddressesUsage = "the addresses NodePort listeners bind, as a comma-separated IPv4 CIDR list (the kube-proxy --nodeport-addresses shape) and/or the preset \"local\" (127.0.0.1 plus this node's own address: its mesh address when joined). Empty, the default, binds every interface. Resolved against this Mac's addresses when the daemon starts and fixed until it restarts. On an untrusted network use \"local\""

// nodePortHostAddrs is the host-address seam the resolution reads
// (proxy.HostAddrs). A package var so a test can name the host's addresses.
var nodePortHostAddrs = proxy.HostAddrs

// resolveNodePortAddresses resolves a --nodeport-addresses spec for this node
// once, at datapath start, against this Mac's addresses and nodeAddress (the
// address the node advertises, which the preset names). An empty spec is the
// wildcard (nil). An unusable spec, or one that selects nothing, is an error,
// so the node refuses to start rather than serving NodePorts nowhere.
func resolveNodePortAddresses(spec, nodeAddress string) ([]netip.Addr, error) {
	if strings.TrimSpace(spec) == "" {
		return nil, nil
	}
	host, err := nodePortHostAddrs()
	if err != nil {
		return nil, fmt.Errorf("--%s: %w", nodePortAddressesFlag, err)
	}
	node, _ := netip.ParseAddr(nodeAddress) // an unparseable address leaves the preset loopback-only
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

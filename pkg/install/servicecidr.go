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

package install

import (
	"fmt"
	"net/netip"

	"k3sm.io/darwin-net/pkg/podnet"
)

// ServiceCIDRFlag is the install flag that names the cluster Service range.
const ServiceCIDRFlag = "service-cidr"

// ValidateServiceCIDR refuses a --service-cidr other than DefaultServiceCIDR.
// The flag reaches only netd's plist, while the apiserver's
// --service-cluster-ip-range, the cluster DNS VIP, the API VIP and the serving
// SANs are all fixed to that one range; any other value would leave netd
// admitting one range and the apiserver allocating ClusterIPs from another.
// An empty value is the default.
func ValidateServiceCIDR(cidr string) error {
	if cidr == "" || cidr == DefaultServiceCIDR {
		return nil
	}
	return fmt.Errorf("--%s %s is not supported: the cluster Service range is fixed at %s, which the apiserver, the cluster DNS address and the serving certificates all use; omit --%s", ServiceCIDRFlag, cidr, DefaultServiceCIDR, ServiceCIDRFlag)
}

// minServiceRangeBits is the shortest IPv4 Service range prefix kube-apiserver
// accepts for --service-cluster-ip-range: its flag validation
// (cmd/kube-apiserver/app/options/validation.go, maxCIDRBits = 20) refuses a
// range with more than 20 host bits, so an IPv4 range is at most a /12.
const minServiceRangeBits = 32 - 20

// serviceRangeNeverOverlaps are the ranges a Service range may not touch: the
// host's loopback, link-local and multicast space, and the cluster pod
// aggregate. A lo0 sweep over any of them removes addresses that are not a
// Service range's.
var serviceRangeNeverOverlaps = []netip.Prefix{
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("224.0.0.0/4"),
	podnet.ClusterPodCIDR,
}

// recordedServiceRangeSafe parses a Service range k3sm reads back rather than
// takes as input (the --service-cidr of an installed netd plist, or the
// uninstall configuration's) and refuses one no working Service range could
// have, before it bounds the root lo0 alias sweep. It is NOT ValidateServiceCIDR:
// that is the install-input rule and admits only DefaultServiceCIDR, while an
// earlier release took any --service-cidr and netd only ever parsed it (the
// `k3sm netd` command's netip.ParsePrefix), so a non-default range an older
// install recorded is legitimate here and must still be flushed. This is a
// safety bound: IPv4 only, no wider than minServiceRangeBits, and clear of
// serviceRangeNeverOverlaps. It returns the masked range.
func recordedServiceRangeSafe(cidr string) (netip.Prefix, error) {
	p, err := netip.ParsePrefix(cidr)
	if err != nil {
		return netip.Prefix{}, err
	}
	p = p.Masked()
	if !p.Addr().Is4() {
		return netip.Prefix{}, fmt.Errorf("the Service range %s is not IPv4", p)
	}
	if p.Bits() < minServiceRangeBits {
		return netip.Prefix{}, fmt.Errorf("the Service range %s is wider than a /%d, the largest kube-apiserver accepts", p, minServiceRangeBits)
	}
	for _, n := range serviceRangeNeverOverlaps {
		if p.Overlaps(n) {
			return netip.Prefix{}, fmt.Errorf("the Service range %s overlaps %s", p, n)
		}
	}
	return p, nil
}

// validateShape is the install request judged from the Config alone, before
// anything is written: the fixed Service range, then the HA request's shape.
func validateShape(cfg Config) error {
	if err := ValidateServiceCIDR(cfg.ServiceCIDR); err != nil {
		return err
	}
	return ValidateHARequest(cfg)
}

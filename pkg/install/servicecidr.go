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

import "fmt"

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

// validateShape is the install request judged from the Config alone, before
// anything is written: the fixed Service range, then the HA request's shape.
func validateShape(cfg Config) error {
	if err := ValidateServiceCIDR(cfg.ServiceCIDR); err != nil {
		return err
	}
	return ValidateHARequest(cfg)
}

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

package executor

import (
	"testing"

	"k3sm.io/k3sm/pkg/defaults"
)

// TestAPIServerServiceRangeIsTheDefault pins the apiserver half of the one
// cluster Service range: --service-cluster-ip-range is defaults.ServiceCIDR,
// the only --service-cidr pkg/install accepts and renders into netd's plist.
func TestAPIServerServiceRangeIsTheDefault(t *testing.T) {
	cfg := Config{WorkDir: "/var/lib/k3sm/server", KinePort: 2379, APIServerPort: 6444, NodeIP: "127.0.0.1"}
	if got := flagValue(apiServerArgs(cfg), "--service-cluster-ip-range"); got != defaults.ServiceCIDR {
		t.Errorf("--service-cluster-ip-range = %q, want defaults.ServiceCIDR %q", got, defaults.ServiceCIDR)
	}
}

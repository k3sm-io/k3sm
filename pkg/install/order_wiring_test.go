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
	"slices"
	"testing"

	"k3sm.io/k3sm/pkg/install/order"
)

// TestManifestDaemonOrderIsOrderStart pins that the installer starts and stops
// its jobs in pkg/install/order's sequence, the one the updater imports: the
// manifest's daemon entries, in manifest order, are order.Start, and the stop
// walk (long-running daemons in reverse) is order.Stop.
func TestManifestDaemonOrderIsOrderStart(t *testing.T) {
	for _, tc := range []struct {
		name       string
		role       Role
		dataVolume bool
	}{
		{"server", RoleServer, false},
		{"agent", RoleAgent, false},
		{"server with data volume", RoleServer, true},
		{"agent with data volume", RoleAgent, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := testConfig(t)
			cfg.Role = tc.role
			cfg = cfg.withDefaults()
			cfg.dataVolumeDeclared = tc.dataVolume
			m := artifactManifest(cfg)

			var got []order.Job
			for _, a := range m {
				if a.kind == kindDaemon {
					got = append(got, order.Job{Label: a.label, Oneshot: a.oneshot})
				}
			}
			if want := order.Start(orderRole(tc.role), tc.dataVolume); !slices.Equal(got, want) {
				t.Errorf("manifest daemon order = %v, want order.Start = %v", got, want)
			}

			var stop []string
			for i := len(m) - 1; i >= 0; i-- {
				if m[i].kind == kindDaemon && !m[i].oneshot {
					stop = append(stop, m[i].label)
				}
			}
			var want []string
			for _, j := range order.Stop(orderRole(tc.role)) {
				want = append(want, j.Label)
			}
			if !slices.Equal(stop, want) {
				t.Errorf("manifest stop order = %v, want order.Stop = %v", stop, want)
			}
		})
	}
}

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

import "testing"

// TestServerPortFlagsReachTheExecutor pins the LAST link of the chain that keeps
// breaking in the same place: a port is allocated, recorded in a manifest, spelled
// on an argv — and then dropped on the floor between the parsed flag and the
// Config the control plane is actually built from. A dropped port does not fail;
// it silently becomes the default, so the second control plane on the host loses
// exactly the bind the allocation existed to give it.
//
// Every port a `k3sm server` can renumber is asserted, with a DISTINCT value per
// field, so a field wired to the neighbouring option is a wrong number rather than
// a coincidence that passes.
func TestServerPortFlagsReachTheExecutor(t *testing.T) {
	opts := serverOptions{
		workDir:               "/tmp/k3sm-test",
		apiPort:               16441,
		kinePort:              12380,
		schedulerPort:         11451,
		controllerManagerPort: 13451,
	}
	cfg := opts.executorConfig(nil)
	for _, tc := range []struct {
		field string
		got   int
		want  int
	}{
		{"APIServerPort", cfg.APIServerPort, opts.apiPort},
		{"KinePort", cfg.KinePort, opts.kinePort},
		{"SchedulerPort", cfg.SchedulerPort, opts.schedulerPort},
		{"ControllerManagerPort", cfg.ControllerManagerPort, opts.controllerManagerPort},
	} {
		if tc.got != tc.want {
			t.Errorf("executorConfig().%s = %d, want the flag's %d", tc.field, tc.got, tc.want)
		}
	}
}

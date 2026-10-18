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
	"testing"
)

// TestNodePodRangeWiring pins which value a node publishes as spec.podCIDR: its
// podnet range (opts.podCIDR) cross-checked against its mesh address, and
// nothing when it allocates no pod addresses.
func TestNodePodRangeWiring(t *testing.T) {
	for _, tc := range []struct {
		name      string
		opts      nodeOptions
		allocates bool
		want      string
	}{
		{"worker with its enrolled mesh address", nodeOptions{podCIDR: "100.64.1.0/24", meshIP: "100.64.1.1"}, true, "100.64.1.0/24"},
		{"single node derives the range's .1", nodeOptions{podCIDR: defaultNodePodCIDR()}, true, defaultNodePodCIDR()},
		{"mesh address outside the range", nodeOptions{podCIDR: "100.64.1.0/24", meshIP: "100.64.2.1"}, true, ""},
		{"no pod network", nodeOptions{podCIDR: "100.64.1.0/24", meshIP: "100.64.1.1"}, false, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := nodePodRange(tc.opts, tc.allocates, nil).Prefix()
			got := ""
			if p.IsValid() {
				got = p.String()
			}
			if got != tc.want {
				t.Fatalf("published range = %q, want %q", got, tc.want)
			}
		})
	}
}

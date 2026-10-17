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

package ports

import "testing"

// TestReservedSetMatchesPredicate pins that the materialized set and the
// predicate agree on every boundary: they are two consumers' shapes of ONE
// policy, and a set built from different bounds than Reserved() checks would let
// admission and the svclb refusal disagree about the same port.
func TestReservedSetMatchesPredicate(t *testing.T) {
	set := ReservedSet()
	for _, p := range []int{0, 21, 22, 23, 53, 80, 88, 443, 445, 548, 631, 1023, 1024, 8080, 10249, 10250, 10251, 29999, 30000, 30500, 32767, 32768, 65535} {
		if got, want := set[int32(p)], Reserved(p); got != want {
			t.Errorf("ReservedSet()[%d] = %v, Reserved(%d) = %v — the set and the predicate must agree", p, got, p, want)
		}
	}
}

// TestReservedBoundaries pins the inclusive bounds and the kubelet port; an
// off-by-one here silently un-guards 30000 or 32767, the two ports a NodePort
// allocation is most likely to hand out first and last.
func TestReservedBoundaries(t *testing.T) {
	tests := []struct {
		port int
		want bool
	}{
		{29999, false},
		{30000, true},
		{32767, true},
		{32768, false},
		{10250, true},
		{10249, false},
		{80, false},
		{443, false},
		{22, true},
		{53, true},
		{88, true},
		{445, true},
		{548, true},
		{631, true},
		{21, false},
		{632, false},
	}
	for _, tt := range tests {
		if got := Reserved(tt.port); got != tt.want {
			t.Errorf("Reserved(%d) = %v, want %v", tt.port, got, tt.want)
		}
	}
}

// TestNodePortRangeRendersTheBounds pins the argv rendering against the same
// constants, so `--service-node-port-range` cannot drift from the reserved set.
func TestNodePortRangeRendersTheBounds(t *testing.T) {
	if got, want := NodePortRange(), "30000-32767"; got != want {
		t.Errorf("NodePortRange() = %q, want %q", got, want)
	}
}

// TestHostServicePortsIsACopy pins that a caller cannot edit the reserved set
// through the slice it was handed.
func TestHostServicePortsIsACopy(t *testing.T) {
	got := HostServicePorts()
	if len(got) != 6 || got[0] != 22 || got[5] != 631 {
		t.Fatalf("HostServicePorts() = %v, want [22 53 88 445 548 631]", got)
	}
	got[0] = 2222
	if !Reserved(22) || Reserved(2222) {
		t.Error("editing the returned slice changed the reserved set")
	}
}

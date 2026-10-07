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

package mlx

import "testing"

// TestProbeTransportDialsThroughTheSegmentClamp pins that the probe transport
// carries its own dialer: a nil DialContext would fall back to the net package
// default and skip the TCP segment clamp on a connection to a pod address.
func TestProbeTransportDialsThroughTheSegmentClamp(t *testing.T) {
	tr := NewProbeTransport()
	if tr.DialContext == nil {
		t.Fatal("probe transport has no DialContext: its connections would bypass the segment clamp")
	}
	if !tr.DisableKeepAlives {
		t.Fatal("probe transport must not pool connections")
	}
}

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

package provider

import "testing"

// TestProviderAdoptsTheNodeSpacer pins that a provider handed the node's
// EventSpacer records through that very instance, not a second spacer of its own.
func TestProviderAdoptsTheNodeSpacer(t *testing.T) {
	spacer := NewEventSpacer(nopRecorder{})
	if got := newEventSpacer(spacer); got != spacer {
		t.Fatalf("newEventSpacer wrapped the node's spacer again: got %T %p, want %p", got, got, spacer)
	}
	if hp := NewHostProcess("n", t.TempDir(), "192.0.2.1", spacer); hp.recorder != spacer {
		t.Fatalf("HostProcess recorder is %T, want the node's spacer", hp.recorder)
	}
}

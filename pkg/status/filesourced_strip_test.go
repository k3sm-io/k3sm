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

package status

import (
	"strings"
	"testing"
)

// TestFileSourcedLineValuesAreStripped pins that the stop marker's actor and
// reason and the applied report's LAN and error print without terminal
// control or bidi characters, keeping the printable text.
func TestFileSourcedLineValuesAreStripped(t *testing.T) {
	const dirty = "a\u001b]0;pwn\u0007b‮c d"
	const clean = "a]0;pwnbcd"
	tests := []struct {
		name string
		line func(v string) string
	}{
		{"stoppedBy actor", func(v string) string {
			return stoppedByLine(Report{StoppedBy: &StoppedBy{Actor: v, Phase: "stopped"}})
		}},
		{"stoppedBy reason", func(v string) string {
			return stoppedByLine(Report{StoppedBy: &StoppedBy{Actor: "user", Reason: v, Phase: "stopped"}})
		}},
		{"applied LAN", func(v string) string {
			return networkLine(Report{Network: &Network{LAN: "on", Recorded: true, Applied: &NetworkApplied{LAN: v}}})
		}},
		{"applied error", func(v string) string {
			return networkLine(Report{Network: &Network{LAN: "on", Recorded: true, Applied: &NetworkApplied{LAN: "on", Error: v}}})
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.line(dirty)
			for _, bad := range []string{"\u001b", "\u0007", "‮", " "} {
				if strings.Contains(got, bad) {
					t.Errorf("line %q carries %U", got, []rune(bad)[0])
				}
			}
			if !strings.Contains(got, clean) {
				t.Errorf("line %q lost the printable text %q", got, clean)
			}
		})
	}
}

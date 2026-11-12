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
	"strings"
	"testing"
)

// TestRemediesQuoteTheirPaths pins that a remedy printing a removal command
// pastes back as ONE argument after `--`: a path with a space would split into
// two operands, and one with a leading dash would be read as an option.
func TestRemediesQuoteTheirPaths(t *testing.T) {
	const path = "-k3sm data/it's here"
	want := "-- " + shellQuote(path)
	cases := []struct {
		name   string
		remedy func(t *testing.T) string
	}{
		{"stuck developer-mode marker", func(t *testing.T) string {
			return stuckMarkerRemedy(path)
		}},
		{"unreadable agent arguments record", func(t *testing.T) string {
			f := newFakeSystem(t)
			f.putFile(path, []byte("not json"))
			_, err := recordedAgentArgs(f, Config{AgentArgsRecord: path})
			if err == nil {
				t.Fatal("recordedAgentArgs read an unparseable record")
			}
			return err.Error()
		}},
		{"unreadable server arguments record", func(t *testing.T) string {
			f := newFakeSystem(t)
			f.putFile(path, []byte("not json"))
			_, err := recordedServerArgs(f, Config{ServerArgsRecord: path})
			if err == nil {
				t.Fatal("recordedServerArgs read an unparseable record")
			}
			return err.Error()
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.remedy(t)
			if !strings.Contains(got, "sudo rm "+want) {
				t.Errorf("remedy %q does not carry %q", got, "sudo rm "+want)
			}
		})
	}
}

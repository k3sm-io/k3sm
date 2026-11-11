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

// TestMatchArgPrefix pins the argparse-style option matching every
// spec.runtime.args refusal uses.
func TestMatchArgPrefix(t *testing.T) {
	flags := []string{"--draft-model", "--draft-tokens", "--adapter-path"}
	cases := []struct {
		name      string
		arg       string
		flags     []string
		wantFlag  string
		wantMatch bool
	}{
		{"exact_match_wins", "--draft", []string{"--draft", "--draft-model"}, "--draft", true},
		{"unambiguous_abbreviation", "--adap", flags, "--adapter-path", true},
		{"shared_abbreviation_matches_neither", "--draft-", flags, "", false},
		{"bare_double_dash", "--", flags, "", false},
		{"non_flag", "draft-model", flags, "", false},
		{"other_option_sharing_letters", "--draft-modelx", flags, "", false},
		// Known limit: the package cannot know the engine's own flags, so a
		// real engine option that is a proper prefix of a checked flag (for
		// example --draft against --draft-model) is matched and refused. It
		// over-refuses on purpose rather than let an abbreviation through.
		{"known_limit_proper_prefix_of_checked_flag", "--draft", []string{"--draft-model"}, "--draft-model", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := MatchArgPrefix(tc.arg, tc.flags)
			if ok != tc.wantMatch || (ok && got != tc.wantFlag) {
				t.Errorf("MatchArgPrefix(%q) = (%q, %v), want (%q, %v)", tc.arg, got, ok, tc.wantFlag, tc.wantMatch)
			}
		})
	}
}

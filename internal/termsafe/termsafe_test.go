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

package termsafe

import (
	"strings"
	"testing"
)

// TestStrip pins what Strip removes (the controls and the invisible or
// line-breaking format runes a terminal could act on) and what it keeps
// (every printable rune, including U+FFFD and the no-break space).
func TestStrip(t *testing.T) {
	for _, tc := range []struct {
		name, in, want string
	}{
		{"ESC", "a\x1bb", "ab"},
		{"BEL", "a\x07b", "ab"},
		{"CR", "a\rb", "ab"},
		{"LF", "a\nb", "ab"},
		{"TAB", "a\tb", "ab"},
		{"DEL", "a\x7fb", "ab"},
		{"C1 CSI", "a\u009bb", "ab"},
		{"zero-width space", "a​b", "ab"},
		{"right-to-left override", "a‮b", "ab"},
		{"left-to-right isolate", "a⁦b", "ab"},
		{"soft hyphen", "a­b", "ab"},
		{"line separator", "a b", "ab"},
		{"paragraph separator", "a b", "ab"},
		{"ASCII", "kine: exit status 1", "kine: exit status 1"},
		{"Latin-1 letter", "é", "é"},
		{"CJK", "漢", "漢"},
		{"emoji", "🚀", "🚀"},
		{"replacement character", "�", "�"},
		{"no-break space", "a b", "a b"},
		{"escape sequence", "\x1b]0;owned\x07\x1b[2J", "]0;owned[2J"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := Strip(tc.in); got != tc.want {
				t.Errorf("Strip(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// TestComponent pins that a valid component name is returned as it is and
// that anything else is the fixed word "unknown".
func TestComponent(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"kine", "kine"},
		{"kube-apiserver", "kube-apiserver"},
		{"etcd-member-route", "etcd-member-route"},
		{"", "unknown"},
		{"Kine", "unknown"},
		{"kine\x1b[2J", "unknown"},
		{"FAKE: install succeeded", "unknown"},
		{"kine‮", "unknown"},
		{strings.Repeat("a", 65), "unknown"},
	} {
		if got := Component(tc.in); got != tc.want {
			t.Errorf("Component(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

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
	"math/rand"
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"
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
		{"zero-width space", "a\u200bb", "ab"},
		{"right-to-left override", "a\u202eb", "ab"},
		{"left-to-right isolate", "a\u2066b", "ab"},
		{"soft hyphen", "a\u00adb", "ab"},
		{"line separator", "a\u2028b", "ab"},
		{"paragraph separator", "a\u2029b", "ab"},
		{"ASCII", "kine: exit status 1", "kine: exit status 1"},
		{"Latin-1 letter", "é", "é"},
		{"CJK", "漢", "漢"},
		{"emoji", "🚀", "🚀"},
		{"replacement character", "�", "�"},
		{"no-break space", "a\u00a0b", "a\u00a0b"},
		{"escape sequence", "\x1b]0;owned\x07\x1b[2J", "]0;owned[2J"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := Strip(tc.in); got != tc.want {
				t.Errorf("Strip(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// TestStripRemovesEveryControlAndFormatRune sweeps every valid rune through
// Strip: each control, format, line-separator or paragraph-separator rune is
// removed and every other rune is kept.
func TestStripRemovesEveryControlAndFormatRune(t *testing.T) {
	doomed := func(r rune) bool {
		return unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || r == 0x2028 || r == 0x2029
	}
	var all strings.Builder
	for r := rune(0); r <= unicode.MaxRune; r++ {
		if r >= 0xD800 && r <= 0xDFFF {
			continue
		}
		got := Strip("a" + string(r) + "b")
		want := "a" + string(r) + "b"
		if doomed(r) {
			want = "ab"
		}
		if got != want {
			t.Errorf("Strip with U+%04X = %q, want %q", r, got, want)
		}
		all.WriteString(got)
	}
	for _, r := range all.String() {
		if doomed(r) {
			t.Errorf("U+%04X survived Strip", r)
		}
	}
}

// TestStripInvalidBytes feeds raw bytes that are not valid UTF-8. Each invalid
// byte becomes one U+FFFD (strings.Map decodes it as RuneError of width 1, and
// U+FFFD is neither a control nor a format rune); a valid ESC is still dropped.
func TestStripInvalidBytes(t *testing.T) {
	for _, tc := range []struct {
		name, in, want string
	}{
		{"bare C1 CSI byte", "a\x9bb", "a\ufffdb"},
		{"ESC CSI as bytes", "a\x1b[2Jb", "a[2Jb"},
		{"0xff byte", "a\xffb", "a\ufffdb"},
		{"truncated two-byte sequence", "a\xc2", "a\ufffd"},
		{"truncated three-byte sequence", "\xe2\x80", "\ufffd\ufffd"},
		{"encoded surrogate", "a\xed\xa0\x80b", "a\ufffd\ufffd\ufffdb"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := Strip(tc.in); got != tc.want {
				t.Errorf("Strip(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// TestStripRandomBytesAgainstTypedRanges feeds 3000 fixed-seed random byte
// strings (length 0-64) to Strip and checks the output against a range list
// typed out here, independent of unicode.IsControl and unicode.Cf.
func TestStripRandomBytesAgainstTypedRanges(t *testing.T) {
	ranges := [][2]rune{
		{0x0000, 0x001F}, {0x007F, 0x009F}, {0x00AD, 0x00AD}, {0x061C, 0x061C},
		{0x200B, 0x200F}, {0x202A, 0x202E}, {0x2028, 0x2029}, {0x2060, 0x2064},
		{0x2066, 0x206F}, {0xFEFF, 0xFEFF}, {0xFFF9, 0xFFFB},
	}
	banned := func(r rune) bool {
		for _, rg := range ranges {
			if r >= rg[0] && r <= rg[1] {
				return true
			}
		}
		return false
	}
	// Bias bytes toward the ones that matter so multi-byte banned runes
	// (U+00AD, U+200B, U+202E, U+FEFF) and C0/C1 bytes appear often.
	interesting := []byte{0x00, 0x07, 0x1b, 0x7f, 0x9b, 0xc2, 0xad, 0xe2, 0x80, 0x8b, 0xae, 0xa8, 0xef, 0xbb, 0xbf, 0xed, 0xff, 'a'}
	rng := rand.New(rand.NewSource(1713))
	for i := 0; i < 3000; i++ {
		in := make([]byte, rng.Intn(65))
		for j := range in {
			if rng.Intn(2) == 0 {
				in[j] = interesting[rng.Intn(len(interesting))]
			} else {
				in[j] = byte(rng.Intn(256))
			}
		}
		out := Strip(string(in))
		if !utf8.ValidString(out) {
			t.Fatalf("Strip(%q) = %q is not valid UTF-8", in, out)
		}
		for j := 0; j < len(out); j++ {
			if out[j] < 0x20 || out[j] == 0x7f {
				t.Fatalf("Strip(%q) = %q holds byte 0x%02x", in, out, out[j])
			}
		}
		for _, r := range out {
			if banned(r) {
				t.Fatalf("Strip(%q) = %q holds U+%04X", in, out, r)
			}
		}
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
		{"kine\u202e", "unknown"},
		{strings.Repeat("a", 65), "unknown"},
	} {
		if got := Component(tc.in); got != tc.want {
			t.Errorf("Component(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

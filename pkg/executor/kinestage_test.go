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

package executor

import (
	"os"
	"strings"
	"testing"
)

// TestKineStagedPredicate is the version-marker staging contract. The predicate it
// replaces was `os.Stat(kine) == nil` — presence — which cannot distinguish a correctly
// staged binary from one an EARLIER release built. Every node that has booted once has
// a kine binary, so under the old predicate a pin change reached fresh installs ONLY
// and silently never reached the installed base. Each case below is a way that could
// happen again.
func TestKineStagedPredicate(t *testing.T) {
	cases := []struct {
		name    string
		binary  bool
		marker  string // "" = write no marker at all; "\x00" = write an EMPTY marker file
		want    bool
		because string
	}{
		{"binary + matching marker", true, DefaultKineVersion + " " + kineBuildVariant, true,
			"the only state that may skip a re-stage"},
		{"binary, no marker", true, "", false,
			"every pre-marker node looks exactly like this — it MUST re-stage"},
		{"binary + older version", true, "v1.14.2 " + kineBuildVariant, false,
			"the pin moved; the staged bytes are the old pin's"},
		{"binary + same version, wrong variant", true, DefaultKineVersion + " cgo", false,
			"one tag builds two different SQLite implementations; version alone is not identity"},
		{"binary + truncated marker", true, DefaultKineVersion, false,
			"a marker without a variant vouches for nothing"},
		{"binary + empty marker file", true, "\x00", false, "an empty marker is not a marker"},
		{"marker but no binary", false, DefaultKineVersion + " " + kineBuildVariant, false,
			"a marker cannot vouch for a binary that is not there"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			bd := t.TempDir()
			if tc.binary {
				if err := os.WriteFile(kinePath(bd), []byte("kine"), 0o755); err != nil {
					t.Fatal(err)
				}
			}
			switch tc.marker {
			case "":
				// no marker file at all
			case "\x00":
				if err := os.WriteFile(kineMarkerPath(bd), nil, 0o644); err != nil {
					t.Fatal(err)
				}
			default:
				if err := os.WriteFile(kineMarkerPath(bd), []byte(tc.marker+"\n"), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			if got := kineStaged(bd, DefaultKineVersion); got != tc.want {
				t.Errorf("kineStaged = %v, want %v — %s", got, tc.want, tc.because)
			}
		})
	}
}

// TestKineMarkerRoundTrip proves the marker records the build VARIANT alongside the
// version, and that the shipped variant is the pure-Go one. "nocgo" is the whole point
// of the collapse: it is what keeps the unmaintained mattn/go-sqlite3 (and a C
// toolchain) out of every k3sm artifact.
func TestKineMarkerRoundTrip(t *testing.T) {
	bd := t.TempDir()
	if err := writeKineMarker(bd, DefaultKineVersion); err != nil {
		t.Fatal(err)
	}
	v, variant := readKineMarker(bd)
	if v != DefaultKineVersion || variant != kineBuildVariant {
		t.Errorf("readKineMarker = (%q,%q), want (%q,%q)", v, variant, DefaultKineVersion, kineBuildVariant)
	}
	if kineBuildVariant != "nocgo" {
		t.Errorf("kineBuildVariant = %q, want \"nocgo\" (the pure-Go modernc.org/sqlite backend)", kineBuildVariant)
	}
	if _, err := os.Stat(kineMarkerPath(bd) + ".tmp"); !os.IsNotExist(err) {
		t.Error("the atomic marker write left its .tmp behind")
	}
}

// TestEnsureKineIntoSkipsOnMatchingMarker proves the fast path does not rebuild — a
// matching marker means the staged binary is left exactly as it is. It is the half of
// the predicate the staleness tests cannot cover: without it, every boot would shell
// out to a Go toolchain a launchd daemon does not have.
func TestEnsureKineIntoSkipsOnMatchingMarker(t *testing.T) {
	bd := t.TempDir()
	if err := os.WriteFile(kinePath(bd), []byte("pretend-kine"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := writeKineMarker(bd, DefaultKineVersion); err != nil {
		t.Fatal(err)
	}
	if err := ensureKineInto(t.Context(), bd, DefaultKineVersion); err != nil {
		t.Fatalf("ensureKineInto on an up-to-date staging = %v, want nil", err)
	}
	got, err := os.ReadFile(kinePath(bd))
	if err != nil || string(got) != "pretend-kine" {
		t.Errorf("staged kine was replaced: %v %q", err, got)
	}
}

// TestEnsureKineBuildsWithoutCGO pins the build environment itself. The gate greps the
// source for CGO_ENABLED=0, which proves the literal is present; this proves it is the
// value the build command actually carries, and that no CGO_ENABLED=1 survives beside
// it. A cgo kine would silently re-introduce mattn/go-sqlite3 into the shipped payload.
func TestEnsureKineBuildsWithoutCGO(t *testing.T) {
	src, err := os.ReadFile("setup.go")
	if err != nil {
		t.Fatal(err)
	}
	fn := string(src)
	start := strings.Index(fn, "func ensureKineInto(")
	if start < 0 {
		t.Fatal("ensureKineInto not found in setup.go")
	}
	body := fn[start:]
	if end := strings.Index(body, "\n// copyFile"); end > 0 {
		body = body[:end]
	}
	if !strings.Contains(body, `"CGO_ENABLED=0"`) {
		t.Error("ensureKineInto does not build kine with CGO_ENABLED=0")
	}
	if strings.Contains(body, `"CGO_ENABLED=1"`) {
		t.Error("ensureKineInto still carries a CGO_ENABLED=1 build env")
	}
}

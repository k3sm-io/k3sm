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
	"os"
	"path/filepath"
	"testing"
)

// TestColorEnabled is the decoration table. Every axis has to be able to turn
// colour OFF on its own: a piped stream, an explicit flag, the NO_COLOR
// convention, and a terminal that cannot render escapes.
func TestColorEnabled(t *testing.T) {
	t.Parallel()

	env := func(pairs map[string]string) func(string) string {
		return func(k string) string { return pairs[k] }
	}

	// A regular file is the stand-in for "not a terminal" — the same verdict a
	// pipe or a $(…) capture gets, and the one a unit test can create.
	notTTY, err := os.Create(filepath.Join(t.TempDir(), "out"))
	if err != nil {
		t.Fatalf("create temp stream: %v", err)
	}
	t.Cleanup(func() { _ = notTTY.Close() })

	// /dev/null is a character device, so IsTerminal says yes — which is exactly
	// what makes it usable as the "a human is watching" stand-in here.
	tty, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		t.Fatalf("open %s: %v", os.DevNull, err)
	}
	t.Cleanup(func() { _ = tty.Close() })

	if !IsTerminal(tty) {
		t.Fatalf("%s is not reported as a character device; the TTY cases below would be vacuous", os.DevNull)
	}
	if IsTerminal(notTTY) {
		t.Fatal("a regular file is reported as a terminal")
	}
	if IsTerminal(nil) {
		t.Fatal("a nil stream is reported as a terminal")
	}

	tests := []struct {
		name    string
		f       *os.File
		noColor bool
		env     map[string]string
		want    bool
	}{
		{"terminal, nothing suppressing it", tty, false, map[string]string{"TERM": "xterm-256color"}, true},
		{"terminal with no TERM at all", tty, false, nil, true},
		{"--no-color wins over a terminal", tty, true, map[string]string{"TERM": "xterm-256color"}, false},
		{"NO_COLOR set to anything disables colour", tty, false, map[string]string{"TERM": "xterm-256color", "NO_COLOR": "1"}, false},
		{"NO_COLOR set to a word still disables colour", tty, false, map[string]string{"NO_COLOR": "yes"}, false},
		{"TERM=dumb disables colour", tty, false, map[string]string{"TERM": "dumb"}, false},
		{"a piped stream disables colour", notTTY, false, map[string]string{"TERM": "xterm-256color"}, false},
		{"a piped stream stays off even with everything else set", notTTY, false, nil, false},
		{"a nil stream is never coloured", nil, false, map[string]string{"TERM": "xterm-256color"}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := ColorEnabled(tc.f, tc.noColor, env(tc.env)); got != tc.want {
				t.Fatalf("ColorEnabled = %v, want %v", got, tc.want)
			}
		})
	}
}

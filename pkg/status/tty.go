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
	"strings"
)

// IsTerminal reports whether f is a character device — the test every CLI uses
// to decide whether a human is reading. A pipe, a file, and a $(…) capture are
// all not terminals, which is exactly when decoration must be off.
func IsTerminal(f *os.File) bool {
	if f == nil {
		return false
	}
	fi, err := f.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}

// ColorEnabled decides whether to emit ANSI colour and glyphs. All four
// conditions must hold: a real terminal, no --no-color, no NO_COLOR in the
// environment (the https://no-color.org convention — its PRESENCE disables
// colour, whatever its value), and a TERM that is not "dumb".
//
// env is injected rather than read from os.Getenv so the decision is a pure
// table test; f is the actual stream being written to, because the answer for
// stdout and the answer for stderr are genuinely different when one is piped.
func ColorEnabled(f *os.File, noColorFlag bool, env func(string) string) bool {
	if noColorFlag || !IsTerminal(f) {
		return false
	}
	if env == nil {
		env = os.Getenv
	}
	if _, present := lookup(env, "NO_COLOR"); present {
		return false
	}
	term, _ := lookup(env, "TERM")
	return strings.TrimSpace(term) != "dumb"
}

// lookup reads a variable through the injected accessor and reports presence.
// An env func cannot distinguish unset from empty, so an empty NO_COLOR is
// treated as absent — matching the ordinary shell case where the variable was
// never exported.
func lookup(env func(string) string, key string) (string, bool) {
	v := env(key)
	return v, v != ""
}

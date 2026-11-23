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

package keystore

import (
	"errors"
	"os"
	"strings"
	"testing"
	"time"
)

// TestMain bans the real primitives behind the package's seams at unit tier:
// before any test runs, each seam is a stub that panics, naming the primitive
// (docs/design/keystore.md § "Package layout and seams"). A test injects the
// fake it needs with setSeam.
func TestMain(m *testing.M) {
	generatedUIDSeam = func(uint32) ([generationSize]byte, error) {
		panic("a unit test reached mbr_uid_to_uuid: inject a fake GeneratedUID lookup")
	}
	uidResolverSeam = func(string) (uint32, error) {
		panic("a unit test reached getpwnam: inject a fake uid resolver")
	}
	timerSeam = func(time.Duration) (<-chan time.Time, func() bool) {
		panic("a unit test reached the clock: inject a fake timer")
	}
	if os.Geteuid() != 0 {
		// rm-scope takes each scope directory for root; a non-root run
		// takes it for itself, and counts its own 0700 directories as an
		// earlier run's work.
		rmRootUID, rmRootGID = os.Geteuid(), os.Getegid()
	}
	os.Exit(m.Run())
}

// setSeam sets *p to v for the test and restores the previous value with
// t.Cleanup, so no fake outlives its test.
func setSeam[T any](t *testing.T, p *T, v T) {
	t.Helper()
	old := *p
	*p = v
	t.Cleanup(func() { *p = old })
}

// neverFires is a timer seam whose deadline never passes.
func neverFires(time.Duration) (<-chan time.Time, func() bool) {
	return make(chan time.Time), func() bool { return true }
}

// firesAt returns a timer seam whose deadline has already passed, recording
// the duration it was asked for.
func firesAt(asked *time.Duration) func(time.Duration) (<-chan time.Time, func() bool) {
	return func(d time.Duration) (<-chan time.Time, func() bool) {
		*asked = d
		c := make(chan time.Time, 1)
		c <- time.Unix(0, 0)
		return c, func() bool { return false }
	}
}

// fakeGUIDs answers each uid's GeneratedUID from table, within the deadline.
// The table is read on every lookup, so a test may change an answer.
func fakeGUIDs(t *testing.T, table map[uint32][generationSize]byte) {
	t.Helper()
	setSeam(t, &generatedUIDSeam, func(uid uint32) ([generationSize]byte, error) {
		g, ok := table[uid]
		if !ok {
			return [generationSize]byte{}, errors.New("no such user")
		}
		return g, nil
	})
	setSeam(t, &timerSeam, neverFires)
}

// guid returns a real-looking GeneratedUID, never the synthesized prefix.
func guid(b byte) [generationSize]byte {
	var g [generationSize]byte
	for i := range g {
		g[i] = b
	}
	g[0] = 0x10
	return g
}

// TestRealPrimitivesUnreachable proves TestMain's stubs are in place: each
// seam, called without a fake, panics naming its primitive.
func TestRealPrimitivesUnreachable(t *testing.T) {
	for _, tt := range []struct {
		primitive string
		call      func()
	}{
		{"mbr_uid_to_uuid", func() { _, _ = generatedUIDSeam(501) }},
		{"getpwnam", func() { _, _ = uidResolverSeam("alice") }},
		{"the clock", func() { _, _ = timerSeam(time.Second) }},
	} {
		t.Run(tt.primitive, func(t *testing.T) {
			defer func() {
				r := recover()
				if s, _ := r.(string); !strings.Contains(s, tt.primitive) {
					t.Fatalf("the seam for %s did not panic naming it: %v", tt.primitive, r)
				}
			}()
			tt.call()
		})
	}
}

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

package images

import (
	"errors"
	"fmt"
	"sort"
	"strings"
)

// ErrLockstep is the sentinel every constants-vs-manifest mismatch wraps.
var ErrLockstep = errors.New("image pin lockstep")

// Lockstep asserts a 1:1 correspondence between the pin constants and the manifest
// entries: every pin has an entry whose mirror reference is byte-identical to the
// constant, and every entry has a pin. Neither direction is optional.
//
// Dropping either direction would leave a real hole. Without pin -> entry, a constant
// could name a digest nothing ever recorded or mirrored. Without entry -> pin, a stale
// entry could sit in the manifest indefinitely, keeping an unused digest tagged and
// making a future reader believe the code consumes it.
//
// This is a pure comparison of two committed artifacts. It touches no registry and no
// network, which is what lets it ride "go test ./..." on every CI run.
func Lockstep(pins []Pin, m *Manifest) error {
	if m == nil {
		return fmt.Errorf("%w: nil manifest", ErrLockstep)
	}
	if len(pins) == 0 {
		return fmt.Errorf("%w: no pins declared — the check would be vacuous", ErrLockstep)
	}

	var problems []string
	pinned := make(map[string]bool, len(pins))
	for _, p := range pins {
		if p.Name == "" || p.Ref == "" {
			problems = append(problems, fmt.Sprintf("pin %+v has an empty name or ref", p))
			continue
		}
		if pinned[p.Name] {
			problems = append(problems, fmt.Sprintf("pin %q is declared twice", p.Name))
			continue
		}
		pinned[p.Name] = true

		e, ok := m.Entry(p.Name)
		if !ok {
			problems = append(problems, fmt.Sprintf(
				"constant %q = %s has NO manifest entry (manifest has: %s)",
				p.Name, p.Ref, strings.Join(m.Names(), ", ")))
			continue
		}
		if e.Mirror != p.Ref {
			problems = append(problems, fmt.Sprintf(
				"constant %q and its manifest entry disagree:\n      constant: %s\n      manifest: %s",
				p.Name, p.Ref, e.Mirror))
		}
	}
	for _, e := range m.Images {
		if !pinned[e.Name] {
			problems = append(problems, fmt.Sprintf(
				"manifest entry %q (%s) is an ORPHAN — no pin constant consumes it",
				e.Name, e.Mirror))
		}
	}
	if len(problems) == 0 {
		return nil
	}
	sort.Strings(problems)
	return fmt.Errorf("%w: %d problem(s):\n    %s",
		ErrLockstep, len(problems), strings.Join(problems, "\n    "))
}

// LockstepFile loads the manifest at path and checks it against the shipped pins.
func LockstepFile(path string) error {
	m, err := LoadManifest(path)
	if err != nil {
		return err
	}
	return Lockstep(Pins(), m)
}

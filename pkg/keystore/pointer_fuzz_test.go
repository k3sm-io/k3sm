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
	"bytes"
	"encoding/binary"
	"errors"
	"testing"
)

// writtenPointer is the pointer plaintext a writer produces for version at
// seq: Put writes version 1, and Rotate records low = version-1 for oauth
// and leaves low 1 for every other kind.
func writtenPointer(version, seq uint64, oauth bool) []byte {
	low := uint64(1)
	if oauth && version >= 2 {
		low = version - 1
	}
	return rangePlaintext(version, seq, low)
}

// FuzzPointerPlaintext is U151's pointer invariant: decodePointer accepts
// exactly what the writers produce, up to each kind's version limit
// (maxOAuthVersion for oauth, maxVersion otherwise). A plaintext it accepts re-encodes to
// itself through the writer's own form for that kind, and is ErrCorrupt
// otherwise; the writer's output for the version and sequence it names
// always decodes back to them.
func FuzzPointerPlaintext(f *testing.F) {
	for _, oauth := range []bool{false, true} {
		for _, v := range []uint64{1, 2, 3, 9, maxVersion} {
			f.Add(writtenPointer(v, v, oauth), oauth)
		}
	}
	f.Add(writtenPointer(maxVersion+1, 2, true), true)
	f.Add(writtenPointer(maxOAuthVersion, 2, true), true)
	f.Add(writtenPointer(maxOAuthVersion+1, 2, true), true)
	f.Add(writtenPointer(maxVersion+1, 2, true), false)
	f.Add(binary.BigEndian.AppendUint64(pointerPlaintext(2, 2), 1), true)
	f.Add(binary.BigEndian.AppendUint64(pointerPlaintext(4, 4), 2), true)
	f.Add(pointerPlaintext(0, 1), false)
	f.Add(pointerPlaintext(maxVersion+1, 1), false)
	f.Add([]byte{}, false)
	f.Fuzz(func(t *testing.T, pt []byte, oauth bool) {
		isOAuth := func(uint64) (bool, error) { return oauth, nil }
		version, seq, low, err := decodePointer(pt, isOAuth)
		if err != nil {
			if !errors.Is(err, ErrCorrupt) {
				t.Fatalf("decodePointer(%x, oauth %t) = %v, not ErrCorrupt", pt, oauth, err)
			}
		} else {
			if version > maxVersion && !oauth || version > maxOAuthVersion {
				t.Fatalf("decodePointer accepted version %d (oauth %t), over its kind's limit", version, oauth)
			}
			if want := writtenPointer(version, seq, oauth); !bytes.Equal(pt, want) {
				t.Fatalf("decodePointer accepted %x (oauth %t) as %d/%d/%d, but the writer writes %x", pt, oauth, version, seq, low, want)
			}
			if want := uint64(1); oauth && version >= 2 && low != version-1 || !oauth && low != want {
				t.Fatalf("decodePointer accepted low %d at version %d (oauth %t)", low, version, oauth)
			}
		}
		// The writer's form for what pt names, when it is in bounds, decodes
		// back to it.
		if len(pt) < 16 {
			return
		}
		v, s := binary.BigEndian.Uint64(pt[:8]), binary.BigEndian.Uint64(pt[8:16])
		if v == 0 || s == 0 || v > versionLimit(map[bool]Kind{true: KindOAuth, false: KindOpaque}[oauth]) {
			return
		}
		w := writtenPointer(v, s, oauth)
		gv, gs, gl, err := decodePointer(w, isOAuth)
		if err != nil || gv != v || gs != s || (oauth && v >= 2 && gl != v-1) {
			t.Fatalf("the writer's %x (oauth %t) decodes as %d/%d/%d, %v", w, oauth, gv, gs, gl, err)
		}
	})
}

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
	"encoding/json"
	"testing"
	"time"
)

// FuzzParseFloorLine drives the user-scope floor's line parser. The floor
// is the service user's, so any process running as it, a restore or a
// stray copy can put any bytes there: the parser must refuse what floorLine
// or tombLine would not write, never panic, and what it accepts must encode
// back to the same bytes. The seeds are committed under testdata/fuzz/FuzzParseFloorLine.
//
// The checksum's property: every byte string either parses, with a
// checksum that matches its body, or is classified (classifyFloorDamage,
// never a panic); and every truncation and every single-byte flip of a
// line that parses never parses, and taints its key or counts as
// unattributable.
func FuzzParseFloorLine(f *testing.F) {
	f.Fuzz(func(t *testing.T, b []byte) {
		r, err := parseFloorLine(b)
		if err != nil {
			kind, _ := classifyFloorDamage(b)
			if kind < taintName || kind > taintNameFlip {
				t.Fatalf("%q: classified as %d, no taint kind", b, kind)
			}
			return
		}
		if body, canonical, match := splitFloorCRC(b); !canonical || !match {
			t.Fatalf("accepted %q, whose checksum does not match %q", b, body)
		}
		for n := range len(b) {
			checkDamagedLine(t, b[:n], r.key)
		}
		for i := range b {
			p := append([]byte(nil), b...)
			p[i] ^= 0x01
			checkDamagedLine(t, p, r.key)
			p[i] ^= 0x01 ^ 0x20
			checkDamagedLine(t, p, r.key)
		}
		if len(b)+1 > maxLogLine {
			t.Fatalf("accepted a %d-byte line", len(b))
		}
		var line []byte
		if r.tomb {
			line, err = tombLine(r.key.scope, r.key.name, r.key.gen)
		} else {
			line, err = floorLine(r.key.scope, r.key.name, r.key.gen, r.seq)
		}
		if err != nil {
			t.Fatalf("accepted %q, which does not encode: %v", b, err)
		}
		if !bytes.Equal(line, append(append([]byte(nil), b...), '\n')) {
			t.Fatalf("accepted %q, which encodes as %q", b, line)
		}
	})
}

// FuzzParseAuditLine drives the audit reader. It must never panic, must
// accept only format version 1 lines of at most 1 KiB, and what it accepts
// must encode back to a line it accepts. The uid a line is charged to is
// stable: it is the scope under the exact key "scope" read by a decoder
// that folds no case and keeps no duplicate, and the re-encoded line is
// charged to the same uid.
func FuzzParseAuditLine(f *testing.F) {
	f.Fuzz(func(t *testing.T, b []byte) {
		r, err := parseAuditLine(b)
		if err != nil {
			return
		}
		if r.V != auditFormat || len(b)+1 > maxLogLine {
			t.Fatalf("accepted %q as %+v", b, r)
		}
		line, err := marshalAuditLine(auditLine{op: r.Op, scope: r.Scope, name: r.Name, namespace: r.Namespace, delivery: r.Delivery, result: r.Result}, time.Unix(1_800_000_000, 0))
		if err != nil {
			// A record re-encoded with its JSON escapes can pass 1 KiB.
			return
		}
		back, err := parseAuditLine(line[:len(line)-1])
		if err != nil {
			t.Fatalf("re-encoded %q does not read back: %v", line, err)
		}
		if scopeUID(back.Scope) != scopeUID(r.Scope) {
			t.Fatalf("%q is charged to uid %d, its re-encoding to %d", b, scopeUID(r.Scope), scopeUID(back.Scope))
		}
		var exact map[string]json.RawMessage
		if err := json.Unmarshal(b, &exact); err != nil {
			t.Fatalf("accepted %q, which is no JSON object: %v", b, err)
		}
		var scope string
		if raw, ok := exact["scope"]; ok {
			if err := json.Unmarshal(raw, &scope); err != nil {
				t.Fatalf("accepted %q, whose scope is no string: %v", b, err)
			}
		}
		if scopeUID(scope) != scopeUID(r.Scope) {
			t.Fatalf("%q is charged to uid %d, but its exact scope key names uid %d", b, scopeUID(r.Scope), scopeUID(scope))
		}
	})
}

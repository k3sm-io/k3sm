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
	"testing"
	"time"
)

// FuzzParseFloorLine drives the user-scope floor's line parser. The floor
// is the service user's, so any process running as it, a restore or a
// stray copy can put any bytes there: the parser must refuse what floorLine
// or tombLine would not write, never panic, and what it accepts must encode
// back to the same bytes. The seeds are committed under testdata/fuzz/FuzzParseFloorLine.
func FuzzParseFloorLine(f *testing.F) {
	f.Fuzz(func(t *testing.T, b []byte) {
		r, err := parseFloorLine(b)
		if err != nil {
			return
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

// FuzzParseAuditLine drives the tolerant audit reader. It must never
// panic, must accept only format version 1 lines of at most 1 KiB, and what
// it accepts must encode back to a line it accepts.
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
		if _, err := parseAuditLine(line[:len(line)-1]); err != nil {
			t.Fatalf("re-encoded %q does not read back: %v", line, err)
		}
	})
}

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
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"strings"
	"testing"

	"k3sm.io/apis/keystore/credential"
)

// badDeliveries is one delivery per field outside its grammar, each with a
// marker value a test can look for in an audit line or an error.
var badDeliveries = []struct {
	name string
	edit func(*delivery)
}{
	{"uid not a UUID", func(d *delivery) { d.uid = "MARKER-not-a-uuid" }},
	{"uid upper case", func(d *delivery) { d.uid = "ABCDEF00-0000-0000-0000-000000000001" }},
	{"name not DNS-1123", func(d *delivery) { d.name = "MARKER_Name" }},
	{"namespace not a label", func(d *delivery) { d.namespace = "marker.ns" }},
	{"namespace too long", func(d *delivery) { d.namespace = strings.Repeat("m", 64) }},
	{"namespace upper case", func(d *delivery) { d.namespace = "MARKER" }},
	{"secretName not DNS-1123", func(d *delivery) { d.secretName = "MARKER/secret" }},
	{"secretName leading dash", func(d *delivery) { d.secretName = "-marker" }},
	{"requestedBy another uid", func(d *delivery) { d.requestedBy = "k3sm:local:1002" }},
	{"requestedBy leading zero", func(d *delivery) { d.requestedBy = "k3sm:local:01001" }},
	{"item field unknown", func(d *delivery) { d.items[0].Field = "MARKERfield" }},
	{"item key not a data key", func(d *delivery) {
		d.items[0].Key = "MARKER key"
	}},
	{"item key dot-dot prefix", func(d *delivery) { d.items[0].Key = "..marker" }},
}

// U14: a delivery's fields are held to their KeyDelivery grammar at add:
// each bad field is refused, nothing is written, and the refusal's audit
// line carries a fixed placeholder, never the value.
func TestDeliveryFieldGrammarAtAdd(t *testing.T) {
	ctx := context.Background()
	s, server, u := newDeliveryScope(t)
	_, audit := userLogs(s)
	if err := u.addDelivery(ctx, testDelivery(1)); err != nil {
		t.Fatalf("a valid delivery: %v", err)
	}
	before := userRecords(t, server)
	for _, tc := range badDeliveries {
		t.Run(tc.name, func(t *testing.T) {
			d := testDelivery(2)
			d.items = append([]credential.Item(nil), d.items...)
			tc.edit(&d)
			n := len(audit.all())
			err := u.addDelivery(ctx, d)
			if err == nil {
				t.Fatal("added")
			}
			if strings.Contains(strings.ToLower(err.Error()), "marker") {
				t.Fatalf("the refusal carries the value: %v", err)
			}
			checkTreeUnchanged(t, before, userRecords(t, server))
			lines := audit.all()[n:]
			if len(lines) != 1 {
				t.Fatalf("%d audit lines for the refusal, want 1", len(lines))
			}
			l := lines[0]
			if l.result == "ok" || l.name != auditPlaceholder || l.namespace != auditPlaceholder {
				t.Fatalf("the refusal's audit line is %+v, want the placeholder", l)
			}
		})
	}
}

// encodeWithDigest marshals d with its digest computed from its fields, as
// a writer that skipped the grammar would.
func encodeWithDigest(ds ...delivery) []byte {
	for i := range ds {
		ds[i].digest = deliveryDigest(ds[i].entry, ds[i].namespace, ds[i].secretName, ds[i].items)
	}
	return marshalDeliveries(ds)
}

// U14: the parser holds a record to the same grammar: an entry with a bad
// field and a correct digest is ErrCorrupt.
func TestDeliveryFieldGrammarAtParse(t *testing.T) {
	if _, err := parseDeliveries(encodeWithDigest(testDelivery(1))); err != nil {
		t.Fatalf("a valid record: %v", err)
	}
	for _, tc := range badDeliveries {
		t.Run(tc.name, func(t *testing.T) {
			d := testDelivery(1)
			d.items = append([]credential.Item(nil), d.items...)
			tc.edit(&d)
			if _, err := parseDeliveries(encodeWithDigest(d)); !errors.Is(err, ErrCorrupt) {
				t.Fatalf("parse: %v, want ErrCorrupt", err)
			}
		})
	}
}

// fixDigests rewrites, in a copy of pt, each entry's digest to the digest of
// the fields before it, as far as the entries parse: a fuzzer's mutation of
// a field then reaches the field and item checks instead of stopping at the
// digest.
func fixDigests(pt []byte) []byte {
	b := append([]byte(nil), pt...)
	if len(b) < 5 {
		return b
	}
	off := 5
	field := func() ([]byte, bool) {
		if len(b)-off < 4 {
			return nil, false
		}
		n := int(binary.BigEndian.Uint32(b[off:]))
		if n < 0 || n > len(b)-off-4 {
			return nil, false
		}
		v := b[off+4 : off+4+n]
		off += 4 + n
		return v, true
	}
	for i := uint32(0); i < binary.BigEndian.Uint32(b[1:5]) && i < maxDeliveries; i++ {
		var fs [7][]byte
		for j := range fs {
			v, ok := field()
			if !ok {
				return b
			}
			fs[j] = v
		}
		if len(b)-off < sha256.Size+9 {
			return b
		}
		h := []byte(deliveryDigestLabel)
		h = appendLP(h, fs[2])
		h = appendLP(h, fs[3])
		h = appendLP(h, fs[4])
		h = appendLP(h, fs[6])
		sum := sha256.Sum256(h)
		copy(b[off:], sum[:])
		off += sha256.Size + 9
	}
	return b
}

// FuzzParseDeliveriesStructured is FuzzParseDeliveries with each entry's
// digest recomputed before the parse, so a mutation reaches the field and
// item grammar. An accepted record has every field in its grammar and
// re-encodes to its input.
func FuzzParseDeliveriesStructured(f *testing.F) {
	f.Add(encodeWithDigest(testDelivery(1)))
	two := testDelivery(2)
	two.withdrawn, two.delivered = true, 7
	two.items = two.items[:1]
	f.Add(encodeWithDigest(testDelivery(1), two))
	for _, tc := range badDeliveries {
		d := testDelivery(3)
		d.items = append([]credential.Item(nil), d.items...)
		tc.edit(&d)
		f.Add(encodeWithDigest(d))
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		b := fixDigests(raw)
		ds, err := parseDeliveries(b)
		if err != nil {
			if !errors.Is(err, ErrCorrupt) {
				t.Fatalf("parse error %v is not ErrCorrupt", err)
			}
			return
		}
		for _, d := range ds {
			if err := checkDeliveryFields(d); err != nil {
				t.Fatalf("accepted a field outside its grammar: %v", err)
			}
		}
		if !bytes.Equal(marshalDeliveries(ds), b) {
			t.Fatal("an accepted record does not re-encode to its input")
		}
	})
}

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
	"crypto/rand"
	"errors"
	"strings"
	"testing"
)

// FuzzResolveEntry holds ResolveEntry to its contract on any input: it never
// panics, any refusal matches ErrInvalidName, and any answer is a valid API
// entry in a scope the store accepts, the input itself unless a short name
// was resolved, which the note then states.
func FuzzResolveEntry(f *testing.F) {
	for _, s := range []string{"user/alice/token", "user/501/token", "system/x", "user/0/a", "user/root/a", "user/1000/a", "user/-a/b", "user/alice/", "user//a", ""} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, in string) {
		setSeam(t, &uidResolverSeam, func(name string) (uint32, error) {
			switch name {
			case "alice":
				return 501, nil
			case "root":
				return 0, nil
			}
			return 0, errors.New("no such account")
		})
		r, err := ResolveEntry(in)
		if err != nil {
			if !errors.Is(err, ErrInvalidName) {
				t.Fatalf("ResolveEntry(%q): %v does not match ErrInvalidName", in, err)
			}
			return
		}
		q := r.Entry.String()
		if _, err := ParseEntry(q); err != nil {
			t.Fatalf("ResolveEntry(%q) answered %q, which does not parse: %v", in, q, err)
		}
		if r.Note == "" && q != in {
			t.Fatalf("ResolveEntry(%q) answered %q with no note", in, q)
		}
		if r.Note != "" && (r.Entry.UID != 501 || !strings.HasSuffix(r.Note, " to user/501")) {
			t.Fatalf("ResolveEntry(%q) resolved to %+v, %q", in, r.Entry, r.Note)
		}
	})
}

// FuzzParseScopeKey holds parseScopeKey to its contract on any bytes: it
// never panics, any refusal matches ErrCorrupt, and anything it accepts is a
// kind-0xFE "scope" record at the key epoch that re-encodes to its input.
func FuzzParseScopeKey(f *testing.F) {
	r := record{kind: kindScopeKey, name: scopeKeyRecordName, version: scopeKeyEpoch, generation: guid(0xA1)}
	if err := r.seal(testKey, "user/501", make([]byte, scopeKeySize), rand.Reader); err != nil {
		f.Fatal(err)
	}
	f.Add(r.marshal())
	f.Add([]byte{})
	f.Add(make([]byte, maxScopeKeyRecordSize))
	f.Fuzz(func(t *testing.T, b []byte) {
		got, err := parseScopeKey(b)
		if err != nil {
			if !errors.Is(err, ErrCorrupt) {
				t.Fatalf("parse error %v is not ErrCorrupt", err)
			}
			return
		}
		if got.kind != kindScopeKey || got.name != scopeKeyRecordName || got.version != scopeKeyEpoch {
			t.Fatalf("accepted kind %#x name %q version %d", got.kind, got.name, got.version)
		}
		if !bytes.Equal(got.marshal(), b) {
			t.Fatal("an accepted scope.key does not re-encode to its input")
		}
	})
}

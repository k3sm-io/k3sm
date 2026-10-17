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
	"errors"
	"fmt"
	"sort"
	"strings"
	"testing"
	"time"
)

// These tests pin the shape of the Store contract only: that a type can
// satisfy it, and that metadata and the sentinel errors round-trip through it.
// The behavioural tests (sealing, the additional data binding, crash-safe
// rotation, the master key checks) arrive with the implementation.

// fakeStore is a minimal in-memory Store used only to exercise the interface
// shape. It encrypts nothing and persists nothing.
type fakeStore struct {
	now     time.Time
	entries map[string][]fakeVersion
}

type fakeVersion struct {
	meta  Version
	value []byte
}

var _ Store = (*fakeStore)(nil)

func newFakeStore() *fakeStore {
	return &fakeStore{
		now:     time.Date(2026, 10, 17, 0, 0, 0, 0, time.UTC),
		entries: map[string][]fakeVersion{},
	}
}

func (f *fakeStore) write(name string, kind Kind, version uint64, value []byte) Version {
	v := Version{
		Name:        name,
		Version:     version,
		Kind:        kind,
		Created:     f.now,
		Fingerprint: fmt.Sprintf("fp-%s-%d", name, version),
	}
	f.entries[name] = append(f.entries[name], fakeVersion{meta: v, value: bytes.Clone(value)})
	return v
}

func (f *fakeStore) Put(_ context.Context, name string, kind Kind, value []byte) (Version, error) {
	if name == "" || strings.ContainsRune(name, '/') || strings.Trim(name, ".") == "" {
		return Version{}, fmt.Errorf("put %q: %w", name, ErrInvalidName)
	}
	if _, ok := f.entries[name]; ok {
		return Version{}, fmt.Errorf("put %s: %w", name, ErrExists)
	}
	return f.write(name, kind, 1, value), nil
}

func (f *fakeStore) Current(_ context.Context, name string) (Version, []byte, error) {
	vs, ok := f.entries[name]
	if !ok {
		return Version{}, nil, ErrNotFound
	}
	last := vs[len(vs)-1]
	return last.meta, bytes.Clone(last.value), nil
}

func (f *fakeStore) Get(_ context.Context, name string, version uint64) (Version, []byte, error) {
	vs, ok := f.entries[name]
	if !ok {
		return Version{}, nil, ErrNotFound
	}
	for _, v := range vs {
		if v.meta.Version == version {
			return v.meta, bytes.Clone(v.value), nil
		}
	}
	return Version{}, nil, ErrVersionNotFound
}

func (f *fakeStore) List(_ context.Context) ([]Entry, error) {
	out := make([]Entry, 0, len(f.entries))
	for name, vs := range f.entries {
		e := Entry{Name: name, Current: vs[len(vs)-1].meta}
		for _, v := range vs {
			e.Versions = append(e.Versions, v.meta)
		}
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func (f *fakeStore) Rotate(_ context.Context, name string, value []byte) (Version, error) {
	vs, ok := f.entries[name]
	if !ok {
		return Version{}, ErrNotFound
	}
	last := vs[len(vs)-1].meta
	return f.write(name, last.Kind, last.Version+1, value), nil
}

func (f *fakeStore) Delete(_ context.Context, name string) error {
	if _, ok := f.entries[name]; !ok {
		return ErrNotFound
	}
	delete(f.entries, name)
	return nil
}

func (f *fakeStore) Rewrap(_ context.Context, newMaster []byte) error {
	if len(newMaster) == 0 {
		return ErrMasterMissing
	}
	return nil
}

func TestStoreContract(t *testing.T) {
	ctx := context.Background()
	tests := []struct {
		name string
		run  func(t *testing.T, s Store)
	}{
		{
			name: "put then current round-trips metadata and value",
			run: func(t *testing.T, s Store) {
				put, err := s.Put(ctx, "signer", KindEd25519, []byte("k1"))
				if err != nil {
					t.Fatalf("Put: %v", err)
				}
				if put.Name != "signer" || put.Version != 1 || put.Kind != KindEd25519 || put.Fingerprint == "" || put.Created.IsZero() {
					t.Fatalf("Put metadata = %+v", put)
				}
				cur, val, err := s.Current(ctx, "signer")
				if err != nil {
					t.Fatalf("Current: %v", err)
				}
				if cur != put || string(val) != "k1" {
					t.Fatalf("Current = %+v %q, want %+v %q", cur, val, put, "k1")
				}
			},
		},
		{
			name: "rotate advances the current version and keeps the old one",
			run: func(t *testing.T, s Store) {
				if _, err := s.Put(ctx, "token", KindOpaque, []byte("v1")); err != nil {
					t.Fatalf("Put: %v", err)
				}
				rot, err := s.Rotate(ctx, "token", []byte("v2"))
				if err != nil {
					t.Fatalf("Rotate: %v", err)
				}
				if rot.Version != 2 || rot.Kind != KindOpaque {
					t.Fatalf("Rotate metadata = %+v", rot)
				}
				cur, val, err := s.Current(ctx, "token")
				if err != nil || cur.Version != 2 || string(val) != "v2" {
					t.Fatalf("Current = %+v %q %v", cur, val, err)
				}
				old, val, err := s.Get(ctx, "token", 1)
				if err != nil || old.Version != 1 || string(val) != "v1" {
					t.Fatalf("Get v1 = %+v %q %v", old, val, err)
				}
			},
		},
		{
			name: "list returns metadata sorted by name",
			run: func(t *testing.T, s Store) {
				for _, n := range []string{"b", "a"} {
					if _, err := s.Put(ctx, n, KindOpaque, []byte(n)); err != nil {
						t.Fatalf("Put %s: %v", n, err)
					}
				}
				if _, err := s.Rotate(ctx, "a", []byte("a2")); err != nil {
					t.Fatalf("Rotate: %v", err)
				}
				got, err := s.List(ctx)
				if err != nil {
					t.Fatalf("List: %v", err)
				}
				if len(got) != 2 || got[0].Name != "a" || got[1].Name != "b" {
					t.Fatalf("List names = %+v", got)
				}
				if got[0].Current.Version != 2 || len(got[0].Versions) != 2 {
					t.Fatalf("List a = %+v", got[0])
				}
			},
		},
		{
			name: "missing entry and missing version are distinct sentinels",
			run: func(t *testing.T, s Store) {
				if _, _, err := s.Current(ctx, "nope"); !errors.Is(err, ErrNotFound) {
					t.Fatalf("Current missing: %v, want ErrNotFound", err)
				}
				if _, err := s.Rotate(ctx, "nope", nil); !errors.Is(err, ErrNotFound) {
					t.Fatalf("Rotate missing: %v, want ErrNotFound", err)
				}
				if _, err := s.Put(ctx, "x", KindOpaque, []byte("x")); err != nil {
					t.Fatalf("Put: %v", err)
				}
				if _, _, err := s.Get(ctx, "x", 9); !errors.Is(err, ErrVersionNotFound) {
					t.Fatalf("Get missing version: %v, want ErrVersionNotFound", err)
				}
			},
		},
		{
			name: "put refuses an existing name and invalid names",
			run: func(t *testing.T, s Store) {
				if _, err := s.Put(ctx, "dup", KindOpaque, []byte("d")); err != nil {
					t.Fatalf("Put: %v", err)
				}
				if _, err := s.Put(ctx, "dup", KindOpaque, []byte("d")); !errors.Is(err, ErrExists) {
					t.Fatalf("second Put: %v, want ErrExists", err)
				}
				for _, bad := range []string{"", ".", "..", "a/b", "../x"} {
					if _, err := s.Put(ctx, bad, KindOpaque, []byte("x")); !errors.Is(err, ErrInvalidName) {
						t.Fatalf("Put %q: %v, want ErrInvalidName", bad, err)
					}
				}
			},
		},
		{
			name: "delete removes the entry",
			run: func(t *testing.T, s Store) {
				if _, err := s.Put(ctx, "gone", KindOpaque, []byte("g")); err != nil {
					t.Fatalf("Put: %v", err)
				}
				if err := s.Delete(ctx, "gone"); err != nil {
					t.Fatalf("Delete: %v", err)
				}
				if _, _, err := s.Current(ctx, "gone"); !errors.Is(err, ErrNotFound) {
					t.Fatalf("Current after Delete: %v, want ErrNotFound", err)
				}
				if err := s.Delete(ctx, "gone"); !errors.Is(err, ErrNotFound) {
					t.Fatalf("second Delete: %v, want ErrNotFound", err)
				}
			},
		},
		{
			name: "rewrap leaves metadata unchanged",
			run: func(t *testing.T, s Store) {
				put, err := s.Put(ctx, "w", KindEd25519, []byte("w"))
				if err != nil {
					t.Fatalf("Put: %v", err)
				}
				if err := s.Rewrap(ctx, []byte("new master")); err != nil {
					t.Fatalf("Rewrap: %v", err)
				}
				cur, _, err := s.Current(ctx, "w")
				if err != nil || cur != put {
					t.Fatalf("Current after Rewrap = %+v %v, want %+v", cur, err, put)
				}
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.run(t, newFakeStore())
		})
	}
}

func TestKindString(t *testing.T) {
	tests := []struct {
		kind Kind
		want string
	}{
		{KindUnknown, "unknown"},
		{KindEd25519, "ed25519"},
		{KindOpaque, "opaque"},
		{Kind(99), "unknown"},
	}
	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			if got := tt.kind.String(); got != tt.want {
				t.Fatalf("Kind(%d).String() = %q, want %q", int(tt.kind), got, tt.want)
			}
		})
	}
}

func TestSentinelsAreDistinct(t *testing.T) {
	all := []error{ErrInvalidName, ErrExists, ErrCorrupt, ErrNotFound, ErrVersionNotFound, ErrEncryptionOff, ErrMasterMissing, ErrMasterUntrusted}
	for i, a := range all {
		for j, b := range all {
			if i != j && errors.Is(a, b) {
				t.Fatalf("%v matches %v", a, b)
			}
		}
	}
}

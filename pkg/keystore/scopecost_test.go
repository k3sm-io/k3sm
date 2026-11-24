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
	"context"
	"os"
	"testing"
	"time"
)

// plantVersions gives user/1001/a of u versions 2 to n, written straight
// to the entry's directory without an fsync, and a pointer naming version
// n at sequence 2, with that floor line: a scope as many rotations leave
// it, made in seconds.
func plantVersions(t testing.TB, s *FileStore, u *UserScope, n uint64) {
	t.Helper()
	err := u.read(context.Background(), func(entries *os.Root, uk keys) error {
		e, err := openUserEntry(entries, "a")
		if err != nil {
			return err
		}
		defer e.close()
		created := s.now().Unix()
		for v := uint64(2); v <= n; v++ {
			rec := record{kind: byte(KindOpaque), name: "a", version: v, generation: e.generation, created: created}
			if err := rec.seal(uk.seal, uk.scope, []byte("a planted value"), s.rand); err != nil {
				return err
			}
			if err := e.root.WriteFile(versionName(v), rec.marshal(), fileMode); err != nil {
				return err
			}
		}
		ptr := record{kind: kindPointer, name: "a", generation: e.generation, created: created}
		if err := ptr.seal(uk.seal, uk.scope, pointerPlaintext(n, 2), s.rand); err != nil {
			return err
		}
		if err := e.root.WriteFile(currentName, ptr.marshal(), fileMode); err != nil {
			return err
		}
		return s.userFloor.append(u.scope, "a", e.generation, 2, true)
	})
	if err != nil {
		t.Fatalf("plant %d versions: %v", n, err)
	}
}

// TestScopeCostAt20kVersions measures list and rotate on a scope of
// 20,000 versions (about 2 MiB of records): the call's time and its
// longest store lock hold, on the wall clock. It is a measurement, not a
// gate, so it runs only with K3SM_KEYSTORE_MEASURE set. "walked" is the
// rotate as it was before the usage figure: the scope walked under the
// lock (no figure kept).
func TestScopeCostAt20kVersions(t *testing.T) {
	if os.Getenv("K3SM_KEYSTORE_MEASURE") == "" {
		t.Skip("a measurement: set K3SM_KEYSTORE_MEASURE to run it")
	}
	ctx := context.Background()
	const versions = 20000
	s, u := rotateScope(t)
	plantVersions(t, s, u, versions)
	var longest time.Duration
	s.holdObserver = func(_ bool, held time.Duration) { longest = max(longest, held) }
	measure := func(name string, fn func() error) {
		longest = 0
		began := time.Now()
		if err := fn(); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		t.Logf("%s at %d versions: %s, longest hold %s", name, versions, time.Since(began), longest)
	}
	measure("list", func() error {
		es, err := u.List(ctx)
		if err == nil && (len(es) != 1 || es[0].Err != nil) {
			t.Fatalf("list: %+v", es)
		}
		return err
	})
	measure("rotate (first, figure walked before the lock)", func() error { _, err := u.Rotate(ctx, "user/1001/a", []byte("next")); return err })
	measure("rotate (figure kept)", func() error { _, err := u.Rotate(ctx, "user/1001/a", []byte("next")); return err })
	userPut(t, u, "user/1001/b", "bee")
	measure("rotate of a one-version entry (figure kept)", func() error { _, err := u.Rotate(ctx, "user/1001/b", []byte("next")); return err })
	kept := s.usage
	s.usage = nil
	measure("rotate (walked under the lock, as before the figure)", func() error { _, err := u.Rotate(ctx, "user/1001/a", []byte("next")); return err })
	s.usage = kept
}

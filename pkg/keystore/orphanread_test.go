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
	"crypto/ed25519"
	"errors"
	"strings"
	"testing"
)

// plantOrphan seals version 1's plaintext of name again as version 2: an
// authenticated sealed version above a pointer that names version 1.
func plantOrphan(t *testing.T, s *FileStore, server, name string) {
	t.Helper()
	var (
		kind Kind
		pt   []byte
	)
	err := s.read(context.Background(), name, func(e *entry, k keys, _ floor) error {
		v, val, err := e.version(k, 1)
		kind, pt = v.Kind, val
		return err
	})
	if err != nil {
		t.Fatalf("open %s version 1: %v", name, err)
	}
	defer clear(pt)
	sealVersion(t, s, server, name, 2, kind, pt)
}

// TestReadsReportOrphanEveryKind is review round 4, item 3: every read of
// a token, ssh, opaque or ed25519 entry reports an authenticated sealed
// version above the pointer as ErrOrphanVersion, as oauth reads do.
func TestReadsReportOrphanEveryKind(t *testing.T) {
	ctx := context.Background()
	s, server := newTypedStore(t)
	mustPutCredential(t, s, "tok", KindToken, tokenEnvelope("t1"))
	if _, _, err := s.GenerateSSH(ctx, "key", "c"); err != nil {
		t.Fatal(err)
	}
	mustPut(t, s, "raw", KindOpaque, []byte("one"))
	mustPut(t, s, "ed", KindEd25519, make([]byte, ed25519.SeedSize))
	for _, name := range []string{"tok", "key", "raw", "ed"} {
		plantOrphan(t, s, server, name)
	}
	for _, name := range []string{"tok", "key"} {
		if _, _, err := s.CurrentCredential(ctx, name); !errors.Is(err, ErrOrphanVersion) {
			t.Errorf("CurrentCredential %s over an orphan: %v, want ErrOrphanVersion", name, err)
		}
		if _, _, err := s.GetCredential(ctx, name, 1); !errors.Is(err, ErrOrphanVersion) {
			t.Errorf("GetCredential %s over an orphan: %v, want ErrOrphanVersion", name, err)
		}
	}
	for _, name := range []string{"raw", "ed"} {
		if _, val, err := s.Current(ctx, name); !errors.Is(err, ErrOrphanVersion) || val != nil {
			t.Errorf("Current %s over an orphan: %v, want ErrOrphanVersion and no value", name, err)
		}
		if _, val, err := s.Get(ctx, name, 1); !errors.Is(err, ErrOrphanVersion) || val != nil {
			t.Errorf("Get %s over an orphan: %v, want ErrOrphanVersion and no value", name, err)
		}
	}
}

// TestReadsRefuseFilesAboveNextByName is item 3's bound: a read opens only
// the version after the current one. A version file further out is refused
// by its number alone, naming it, and a file at the next version of a kind
// this build does not know is refused naming it, not as a newer k3sm's
// record. A file at the next version that does not authenticate is a true
// orphan, which the next Rotate discards, and does not stop a read.
func TestReadsRefuseFilesAboveNextByName(t *testing.T) {
	ctx := context.Background()
	t.Run("further out", func(t *testing.T) {
		s, server := newTestStore(t)
		mustPut(t, s, "raw", KindOpaque, []byte("one"))
		writeFile(t, entryPath(server, "raw", "v9"), "not a record")
		_, _, err := s.Current(ctx, "raw")
		if !errors.Is(err, ErrCorrupt) || !strings.Contains(err.Error(), "v9") {
			t.Fatalf("Current over v9: %v, want ErrCorrupt naming v9", err)
		}
	})
	t.Run("unsupported kind", func(t *testing.T) {
		s, server := newTestStore(t)
		mustPut(t, s, "raw", KindOpaque, []byte("one"))
		b := make([]byte, headerSize+8)
		b[0], b[1] = recordFormat, kindFirstUnassigned
		writeFile(t, entryPath(server, "raw", "v2"), string(b))
		_, _, err := s.Current(ctx, "raw")
		if !errors.Is(err, ErrCorrupt) || errors.Is(err, ErrKindUnsupported) || !strings.Contains(err.Error(), "v2") {
			t.Fatalf("Current over an unsupported-kind v2: %v, want ErrCorrupt naming v2, not ErrKindUnsupported", err)
		}
	})
	t.Run("true orphan", func(t *testing.T) {
		s, server := newTestStore(t)
		mustPut(t, s, "raw", KindOpaque, []byte("one"))
		writeFile(t, entryPath(server, "raw", "v2"), "not a record")
		mustCurrent(t, s, "raw", "one")
	})
}

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
	"errors"
	"fmt"
	"os"
	"testing"
)

// captureFailedVersion runs write with a fault at the sync of file, after
// the version file is in place and before the flip, and returns that file's
// bytes as they were then: a sealed record of the version that never became
// current.
func captureFailedVersion(t *testing.T, s *FileStore, server, name, file string, write func() error) []byte {
	t.Helper()
	var got []byte
	s.step = func(step string) error {
		if step != "sync "+file {
			return nil
		}
		b, err := os.ReadFile(entryPath(server, name, file))
		if err != nil {
			t.Errorf("%s at its sync: %v", file, err)
		}
		got = b
		return fmt.Errorf("injected failure at %s", step)
	}
	defer func() { s.step = func(string) error { return nil } }()
	if err := write(); err == nil {
		t.Fatal("the write succeeded through a fault")
	}
	if got == nil {
		t.Fatalf("the fault did not fire at the sync of %s", file)
	}
	return got
}

// TestRotateIfRefusesSameNumberDifferentRecord is review round 4, item 1b:
// a version's identity covers its record, so RotateIf cannot pass across two
// different records that share a version number (an ABA through a failed
// attempt's file copied over the committed one).
func TestRotateIfRefusesSameNumberDifferentRecord(t *testing.T) {
	ctx := context.Background()
	s, server := newTypedStore(t)
	mustPutCredential(t, s, "tok", KindToken, tokenEnvelope("t1"))
	attemptA := captureFailedVersion(t, s, server, "tok", "v2", func() error {
		_, err := s.RotateCredential(ctx, "tok", KindToken, tokenEnvelope("tA"))
		return err
	})
	mustRotateCredential(t, s, "tok", KindToken, tokenEnvelope("tB"))
	read, _ := mustCredential(t, s, "tok")
	writeFile(t, entryPath(server, "tok", "v2"), string(attemptA))
	if _, err := s.RotateIf(ctx, "tok", KindToken, read, tokenEnvelope("t3")); !errors.Is(err, ErrVersionStale) {
		t.Fatalf("RotateIf across a different record at the same version: %v, want ErrVersionStale", err)
	}
}

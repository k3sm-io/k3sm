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

// TestAdoptRefusesReplacedOrphan is review round 4, item 1c: Adopt takes the
// identity Orphan reported, and refuses when the file at cur+1 has since
// been replaced by another sealed record of the same version.
func TestAdoptRefusesReplacedOrphan(t *testing.T) {
	ctx := context.Background()
	s, server := newTypedStore(t)
	mustPutCredential(t, s, "k", KindOAuth, oauthEnvelope("a1", "r1"))
	attemptA := captureFailedVersion(t, s, server, "k", "v2", func() error {
		_, err := s.RotateCredential(ctx, "k", KindOAuth, oauthEnvelope("a2", "r2"))
		return err
	})
	if err := os.Remove(entryPath(server, "k", "v2")); err != nil && !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
	crashAfterVersionWrite(t, s, server, "k", func() error {
		_, err := s.RotateCredential(ctx, "k", KindOAuth, oauthEnvelope("b2", "rb2"))
		return err
	})
	info, err := s.Orphan(ctx, "k")
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, entryPath(server, "k", "v2"), string(attemptA))
	if _, err := s.Adopt(ctx, "k", info.Orphan); !errors.Is(err, ErrVersionStale) {
		t.Fatalf("Adopt of a replaced orphan: %v, want ErrVersionStale", err)
	}
	if got := sealedRefresh(t, s, "k", 1); got != "r1" {
		t.Fatalf("version 1 refresh %q after the refused adopt, want r1", got)
	}
	// The orphan Orphan reports now is attempt A, and adopting that one
	// goes through.
	info, err = s.Orphan(ctx, "k")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Adopt(ctx, "k", info.Orphan); err != nil {
		t.Fatalf("Adopt of the orphan just reported: %v", err)
	}
	if got := sealedRefresh(t, s, "k", 2); got != "r2" {
		t.Fatalf("adopted refresh %q, want r2", got)
	}
}

// TestOAuthPreFlipFailureKeepsVersion is review round 4, item 2: an oauth
// rotation that fails after its version file is in place and before the
// pointer flip keeps that file, which holds the provider's new pair, and
// says so with ErrOrphanVersion; Orphan and Adopt then recover it. Other
// kinds still remove it.
func TestOAuthPreFlipFailureKeepsVersion(t *testing.T) {
	ctx := context.Background()
	for _, step := range []string{"sync v2", "write current"} {
		t.Run(step, func(t *testing.T) {
			s, server := newTypedStore(t)
			mustPutCredential(t, s, "k", KindOAuth, oauthEnvelope("a1", "r1"))
			s.step = failAt(step)
			v, err := s.RotateCredential(ctx, "k", KindOAuth, oauthEnvelope("a2", "r2"))
			s.step = func(string) error { return nil }
			if !errors.Is(err, ErrOrphanVersion) || errors.Is(err, ErrCommitted) || v != (Version{}) {
				t.Fatalf("RotateCredential failing at %s = %+v, %v; want a zero Version and ErrOrphanVersion", step, v, err)
			}
			if _, err := os.Lstat(entryPath(server, "k", "v2")); err != nil {
				t.Fatalf("the failed oauth rotation removed its v2: %v", err)
			}
			if _, _, err := s.CurrentCredential(ctx, "k"); !errors.Is(err, ErrOrphanVersion) {
				t.Fatalf("CurrentCredential after the failure: %v, want ErrOrphanVersion", err)
			}
			if _, err := s.Adopt(ctx, "k", mustOrphan(t, s, "k")); err != nil {
				t.Fatalf("Adopt the kept version: %v", err)
			}
			if got := sealedRefresh(t, s, "k", 2); got != "r2" {
				t.Fatalf("adopted refresh %q, want r2", got)
			}
		})
		t.Run(step+" token", func(t *testing.T) {
			s, server := newTypedStore(t)
			mustPutCredential(t, s, "k", KindToken, tokenEnvelope("t1"))
			s.step = failAt(step)
			_, err := s.RotateCredential(ctx, "k", KindToken, tokenEnvelope("t2"))
			s.step = func(string) error { return nil }
			if err == nil || errors.Is(err, ErrOrphanVersion) {
				t.Fatalf("token RotateCredential failing at %s: %v, want an error that is not ErrOrphanVersion", step, err)
			}
			if _, err := os.Lstat(entryPath(server, "k", "v2")); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("the failed token rotation left its v2: %v", err)
			}
		})
	}
}

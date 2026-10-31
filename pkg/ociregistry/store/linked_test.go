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

package store

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"

	"k3sm.io/k3sm/pkg/ociregistry/ref"
)

// linkedSession leaves a session the way a commit that linked it into blobs/
// and stopped before removing it does: the session inode has two links.
func linkedSession(t *testing.T, s *Store, body []byte) (id string, blob string) {
	t.Helper()
	ctx := context.Background()
	n := name(t, "app")
	id, err := s.NewUpload(ctx, n)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.AppendUpload(ctx, n, id, 0, bytes.NewReader(body)); err != nil {
		t.Fatal(err)
	}
	src, _ := s.uploadPath(n, id)
	blob, _ = s.blobPath(n, digest.FromBytes(body))
	if err := os.MkdirAll(filepath.Dir(blob), dirMode); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(src, blob); err != nil {
		t.Fatal(err)
	}
	return id, blob
}

// TestLinkedSessionCanFinish: a session already linked into blobs/ can be
// cancelled and its commit retried, and neither touches the blob; an append
// to it is still refused.
func TestLinkedSessionCanFinish(t *testing.T) {
	body := []byte("committed bytes")
	d := digest.FromBytes(body)
	for _, finish := range []string{"cancel", "retried commit", "retried hashed commit"} {
		t.Run(finish, func(t *testing.T) {
			s := newStore(t)
			ctx := context.Background()
			n := name(t, "app")
			id, blob := linkedSession(t, s, body)
			if _, err := s.AppendUpload(ctx, n, id, -1, strings.NewReader("more")); !errors.Is(err, ErrUploadUnknown) {
				t.Fatalf("append to a linked session = %v, want ErrUploadUnknown", err)
			}
			var err error
			switch finish {
			case "cancel":
				err = s.CancelUpload(ctx, n, id)
			case "retried commit":
				err = s.CommitUpload(ctx, n, id, d)
			default:
				err = s.CommitHashedUpload(ctx, n, id, d, int64(len(body)))
			}
			if err != nil {
				t.Fatalf("%s: %v", finish, err)
			}
			if _, err := s.UploadSize(ctx, n, id); !errors.Is(err, ErrUploadUnknown) {
				t.Errorf("session after %s = %v, want gone", finish, err)
			}
			got, err := os.ReadFile(blob)
			if err != nil || !bytes.Equal(got, body) {
				t.Errorf("blob after %s = %q, %v", finish, got, err)
			}
			fi, _ := os.Stat(blob)
			if nlink(fi) != 1 {
				t.Errorf("blob has %d links after %s, want 1", nlink(fi), finish)
			}
		})
	}
}

// TestHashedCommitFallsBackToRehash: a streamed hash that covers fewer bytes
// than the session holds is not trusted; the file is hashed again.
func TestHashedCommitFallsBackToRehash(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	n := name(t, "app")
	id, err := s.NewUpload(ctx, n)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.AppendUpload(ctx, n, id, 0, strings.NewReader("abcdef")); err != nil {
		t.Fatal(err)
	}
	if err := s.CommitHashedUpload(ctx, n, id, digest.FromString("abc"), 3); !errors.Is(err, ErrDigestMismatch) {
		t.Fatalf("hashed commit over a longer session = %v, want ErrDigestMismatch", err)
	}
	if err := s.CommitHashedUpload(ctx, n, id, digest.FromString("abcdef"), 6); err != nil {
		t.Fatal(err)
	}
}

// TestDeleteDigestChecked: a failing check deletes nothing.
func TestDeleteDigestChecked(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	n := name(t, "app")
	body := []byte(`{"schemaVersion":2}`)
	desc, err := s.PutManifest(ctx, n, ref.Reference{Tag: "v1"}, ispec.MediaTypeImageManifest, body)
	if err != nil {
		t.Fatal(err)
	}
	refuse := errors.New("refused")
	if err := s.DeleteDigestChecked(ctx, n, desc.Digest, func([]ispec.Descriptor) error { return refuse }); !errors.Is(err, refuse) {
		t.Fatalf("checked delete = %v, want the check's error", err)
	}
	if _, err := s.Resolve(n, ref.Reference{Tag: "v1"}); err != nil {
		t.Fatalf("tag after a refused delete: %v", err)
	}
	if err := s.DeleteDigestChecked(ctx, n, desc.Digest, func([]ispec.Descriptor) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteDigestChecked(ctx, n, desc.Digest, func([]ispec.Descriptor) error { return nil }); !errors.Is(err, ErrManifestUnknown) {
		t.Fatalf("second delete = %v, want ErrManifestUnknown", err)
	}
}

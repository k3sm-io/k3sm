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
	"context"
	"errors"
	"fmt"
	"testing"

	"k3sm.io/k3sm/pkg/ociregistry/ref"
)

// lowerIndexLimit sets the index.json limit to n bytes for the test.
func lowerIndexLimit(t *testing.T, n int64) {
	t.Helper()
	old := maxIndexLen
	maxIndexLen = n
	t.Cleanup(func() { maxIndexLen = old })
}

// TestTagsCannotPushTheIndexPastItsReadLimit pushes tags until the next one
// would take index.json past the size the store reads. That push fails with
// ErrIndexFull and writes nothing, so the repository stays readable, its tags
// can still be deleted, and a push fits again once they are.
func TestTagsCannotPushTheIndexPastItsReadLimit(t *testing.T) {
	lowerIndexLimit(t, 2048)
	ctx := context.Background()
	s := newStore(t)
	n := name(t, "app")
	body := []byte(`{"schemaVersion":2}`)
	put := func(tag string) error {
		_, err := s.PutManifest(ctx, n, ref.Reference{Tag: tag}, "application/vnd.oci.image.manifest.v1+json", body)
		return err
	}
	var tags []string
	for i := range 1000 {
		tag := fmt.Sprintf("t%03d", i)
		err := put(tag)
		if errors.Is(err, ErrIndexFull) {
			break
		}
		if err != nil {
			t.Fatalf("push %s: %v", tag, err)
		}
		tags = append(tags, tag)
	}
	if len(tags) == 0 || len(tags) == 1000 {
		t.Fatalf("%d tags pushed; want the limit reached after some", len(tags))
	}
	idx, err := s.Index(n)
	if err != nil {
		t.Fatalf("the repository is unreadable after %d tags: %v", len(tags), err)
	}
	if len(idx.Manifests) != len(tags) {
		t.Fatalf("index holds %d rows, want %d: the refused push wrote", len(idx.Manifests), len(tags))
	}
	if err := s.DeleteTag(ctx, n, tags[0]); err != nil {
		t.Fatalf("delete a tag of a full index: %v", err)
	}
	if err := put("again"); err != nil {
		t.Fatalf("push after a delete made room: %v", err)
	}
}

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
	"testing"
	"time"

	"github.com/opencontainers/go-digest"
)

func TestTouchBlob(t *testing.T) {
	ctx := context.Background()
	t.Run("a held blob's mtime becomes now", func(t *testing.T) {
		s := newStore(t)
		at := time.Now().Add(3 * time.Hour).Truncate(time.Second)
		s.SetClock(func() time.Time { return at })
		n := name(t, "app")
		body := []byte("layer")
		d := digest.FromBytes(body)
		if err := s.PutBlob(ctx, n, d, bytes.NewReader(body)); err != nil {
			t.Fatal(err)
		}
		dir, err := n.Dir(s.Root())
		if err != nil {
			t.Fatal(err)
		}
		p := filepath.Join(dir, "blobs", "sha256", d.Encoded())
		old := time.Now().Add(-48 * time.Hour)
		if err := os.Chtimes(p, old, old); err != nil {
			t.Fatal(err)
		}
		if err := s.TouchBlob(ctx, n, d); err != nil {
			t.Fatal(err)
		}
		fi, err := os.Stat(p)
		if err != nil {
			t.Fatal(err)
		}
		if !fi.ModTime().Equal(at) {
			t.Errorf("mtime %s, want %s", fi.ModTime(), at)
		}
	})
	t.Run("an absent blob is unknown and takes no lock", func(t *testing.T) {
		s := newStore(t)
		d := digest.FromBytes([]byte("never"))
		for _, repo := range []string{"app", "missing"} {
			if repo == "app" {
				if err := s.Init(ctx, name(t, repo)); err != nil {
					t.Fatal(err)
				}
			}
			before, err := os.ReadDir(filepath.Join(s.StateDir(), locksDir))
			if err != nil && !errors.Is(err, os.ErrNotExist) {
				t.Fatal(err)
			}
			if err := s.TouchBlob(ctx, name(t, repo), d); !errors.Is(err, ErrBlobUnknown) {
				t.Errorf("%s: err %v, want ErrBlobUnknown", repo, err)
			}
			after, err := os.ReadDir(filepath.Join(s.StateDir(), locksDir))
			if err != nil && !errors.Is(err, os.ErrNotExist) {
				t.Fatal(err)
			}
			if len(after) != len(before) {
				t.Errorf("%s: a probe of an absent blob created a lock file", repo)
			}
		}
	})
}

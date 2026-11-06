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

package gc

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	ispec "github.com/opencontainers/image-spec/specs-go/v1"

	"k3sm.io/k3sm/pkg/ociregistry/ref"
)

// keepFirstRow rewrites n's index.json behind the store's back with only its
// first row, as a rolled-back or foreign-written index would leave it.
func (e *env) keepFirstRow(t *testing.T, n ref.Name) {
	t.Helper()
	idx, err := e.s.Index(n)
	if err != nil {
		t.Fatal(err)
	}
	idx.Manifests = idx.Manifests[:1]
	b, err := json.Marshal(idx)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(e.dir(t, n), "index.json"), b, 0o600); err != nil {
		t.Fatal(err)
	}
}

// TestDroppedRowsStopTheSweep drops rows from index.json behind the store's
// back, keeping one tag. The images whose rows went are described by no row,
// so without the row count every blob of theirs would be reaped with no brake.
// The sweep stops before it plans, reports the repository as stopped, reaps
// nothing, and stays stopped through a later push. Rows the store removes
// itself, by a tag delete or a sweep, do not trip it.
func TestDroppedRowsStopTheSweep(t *testing.T) {
	t.Run("rows dropped behind the store's back", func(t *testing.T) {
		e := newEnv(t)
		n := name(t, "app")
		e.clk.set(-2 * time.Hour)
		e.push(t, n, "v1", "kept", []byte("kept layer"))
		var lost []image
		for _, tag := range []string{"v2", "v3"} {
			lost = append(lost, e.push(t, n, tag, "lost "+tag, []byte(tag+" layer 1"), []byte(tag+" layer 2")))
		}
		c := e.collector(t, -3*time.Hour)
		e.ran(t)
		e.clk.set(0)
		e.sweep(t, c) // a clean sweep before the loss
		e.keepFirstRow(t, n)

		for i, between := range []func(){nil, func() { e.push(t, n, "v4", "later", []byte("later layer")) }} {
			if between != nil {
				between()
			}
			rep, err := c.Sweep(e.ctx)
			if !errors.Is(err, ErrRowsLost) || !slices.Equal(rep.Stopped, []string{"app"}) {
				t.Fatalf("sweep %d: %+v, %v; want ErrRowsLost for app", i, rep, err)
			}
			if len(rep.Objects) != 0 {
				t.Fatalf("sweep %d reaped %+v", i, rep.Objects)
			}
			for _, img := range lost {
				if err := e.whole(n, img); err != nil {
					t.Fatalf("sweep %d: %v", i, err)
				}
			}
		}
	})
	t.Run("tag deletes and sweeps keep the count", func(t *testing.T) {
		e := newEnv(t)
		n := name(t, "app")
		e.clk.set(-2 * time.Hour)
		e.push(t, n, "v1", "kept", []byte("kept layer 1"), []byte("kept layer 2"))
		gone := e.push(t, n, "v2", "gone", []byte("gone layer"))
		c := e.collector(t, -3*time.Hour)
		e.ran(t)
		e.clk.set(0)
		e.sweep(t, c)
		if err := e.s.DeleteTag(e.ctx, n, "v2"); err != nil {
			t.Fatal(err)
		}
		rep := e.sweep(t, c)
		if rep.Count(KindManifest) != 1 || e.has(n, gone.manifest.Digest) {
			t.Fatalf("report %+v: want the untagged row and its image reaped", rep)
		}
		if err := e.s.DeleteDigest(e.ctx, n, mustRow(t, e, n, "v1").Digest); err != nil {
			t.Fatal(err)
		}
		e.sweep(t, c)
	})
}

func mustRow(t *testing.T, e *env, n ref.Name, tag string) ispec.Descriptor {
	t.Helper()
	idx, err := e.s.Index(n)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range idx.Manifests {
		if r.Annotations[ispec.AnnotationRefName] == tag {
			return r
		}
	}
	t.Fatalf("no row for %s", tag)
	return ispec.Descriptor{}
}

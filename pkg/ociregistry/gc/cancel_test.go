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
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"

	"k3sm.io/k3sm/pkg/ociregistry/store"
)

// TestScanDedupesDigestsAndHonoursCancel pins that a body repeating one digest
// costs one scan result and one queue entry, that deduping the queue leaves a
// later naming by a readable body able to fail the plan, and that the mark
// stops on a cancelled context before it reads a body.
func TestScanDedupesDigestsAndHonoursCancel(t *testing.T) {
	dg := func(s string) digest.Digest { return digest.FromString(s) }
	x := dg("x")

	t.Run("a body with 1000 repeats of one digest yields one result and one queue entry", func(t *testing.T) {
		body := `[` + strings.Repeat(`"`+x.String()+`",`, 1000) + `"` + x.String() + `"]`
		if got := scanDigests([]byte(body)); len(got) != 1 || got[0] != x {
			t.Errorf("scan found %d digests, want exactly %v", len(got), x)
		}

		root, child := dg("root"), dg("child")
		idx := ispec.Index{Manifests: []ispec.Descriptor{{Digest: root, Annotations: map[string]string{ispec.AnnotationRefName: "t"}}}}
		cont := store.Contents{Blobs: []store.Blob{{Digest: root}, {Digest: child}, {Digest: x}}}
		reads := map[digest.Digest]int{}
		refsOf := func(d digest.Digest) (refs, error) {
			reads[d]++
			switch d {
			case root:
				return refs{Manifests: []ispec.Descriptor{{Digest: child}}}, nil
			case child:
				named := make([]digest.Digest, 1000)
				for i := range named {
					named[i] = x
				}
				return refs{}, &unparsedError{d: d, named: named}
			}
			return refs{}, &unverifiedError{d: d, size: 1}
		}
		if _, err := makePlan(idx, cont, time.Time{}, refsOf); err != nil {
			t.Fatal(err)
		}
		if reads[x] != 1 {
			t.Fatalf("the repeated digest entered the queue %d times, want 1", reads[x])
		}
	})

	t.Run("a repeated digest seen by the scan then named by a readable index still fails the plan", func(t *testing.T) {
		root, scan, index := dg("root"), dg("scan"), dg("index")
		idx := ispec.Index{Manifests: []ispec.Descriptor{{Digest: root, Annotations: map[string]string{ispec.AnnotationRefName: "t"}}}}
		cont := store.Contents{Blobs: []store.Blob{{Digest: root}, {Digest: scan}, {Digest: index}, {Digest: x}}}
		refsOf := func(d digest.Digest) (refs, error) {
			switch d {
			case root:
				return refs{Manifests: []ispec.Descriptor{{Digest: scan}, {Digest: index}}}, nil
			case scan:
				return refs{}, &unparsedError{d: d, named: []digest.Digest{x, x}}
			case index:
				return refs{Manifests: []ispec.Descriptor{{Digest: x}}}, nil
			}
			return refs{}, &unverifiedError{d: d, size: 1}
		}
		if _, err := makePlan(idx, cont, time.Time{}, refsOf); !errors.Is(err, ErrUnreadable) {
			t.Fatalf("got %v, want ErrUnreadable", err)
		}
	})

	t.Run("a cancelled context ends the mark with context.Canceled and deletes nothing", func(t *testing.T) {
		e := newEnv(t)
		n := name(t, "app")
		e.clk.set(-2 * time.Hour)
		img := e.push(t, n, "v1", "cancel")
		orphan := e.blob(t, n, []byte("orphan"))
		c := e.collector(t, -3*time.Hour)
		e.clk.set(time.Hour)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if _, err := c.mark(ctx, n, c.now().Add(-c.grace)); !errors.Is(err, context.Canceled) {
			t.Fatalf("mark: got %v, want context.Canceled", err)
		}
		if _, err := c.sweepRepo(ctx, n, false); !errors.Is(err, context.Canceled) {
			t.Fatalf("sweepRepo: got %v, want context.Canceled", err)
		}
		for _, d := range append(img.blobs(), orphan.Digest) {
			if !e.has(n, d) {
				t.Fatalf("blob %s was deleted", d)
			}
		}
	})
}

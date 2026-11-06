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
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/opencontainers/go-digest"
	"github.com/opencontainers/image-spec/specs-go"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"

	"k3sm.io/k3sm/pkg/ociregistry/ref"
	"k3sm.io/k3sm/pkg/ociregistry/store"
)

// indexBody is an image index naming children.
func indexBody(t *testing.T, children ...ispec.Descriptor) []byte {
	t.Helper()
	b, err := json.Marshal(ispec.Index{Versioned: specs.Versioned{SchemaVersion: 2}, MediaType: ispec.MediaTypeImageIndex, Manifests: children})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// keeper pushes a tagged image with enough layers that reaping one orphan is
// below the half brake.
func (e *env) keeper(t *testing.T, n ref.Name) image {
	t.Helper()
	return e.push(t, n, "keep", "keep "+n.String(), []byte(n.String()+"1"), []byte(n.String()+"2"), []byte(n.String()+"3"), []byte(n.String()+"4"))
}

// TestIndexChildThatIsNoManifestDoesNotStopTheSweep names, as an index's child,
// a blob that was never pushed as a manifest. Anyone who can push can do this,
// and a child need not exist at PUT, so the blob can arrive after the index and
// the descriptor can claim any media type. The child has no row and verifies, so
// the sweep keeps the blob and goes on. A child too large to verify is the plan
// failure TestUnreadableChildNeverReleasesWhatItNames pins.
func TestIndexChildThatIsNoManifestDoesNotStopTheSweep(t *testing.T) {
	for _, tc := range []struct {
		name, mediaType string
		body            []byte
	}{
		{"binary under a layer media type", ispec.MediaTypeImageLayerGzip, []byte("\x1f\x8bnot json")},
		{"binary under a manifest media type", ispec.MediaTypeImageManifest, []byte("\x1f\x8bnot json")},
		{"json with no shape under an index media type", ispec.MediaTypeImageIndex, []byte(`{"schemaVersion":2}`)},
		{"a schema1 body under a manifest media type", ispec.MediaTypeImageManifest, []byte(`{"schemaVersion":1,"fsLayers":[]}`)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t)
			n := name(t, "app")
			e.clk.set(-2 * time.Hour)
			e.keeper(t, n)
			child := e.blob(t, n, tc.body)
			child.MediaType = tc.mediaType
			idx := e.putManifest(t, n, "idx", ispec.MediaTypeImageIndex, indexBody(t, child))
			orphan := e.blob(t, n, []byte("orphan"))
			c := e.collector(t, -3*time.Hour)
			e.ran(t)
			e.clk.set(0)

			rep, err := c.Sweep(e.ctx)
			if err != nil || len(rep.Failed) != 0 {
				t.Fatalf("sweep: %+v, %v; want no failure", rep, err)
			}
			if e.has(n, orphan.Digest) {
				t.Error("the orphan survived")
			}
			if !e.has(n, child.Digest) || !e.has(n, idx.Digest) {
				t.Error("the sweep reaped the index or the blob it names")
			}
		})
	}
}

// TestChildDigestThatNamesNoBlobDoesNotStopTheSweep stores a manifest with a
// manifests field the server's image-manifest decoding ignores, naming a digest
// no blob can have. It names nothing, so there is nothing to protect.
func TestChildDigestThatNamesNoBlobDoesNotStopTheSweep(t *testing.T) {
	for _, bad := range []string{"not-a-digest", "sha256:short", "../../index.json", ""} {
		t.Run(bad, func(t *testing.T) {
			e := newEnv(t)
			n := name(t, "app")
			e.clk.set(-2 * time.Hour)
			img := e.keeper(t, n)
			body, err := json.Marshal(struct {
				SchemaVersion int                `json:"schemaVersion"`
				Config        ispec.Descriptor   `json:"config"`
				Layers        []ispec.Descriptor `json:"layers"`
				Manifests     []ispec.Descriptor `json:"manifests"`
			}{2, img.config, img.layers, []ispec.Descriptor{{MediaType: ispec.MediaTypeImageManifest, Digest: digest.Digest(bad)}}})
			if err != nil {
				t.Fatal(err)
			}
			e.putManifest(t, n, "odd", ispec.MediaTypeImageManifest, body)
			orphan := e.blob(t, n, []byte("orphan"))
			c := e.collector(t, -3*time.Hour)
			e.ran(t)
			e.clk.set(0)
			rep, err := c.Sweep(e.ctx)
			if err != nil || len(rep.Failed) != 0 {
				t.Fatalf("sweep: %+v, %v; want no failure", rep, err)
			}
			if e.has(n, orphan.Digest) {
				t.Error("the orphan survived")
			}
		})
	}
}

// TestChildWithARowStaysFailClosed is the other side of the rule: a child the
// index.json holds a row for was stored as a manifest, so a body the collector
// cannot read may name content it cannot see, and the repository's sweep stops.
func TestChildWithARowStaysFailClosed(t *testing.T) {
	for _, tc := range []struct {
		name string
		at   time.Duration
	}{
		{"past the grace", -2 * time.Hour},
		{"inside the grace", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t)
			n := name(t, "app")
			e.clk.set(-2 * time.Hour)
			e.keeper(t, n)
			orphan := e.blob(t, n, []byte("orphan"))
			c := e.collector(t, -3*time.Hour)
			e.ran(t)
			e.clk.set(tc.at)
			child := e.putManifest(t, n, "", ispec.MediaTypeImageIndex, []byte(`{"schemaVersion":2}`))
			e.putManifest(t, n, "idx", ispec.MediaTypeImageIndex, indexBody(t, child))
			e.clk.set(0)

			rep, err := c.Sweep(e.ctx)
			if !errors.Is(err, ErrUnreadable) || !slices.Equal(rep.Failed, []string{"app"}) {
				t.Fatalf("sweep: %+v, %v; want ErrUnreadable for app", rep, err)
			}
			if !e.has(n, orphan.Digest) {
				t.Error("a sweep over a child it could not read deleted the orphan")
			}
		})
	}
}

// TestRowlessChildThatParsesIsStillFollowed pins that a blob that does read as a
// manifest keeps what it names, row or no row.
func TestRowlessChildThatParsesIsStillFollowed(t *testing.T) {
	e := newEnv(t)
	n := name(t, "app")
	e.clk.set(-2 * time.Hour)
	e.keeper(t, n)
	cfg := e.blob(t, n, []byte(`{"seed":"rowless"}`))
	layer := e.blob(t, n, []byte("rowless layer"))
	child := e.blob(t, n, manifestBody(t, cfg, []ispec.Descriptor{layer}, nil))
	child.MediaType = ispec.MediaTypeImageManifest
	e.putManifest(t, n, "idx", ispec.MediaTypeImageIndex, indexBody(t, child))
	orphan := e.blob(t, n, []byte("orphan"))
	c := e.collector(t, -3*time.Hour)
	e.ran(t)
	e.clk.set(0)

	e.sweep(t, c)
	if e.has(n, orphan.Digest) {
		t.Error("the orphan survived")
	}
	for _, d := range []digest.Digest{child.Digest, cfg.Digest, layer.Digest} {
		if !e.has(n, d) {
			t.Errorf("%s was reaped; the rowless child names it", d)
		}
	}
}

// rawDesc is a descriptor as JSON text, for a body json.Marshal would not write.
func rawDesc(d digest.Digest) string {
	return `{"mediaType":"application/octet-stream","digest":"` + d.String() + `","size":1}`
}

// TestUnreadableChildNeverReleasesWhatItNames names, as an index's child with
// no row, a body the strict read refuses. A body that is too large or does not
// hash to its name may be anything, so the plan fails. Any other is kept along
// with every digest its JSON holds, so a real manifest's blobs survive, and a
// blob pushed as a child does not stop the sweep.
func TestUnreadableChildNeverReleasesWhatItNames(t *testing.T) {
	const mt = `"mediaType":"` + ispec.MediaTypeImageManifest + `"`
	for _, tc := range []struct {
		name string
		// body returns the child's body and the blobs it must keep; the
		// config and layers it names are stored past the grace.
		body func(t *testing.T, e *env, n ref.Name) ([]byte, []digest.Digest)
		// corrupt, when set, replaces the child's stored bytes.
		corrupt  []byte
		wantFail bool
	}{
		{
			name: "hash mismatch fails the plan",
			body: func(t *testing.T, e *env, n ref.Name) ([]byte, []digest.Digest) {
				cfg, layer := e.blob(t, n, []byte(`{"seed":"cfg"}`)), e.blob(t, n, []byte("layer"))
				return manifestBody(t, cfg, []ispec.Descriptor{layer}, nil), []digest.Digest{cfg.Digest, layer.Digest}
			},
			corrupt:  []byte("not what it was named for"),
			wantFail: true,
		},
		{
			name: "oversized fails the plan",
			body: func(t *testing.T, e *env, n ref.Name) ([]byte, []digest.Digest) {
				cfg := e.blob(t, n, []byte(`{"seed":"cfg"}`))
				return append(manifestBody(t, cfg, nil, nil), bytes.Repeat([]byte(" "), store.MaxManifestSize+1)...), []digest.Digest{cfg.Digest}
			},
			wantFail: true,
		},
		{
			name: "a duplicate config whose last value is null keeps both and the layers",
			body: func(t *testing.T, e *env, n ref.Name) ([]byte, []digest.Digest) {
				first, second := e.blob(t, n, []byte(`{"seed":"first"}`)), e.blob(t, n, []byte(`{"seed":"second"}`))
				l1, l2, l3 := e.blob(t, n, []byte("l1")), e.blob(t, n, []byte("l2")), e.blob(t, n, []byte("l3"))
				body := `{"schemaVersion":2,` + mt +
					`,"config":` + rawDesc(first.Digest) + `,"config":` + rawDesc(second.Digest) +
					`,"layers":[` + rawDesc(l1.Digest) + `,` + rawDesc(l2.Digest) + `],"layers":[` + rawDesc(l3.Digest) + `]` +
					`,"config":null}`
				return []byte(body), []digest.Digest{first.Digest, second.Digest, l1.Digest, l2.Digest, l3.Digest}
			},
		},
		{
			name: "a non-JSON blob does not stop the sweep",
			body: func(*testing.T, *env, ref.Name) ([]byte, []digest.Digest) {
				return []byte("\x1f\x8bnot json"), nil
			},
		},
		{
			name: "truncated JSON keeps the digests before the break",
			body: func(t *testing.T, e *env, n ref.Name) ([]byte, []digest.Digest) {
				cfg, layer := e.blob(t, n, []byte(`{"seed":"cfg"}`)), e.blob(t, n, []byte("layer"))
				body := `{"schemaVersion":2,` + mt + `,"config":` + rawDesc(cfg.Digest) + `,"layers":[` + rawDesc(layer.Digest) + `,{"digest":"sha256:`
				return []byte(body), []digest.Digest{cfg.Digest, layer.Digest}
			},
		},
		{
			name: "a number no float holds does not end the scan",
			body: func(t *testing.T, e *env, n ref.Name) ([]byte, []digest.Digest) {
				cfg := e.blob(t, n, []byte(`{"seed":"cfg"}`))
				body := `{"schemaVersion":2,` + mt + `,"huge":1e999,"config":` + rawDesc(cfg.Digest) + `,"config":null}`
				return []byte(body), []digest.Digest{cfg.Digest}
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t)
			n := name(t, "app")
			e.clk.set(-2 * time.Hour)
			e.keeper(t, n)
			body, keep := tc.body(t, e, n)
			child := e.blob(t, n, body)
			child.MediaType = ispec.MediaTypeImageManifest
			idx := e.putManifest(t, n, "idx", ispec.MediaTypeImageIndex, indexBody(t, child))
			orphan := e.blob(t, n, []byte("orphan"))
			if tc.corrupt != nil {
				p := e.blobFile(t, n, child.Digest)
				if err := os.Remove(p); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(p, tc.corrupt, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			c := e.collector(t, -3*time.Hour)
			e.ran(t)
			e.clk.set(0)

			rep, err := c.Sweep(e.ctx)
			if tc.wantFail {
				if !errors.Is(err, ErrUnreadable) || !slices.Equal(rep.Failed, []string{"app"}) {
					t.Fatalf("sweep: %+v, %v; want ErrUnreadable for app", rep, err)
				}
				if !e.has(n, orphan.Digest) {
					t.Error("a sweep that failed its plan reaped the orphan")
				}
			} else {
				if err != nil || len(rep.Failed) != 0 {
					t.Fatalf("sweep: %+v, %v; want no failure", rep, err)
				}
				if e.has(n, orphan.Digest) {
					t.Error("the orphan survived")
				}
			}
			for _, d := range append(keep, child.Digest, idx.Digest) {
				if !e.has(n, d) {
					t.Errorf("%s was reaped; the child may name it", d)
				}
			}
		})
	}
}

// unreadableBody is a body the strict read refuses that names ds as an index
// would.
func unreadableBody(ds ...digest.Digest) []byte {
	descs := make([]string, 0, len(ds))
	for _, d := range ds {
		descs = append(descs, rawDesc(d))
	}
	return []byte(`{"schemaVersion":1,"manifests":[` + strings.Join(descs, ",") + `]}`)
}

// TestScanFoundManifestIsFollowed pins what a digest found by the scan is: a
// candidate to follow through a body already in the store. A body that cannot be
// verified is referenced only and stops nothing, a manifest is followed, and a
// body the strict read refuses is scanned in turn.
func TestScanFoundManifestIsFollowed(t *testing.T) {
	// fixture is one repository past the grace, whose tagged index names as a
	// child the body root returns, with what the sweep must leave.
	type fixture struct {
		root []byte
		keep []digest.Digest
		// after runs once every blob is stored, to damage one.
		after func(t *testing.T, e *env, n ref.Name)
	}
	realManifest := func(t *testing.T, e *env, n ref.Name, seed string) (ispec.Descriptor, []digest.Digest) {
		t.Helper()
		cfg := e.blob(t, n, []byte(`{"seed":"`+seed+` config"}`))
		l1, l2 := e.blob(t, n, []byte(seed+" layer 1")), e.blob(t, n, []byte(seed+" layer 2"))
		m := e.blob(t, n, manifestBody(t, cfg, []ispec.Descriptor{l1, l2}, nil))
		m.MediaType = ispec.MediaTypeImageManifest
		return m, []digest.Digest{m.Digest, cfg.Digest, l1.Digest, l2.Digest}
	}
	for _, tc := range []struct {
		name string
		make func(t *testing.T, e *env, n ref.Name) fixture
	}{
		{"an unreadable index naming a real manifest keeps its config and layers", func(t *testing.T, e *env, n ref.Name) fixture {
			m, keep := realManifest(t, e, n, "real")
			return fixture{root: unreadableBody(m.Digest), keep: keep}
		}},
		{"a scan-found oversized blob is kept and does not fail the plan", func(t *testing.T, e *env, n ref.Name) fixture {
			big := e.blob(t, n, bytes.Repeat([]byte("L"), store.MaxManifestSize+1))
			m, keep := realManifest(t, e, n, "after the big one")
			return fixture{root: unreadableBody(big.Digest, m.Digest), keep: append(keep, big.Digest)}
		}},
		{"a scan-found body with a bad hash is kept and does not fail the plan", func(t *testing.T, e *env, n ref.Name) fixture {
			bad := e.blob(t, n, []byte("the bytes this digest names"))
			m, keep := realManifest(t, e, n, "after the bad one")
			return fixture{root: unreadableBody(bad.Digest, m.Digest), keep: append(keep, bad.Digest), after: func(t *testing.T, e *env, n ref.Name) {
				p := e.blobFile(t, n, bad.Digest)
				if err := os.Remove(p); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(p, []byte("other bytes"), 0o600); err != nil {
					t.Fatal(err)
				}
				e.backdate(t, p, -2*time.Hour)
			}}
		}},
		{"a scan-found unreadable body's digests are kept too", func(t *testing.T, e *env, n ref.Name) fixture {
			m, keep := realManifest(t, e, n, "two scans down")
			loose := e.blob(t, n, []byte("loose"))
			inner := e.blob(t, n, unreadableBody(m.Digest, loose.Digest))
			return fixture{root: unreadableBody(inner.Digest), keep: append(keep, inner.Digest, loose.Digest)}
		}},
		{"an index found by the scan has its children followed", func(t *testing.T, e *env, n ref.Name) fixture {
			m, keep := realManifest(t, e, n, "under a readable index")
			inner := e.blob(t, n, indexBody(t, m))
			return fixture{root: unreadableBody(inner.Digest), keep: append(keep, inner.Digest)}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t)
			n := name(t, "app")
			e.clk.set(-2 * time.Hour)
			e.keeper(t, n)
			f := tc.make(t, e, n)
			root := e.blob(t, n, f.root)
			root.MediaType = ispec.MediaTypeImageIndex
			idx := e.putManifest(t, n, "idx", ispec.MediaTypeImageIndex, indexBody(t, root))
			orphan := e.blob(t, n, []byte("orphan"))
			if f.after != nil {
				f.after(t, e, n)
			}
			c := e.collector(t, -3*time.Hour)
			e.ran(t)
			e.clk.set(0)

			rep, err := c.Sweep(e.ctx)
			if err != nil || len(rep.Failed) != 0 {
				t.Fatalf("sweep: %+v, %v; want no failure", rep, err)
			}
			if e.has(n, orphan.Digest) {
				t.Error("the orphan survived")
			}
			for _, d := range append(f.keep, root.Digest, idx.Digest) {
				if !e.has(n, d) {
					t.Errorf("%s was reaped; the scan found its way to it", d)
				}
			}
		})
	}

	// Two bodies cannot name each other's hash in a store, so the plan is given
	// them through refsOf. The stub fails on a repeat read, so a walk with no
	// visited set goes red instead of running out the test timeout.
	t.Run("a cycle between two unreadable bodies terminates", func(t *testing.T) {
		root, a, b := digest.FromString("root"), digest.FromString("a"), digest.FromString("b")
		layer, orphan := digest.FromString("layer"), digest.FromString("orphan")
		named := map[digest.Digest][]digest.Digest{a: {b}, b: {a, layer}}
		read := map[digest.Digest]int{}
		past := time.Now().Add(-time.Hour)
		var cont store.Contents
		for _, d := range []digest.Digest{root, a, b, layer, orphan} {
			cont.Blobs = append(cont.Blobs, store.Blob{Digest: d, Size: 1, ModTime: past})
		}
		idx := ispec.Index{Manifests: []ispec.Descriptor{{Digest: root, Annotations: map[string]string{ispec.AnnotationRefName: "idx"}}}}
		p, err := makePlan(idx, cont, time.Now(), func(d digest.Digest) (refs, error) {
			if read[d]++; read[d] > 1 {
				t.Fatalf("%s was read again", d)
			}
			if d == root {
				return refs{SchemaVersion: 2, Manifests: []ispec.Descriptor{{Digest: a}}}, nil
			}
			return refs{}, &unparsedError{d: d, cause: errors.New("refused"), named: named[d]}
		})
		if err != nil {
			t.Fatal(err)
		}
		if got := sortedKeys(p.blobs); !slices.Equal(got, []digest.Digest{orphan}) {
			t.Fatalf("the plan reaps %v, want only the orphan", got)
		}
		if read[a] != 1 || read[b] != 1 {
			t.Fatalf("reads %v: want one read of each body in the cycle", read)
		}
	})

	// A digest named many times in a body, or in several, is read once, and one
	// the store does not hold is not read at all.
	t.Run("only a stored body is read, and once", func(t *testing.T) {
		e := newEnv(t)
		n := name(t, "app")
		e.clk.set(-2 * time.Hour)
		e.keeper(t, n)
		m, keep := realManifest(t, e, n, "named twice")
		big := e.blob(t, n, bytes.Repeat([]byte("L"), store.MaxManifestSize+1))
		absent := digest.FromString("no such blob")
		inner := e.blob(t, n, unreadableBody(m.Digest, big.Digest, big.Digest))
		root := e.blob(t, n, unreadableBody(absent, m.Digest, inner.Digest, big.Digest, m.Digest))
		root.MediaType = ispec.MediaTypeImageIndex
		e.putManifest(t, n, "idx", ispec.MediaTypeImageIndex, indexBody(t, root))
		c := e.collector(t, -3*time.Hour)
		e.ran(t)
		e.clk.set(0)
		read := map[digest.Digest]int{}
		c.onRead = func(_ ref.Name, d digest.Digest) { read[d]++ }

		e.sweep(t, c)
		if read[absent] != 0 {
			t.Errorf("read %s, which the store does not hold", absent)
		}
		for _, d := range []digest.Digest{root.Digest, inner.Digest, m.Digest, big.Digest} {
			if read[d] != 1 {
				t.Errorf("%s was read %d times, want once", d, read[d])
			}
		}
		for _, d := range append(keep, big.Digest) {
			if !e.has(n, d) {
				t.Errorf("%s was reaped", d)
			}
		}
	})

	// A manifest with an old untagged row is a candidate for reaping until
	// something kept reaches it, and the scan reaching it counts.
	t.Run("a scan-found manifest with an untagged row keeps its row", func(t *testing.T) {
		e := newEnv(t)
		n := name(t, "app")
		e.clk.set(-2 * time.Hour)
		e.keeper(t, n)
		img := e.push(t, n, "", "an untagged image", []byte("untagged layer"))
		root := e.blob(t, n, unreadableBody(img.manifest.Digest))
		root.MediaType = ispec.MediaTypeImageIndex
		e.putManifest(t, n, "idx", ispec.MediaTypeImageIndex, indexBody(t, root))
		c := e.collector(t, -3*time.Hour)
		e.ran(t)
		e.clk.set(0)

		rep := e.sweep(t, c)
		if rep.Count(KindManifest) != 0 {
			t.Errorf("reaped a row the scan reached: %+v", rep.Objects)
		}
		for _, d := range img.blobs() {
			if !e.has(n, d) {
				t.Errorf("%s was reaped", d)
			}
		}
	})

	// What the scan finds is not what a readable index names: the same oversized
	// digest reached both ways fails the plan, whichever is walked first. The row
	// order decides that, and a pusher chooses the row order.
	t.Run("an oversized child of a readable index fails the plan though the scan found it first", func(t *testing.T) {
		for _, scanFirst := range []bool{true, false} {
			e := newEnv(t)
			n := name(t, "app")
			e.clk.set(-2 * time.Hour)
			e.keeper(t, n)
			big := e.blob(t, n, bytes.Repeat([]byte("L"), store.MaxManifestSize+1))
			big.MediaType = ispec.MediaTypeImageManifest
			scanner := e.blob(t, n, unreadableBody(big.Digest))
			scanner.MediaType = ispec.MediaTypeImageIndex
			strict := e.blob(t, n, indexBody(t, big))
			strict.MediaType = ispec.MediaTypeImageIndex
			first, second := scanner, strict
			if !scanFirst {
				first, second = strict, scanner
			}
			e.putManifest(t, n, "first", ispec.MediaTypeImageIndex, indexBody(t, first))
			e.putManifest(t, n, "second", ispec.MediaTypeImageIndex, indexBody(t, second))
			orphan := e.blob(t, n, []byte("orphan"))
			c := e.collector(t, -3*time.Hour)
			e.ran(t)
			e.clk.set(0)

			rep, err := c.Sweep(e.ctx)
			if !errors.Is(err, ErrUnreadable) || !slices.Equal(rep.Failed, []string{"app"}) {
				t.Fatalf("scanFirst=%v: sweep: %+v, %v; want ErrUnreadable for app", scanFirst, rep, err)
			}
			if !e.has(n, orphan.Digest) {
				t.Errorf("scanFirst=%v: a sweep that failed its plan reaped the orphan", scanFirst)
			}
		}
	})

	// A readable index the scan finds is followed as any index is, so its oversized
	// child fails the plan as a kept index's would.
	t.Run("a scan-found index naming an oversized child fails the plan", func(t *testing.T) {
		e := newEnv(t)
		n := name(t, "app")
		e.clk.set(-2 * time.Hour)
		e.keeper(t, n)
		big := e.blob(t, n, bytes.Repeat([]byte("L"), store.MaxManifestSize+1))
		big.MediaType = ispec.MediaTypeImageManifest
		inner := e.blob(t, n, indexBody(t, big))
		root := e.blob(t, n, unreadableBody(inner.Digest))
		root.MediaType = ispec.MediaTypeImageIndex
		e.putManifest(t, n, "idx", ispec.MediaTypeImageIndex, indexBody(t, root))
		c := e.collector(t, -3*time.Hour)
		e.ran(t)
		e.clk.set(0)

		if _, err := c.Sweep(e.ctx); !errors.Is(err, ErrUnreadable) {
			t.Fatalf("sweep: %v; want ErrUnreadable", err)
		}
	})
}

// TestScanDigests covers the token scan: what it finds, where it stops, and that
// a body at the size cap, in the shapes hardest on a decoder, ends without a panic.
func TestScanDigests(t *testing.T) {
	sha512 := digest.SHA512.FromString("x").String()
	for _, tc := range []struct {
		name, body string
		want       []digest.Digest
	}{
		{"every occurrence of a repeated key", `{"config":{"digest":"` + dgA + `"},"config":{"digest":"` + dgB + `"},"config":null}`, []digest.Digest{dgA, dgB}},
		{"any depth", `[[{"a":[{"b":{"c":"` + dgA + `"}}]}]]`, []digest.Digest{dgA}},
		{"a top-level string", `"` + dgA + `"`, []digest.Digest{dgA}},
		{"values after the first top-level value", `{} "` + dgA + `"`, []digest.Digest{dgA}},
		{"an escaped digest", `["sha256:\u0061` + dgA[8:] + `"]`, []digest.Digest{dgA}},
		{"sha512", `["` + sha512 + `"]`, []digest.Digest{digest.Digest(sha512)}},
		{"schema1 blobSum", `{"schemaVersion":1,"fsLayers":[{"blobSum":"` + dgA + `"}]}`, []digest.Digest{dgA}},
		{"past a number no float holds", `[1e999,-1e999,"` + dgA + `"]`, []digest.Digest{dgA}},
		{"not digests", `["sha256:short","md5:d41d8cd98f00b204e9800998ecf8427e","SHA256:` + dgA[7:] + `",1,true,null]`, nil},
		{"up to a syntax error", `["` + dgA + `",}"` + dgB + `"]`, []digest.Digest{dgA}},
		{"up to a truncated string", `["` + dgA + `","` + dgB[:20], []digest.Digest{dgA}},
		{"up to a mismatched close", `["` + dgA + `"}"` + dgB + `"`, []digest.Digest{dgA}},
		{"not JSON", "\x1f\x8b" + dgA, nil},
		{"empty", ``, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := scanDigests([]byte(tc.body)); !slices.Equal(got, tc.want) {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
		})
	}
	filled := func(open, unit string) []byte {
		n := (store.MaxManifestSize - len(open)) / len(unit)
		return append([]byte(open), bytes.Repeat([]byte(unit), n)...)
	}
	digestUnit := `"` + dgA + `",`
	for _, tc := range []struct {
		name string
		body []byte
		want int
	}{
		{"open arrays", filled("", "["), 0},
		{"open objects", filled("", `{"a":`), 0},
		{"a long string", filled(`"`, "x"), 0},
		{"many small values", filled("[", "1,"), 0},
		{"repeats of one digest", filled("[", digestUnit), 1},
	} {
		t.Run("at the cap: "+tc.name, func(t *testing.T) {
			if got := len(scanDigests(tc.body)); got != tc.want {
				t.Fatalf("found %d digests, want %d", got, tc.want)
			}
		})
	}
}

// TestSHA512ChildIsStillFollowed pins that the digest check is the child's own
// algorithm's: a sha512 child reads as any other, and a body it names by sha512
// is as named as one by sha256.
func TestSHA512ChildIsStillFollowed(t *testing.T) {
	put := func(t *testing.T, e *env, n ref.Name, body []byte) ispec.Descriptor {
		t.Helper()
		d := digest.SHA512.FromBytes(body)
		if err := e.s.PutBlob(e.ctx, n, d, bytes.NewReader(body)); err != nil {
			t.Fatal(err)
		}
		return ispec.Descriptor{MediaType: ispec.MediaTypeImageManifest, Digest: d, Size: int64(len(body))}
	}
	for _, tc := range []struct {
		name string
		body func(t *testing.T, cfg, layer ispec.Descriptor) []byte
	}{
		{"a child that parses", func(t *testing.T, cfg, layer ispec.Descriptor) []byte {
			return manifestBody(t, cfg, []ispec.Descriptor{layer}, nil)
		}},
		{"a child the strict read refuses", func(_ *testing.T, cfg, layer ispec.Descriptor) []byte {
			return []byte(`{"schemaVersion":2,"config":` + rawDesc(cfg.Digest) + `,"layers":[` + rawDesc(layer.Digest) + `],"config":null}`)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t)
			n := name(t, "app")
			e.clk.set(-2 * time.Hour)
			e.keeper(t, n)
			cfg := put(t, e, n, []byte(`{"seed":"sha512"}`))
			layer := put(t, e, n, []byte("sha512 layer"))
			child := put(t, e, n, tc.body(t, cfg, layer))
			e.putManifest(t, n, "idx", ispec.MediaTypeImageIndex, indexBody(t, child))
			orphan := e.blob(t, n, []byte("orphan"))
			c := e.collector(t, -3*time.Hour)
			e.ran(t)
			e.clk.set(0)

			e.sweep(t, c)
			if e.has(n, orphan.Digest) {
				t.Error("the orphan survived")
			}
			for _, d := range []digest.Digest{child.Digest, cfg.Digest, layer.Digest} {
				if !e.has(n, d) {
					t.Errorf("%s was reaped; the sha512 child names it", d)
				}
			}
		})
	}
}

// TestReviewedRepositoryStaysReviewedAfterAFailure fails a reviewed repository
// and an unreviewed one in the same sweep, by a body that cannot be found and by
// one that cannot be opened. The reviewed one stays in the marker, so a failure
// that passes does not send it back to report-only; the unreviewed one stays out.
func TestReviewedRepositoryStaysReviewedAfterAFailure(t *testing.T) {
	for _, tc := range []struct {
		name string
		root bool // the case cannot run as root
		// breakIt fails reads of the body at p and returns its repair.
		breakIt func(t *testing.T, p string) func()
	}{
		{"a body that cannot be found", false, func(t *testing.T, p string) func() {
			if err := os.Rename(p, p+".aside"); err != nil {
				t.Fatal(err)
			}
			return func() {
				if err := os.Rename(p+".aside", p); err != nil {
					t.Fatal(err)
				}
			}
		}},
		{"a body that cannot be opened", true, func(t *testing.T, p string) func() {
			if err := os.Chmod(p, 0); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = os.Chmod(p, 0o600) })
			return func() {
				if err := os.Chmod(p, 0o600); err != nil {
					t.Fatal(err)
				}
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.root && os.Geteuid() == 0 {
				t.Skip("root opens a mode-0 file")
			}
			e := newEnv(t)
			e.clk.set(-2 * time.Hour)
			old, fresh := name(t, "reviewed"), name(t, "unreviewed")
			oldImg := e.keeper(t, old)
			oldOrphan := e.blob(t, old, []byte("reviewed orphan")).Digest
			c := e.collector(t, -3*time.Hour)
			e.ran(t) // names only the repository that exists so far
			e.clk.set(-2 * time.Hour)
			freshImg := e.keeper(t, fresh)
			freshOrphan := e.blob(t, fresh, []byte("unreviewed orphan")).Digest
			e.clk.set(0)
			repairOld := tc.breakIt(t, e.blobFile(t, old, oldImg.manifest.Digest))
			repairFresh := tc.breakIt(t, e.blobFile(t, fresh, freshImg.manifest.Digest))

			rep, err := c.Sweep(e.ctx)
			if err == nil || !slices.Equal(rep.Failed, []string{"reviewed", "unreviewed"}) || !slices.Equal(rep.Reviewing, []string{"unreviewed"}) {
				t.Fatalf("sweep under the failure: %+v, %v; want both failed and only unreviewed in review", rep, err)
			}
			marker, err := os.ReadFile(filepath.Join(e.s.StateDir(), MarkerName))
			if err != nil {
				t.Fatal(err)
			}
			var m markerRecord
			if err := json.Unmarshal(marker, &m); err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(m.Reviewed, []string{"reviewed"}) {
				t.Fatalf("the marker names %v after the failure, want only the repository reviewed before it", m.Reviewed)
			}

			repairOld()
			repairFresh()
			rep = e.sweep(t, c)
			if !slices.Equal(rep.Reviewing, []string{"unreviewed"}) {
				t.Fatalf("sweep after the repair: %+v; want only unreviewed in review", rep)
			}
			if e.has(old, oldOrphan) {
				t.Error("the reviewed repository went back to report-only: its orphan survived")
			}
			if !e.has(fresh, freshOrphan) {
				t.Error("the unreviewed repository deleted before its review")
			}
		})
	}
}

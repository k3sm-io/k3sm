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
	"slices"
	"testing"
	"time"

	"github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"

	"k3sm.io/k3sm/pkg/ociregistry/ref"
)

// referrer pushes an untagged manifest whose subject is subject, with a config
// and one layer of its own.
func (e *env) referrer(t *testing.T, n ref.Name, seed string, subject ispec.Descriptor) image {
	t.Helper()
	var img image
	img.config = e.blob(t, n, []byte(`{"seed":"`+seed+`"}`))
	img.layers = []ispec.Descriptor{e.blob(t, n, []byte(seed+" signature"))}
	img.body = manifestBody(t, img.config, img.layers, &subject)
	img.manifest = e.putManifest(t, n, "", ispec.MediaTypeImageManifest, img.body)
	return img
}

// TestSubjectRowDoesNotStickTheBrake: a repository whose rows are all untagged,
// one of them a referrer whose subject is gone or is itself reaped, is emptied
// by a sweep. The referrer is an orphan, so it does not hold its row, and the
// plan then removes every row: the brake lets that through, as it does any
// repository a delete emptied, instead of stopping every sweep until a person
// deletes the referrer.
func TestSubjectRowDoesNotStickTheBrake(t *testing.T) {
	cases := []struct {
		name string
		// gone makes the subject absent, or leaves it for the sweep to reap.
		gone func(t *testing.T, e *env, n ref.Name, subject image)
		// chained adds a referrer whose subject is the first referrer.
		chained bool
	}{
		{
			name: "subject row deleted",
			gone: func(t *testing.T, e *env, n ref.Name, subject image) {
				t.Helper()
				if err := e.s.DeleteDigest(e.ctx, n, subject.manifest.Digest); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "subject untagged past the grace",
			gone: func(*testing.T, *env, ref.Name, image) {},
		},
		{
			name:    "a referrer of a referrer of a reaped subject",
			gone:    func(*testing.T, *env, ref.Name, image) {},
			chained: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t)
			n := name(t, "app")
			e.clk.set(-2 * time.Hour)
			subject := e.push(t, n, "", "subject", []byte("layer one"), []byte("layer two"))
			r := e.referrer(t, n, "sig", subject.manifest)
			all := slices.Concat(subject.blobs(), r.blobs())
			if tc.chained {
				all = append(all, e.referrer(t, n, "sig-of-sig", r.manifest).blobs()...)
			}
			tc.gone(t, e, n, subject)
			c := e.collector(t, -3*time.Hour)
			e.ran(t)
			e.clk.set(0)

			for i := range 3 {
				rep, err := c.Sweep(e.ctx)
				if err != nil || len(rep.Stopped) != 0 || len(rep.Failed) != 0 {
					t.Fatalf("sweep %d: %v, stopped %v, failed %v; want no stop", i, err, rep.Stopped, rep.Failed)
				}
			}
			for _, d := range all {
				if e.has(n, d) {
					t.Errorf("%s survived", d)
				}
			}
			idx, err := e.s.Index(n)
			if err == nil && len(idx.Manifests) != 0 {
				t.Errorf("index keeps %d rows, want none", len(idx.Manifests))
			}
		})
	}
}

// TestLiveSubjectKeepsItsReferrer: a referrer whose subject is present and kept
// keeps its row and every blob it names, and so does a referrer of that
// referrer, while the sweep reaps what nothing keeps.
func TestLiveSubjectKeepsItsReferrer(t *testing.T) {
	cases := []struct {
		name string
		// subject pushes the subject at offset -2h and returns it.
		subject func(t *testing.T, e *env, n ref.Name) image
	}{
		{
			name: "tagged subject",
			subject: func(t *testing.T, e *env, n ref.Name) image {
				return e.push(t, n, "v1", "subject", []byte("layer"))
			},
		},
		{
			name: "untagged subject a tagged index names",
			subject: func(t *testing.T, e *env, n ref.Name) image {
				img := e.push(t, n, "", "subject", []byte("layer"))
				body, err := jsonIndex(img.manifest)
				if err != nil {
					t.Fatal(err)
				}
				e.putManifest(t, n, "multi", ispec.MediaTypeImageIndex, body)
				return img
			},
		},
		{
			name: "untagged subject inside the grace",
			subject: func(t *testing.T, e *env, n ref.Name) image {
				e.clk.set(-10 * time.Minute)
				defer e.clk.set(-2 * time.Hour)
				return e.push(t, n, "", "subject", []byte("layer"))
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t)
			n := name(t, "app")
			e.clk.set(-2 * time.Hour)
			subject := tc.subject(t, e, n)
			r := e.referrer(t, n, "sig", subject.manifest)
			rr := e.referrer(t, n, "sig-of-sig", r.manifest)
			gone := e.push(t, n, "", "gone", []byte("gone layer"))
			c := e.collector(t, -3*time.Hour)
			e.ran(t)
			e.clk.set(0)

			rep := e.sweep(t, c)
			if len(rep.Stopped) != 0 || len(rep.Failed) != 0 {
				t.Fatalf("stopped %v, failed %v; want neither", rep.Stopped, rep.Failed)
			}
			for _, d := range slices.Concat(subject.blobs(), r.blobs(), rr.blobs()) {
				if !e.has(n, d) {
					t.Errorf("%s was reaped", d)
				}
			}
			for _, d := range gone.blobs() {
				if e.has(n, d) {
					t.Errorf("%s survived", d)
				}
			}
			idx, err := e.s.Index(n)
			if err != nil {
				t.Fatal(err)
			}
			rows := map[digest.Digest]bool{}
			for _, row := range idx.Manifests {
				rows[row.Digest] = true
			}
			for _, d := range []digest.Digest{r.manifest.Digest, rr.manifest.Digest} {
				if !rows[d] {
					t.Errorf("the referrer row %s was removed", d)
				}
			}
		})
	}
}

// TestUnparsableSubjectKeepsItsReferrer: a referrer whose subject digest is not
// a digest names nothing the collector can judge, so it fails closed: the row
// and every blob it names are kept, as an untagged row with a subject was
// before referrers could be orphaned.
func TestUnparsableSubjectKeepsItsReferrer(t *testing.T) {
	for _, bad := range []string{"", "sha256:not-hex", "md5:d41d8cd98f00b204e9800998ecf8427e", "nonsense"} {
		t.Run(bad, func(t *testing.T) {
			e := newEnv(t)
			n := name(t, "app")
			e.clk.set(-2 * time.Hour)
			r := e.referrer(t, n, "sig", ispec.Descriptor{MediaType: ispec.MediaTypeImageManifest, Digest: digest.Digest(bad), Size: 2})
			c := e.collector(t, -3*time.Hour)
			e.ran(t)
			e.clk.set(0)

			rep := e.sweep(t, c)
			if len(rep.Stopped) != 0 || len(rep.Failed) != 0 || len(rep.Objects) != 0 {
				t.Fatalf("report %+v, want nothing reaped and no stop", rep)
			}
			for _, d := range r.blobs() {
				if !e.has(n, d) {
					t.Errorf("%s was reaped", d)
				}
			}
			idx, err := e.s.Index(n)
			if err != nil {
				t.Fatal(err)
			}
			if len(idx.Manifests) != 1 || idx.Manifests[0].Digest != r.manifest.Digest {
				t.Errorf("rows %v, want the referrer's", idx.Manifests)
			}
		})
	}
}

// TestSubjectPushedBetweenMarkAndLock: the mark finds a referrer whose subject
// is absent and plans to reap it, then the subject is pushed before the locked
// pass. The rows changed, so the locked pass deletes nothing and the sweep
// marks again, finds the subject live, and keeps the referrer and its blobs.
func TestSubjectPushedBetweenMarkAndLock(t *testing.T) {
	e := newEnv(t)
	n := name(t, "app")
	cfgBody, layerBody := []byte(`{"seed":"late subject"}`), []byte("late layer")
	cfg := ispec.Descriptor{Digest: digest.FromBytes(cfgBody), Size: int64(len(cfgBody))}
	layer := ispec.Descriptor{MediaType: ispec.MediaTypeImageLayer, Digest: digest.FromBytes(layerBody), Size: int64(len(layerBody))}
	subjectBody := manifestBody(t, cfg, []ispec.Descriptor{layer}, nil)
	subject := ispec.Descriptor{MediaType: ispec.MediaTypeImageManifest, Digest: digest.FromBytes(subjectBody), Size: int64(len(subjectBody))}

	e.clk.set(-2 * time.Hour)
	r := e.referrer(t, n, "sig", subject)
	c := e.collector(t, -3*time.Hour)
	e.ran(t)
	e.clk.set(0)

	// Each mark reads the referrer's body once, so two reads are a replan.
	marks := 0
	c.onRead = func(m ref.Name, d digest.Digest) {
		if m == n && d == r.manifest.Digest {
			marks++
		}
	}
	var pushed bool
	c.afterMark = func(m ref.Name) {
		if m != n || pushed {
			return
		}
		pushed = true
		e.blob(t, n, cfgBody)
		e.blob(t, n, layerBody)
		e.putManifest(t, n, "", ispec.MediaTypeImageManifest, subjectBody)
	}
	rep := e.sweep(t, c)
	if marks != 2 {
		t.Errorf("the referrer was read by %d marks, want 2 (a replan after the push)", marks)
	}
	if len(rep.Objects) != 0 || len(rep.Stopped) != 0 || len(rep.Failed) != 0 {
		t.Errorf("report %+v, want nothing reaped and no stop", rep)
	}
	for _, d := range slices.Concat(r.blobs(), []digest.Digest{subject.Digest, cfg.Digest, layer.Digest}) {
		if !e.has(n, d) {
			t.Errorf("%s was reaped", d)
		}
	}
	idx, err := e.s.Index(n)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.ContainsFunc(idx.Manifests, func(row ispec.Descriptor) bool { return row.Digest == r.manifest.Digest }) {
		t.Error("the referrer row was removed")
	}
}

// TestSubjectTouchedBetweenMarkAndLock: the mark finds an untagged subject past
// the grace, plans to reap it and so its referrer, then a write touches the
// subject before the locked pass. The rows did not change, so there is no
// replan: the locked pass re-states the blobs, finds the subject inside the
// grace, keeps it and its referrer, and only what both passes reap goes.
func TestSubjectTouchedBetweenMarkAndLock(t *testing.T) {
	e := newEnv(t)
	n := name(t, "app")
	e.clk.set(-2 * time.Hour)
	subject := e.push(t, n, "", "subject", []byte("layer"))
	r := e.referrer(t, n, "sig", subject.manifest)
	c := e.collector(t, -3*time.Hour)
	e.ran(t)
	e.clk.set(0)

	marks := 0
	c.afterMark = func(m ref.Name) {
		if m != n {
			return
		}
		marks++
		if err := e.s.TouchBlob(e.ctx, n, subject.manifest.Digest); err != nil {
			t.Error(err)
		}
	}
	rep := e.sweep(t, c)
	if marks != 1 {
		t.Errorf("the repository was marked %d times, want 1", marks)
	}
	if len(rep.Objects) != 0 || len(rep.Stopped) != 0 || len(rep.Failed) != 0 {
		t.Errorf("report %+v, want nothing reaped and no stop", rep)
	}
	for _, d := range slices.Concat(subject.blobs(), r.blobs()) {
		if !e.has(n, d) {
			t.Errorf("%s was reaped", d)
		}
	}
	idx, err := e.s.Index(n)
	if err != nil {
		t.Fatal(err)
	}
	if len(idx.Manifests) != 2 {
		t.Errorf("index has %d rows, want the subject's and the referrer's", len(idx.Manifests))
	}
}

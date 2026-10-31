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

	"github.com/opencontainers/go-digest"
	"github.com/opencontainers/image-spec/specs-go"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	"golang.org/x/sys/unix"

	"k3sm.io/k3sm/pkg/ociregistry/store"
)

func TestNewRefusesNoGrace(t *testing.T) {
	e := newEnv(t)
	if _, err := New(e.s, Options{}); err == nil {
		t.Fatal("New accepted a zero grace")
	}
}

func TestNoSweepWithinOneGraceOfStart(t *testing.T) {
	e := newEnv(t)
	c := e.collector(t, 0)
	e.ran(t)
	for _, at := range []time.Duration{0, grace - time.Second} {
		e.clk.set(at)
		if _, err := c.Sweep(e.ctx); !errors.Is(err, ErrTooSoon) {
			t.Fatalf("sweep at +%s: %v, want ErrTooSoon", at, err)
		}
	}
	e.clk.set(grace)
	e.sweep(t, c)
}

func TestFirstSweepReportsOnly(t *testing.T) {
	e := newEnv(t)
	n := name(t, "app")
	e.clk.set(-2 * time.Hour)
	e.push(t, n, "v1", "app", []byte("layer"))
	orphan := e.blob(t, n, []byte("orphan"))
	c := e.collector(t, -3*time.Hour)
	e.clk.set(0)

	rep := e.sweep(t, c)
	if !rep.ReportOnly || rep.Count(KindBlob) != 1 || rep.Objects[0].Name != orphan.Digest.String() {
		t.Fatalf("first sweep: %+v, want report-only naming the orphan", rep)
	}
	if !e.has(n, orphan.Digest) {
		t.Fatal("the report-only sweep deleted the orphan")
	}
	if _, err := os.Lstat(filepath.Join(e.s.StateDir(), MarkerName)); err != nil {
		t.Fatalf("no marker after the first sweep: %v", err)
	}
	rep = e.sweep(t, c)
	if rep.ReportOnly || rep.Count(KindBlob) != 1 || e.has(n, orphan.Digest) {
		t.Fatalf("second sweep: %+v, want the orphan reaped", rep)
	}
}

func TestRetention(t *testing.T) {
	e := newEnv(t)
	n := name(t, "app")
	e.clk.set(-2 * time.Hour)
	shared := []byte("shared layer")
	tagged := e.push(t, n, "v1", "tagged", shared)

	// A tagged index whose children are untagged rows.
	childA := e.push(t, n, "", "child-a", []byte("a layer"))
	childB := e.push(t, n, "", "child-b", []byte("b layer"))
	idxBody, err := jsonIndex(childA.manifest, childB.manifest)
	if err != nil {
		t.Fatal(err)
	}
	index := e.putManifest(t, n, "multi", ispec.MediaTypeImageIndex, idxBody)

	// An untagged referrer: it carries a subject.
	refCfg := e.blob(t, n, []byte(`{"seed":"sig"}`))
	refLayer := e.blob(t, n, []byte("signature"))
	subject := tagged.manifest
	referrerBody := manifestBody(t, refCfg, []ispec.Descriptor{refLayer}, &subject)
	referrer := e.putManifest(t, n, "", ispec.MediaTypeImageManifest, referrerBody)

	// An untagged image past the grace, with one exclusive and one shared
	// layer: its row, manifest, config and exclusive layer go.
	gone := e.push(t, n, "", "gone", []byte("exclusive layer"), shared)
	oldSession := e.session(t, n, "stale")
	e.backdate(t, e.sessionFile(t, n, oldSession), -2*time.Hour)

	// An untagged image inside the grace stays.
	e.clk.set(-10 * time.Minute)
	young := e.push(t, n, "", "young", []byte("young layer"))
	liveSession := e.session(t, n, "live")

	c := e.collector(t, -3*time.Hour)
	e.ran(t)
	e.clk.set(0)
	rep := e.sweep(t, c)

	reaped := []digest.Digest{gone.manifest.Digest, gone.config.Digest, gone.layers[0].Digest}
	for _, d := range reaped {
		if e.has(n, d) {
			t.Errorf("%s survived", d)
		}
	}
	kept := slices.Concat(tagged.blobs(), childA.blobs(), childB.blobs(), young.blobs(),
		[]digest.Digest{index.Digest, referrer.Digest, refCfg.Digest, refLayer.Digest})
	for _, d := range kept {
		if !e.has(n, d) {
			t.Errorf("%s was reaped", d)
		}
	}
	idx, err := e.s.Index(n)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range idx.Manifests {
		if r.Digest == gone.manifest.Digest {
			t.Error("the untagged row past the grace is still in index.json")
		}
	}
	if len(idx.Manifests) != 6 {
		t.Errorf("index has %d rows, want 6 (v1, two children, multi, referrer, young)", len(idx.Manifests))
	}
	if _, err := e.s.UploadSize(e.ctx, n, oldSession); err == nil {
		t.Error("the idle session survived")
	}
	if _, err := e.s.UploadSize(e.ctx, n, liveSession); err != nil {
		t.Errorf("the live session was reaped: %v", err)
	}
	if rep.Count(KindManifest) != 1 || rep.Count(KindBlob) != 3 || rep.Count(KindUpload) != 1 {
		t.Errorf("report %+v, want 1 manifest, 3 blobs, 1 upload", rep)
	}
}

func jsonIndex(children ...ispec.Descriptor) ([]byte, error) {
	return json.Marshal(ispec.Index{Versioned: specs.Versioned{SchemaVersion: 2}, MediaType: ispec.MediaTypeImageIndex, Manifests: children})
}

func TestStopsAtHalfARepository(t *testing.T) {
	e := newEnv(t)
	n := name(t, "app")
	e.clk.set(-2 * time.Hour)
	img := e.push(t, n, "v1", "app", []byte("layer"))
	var orphans []digest.Digest
	for _, b := range []string{"o1", "o2", "o3", "o4"} {
		orphans = append(orphans, e.blob(t, n, []byte(b)).Digest)
	}
	c := e.collector(t, -3*time.Hour)
	e.ran(t)
	e.clk.set(0)

	rep, err := c.Sweep(e.ctx)
	if !errors.Is(err, ErrMassDelete) || !slices.Equal(rep.Stopped, []string{"app"}) {
		t.Fatalf("sweep of 4 of 7 blobs: %v, stopped %v; want ErrMassDelete for app", err, rep.Stopped)
	}
	for _, d := range orphans {
		if !e.has(n, d) {
			t.Fatalf("the stopped sweep deleted %s", d)
		}
	}

	// Emptied by delete: every row is gone, so every blob may go.
	if err := e.s.DeleteDigest(e.ctx, n, img.manifest.Digest); err != nil {
		t.Fatal(err)
	}
	rep = e.sweep(t, c)
	if rep.Count(KindBlob) != 7 {
		t.Fatalf("sweep of the emptied repository reaped %d blobs, want 7", rep.Count(KindBlob))
	}
	// The layout goes once index.json is past the grace too.
	if rep.Count(KindRepository) != 0 {
		t.Fatal("the layout went while index.json was inside the grace")
	}
	e.backdate(t, filepath.Join(e.dir(t, n), "index.json"), -2*time.Hour)
	rep = e.sweep(t, c)
	if rep.Count(KindRepository) != 1 {
		t.Fatalf("report %+v, want the empty repository reaped", rep)
	}
	repos, err := e.s.Repositories()
	if err != nil || len(repos) != 0 {
		t.Fatalf("repositories after the empty one went: %v, %v", repos, err)
	}
	// A push recreates it.
	e.push(t, n, "v2", "again", []byte("new layer"))
	if _, err := e.s.Tags(n); err != nil {
		t.Fatalf("push after the layout went: %v", err)
	}
}

// TestReapsCommittedSession covers a commit that linked the session into
// blobs/ and stopped before removing it: the session's inode has two links,
// so the store's session check refuses it and a cancel cannot remove it.
func TestReapsCommittedSession(t *testing.T) {
	e := newEnv(t)
	n := name(t, "app")
	body := "committed body"
	id := e.session(t, n, body)
	d := digest.FromString(body)
	blob := e.blobFile(t, n, d)
	if err := os.MkdirAll(filepath.Dir(blob), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(e.sessionFile(t, n, id), blob); err != nil {
		t.Fatal(err)
	}
	if err := e.s.CancelUpload(e.ctx, n, id); !errors.Is(err, store.ErrUploadUnknown) {
		t.Fatalf("cancel of a linked session: %v, want ErrUploadUnknown", err)
	}

	// A second such session whose lock an upload operation holds is left.
	busy := e.session(t, n, "busy body")
	busyBlob := e.blobFile(t, n, digest.FromString("busy body"))
	if err := os.Link(e.sessionFile(t, n, busy), busyBlob); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(e.sessionFile(t, n, busy))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX); err != nil {
		t.Fatal(err)
	}

	c := e.collector(t, -3*time.Hour)
	e.ran(t)
	e.clk.set(0)
	rep := e.sweep(t, c)
	if rep.Count(KindUpload) != 1 || rep.Objects[0].Name != id || rep.Objects[0].Reason != reasonCommitted {
		t.Fatalf("report %+v, want the committed session reaped", rep)
	}
	if _, err := os.Lstat(e.sessionFile(t, n, id)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the committed session is still there: %v", err)
	}
	if b, err := os.ReadFile(blob); err != nil || string(b) != body {
		t.Fatalf("the blob lost its content: %q, %v", b, err)
	}
	if _, err := os.Lstat(e.sessionFile(t, n, busy)); err != nil {
		t.Fatalf("the busy session was reaped: %v", err)
	}
}

// TestReapsTempLinks covers .tmp-<uuid> links a crash left between a blob
// replacement's link and its rename: they are reaped and never counted as
// blobs, so they neither trip the half-repository stop nor are mistaken for
// content.
func TestReapsTempLinks(t *testing.T) {
	e := newEnv(t)
	n := name(t, "app")
	img := e.push(t, n, "v1", "app", []byte("layer"))
	src := e.blobFile(t, n, img.layers[0].Digest)
	var temps []string
	for _, id := range []string{
		"0b0e8e7a-1c1d-4e3f-8a9b-0c1d2e3f4a5b",
		"1b0e8e7a-1c1d-4e3f-8a9b-0c1d2e3f4a5b",
		"2b0e8e7a-1c1d-4e3f-8a9b-0c1d2e3f4a5b",
		"3b0e8e7a-1c1d-4e3f-8a9b-0c1d2e3f4a5b",
	} {
		p := filepath.Join(filepath.Dir(src), ".tmp-"+id)
		if err := os.Link(src, p); err != nil {
			t.Fatal(err)
		}
		temps = append(temps, p)
	}
	cont, err := e.s.Contents(n)
	if err != nil {
		t.Fatal(err)
	}
	if len(cont.Blobs) != 3 || len(cont.Temps) != 4 {
		t.Fatalf("contents: %d blobs, %d temps; want 3 and 4", len(cont.Blobs), len(cont.Temps))
	}

	c := e.collector(t, -3*time.Hour)
	e.ran(t)
	e.clk.set(0)
	rep := e.sweep(t, c)
	if rep.Count(KindTemp) != 4 || rep.Count(KindBlob) != 0 {
		t.Fatalf("report %+v, want 4 temps and no blob", rep)
	}
	for _, p := range temps {
		if _, err := os.Lstat(p); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("%s survived: %v", p, err)
		}
	}
	for _, d := range img.blobs() {
		if !e.has(n, d) {
			t.Errorf("%s was reaped", d)
		}
	}
}

// TestFailsClosedOnAMissingManifest covers a tagged row whose manifest body
// is gone: what it referenced cannot be known, so nothing is deleted.
func TestFailsClosedOnAMissingManifest(t *testing.T) {
	e := newEnv(t)
	n := name(t, "app")
	e.clk.set(-2 * time.Hour)
	img := e.push(t, n, "v1", "app", []byte("layer"))
	if err := os.Remove(e.blobFile(t, n, img.manifest.Digest)); err != nil {
		t.Fatal(err)
	}
	c := e.collector(t, -3*time.Hour)
	e.ran(t)
	e.clk.set(0)
	if _, err := c.Sweep(e.ctx); !errors.Is(err, ErrUnreadable) {
		t.Fatalf("sweep: %v, want ErrUnreadable", err)
	}
	for _, d := range img.blobs()[1:] {
		if !e.has(n, d) {
			t.Errorf("%s was reaped", d)
		}
	}
}

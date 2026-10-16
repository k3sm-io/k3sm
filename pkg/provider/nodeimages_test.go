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

package provider

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"

	runtimev1 "k3sm.io/apis/runtime/v1"
	"k3sm.io/runtimed/pkg/image"
)

// fakeImageRuntime is an ImageInventory holding a fixed index, or failing. A
// non-nil block makes every listing wait until it is closed (or its context
// ends), standing in for a slow or stuck index read.
type fakeImageRuntime struct {
	mu       sync.Mutex
	entries  []image.IndexEntry
	err      error
	block    chan struct{}
	calls    int
	deadline time.Duration
}

func (f *fakeImageRuntime) ImageIndexSnapshot(ctx context.Context) ([]image.IndexEntry, error) {
	f.mu.Lock()
	f.calls++
	if d, ok := ctx.Deadline(); ok {
		f.deadline = time.Until(d)
	}
	block := f.block
	f.mu.Unlock()
	if block != nil {
		select {
		case <-block:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return nil, f.err
	}
	return append([]image.IndexEntry(nil), f.entries...), nil
}

func (f *fakeImageRuntime) set(entries []image.IndexEntry, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.entries, f.err = entries, err
}

// dig returns the sha256 digest of seed, a distinct well-formed digest per seed.
func dig(seed string) string {
	return fmt.Sprintf("sha256:%x", sha256.Sum256([]byte(seed)))
}

// indexEntry builds one index record whose manifest total is size bytes: the
// manifest descriptor carries the whole size, with no config or layers.
func indexEntry(ref, digest string, size int64) image.IndexEntry {
	return image.IndexEntry{
		Reference:  ref,
		Manifest:   &runtimev1.ImageManifest{Reference: ref},
		Descriptor: &runtimev1.Descriptor{Digest: digest, Size: size},
	}
}

// newImageStatusHarness is newNodeStatusHarness with the runtime's image
// inventory passed through NodeStatusConfig.Images, the production path.
func newImageStatusHarness(t *testing.T, inv ImageInventory, log *slog.Logger) *nodeStatusHarness {
	t.Helper()
	h := newNodeStatusHarness(t, bootstrapNode())
	p, err := NewNodeStatusProvider(NodeStatusConfig{
		Node:           bootstrapNode(),
		DataRoot:       "/var/lib/k3sm",
		RuntimeHealthy: h.runtimeHealthy,
		Images:         inv,
		Log:            log,
	})
	if err != nil {
		t.Fatalf("NewNodeStatusProvider: %v", err)
	}
	p.sample = h.sample
	p.now = h.nowFn
	p.publish = h.publishFn
	h.p = p
	return h
}

// refreshThenStep runs one cycle, which starts an image listing, waits for
// that listing to finish, then runs the cycle that publishes its answer.
func refreshThenStep(h *nodeStatusHarness) *corev1.Node {
	h.t.Helper()
	h.step()
	h.p.imagesWG.Wait()
	return h.step()
}

// TestNodeStatusListsImages is the gate: the published node carries
// Node.status.images built from the runtime's image list the way a kubelet
// builds it — one entry per image, digest references then tags, sizeBytes from
// the manifest total, largest first, the 50 largest kept — and a failed listing
// keeps the previous list instead of publishing an empty one.
func TestNodeStatusListsImages(t *testing.T) {
	app, tool, base := dig("app"), dig("tool"), dig("base")
	three := []image.IndexEntry{
		indexEntry("registry.example/tool:latest", tool, 100),
		indexEntry("registry.example/app:v1", app, 300),
		indexEntry("registry.example/base@"+base, base, 200),
	}
	wantThree := []corev1.ContainerImage{
		{Names: []string{"registry.example/app@" + app, "registry.example/app:v1"}, SizeBytes: 300},
		{Names: []string{"registry.example/base@" + base}, SizeBytes: 200},
		{Names: []string{"registry.example/tool@" + tool, "registry.example/tool:latest"}, SizeBytes: 100},
	}

	t.Run("three images, sorted largest first", func(t *testing.T) {
		h := newImageStatusHarness(t, &fakeImageRuntime{entries: three}, discardLog())
		if got := refreshThenStep(h).Status.Images; !reflect.DeepEqual(got, wantThree) {
			t.Errorf("Status.Images =\n  %+v\nwant\n  %+v", got, wantThree)
		}
	})

	t.Run("one image under two tags is one entry with every name", func(t *testing.T) {
		entries := append([]image.IndexEntry{indexEntry("registry.example/app:stable", app, 300)}, three...)
		h := newImageStatusHarness(t, &fakeImageRuntime{entries: entries}, discardLog())
		got := refreshThenStep(h).Status.Images
		want := []string{"registry.example/app@" + app, "registry.example/app:stable", "registry.example/app:v1"}
		if len(got) != 3 || !reflect.DeepEqual(got[0].Names, want) || got[0].SizeBytes != 300 {
			t.Errorf("Status.Images = %+v, want 3 entries, the first named %v at 300 bytes", got, want)
		}
	})

	t.Run("55 images keep the 50 largest", func(t *testing.T) {
		var entries []image.IndexEntry
		for i := 1; i <= 55; i++ {
			entries = append(entries, indexEntry(fmt.Sprintf("registry.example/img%02d:v1", i), dig(fmt.Sprint(i)), int64(i)))
		}
		h := newImageStatusHarness(t, &fakeImageRuntime{entries: entries}, discardLog())
		got := refreshThenStep(h).Status.Images
		if len(got) != nodeStatusMaxImages || nodeStatusMaxImages != 50 {
			t.Fatalf("published %d images (cap %d), want the kubelet default of 50", len(got), nodeStatusMaxImages)
		}
		for i, img := range got {
			if want := int64(55 - i); img.SizeBytes != want {
				t.Errorf("Status.Images[%d].SizeBytes = %d, want %d (largest first, the 5 smallest dropped)", i, img.SizeBytes, want)
			}
		}
	})

	t.Run("a failed listing keeps the previous images", func(t *testing.T) {
		fake := &fakeImageRuntime{entries: three}
		h := newImageStatusHarness(t, fake, discardLog())
		if got := refreshThenStep(h).Status.Images; !reflect.DeepEqual(got, wantThree) {
			t.Fatalf("first refresh Status.Images = %+v, want %+v", got, wantThree)
		}
		fake.set(nil, errors.New("index unreadable"))
		if got := refreshThenStep(h).Status.Images; !reflect.DeepEqual(got, wantThree) {
			t.Errorf("after a failed listing Status.Images = %+v, want the previous %+v", got, wantThree)
		}
		fake.set(three[:1], nil)
		if got := refreshThenStep(h).Status.Images; len(got) != 1 || got[0].SizeBytes != 100 {
			t.Errorf("after recovery Status.Images = %+v, want the one image the runtime now lists", got)
		}
	})

	t.Run("a failure before any listing publishes no images", func(t *testing.T) {
		h := newImageStatusHarness(t, &fakeImageRuntime{err: errors.New("down")}, discardLog())
		if got := refreshThenStep(h).Status.Images; got != nil {
			t.Errorf("Status.Images = %+v, want none before a listing has succeeded", got)
		}
	})

	t.Run("a runtime without an image store publishes no images", func(t *testing.T) {
		h := newImageStatusHarness(t, nil, discardLog())
		if got := refreshThenStep(h).Status.Images; got != nil {
			t.Errorf("Status.Images = %+v, want none without an image inventory", got)
		}
	})
}

// TestNodeStatusImageListingIsOffThePublishPath pins that a listing which does
// not return never delays a publication: the cycle publishes the cached list at
// once, a second cycle starts no second listing, and the answer lands on the
// first cycle after the listing returns. The listing runs under a 5s bound.
func TestNodeStatusImageListingIsOffThePublishPath(t *testing.T) {
	fake := &fakeImageRuntime{entries: []image.IndexEntry{indexEntry("registry.example/app:v1", dig("app"), 7)}, block: make(chan struct{})}
	h := newImageStatusHarness(t, fake, discardLog())

	for i := range 2 {
		done := make(chan struct{}, 1)
		go func() {
			h.p.monitor.sampleOnce()
			if err := h.p.publishOnce(context.Background()); err != nil {
				t.Errorf("publishOnce: %v", err)
			}
			done <- struct{}{}
		}()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Fatalf("cycle %d did not publish within 2s while the image listing was blocked", i+1)
		}
	}
	h.mu.Lock()
	published := len(h.published)
	last := h.published[published-1]
	h.mu.Unlock()
	if published != 2 || last.Status.Images != nil {
		t.Errorf("published %d nodes, last with images %+v; want 2 publications, no images yet", published, last.Status.Images)
	}

	close(fake.block)
	h.p.imagesWG.Wait()
	fake.mu.Lock()
	calls, deadline := fake.calls, fake.deadline
	fake.mu.Unlock()
	if calls != 1 {
		t.Errorf("listing ran %d times across two cycles, want 1 (one in flight at a time)", calls)
	}
	if deadline <= 0 || deadline > nodeImagesListTimeout || nodeImagesListTimeout != 5*time.Second {
		t.Errorf("listing context deadline %v (bound %v), want a bound of at most 5s", deadline, nodeImagesListTimeout)
	}
	if got := h.step().Status.Images; len(got) != 1 || got[0].SizeBytes != 7 {
		t.Errorf("after the listing returned Status.Images = %+v, want the one listed image", got)
	}
}

// TestNodeStatusImageListingLogsTransitions pins the log contract: a failing
// listing warns once when it starts failing, not every cycle, and the
// recovery is logged once.
func TestNodeStatusImageListingLogsTransitions(t *testing.T) {
	var logs bytes.Buffer
	fake := &fakeImageRuntime{entries: []image.IndexEntry{indexEntry("registry.example/app:v1", dig("app"), 7)}}
	h := newImageStatusHarness(t, fake, slog.New(slog.NewTextHandler(&logs, nil)))
	count := func(level string) int { return strings.Count(logs.String(), "level="+level) }

	refreshThenStep(h)
	fake.set(nil, errors.New("damaged index record"))
	for range 3 {
		refreshThenStep(h)
	}
	if n := count("WARN"); n != 1 || !strings.Contains(logs.String(), "damaged index record") {
		t.Errorf("three failing refreshes logged %d Warn lines, want 1 carrying the error:\n%s", n, logs.String())
	}
	fake.set([]image.IndexEntry{indexEntry("registry.example/app:v1", dig("app"), 7)}, nil)
	refreshThenStep(h)
	refreshThenStep(h)
	if n := count("INFO"); n != 1 {
		t.Errorf("recovery logged %d Info lines, want 1:\n%s", n, logs.String())
	}
	fake.set(nil, errors.New("damaged again"))
	refreshThenStep(h)
	if n := count("WARN"); n != 2 {
		t.Errorf("a second failure after recovery: %d Warn lines in total, want 2:\n%s", n, logs.String())
	}
}

// TestNodeImagesNames pins how names are formed and grouped: the
// multi-platform index digest wins over the manifest's own (it is what the tag
// pointed at), a registry port is not mistaken for a tag with or without a
// digest, an entry with no recorded digest stands alone under its reference,
// and a reference carrying userinfo is never published.
func TestNodeImagesNames(t *testing.T) {
	viaIndex := indexEntry("localhost:5000/team/app:v2", dig("manifest"), 10)
	viaIndex.Manifest.IndexDigest = dig("index")
	tests := []struct {
		name    string
		entries []image.IndexEntry
		want    []corev1.ContainerImage
	}{
		{
			name:    "index digest wins and the port survives",
			entries: []image.IndexEntry{viaIndex},
			want:    []corev1.ContainerImage{{Names: []string{"localhost:5000/team/app@" + dig("index"), "localhost:5000/team/app:v2"}, SizeBytes: 10}},
		},
		{
			name:    "port without a tag",
			entries: []image.IndexEntry{indexEntry("registry:5000/app", dig("p"), 3)},
			want:    []corev1.ContainerImage{{Names: []string{"registry:5000/app@" + dig("p"), "registry:5000/app"}, SizeBytes: 3}},
		},
		{
			name:    "port without a tag, by digest",
			entries: []image.IndexEntry{indexEntry("registry:5000/app@"+dig("p"), dig("p"), 3)},
			want:    []corev1.ContainerImage{{Names: []string{"registry:5000/app@" + dig("p")}, SizeBytes: 3}},
		},
		{
			name:    "no recorded digest",
			entries: []image.IndexEntry{{Reference: "registry.example/old:v1", Manifest: &runtimev1.ImageManifest{}}},
			want:    []corev1.ContainerImage{{Names: []string{"registry.example/old:v1"}, SizeBytes: 0}},
		},
		{
			name: "userinfo is dropped",
			entries: []image.IndexEntry{
				indexEntry("user:secret@registry.example/app:v1", dig("u1"), 9),
				indexEntry("user@registry.example/app:v1", dig("u2"), 9),
				indexEntry("user:secret@registry.example:5000", dig("u3"), 9),
				indexEntry("registry.example/ok:v1", dig("ok"), 1),
			},
			want: []corev1.ContainerImage{{Names: []string{"registry.example/ok@" + dig("ok"), "registry.example/ok:v1"}, SizeBytes: 1}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := nodeImages(tt.entries, -1)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("nodeImages =\n  %+v\nwant\n  %+v", got, tt.want)
			}
			for _, img := range got {
				for _, n := range img.Names {
					if strings.Contains(n, "secret") || strings.HasPrefix(n, "user") {
						t.Errorf("published name %q carries userinfo", n)
					}
				}
			}
		})
	}
}

// TestNodeImagesTieBreakAtCap pins that equal sizes are ordered by name, so the
// 50 kept at the cap are the same set in the same order whatever order the
// index returned them in.
func TestNodeImagesTieBreakAtCap(t *testing.T) {
	var entries []image.IndexEntry
	for i := range 55 {
		entries = append(entries, indexEntry(fmt.Sprintf("registry.example/img%02d:v1", i), dig(fmt.Sprint(i)), 42))
	}
	want := nodeImages(entries, nodeStatusMaxImages)
	if len(want) != nodeStatusMaxImages {
		t.Fatalf("kept %d images, want %d", len(want), nodeStatusMaxImages)
	}
	r := rand.New(rand.NewPCG(1, 2))
	for trial := range 20 {
		shuffled := append([]image.IndexEntry(nil), entries...)
		r.Shuffle(len(shuffled), func(i, j int) { shuffled[i], shuffled[j] = shuffled[j], shuffled[i] })
		if got := nodeImages(shuffled, nodeStatusMaxImages); !reflect.DeepEqual(got, want) {
			t.Fatalf("trial %d: shuffled input changed the output at the cap", trial)
		}
	}
	for i := 1; i < len(want); i++ {
		if want[i-1].Names[0] >= want[i].Names[0] {
			t.Errorf("equal sizes not ordered by name at %d: %q then %q", i, want[i-1].Names[0], want[i].Names[0])
		}
	}
}

// TestNodeImagesNamesCap pins the kubelet's five-names-per-image cap, digests
// first.
func TestNodeImagesNamesCap(t *testing.T) {
	var entries []image.IndexEntry
	for i := range 7 {
		entries = append(entries, indexEntry(fmt.Sprintf("registry.example/app:t%d", i), dig("same"), 5))
	}
	got := nodeImages(entries, nodeStatusMaxImages)
	if len(got) != 1 || len(got[0].Names) != nodeStatusMaxNamesPerImage || got[0].Names[0] != "registry.example/app@"+dig("same") {
		t.Errorf("nodeImages = %+v, want one entry with %d names, the digest first", got, nodeStatusMaxNamesPerImage)
	}
}

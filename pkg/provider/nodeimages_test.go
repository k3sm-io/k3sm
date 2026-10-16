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
	"errors"
	"fmt"
	"log/slog"
	"reflect"
	"strings"
	"sync"
	"testing"

	corev1 "k8s.io/api/core/v1"

	runtimev1 "k3sm.io/apis/runtime/v1"
	"k3sm.io/runtimed/pkg/image"
)

// fakeImageRuntime is an ImageInventory holding a fixed index, or failing.
type fakeImageRuntime struct {
	mu      sync.Mutex
	entries []image.IndexEntry
	err     error
}

func (f *fakeImageRuntime) ImageIndexSnapshot(ctx context.Context) ([]image.IndexEntry, error) {
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

// TestNodeStatusListsImages is the gate: the published node carries
// Node.status.images built from the runtime's image list the way a kubelet
// builds it — one entry per image, digest references then tags, sizeBytes from
// the manifest total, largest first, the 50 largest kept — and a failed listing
// keeps the previous list instead of publishing an empty one.
func TestNodeStatusListsImages(t *testing.T) {
	const (
		app  = "sha256:aaaa"
		tool = "sha256:bbbb"
		base = "sha256:cccc"
	)
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
		if got := h.step().Status.Images; !reflect.DeepEqual(got, wantThree) {
			t.Errorf("Status.Images =\n  %+v\nwant\n  %+v", got, wantThree)
		}
	})

	t.Run("one image under two tags is one entry with every name", func(t *testing.T) {
		entries := append([]image.IndexEntry{indexEntry("registry.example/app:stable", app, 300)}, three...)
		h := newImageStatusHarness(t, &fakeImageRuntime{entries: entries}, discardLog())
		got := h.step().Status.Images
		want := []string{"registry.example/app@" + app, "registry.example/app:stable", "registry.example/app:v1"}
		if len(got) != 3 || !reflect.DeepEqual(got[0].Names, want) || got[0].SizeBytes != 300 {
			t.Errorf("Status.Images = %+v, want 3 entries, the first named %v at 300 bytes", got, want)
		}
	})

	t.Run("55 images keep the 50 largest", func(t *testing.T) {
		var entries []image.IndexEntry
		for i := 1; i <= 55; i++ {
			entries = append(entries, indexEntry(fmt.Sprintf("registry.example/img%02d:v1", i), fmt.Sprintf("sha256:%02d", i), int64(i)))
		}
		h := newImageStatusHarness(t, &fakeImageRuntime{entries: entries}, discardLog())
		got := h.step().Status.Images
		if len(got) != nodeStatusMaxImages || nodeStatusMaxImages != 50 {
			t.Fatalf("published %d images (cap %d), want the kubelet default of 50", len(got), nodeStatusMaxImages)
		}
		for i, img := range got {
			if want := int64(55 - i); img.SizeBytes != want {
				t.Errorf("Status.Images[%d].SizeBytes = %d, want %d (largest first, the 5 smallest dropped)", i, img.SizeBytes, want)
			}
		}
	})

	t.Run("a failed listing keeps the previous images and warns once", func(t *testing.T) {
		var logs bytes.Buffer
		fake := &fakeImageRuntime{entries: three}
		h := newImageStatusHarness(t, fake, slog.New(slog.NewTextHandler(&logs, nil)))
		if got := h.step().Status.Images; !reflect.DeepEqual(got, wantThree) {
			t.Fatalf("first refresh Status.Images = %+v, want %+v", got, wantThree)
		}
		fake.set(nil, errors.New("index unreadable"))
		if got := h.step().Status.Images; !reflect.DeepEqual(got, wantThree) {
			t.Errorf("after a failed listing Status.Images = %+v, want the previous %+v", got, wantThree)
		}
		if n := strings.Count(logs.String(), "level=WARN"); n != 1 {
			t.Errorf("one failed listing logged %d Warn lines, want 1:\n%s", n, logs.String())
		}
		if !strings.Contains(logs.String(), "index unreadable") {
			t.Errorf("Warn line does not carry the listing error:\n%s", logs.String())
		}
		fake.set(three[:1], nil)
		if got := h.step().Status.Images; len(got) != 1 || got[0].SizeBytes != 100 {
			t.Errorf("after recovery Status.Images = %+v, want the one image the runtime now lists", got)
		}
	})

	t.Run("a failure before any listing publishes no images", func(t *testing.T) {
		h := newImageStatusHarness(t, &fakeImageRuntime{err: errors.New("down")}, discardLog())
		if got := h.step().Status.Images; got != nil {
			t.Errorf("Status.Images = %+v, want none before a listing has succeeded", got)
		}
	})

	t.Run("a runtime without an image store publishes no images", func(t *testing.T) {
		h := newImageStatusHarness(t, nil, discardLog())
		if got := h.step().Status.Images; got != nil {
			t.Errorf("Status.Images = %+v, want none without an image inventory", got)
		}
	})
}

// TestNodeImagesDigestNames pins how digest references are formed and grouped:
// the multi-platform index digest wins over the manifest's own (it is what the
// tag pointed at), a registry port is not mistaken for a tag, and an entry with
// no recorded digest stands alone under its reference.
func TestNodeImagesDigestNames(t *testing.T) {
	viaIndex := indexEntry("localhost:5000/team/app:v2", "sha256:manifest", 10)
	viaIndex.Manifest.IndexDigest = "sha256:index"
	noDigest := image.IndexEntry{Reference: "registry.example/old:v1", Manifest: &runtimev1.ImageManifest{}}

	got := nodeImages([]image.IndexEntry{viaIndex, noDigest}, -1)
	want := []corev1.ContainerImage{
		{Names: []string{"localhost:5000/team/app@sha256:index", "localhost:5000/team/app:v2"}, SizeBytes: 10},
		{Names: []string{"registry.example/old:v1"}, SizeBytes: 0},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("nodeImages =\n  %+v\nwant\n  %+v", got, want)
	}
}

// TestNodeImagesNamesCap pins the kubelet's five-names-per-image cap, digests
// first.
func TestNodeImagesNamesCap(t *testing.T) {
	var entries []image.IndexEntry
	for i := range 7 {
		entries = append(entries, indexEntry(fmt.Sprintf("registry.example/app:t%d", i), "sha256:same", 5))
	}
	got := nodeImages(entries, nodeStatusMaxImages)
	if len(got) != 1 || len(got[0].Names) != nodeStatusMaxNamesPerImage || got[0].Names[0] != "registry.example/app@sha256:same" {
		t.Errorf("nodeImages = %+v, want one entry with %d names, the digest first", got, nodeStatusMaxNamesPerImage)
	}
}

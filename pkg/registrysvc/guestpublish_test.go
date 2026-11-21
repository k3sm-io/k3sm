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

package registrysvc

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"

	artifactv1 "k3sm.io/apis/artifact/v1"
	"k3sm.io/k3sm/pkg/ociregistry/api"
	"k3sm.io/k3sm/pkg/ociregistry/store"
	"k3sm.io/runtimed/pkg/guestartifacts"
)

// guestTestRegistry is the real registry API over a temporary store, behind a
// handler that counts the writes a publish sends.
type guestTestRegistry struct {
	rt http.RoundTripper

	mu           sync.Mutex
	uploads      int // blob upload sessions started (POST .../blobs/uploads/)
	manifestPuts int // manifest PUTs
}

func newGuestTestRegistry(t *testing.T) *guestTestRegistry {
	t.Helper()
	st, err := store.OpenWorkDir(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	srv, err := api.New(api.Config{Store: st, GCGrace: time.Hour, Authorize: api.AllowAll, FreeSpace: plentyFree})
	if err != nil {
		t.Fatal(err)
	}
	g := &guestTestRegistry{}
	g.rt = handlerTransport{h: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		g.mu.Lock()
		switch {
		case r.Method == http.MethodPost && strings.Contains(r.URL.Path, "/blobs/uploads/"):
			g.uploads++
		case r.Method == http.MethodPut && strings.Contains(r.URL.Path, "/manifests/"):
			g.manifestPuts++
		}
		g.mu.Unlock()
		srv.ServeHTTP(w, r)
	})}
	return g
}

// counts returns and resets the write counters.
func (g *guestTestRegistry) counts() (uploads, manifestPuts int) {
	g.mu.Lock()
	defer g.mu.Unlock()
	uploads, manifestPuts = g.uploads, g.manifestPuts
	g.uploads, g.manifestPuts = 0, 0
	return uploads, manifestPuts
}

// access is a GuestPublisher.Access that reaches this registry.
func (g *guestTestRegistry) access(context.Context) (string, []remote.Option, error) {
	return guestTestAuthority, []remote.Option{remote.WithTransport(g.rt)}, nil
}

// manifest reads the manifest the guest tag names, and its digest.
func (g *guestTestRegistry) manifest(t *testing.T, tag string) (ispec.Manifest, string) {
	t.Helper()
	ref, err := name.NewTag(guestTestAuthority + "/" + guestartifacts.GuestStoreRepository + ":" + tag)
	if err != nil {
		t.Fatal(err)
	}
	desc, err := remote.Get(ref, remote.WithTransport(g.rt), remote.WithContext(t.Context()))
	if err != nil {
		t.Fatalf("get %s: %v", ref, err)
	}
	var m ispec.Manifest
	if err := json.Unmarshal(desc.Manifest, &m); err != nil {
		t.Fatalf("decode manifest: %v", err)
	}
	return m, desc.Digest.String()
}

const guestTestAuthority = "registry.test"

// writeGuestFile writes body to dir/name and returns its path and hex sha256.
func writeGuestFile(t *testing.T, dir, name, body string) (string, string) {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return p, digest.FromString(body).Encoded()
}

// guestTestSet is the set the server would publish for a pin whose digests
// are those of the two files, derived through the runtime's own seam.
func guestTestSet(t *testing.T, version, kernelPath, kernelHex, initPath, initHex string) GuestSet {
	t.Helper()
	a, err := guestartifacts.NewStoreArtifact(version, guestartifacts.GuestKernelPin{
		KernelVersion:   "v6.18.57",
		ImageSHA256:     kernelHex,
		InitramfsSHA256: initHex,
		ReleaseURL:      "https://release.invalid/guest",
	})
	if err != nil {
		t.Fatal(err)
	}
	return GuestSet{Artifact: a, Files: map[string]string{
		guestartifacts.ImageFileName:     kernelPath,
		guestartifacts.InitramfsFileName: initPath,
	}}
}

// TestServerPublishesGuestArtifacts proves the server publishes the guest
// kernel and initramfs it verified to its own registry as the guest
// repository's pin tag, with the guest artifactType and the pin's digests as
// its two raw layers; that a second publish uploads no blob and rewrites no
// tag; that a tag naming another manifest is corrected; and that a failed
// attempt is retried with a growing backoff.
func TestServerPublishesGuestArtifacts(t *testing.T) {
	const pin = "v6.18.57-bc162009c43b"
	dir := t.TempDir()
	kernelPath, kernelHex := writeGuestFile(t, dir, guestartifacts.ImageFileName, "fake guest kernel image")
	initPath, initHex := writeGuestFile(t, dir, guestartifacts.InitramfsFileName, "fake guest initramfs cpio")
	kernelDigest, initDigest := digest.NewDigestFromEncoded(digest.SHA256, kernelHex), digest.NewDigestFromEncoded(digest.SHA256, initHex)
	set := guestTestSet(t, pin, kernelPath, kernelHex, initPath, initHex)

	t.Run("publishes the manifest, then re-publishes as a no-op", func(t *testing.T) {
		reg := newGuestTestRegistry(t)
		p := GuestPublisher{Access: reg.access, Logger: quietLogger()}

		got, err := p.Publish(t.Context(), set)
		if err != nil {
			t.Fatalf("publish: %v", err)
		}
		if !got.Tagged {
			t.Error("first publish: Tagged = false, want the tag written")
		}
		uploads, puts := reg.counts()
		if uploads != 3 || puts != 1 {
			t.Errorf("first publish: %d blob uploads and %d manifest PUTs, want 3 (config, kernel, initramfs) and 1", uploads, puts)
		}

		m, d := reg.manifest(t, pin)
		if d != got.Digest.String() {
			t.Errorf("tag names %s, publish reported %s", d, got.Digest)
		}
		if m.MediaType != ispec.MediaTypeImageManifest {
			t.Errorf("mediaType = %q, want %q", m.MediaType, ispec.MediaTypeImageManifest)
		}
		if m.ArtifactType != artifactv1.ArtifactTypeGuest {
			t.Errorf("artifactType = %q, want %q", m.ArtifactType, artifactv1.ArtifactTypeGuest)
		}
		if m.Config.MediaType != ispec.MediaTypeEmptyJSON || m.Config.Digest != ispec.DescriptorEmptyJSON.Digest {
			t.Errorf("config = %s %s, want the empty JSON descriptor", m.Config.MediaType, m.Config.Digest)
		}
		want := []struct {
			mediaType string
			digest    digest.Digest
			size      int64
			title     string
		}{
			{artifactv1.MediaTypeGuestKernel, kernelDigest, int64(len("fake guest kernel image")), guestartifacts.ImageFileName},
			{artifactv1.MediaTypeGuestInitramfs, initDigest, int64(len("fake guest initramfs cpio")), guestartifacts.InitramfsFileName},
		}
		if len(m.Layers) != len(want) {
			t.Fatalf("%d layers, want %d", len(m.Layers), len(want))
		}
		for i, w := range want {
			l := m.Layers[i]
			if l.MediaType != w.mediaType || l.Digest != w.digest || l.Size != w.size {
				t.Errorf("layer %d = %s %s %d, want %s %s %d", i, l.MediaType, l.Digest, l.Size, w.mediaType, w.digest, w.size)
			}
			if got := l.Annotations[ispec.AnnotationTitle]; got != w.title {
				t.Errorf("layer %d title = %q, want %q (the worker finds the layer by it)", i, got, w.title)
			}
		}

		again, err := p.Publish(t.Context(), set)
		if err != nil {
			t.Fatalf("re-publish: %v", err)
		}
		if again.Tagged {
			t.Error("re-publish: Tagged = true, want the tag left alone")
		}
		if again.Digest != got.Digest {
			t.Errorf("re-publish digest %s, want %s", again.Digest, got.Digest)
		}
		if uploads, puts := reg.counts(); uploads != 0 || puts != 0 {
			t.Errorf("re-publish: %d blob uploads and %d manifest PUTs, want 0 and 0", uploads, puts)
		}
	})

	t.Run("a tag naming another manifest is rewritten, present blobs are not", func(t *testing.T) {
		reg := newGuestTestRegistry(t)
		p := GuestPublisher{Access: reg.access, Logger: quietLogger()}
		stalePath, staleHex := writeGuestFile(t, dir, "stale-initramfs", "an older initramfs")
		stale := guestTestSet(t, pin, kernelPath, kernelHex, stalePath, staleHex)
		if _, err := p.Publish(t.Context(), stale); err != nil {
			t.Fatalf("publish stale: %v", err)
		}
		reg.counts()

		got, err := p.Publish(t.Context(), set)
		if err != nil {
			t.Fatalf("publish: %v", err)
		}
		if !got.Tagged {
			t.Error("Tagged = false, want the stale tag rewritten")
		}
		if uploads, puts := reg.counts(); uploads != 1 || puts != 1 {
			t.Errorf("%d blob uploads and %d manifest PUTs, want 1 (the new initramfs only) and 1", uploads, puts)
		}
		if _, d := reg.manifest(t, pin); d != got.Digest.String() {
			t.Errorf("tag names %s, want %s", d, got.Digest)
		}
	})

	t.Run("a file whose bytes do not match the pin is refused", func(t *testing.T) {
		reg := newGuestTestRegistry(t)
		p := GuestPublisher{Access: reg.access, Logger: quietLogger()}
		bad := guestTestSet(t, pin, kernelPath, digest.FromString("not the kernel").Encoded(), initPath, initHex)
		if _, err := p.Publish(t.Context(), bad); err == nil {
			t.Fatal("publish of a mismatched kernel succeeded")
		}
		if uploads, puts := reg.counts(); uploads != 0 || puts != 0 {
			t.Errorf("%d blob uploads and %d manifest PUTs for a refused file, want 0 and 0", uploads, puts)
		}
	})

	t.Run("a failed attempt is retried with a growing backoff", func(t *testing.T) {
		reg := newGuestTestRegistry(t)
		failures := 3
		var waits []time.Duration
		p := GuestPublisher{
			Logger: quietLogger(),
			Access: func(ctx context.Context) (string, []remote.Option, error) {
				if failures > 0 {
					failures--
					return "", nil, errors.New("registry not up yet")
				}
				return reg.access(ctx)
			},
			wait: func(_ context.Context, d time.Duration) bool {
				waits = append(waits, d)
				return true
			},
		}
		if !p.Run(t.Context(), set) {
			t.Fatal("Run gave up, want it to publish after the failures")
		}
		if len(waits) != 3 {
			t.Fatalf("%d waits, want 3: %v", len(waits), waits)
		}
		for i := 1; i < len(waits); i++ {
			if waits[i] <= waits[i-1] {
				t.Errorf("backoff did not grow: %v", waits)
			}
		}
		if _, d := reg.manifest(t, pin); d == "" {
			t.Error("no manifest after Run")
		}
	})

	t.Run("a cancelled run stops without publishing", func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		p := GuestPublisher{
			Logger: quietLogger(),
			Access: func(context.Context) (string, []remote.Option, error) {
				return "", nil, errors.New("registry not up yet")
			},
			wait: func(context.Context, time.Duration) bool { cancel(); return false },
		}
		if p.Run(ctx, set) {
			t.Fatal("Run reported a publish under a cancelled context")
		}
	})
}

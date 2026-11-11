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

package main

import (
	"net/http"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	ggcrv1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/google/go-containerregistry/pkg/v1/remote"

	"k3sm.io/k3sm/pkg/registrysvc"
)

// repointOnHead serves every request with the registry server in process, and
// once the first manifest HEAD of tag has been answered, runs repoint before
// the answer reaches the client: a push that lands between untag's comparison
// and its DELETE.
type repointOnHead struct {
	base    http.RoundTripper
	tag     string
	once    *sync.Once
	repoint func()
}

// RoundTrip serves req through base, running repoint after the first HEAD of
// the tag's manifest.
func (t repointOnHead) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := t.base.RoundTrip(req)
	if err == nil && req.Method == http.MethodHead && strings.HasSuffix(req.URL.Path, "/manifests/"+t.tag) {
		t.once.Do(t.repoint)
	}
	return resp, err
}

// TestImageUntagDigestGuardHoldsAgainstConcurrentRepoint pins that `k3sm
// image untag --digest` removes nothing once the tag stops naming that digest,
// even when a push re-points the tag after untag read it: the delete is
// conditional at the registry, not only checked before it is sent.
func TestImageUntagDigestGuardHoldsAgainstConcurrentRepoint(t *testing.T) {
	srv := newRegistryServer(t)
	direct := []remote.Option{remote.WithContext(t.Context()), remote.WithTransport(handlerTransport{srv})}
	const port = 6450
	ref, err := name.NewTag(registrysvc.LoopbackAuthority(port) + "/app:v1")
	if err != nil {
		t.Fatal(err)
	}
	image := func() ggcrv1.Image {
		img, err := random.Image(128, 1)
		if err != nil {
			t.Fatal(err)
		}
		return img
	}
	old, repointed := image(), image()
	if err := remote.Write(ref, old, direct...); err != nil {
		t.Fatalf("seed the old manifest: %v", err)
	}

	dir := t.TempDir()
	if err := os.MkdirAll(registrysvc.StateDir(dir), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := registrysvc.WriteCredential(dir, registrysvc.Credential{
		Address: "127.0.0.1:6450", Username: "k3sm", Password: "secret",
	}); err != nil {
		t.Fatalf("write credential: %v", err)
	}
	t.Setenv("K3SM_WORK_DIR", dir)

	var pushErr error
	prev := defaultRegistryTransport
	defaultRegistryTransport = repointOnHead{
		base: handlerTransport{srv},
		tag:  "v1",
		once: new(sync.Once),
		repoint: func() {
			pushErr = remote.Write(ref, repointed, direct...)
		},
	}
	t.Cleanup(func() { defaultRegistryTransport = prev })

	out, err := runImageCmd(t, []string{"--work-dir", dir, "untag", "app:v1", "--digest", mustDigest(t, old)})
	if pushErr != nil {
		t.Fatalf("the concurrent push failed: %v", pushErr)
	}
	if err == nil {
		t.Errorf("untag --digest of a tag re-pointed after the comparison succeeded:\n%s", out)
	} else if !strings.Contains(err.Error(), "nothing was removed") {
		t.Errorf("untag error = %v, want it to say nothing was removed", err)
	}
	desc, err := remote.Head(ref, direct...)
	if err != nil {
		t.Fatalf("the re-pointed tag is gone: %v", err)
	}
	if got, want := desc.Digest.String(), mustDigest(t, repointed); got != want {
		t.Errorf("app:v1 = %s, want the re-pointed %s", got, want)
	}
}

// TestImageUntagDigestDeletesAnUnmovedTag pins the other half of the guard
// against the registry server: a tag that still names the --digest is removed,
// so the conditional delete is not a refusal of every guarded untag.
func TestImageUntagDigestDeletesAnUnmovedTag(t *testing.T) {
	srv := newRegistryServer(t)
	direct := []remote.Option{remote.WithContext(t.Context()), remote.WithTransport(handlerTransport{srv})}
	ref, err := name.NewTag(registrysvc.LoopbackAuthority(6450) + "/app:v1")
	if err != nil {
		t.Fatal(err)
	}
	img, err := random.Image(128, 1)
	if err != nil {
		t.Fatal(err)
	}
	if err := remote.Write(ref, img, direct...); err != nil {
		t.Fatalf("seed: %v", err)
	}
	dir := t.TempDir()
	if err := os.MkdirAll(registrysvc.StateDir(dir), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := registrysvc.WriteCredential(dir, registrysvc.Credential{
		Address: "127.0.0.1:6450", Username: "k3sm", Password: "secret",
	}); err != nil {
		t.Fatalf("write credential: %v", err)
	}
	t.Setenv("K3SM_WORK_DIR", dir)
	prev := defaultRegistryTransport
	defaultRegistryTransport = handlerTransport{srv}
	t.Cleanup(func() { defaultRegistryTransport = prev })

	if out, err := runImageCmd(t, []string{"--work-dir", dir, "untag", "app:v1", "--digest", mustDigest(t, img)}); err != nil {
		t.Fatalf("untag --digest of an unmoved tag: %v\n%s", err, out)
	}
	if _, err := remote.Head(ref, direct...); err == nil {
		t.Errorf("app:v1 survived its untag")
	}
}

// recordingTransport serves with base and counts the requests it carried.
type recordingTransport struct {
	base http.RoundTripper
	n    *int
}

// RoundTrip counts req and serves it through base.
func (t recordingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	*t.n++
	return t.base.RoundTrip(req)
}

// TestImageUntagDeleteAccessUsesTheBoundTransport pins what untag's If-Match wrap
// assumes: registryDeleteAccess's transport is boundRequests(nil), the one
// over defaultRegistryTransport. imageUntag rebuilds that transport under the
// wrap, so an access that carried any other transport would be replaced
// silently; this fails instead.
func TestImageUntagDeleteAccessUsesTheBoundTransport(t *testing.T) {
	srv := newRegistryServer(t)
	dir := t.TempDir()
	if err := os.MkdirAll(registrysvc.StateDir(dir), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := registrysvc.WriteCredential(dir, registrysvc.Credential{
		Address: "127.0.0.1:6450", Username: "k3sm", Password: "secret",
	}); err != nil {
		t.Fatalf("write credential: %v", err)
	}
	t.Setenv("K3SM_WORK_DIR", dir)
	var n int
	prev := defaultRegistryTransport
	defaultRegistryTransport = recordingTransport{base: handlerTransport{srv}, n: &n}
	t.Cleanup(func() { defaultRegistryTransport = prev })

	acc, err := registryDeleteAccess(t.Context(), dir)
	if err != nil {
		t.Fatalf("registryDeleteAccess: %v", err)
	}
	ref, err := name.NewTag(acc.authority + "/app:v1")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := remote.Head(ref, acc.opts...); err == nil {
		t.Fatalf("HEAD of an absent tag succeeded")
	}
	if n == 0 {
		t.Errorf("the delete access's requests bypassed defaultRegistryTransport; imageUntag's If-Match wrap over boundRequests(nil) would replace its transport")
	}
}

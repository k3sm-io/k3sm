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

package modelpack

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"

	"k3sm.io/k3sm/pkg/registryclient/registrytest"
)

// variantRegistry is a writable in-process registry, the tag
// models/tiny:latest on it, and the option that reaches it.
func variantRegistry(t *testing.T) (*registrytest.Registry, name.Tag, remote.Option) {
	t.Helper()
	reg := registrytest.New()
	reg.AcceptWrites = true
	tag, err := name.NewTag("registry.test/models/tiny:latest")
	if err != nil {
		t.Fatal(err)
	}
	return reg, tag, remote.WithTransport(handlerTransport{reg.Handler()})
}

// handlerTransport serves every request with h in process, through a
// response recorder: no socket is opened.
type handlerTransport struct{ h http.Handler }

func (t handlerTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	in := req.Clone(req.Context())
	in.RequestURI = req.URL.RequestURI()
	if in.Body == nil {
		in.Body = http.NoBody
	}
	rec := httptest.NewRecorder()
	t.h.ServeHTTP(rec, in)
	resp := rec.Result()
	resp.Request = req
	return resp, nil
}

// readIndex reads the index tag names: its media type and its entries as
// variant -> manifest digest, in index order.
func readIndex(t *testing.T, tag name.Tag, opt remote.Option) (string, []string, map[string]string) {
	t.Helper()
	got, err := remote.Get(tag, opt)
	if err != nil {
		t.Fatal(err)
	}
	var idx ispec.Index
	if err := json.Unmarshal(got.Manifest, &idx); err != nil {
		t.Fatal(err)
	}
	var order []string
	byVariant := map[string]string{}
	for _, d := range idx.Manifests {
		v := d.Annotations[AnnotationVariant]
		if d.MediaType != ispec.MediaTypeImageManifest {
			t.Errorf("entry %s media type %q", v, d.MediaType)
		}
		order = append(order, v)
		byVariant[v] = d.Digest.String()
	}
	return string(got.MediaType), order, byVariant
}

// TestPushVariantUpdatesIndex: pushing 4bit, then 8bit, then a new 4bit
// leaves an index of exactly two entries, sorted by variant, the 4bit one
// naming the newest manifest; each variant manifest is in the repository by
// digest; and a variant push over a tag that names a plain manifest is
// refused without converting it.
func TestPushVariantUpdatesIndex(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	reg, tag, opt := variantRegistry(t)

	q4 := build(t, writeTree(t, map[string]string{"config.json": `{"q":4}`, "model.safetensors": "four"}))
	q8 := build(t, writeTree(t, map[string]string{"config.json": `{"q":8}`, "model.safetensors": "eight"}))
	q4b := build(t, writeTree(t, map[string]string{"config.json": `{"q":4}`, "model.safetensors": "four again"}))

	var digests []string
	for _, step := range []struct {
		variant string
		a       *Artifact
	}{{"8bit", q8}, {"4bit", q4}, {"4bit", q4b}} {
		d, err := PushVariant(ctx, tag, step.a, step.variant, opt)
		if err != nil {
			t.Fatalf("PushVariant(%s): %v", step.variant, err)
		}
		digests = append(digests, d)
		if !reg.HasBlob("models/tiny", step.a.ConfigDescriptor.Digest.String()) {
			t.Errorf("%s: config blob not pushed", step.variant)
		}
	}
	mt, order, byVariant := readIndex(t, tag, opt)
	if mt != ispec.MediaTypeImageIndex {
		t.Errorf("tag media type %q, want %q", mt, ispec.MediaTypeImageIndex)
	}
	if strings.Join(order, ",") != "4bit,8bit" {
		t.Errorf("index entries %v, want [4bit 8bit]", order)
	}
	if byVariant["4bit"] != q4b.Digest.String() || byVariant["8bit"] != q8.Digest.String() {
		t.Errorf("index = %v, want 4bit=%s 8bit=%s", byVariant, q4b.Digest, q8.Digest)
	}
	if d, ok := reg.Manifest("models/tiny", "latest"); !ok || d != digests[2] {
		t.Errorf("tag names %s, PushVariant returned %s", d, digests[2])
	}
	for _, a := range []*Artifact{q4, q8, q4b} {
		if _, err := remote.Head(tag.Context().Digest(a.Digest.String()), opt); err != nil {
			t.Errorf("manifest %s not in the repository by digest: %v", a.Digest, err)
		}
	}

	// The same push again changes nothing: the same digest, no new write.
	before := len(reg.Writes())
	if d, err := PushVariant(ctx, tag, q4b, "4bit", opt); err != nil || d != digests[2] {
		t.Errorf("re-push = %s, %v; want %s", d, err, digests[2])
	}
	if n := len(reg.Writes()) - before; n != 0 {
		t.Errorf("re-push made %d writes, want 0", n)
	}

	// The same set of variants pushed in the other order makes the same index.
	_, other, otherOpt := variantRegistry(t)
	for _, step := range []struct {
		variant string
		a       *Artifact
	}{{"4bit", q4b}, {"8bit", q8}} {
		if _, err := PushVariant(ctx, other, step.a, step.variant, otherOpt); err != nil {
			t.Fatal(err)
		}
	}
	if d, err := remote.Head(other, otherOpt); err != nil || d.Digest.String() != digests[2] {
		t.Errorf("index from the other order = %v, %v; want %s", d, err, digests[2])
	}

	// A plain manifest at the tag is refused, and stays a plain manifest.
	plainReg, plain, plainOpt := variantRegistry(t)
	if err := Push(ctx, plain, q4, plainOpt); err != nil {
		t.Fatal(err)
	}
	if _, err := PushVariant(ctx, plain, q8, "8bit", plainOpt); !errors.Is(err, ErrTagIsManifest) {
		t.Errorf("variant over a plain manifest: err = %v, want ErrTagIsManifest", err)
	}
	if d, ok := plainReg.Manifest("models/tiny", "latest"); !ok || d != q4.Digest.String() {
		t.Errorf("plain tag now names %s, want %s unchanged", d, q4.Digest)
	}
	if plainReg.HasBlob("models/tiny", q8.ConfigDescriptor.Digest.String()) {
		t.Error("a refused variant push uploaded a blob")
	}
}

// TestValidateVariant pins the variant grammar.
func TestValidateVariant(t *testing.T) {
	for _, tc := range []struct {
		v  string
		ok bool
	}{
		{"4bit", true},
		{"bf16", true},
		{"Q4_K_M.v2-x", true},
		{strings.Repeat("a", 128), true},
		{"", false},
		{strings.Repeat("a", 129), false},
		{"4 bit", false},
		{"4bit/x", false},
		{"4bit:x", false},
		{"ä", false},
	} {
		err := ValidateVariant(tc.v)
		if (err == nil) != tc.ok {
			t.Errorf("ValidateVariant(%q) = %v, want ok=%v", tc.v, err, tc.ok)
		}
		if err != nil && !errors.Is(err, ErrInvalidVariant) {
			t.Errorf("ValidateVariant(%q) = %v, want ErrInvalidVariant", tc.v, err)
		}
	}
}

// hookTransport runs before once, ahead of the first request that matches,
// then serves every request through next.
type hookTransport struct {
	next   http.RoundTripper
	match  func(*http.Request) bool
	before func()
	done   bool
}

func (h *hookTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if !h.done && h.match(req) {
		h.done = true
		h.before()
	}
	return h.next.RoundTrip(req)
}

// TestPushVariantMergesIntoTheIndexAtPut: the variant is merged into the
// index the tag names just before the write, not the one read before the
// upload, so an entry another writer added during the upload survives; and a
// tag turned into a plain manifest during the upload is still refused.
func TestPushVariantMergesIntoTheIndexAtPut(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	q4 := build(t, writeTree(t, map[string]string{"config.json": `{"q":4}`, "model.safetensors": "four"}))
	q8 := build(t, writeTree(t, map[string]string{"config.json": `{"q":8}`, "model.safetensors": "eight"}))
	bf := build(t, writeTree(t, map[string]string{"config.json": `{"q":16}`, "model.safetensors": "bf16"}))
	// The upload of the variant manifest by digest: after the first read of
	// the tag, before the second.
	manifestByDigest := func(req *http.Request) bool {
		return req.Method == http.MethodPut && strings.Contains(req.URL.Path, "/manifests/sha256:")
	}

	t.Run("an entry added during the upload survives", func(t *testing.T) {
		reg, tag, opt := variantRegistry(t)
		if _, err := PushVariant(ctx, tag, q4, "4bit", opt); err != nil {
			t.Fatal(err)
		}
		hook := &hookTransport{next: handlerTransport{reg.Handler()}, match: manifestByDigest, before: func() {
			if _, err := PushVariant(ctx, tag, bf, "bf16", opt); err != nil {
				t.Errorf("the other writer: %v", err)
			}
		}}
		if _, err := PushVariant(ctx, tag, q8, "8bit", remote.WithTransport(hook)); err != nil {
			t.Fatal(err)
		}
		if !hook.done {
			t.Fatal("the other writer never ran")
		}
		_, order, byVariant := readIndex(t, tag, opt)
		if strings.Join(order, ",") != "4bit,8bit,bf16" {
			t.Errorf("index entries %v, want [4bit 8bit bf16]", order)
		}
		if byVariant["bf16"] != bf.Digest.String() || byVariant["8bit"] != q8.Digest.String() || byVariant["4bit"] != q4.Digest.String() {
			t.Errorf("index = %v", byVariant)
		}
	})

	t.Run("a plain manifest written during the upload is refused", func(t *testing.T) {
		reg, tag, opt := variantRegistry(t)
		if _, err := PushVariant(ctx, tag, q4, "4bit", opt); err != nil {
			t.Fatal(err)
		}
		hook := &hookTransport{next: handlerTransport{reg.Handler()}, match: manifestByDigest, before: func() {
			if err := Push(ctx, tag, bf, opt); err != nil {
				t.Errorf("the other writer: %v", err)
			}
		}}
		if _, err := PushVariant(ctx, tag, q8, "8bit", remote.WithTransport(hook)); !errors.Is(err, ErrTagIsManifest) {
			t.Errorf("err = %v, want ErrTagIsManifest", err)
		}
		if d, ok := reg.Manifest("models/tiny", "latest"); !ok || d != bf.Digest.String() {
			t.Errorf("tag names %s, want the plain manifest %s left alone", d, bf.Digest)
		}
	})
}

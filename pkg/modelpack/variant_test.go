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
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"

	"k3sm.io/k3sm/pkg/registryclient/registrytest"
)

// variantRegistry serves a writable in-process registry and returns the tag
// models/tiny:latest on it.
func variantRegistry(t *testing.T) (*registrytest.Registry, name.Tag) {
	t.Helper()
	reg := registrytest.New()
	reg.AcceptWrites = true
	srv := httptest.NewServer(reg.Handler())
	t.Cleanup(srv.Close)
	tag, err := name.NewTag(strings.TrimPrefix(srv.URL, "http://")+"/models/tiny:latest", name.Insecure)
	if err != nil {
		t.Fatal(err)
	}
	return reg, tag
}

// readIndex reads the index tag names: its media type and its entries as
// variant -> manifest digest, in index order.
func readIndex(t *testing.T, tag name.Tag) (string, []string, map[string]string) {
	t.Helper()
	got, err := remote.Get(tag)
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
	reg, tag := variantRegistry(t)

	q4 := build(t, writeTree(t, map[string]string{"config.json": `{"q":4}`, "model.safetensors": "four"}))
	q8 := build(t, writeTree(t, map[string]string{"config.json": `{"q":8}`, "model.safetensors": "eight"}))
	q4b := build(t, writeTree(t, map[string]string{"config.json": `{"q":4}`, "model.safetensors": "four again"}))

	var digests []string
	for _, step := range []struct {
		variant string
		a       *Artifact
	}{{"8bit", q8}, {"4bit", q4}, {"4bit", q4b}} {
		d, err := PushVariant(ctx, tag, step.a, step.variant)
		if err != nil {
			t.Fatalf("PushVariant(%s): %v", step.variant, err)
		}
		digests = append(digests, d)
		if !reg.HasBlob("models/tiny", step.a.ConfigDescriptor.Digest.String()) {
			t.Errorf("%s: config blob not pushed", step.variant)
		}
	}
	mt, order, byVariant := readIndex(t, tag)
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
		if _, err := remote.Head(tag.Context().Digest(a.Digest.String())); err != nil {
			t.Errorf("manifest %s not in the repository by digest: %v", a.Digest, err)
		}
	}

	// The same push again changes nothing: the same digest, no new write.
	before := len(reg.Writes())
	if d, err := PushVariant(ctx, tag, q4b, "4bit"); err != nil || d != digests[2] {
		t.Errorf("re-push = %s, %v; want %s", d, err, digests[2])
	}
	if n := len(reg.Writes()) - before; n != 0 {
		t.Errorf("re-push made %d writes, want 0", n)
	}

	// The same set of variants pushed in the other order makes the same index.
	_, other := variantRegistry(t)
	for _, step := range []struct {
		variant string
		a       *Artifact
	}{{"4bit", q4b}, {"8bit", q8}} {
		if _, err := PushVariant(ctx, other, step.a, step.variant); err != nil {
			t.Fatal(err)
		}
	}
	if d, err := remote.Head(other); err != nil || d.Digest.String() != digests[2] {
		t.Errorf("index from the other order = %v, %v; want %s", d, err, digests[2])
	}

	// A plain manifest at the tag is refused, and stays a plain manifest.
	plainReg, plain := variantRegistry(t)
	if err := Push(ctx, plain, q4); err != nil {
		t.Fatal(err)
	}
	if _, err := PushVariant(ctx, plain, q8, "8bit"); !errors.Is(err, ErrTagIsManifest) {
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

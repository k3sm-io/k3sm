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
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/opencontainers/image-spec/specs-go"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"

	artifactv1 "k3sm.io/apis/artifact/v1"

	"k3sm.io/k3sm/pkg/ociregistry/ref"
)

// modelKeep is the retention class the tests give the model artifact type.
const modelKeep = 24 * time.Hour

// artifact pushes a manifest of the given artifactType (or, when artifactType
// is empty, one typed by its config media type cfgType) with one layer, under
// tag ("" for by digest).
func (e *env) artifact(t *testing.T, n ref.Name, tag, seed, artifactType, cfgType string, subject *ispec.Descriptor) image {
	t.Helper()
	var img image
	img.config = e.blob(t, n, []byte(`{"seed":"`+seed+`"}`))
	img.config.MediaType = cfgType
	img.layers = []ispec.Descriptor{e.blob(t, n, []byte(seed+" weights"))}
	m := ispec.Manifest{
		Versioned: specs.Versioned{SchemaVersion: 2}, MediaType: ispec.MediaTypeImageManifest,
		ArtifactType: artifactType, Config: img.config, Layers: img.layers, Subject: subject,
	}
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	img.body = b
	img.manifest = e.putManifest(t, n, tag, ispec.MediaTypeImageManifest, b)
	return img
}

// retained returns a collector started at offset at with the model class.
func (e *env) retained(t *testing.T, at time.Duration) *Collector {
	t.Helper()
	e.clk.set(at)
	c, err := New(e.s, Options{
		Grace: grace, Now: e.clk.now, Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
		Retention: map[string]time.Duration{artifactv1.ArtifactTypeModel: modelKeep},
	})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// TestRetentionByArtifactType: a retention class keeps an untagged manifest of
// its artifact type, and every blob it names, until the manifest is as old as
// the class, while an untagged image of the same age is reaped at the grace. A
// manifest past its class is reaped like any other, a tagged one is kept at any
// age, the type falls back to the config media type, a referrer of a retained
// manifest is kept with it, and a class shorter than the grace is refused, so a
// class can only keep more.
func TestRetentionByArtifactType(t *testing.T) {
	type pushed struct{ kept, reaped []image }
	cases := []struct {
		name string
		// age is how long before the sweep the content is pushed.
		age  time.Duration
		push func(t *testing.T, e *env, n ref.Name) pushed
	}{
		{
			name: "untagged model inside its class is kept, an image of the same age is not",
			age:  2 * time.Hour,
			push: func(t *testing.T, e *env, n ref.Name) pushed {
				m := e.artifact(t, n, "", "model", artifactv1.ArtifactTypeModel, artifactv1.MediaTypeModelConfig, nil)
				img := e.push(t, n, "", "image", []byte("image layer"))
				return pushed{kept: []image{m}, reaped: []image{img}}
			},
		},
		{
			name: "untagged model past its class is reaped",
			age:  modelKeep + time.Hour,
			push: func(t *testing.T, e *env, n ref.Name) pushed {
				m := e.artifact(t, n, "", "model", artifactv1.ArtifactTypeModel, artifactv1.MediaTypeModelConfig, nil)
				return pushed{reaped: []image{m}}
			},
		},
		{
			name: "tagged model is kept past its class",
			age:  modelKeep + time.Hour,
			push: func(t *testing.T, e *env, n ref.Name) pushed {
				m := e.artifact(t, n, "v1", "model", artifactv1.ArtifactTypeModel, artifactv1.MediaTypeModelConfig, nil)
				return pushed{kept: []image{m}}
			},
		},
		{
			name: "the class follows the config media type when artifactType is empty",
			age:  2 * time.Hour,
			push: func(t *testing.T, e *env, n ref.Name) pushed {
				m := e.artifact(t, n, "", "model", "", artifactv1.ArtifactTypeModel, nil)
				w := e.artifact(t, n, "", "wasm", "", artifactv1.MediaTypeWasmConfig, nil)
				return pushed{kept: []image{m}, reaped: []image{w}}
			},
		},
		{
			name: "a referrer of a retained model is kept with it",
			age:  2 * time.Hour,
			push: func(t *testing.T, e *env, n ref.Name) pushed {
				m := e.artifact(t, n, "", "model", artifactv1.ArtifactTypeModel, artifactv1.MediaTypeModelConfig, nil)
				sig := e.referrer(t, n, "sig", m.manifest)
				return pushed{kept: []image{m, sig}}
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t)
			n := name(t, "models")
			e.clk.set(-tc.age)
			// A tagged anchor with enough blobs that the half brake is not what
			// decides: the class, not a brake, keeps what is kept.
			anchor := e.push(t, n, "anchor", "anchor", []byte("a1"), []byte("a2"), []byte("a3"), []byte("a4"), []byte("a5"))
			got := tc.push(t, e, n)
			c := e.retained(t, -tc.age-time.Hour)
			e.ran(t)
			e.clk.set(0)

			rep, err := c.Sweep(e.ctx)
			if err != nil || len(rep.Stopped) != 0 || len(rep.Failed) != 0 {
				t.Fatalf("sweep: %v, stopped %v, failed %v; want no stop", err, rep.Stopped, rep.Failed)
			}
			for _, img := range append([]image{anchor}, got.kept...) {
				if err := e.whole(n, img); err != nil {
					t.Errorf("kept manifest %s: %v", img.manifest.Digest, err)
				}
			}
			for _, img := range got.reaped {
				for _, d := range img.blobs() {
					if e.has(n, d) {
						t.Errorf("%s of %s survived, want reaped", d, img.manifest.Digest)
					}
				}
			}
		})
	}

	t.Run("a class shorter than the grace is refused", func(t *testing.T) {
		e := newEnv(t)
		for _, r := range []map[string]time.Duration{
			{artifactv1.ArtifactTypeModel: grace - time.Second},
			{artifactv1.ArtifactTypeModel: 0},
			{"": modelKeep},
		} {
			if _, err := New(e.s, Options{Grace: grace, Retention: r}); err == nil {
				t.Errorf("New with retention %v: no error, want a refusal", r)
			}
		}
	})
}

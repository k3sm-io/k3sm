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
	"errors"
	"io"
	"log/slog"
	"path/filepath"
	"testing"
	"time"

	"github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"

	"k3sm.io/k3sm/pkg/ociregistry/ref"
	"k3sm.io/k3sm/pkg/ociregistry/store"
)

func TestAbandoned(t *testing.T) {
	cutoff := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	old, recent := cutoff.Add(-time.Hour), cutoff.Add(time.Nanosecond)
	d := digest.FromString("1")
	blobs := func(ts ...time.Time) []store.Blob {
		var out []store.Blob
		for _, t := range ts {
			out = append(out, store.Blob{Digest: d, ModTime: t})
		}
		return out
	}
	cases := []struct {
		name string
		rows []ispec.Descriptor
		cont store.Contents
		want bool
	}{
		{name: "no rows, index and blobs past the horizon", cont: store.Contents{IndexModTime: old, Blobs: blobs(old, old)}, want: true},
		{name: "everything exactly at the horizon", cont: store.Contents{IndexModTime: cutoff, Blobs: blobs(cutoff)}, want: true},
		{name: "a recent index", cont: store.Contents{IndexModTime: recent, Blobs: blobs(old)}},
		{name: "one recent blob (a push that resumed)", cont: store.Contents{IndexModTime: old, Blobs: blobs(old, recent)}},
		{name: "a recent upload session", cont: store.Contents{IndexModTime: old, Blobs: blobs(old), Sessions: []store.Session{{ID: "u", ModTime: recent}}}},
		{name: "an old upload session", cont: store.Contents{IndexModTime: old, Blobs: blobs(old), Sessions: []store.Session{{ID: "u", ModTime: old}}}, want: true},
		{name: "a row, everything old", rows: []ispec.Descriptor{{Digest: d}}, cont: store.Contents{IndexModTime: old, Blobs: blobs(old)}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := abandoned(ispec.Index{Manifests: tc.rows}, tc.cont, cutoff); got != tc.want {
				t.Fatalf("abandoned = %v, want %v", got, tc.want)
			}
		})
	}
}

// firstPush writes a first push into n: three blobs at offset blobsAt and an
// index.json, with no row, backdated to indexAt.
func (e *env) firstPush(t *testing.T, n ref.Name, blobsAt, indexAt time.Duration) []digest.Digest {
	t.Helper()
	e.clk.set(blobsAt)
	var ds []digest.Digest
	for _, b := range []string{"config", "l1", "l2"} {
		ds = append(ds, e.blob(t, n, []byte(b)).Digest)
	}
	e.backdate(t, filepath.Join(e.dir(t, n), "index.json"), indexAt)
	return ds
}

// TestAbandonedFirstPushIsFreed: a first push abandoned before any manifest
// is braked while it is younger than the abandon horizon, and reaped by the
// grace rule once it is older.
func TestAbandonedFirstPushIsFreed(t *testing.T) {
	e := newEnv(t)
	n := name(t, "app")
	horizon := AbandonFactor * grace
	ds := e.firstPush(t, n, -horizon-6*time.Hour, -horizon-7*time.Hour)
	c := e.collector(t, -horizon-8*time.Hour)
	e.ran(t)

	e.clk.set(-12 * time.Hour)
	if _, err := c.Sweep(e.ctx); !errors.Is(err, ErrMassDelete) {
		t.Fatalf("a sweep inside the horizon: %v, want ErrMassDelete", err)
	}
	if !e.hasAll(n, ds) {
		t.Fatal("a sweep inside the horizon reaped the first push")
	}

	e.clk.set(0)
	rep := e.sweep(t, c)
	if len(rep.Stopped) != 0 || rep.Count(KindBlob) != len(ds) {
		t.Fatalf("report %+v, want %d blobs reaped and no stop", rep, len(ds))
	}
	for _, d := range ds {
		if e.has(n, d) {
			t.Errorf("%s survived past the abandon horizon", d)
		}
	}
}

// TestRecentFirstPushStaysBraked: a first push whose blobs are past the grace
// but not the abandon horizon, or an old one a push has written to again,
// stays under the brake.
func TestRecentFirstPushStaysBraked(t *testing.T) {
	horizon := AbandonFactor * grace
	for _, tc := range []struct {
		name string
		run  func(t *testing.T, e *env, n ref.Name) []digest.Digest
	}{
		{"blobs past the grace, inside the horizon", func(t *testing.T, e *env, n ref.Name) []digest.Digest {
			return e.firstPush(t, n, -3*time.Hour, -4*time.Hour)
		}},
		{"an old first push with one new blob", func(t *testing.T, e *env, n ref.Name) []digest.Digest {
			ds := e.firstPush(t, n, -horizon-6*time.Hour, -horizon-7*time.Hour)
			e.clk.set(-2 * time.Hour)
			return append(ds, e.blob(t, n, []byte("l3")).Digest)
		}},
		{"an old first push with a live upload session", func(t *testing.T, e *env, n ref.Name) []digest.Digest {
			ds := e.firstPush(t, n, -horizon-6*time.Hour, -horizon-7*time.Hour)
			e.clk.set(0)
			e.session(t, n, "part of l3")
			return ds
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t)
			n := name(t, "app")
			ds := tc.run(t, e, n)
			c := e.collector(t, -horizon-8*time.Hour)
			e.ran(t)
			e.clk.set(0)
			if _, err := c.Sweep(e.ctx); !errors.Is(err, ErrMassDelete) {
				t.Fatalf("sweep: %v, want ErrMassDelete", err)
			}
			if !e.hasAll(n, ds) {
				t.Fatal("the sweep reaped blobs of a first push inside the abandon horizon")
			}
		})
	}
}

// TestAbandonOption: zero is AbandonFactor grace periods; a horizon must be
// longer than the grace, and a configured one is the one applied.
func TestAbandonOption(t *testing.T) {
	e := newEnv(t)
	discard := slog.New(slog.NewTextHandler(io.Discard, nil))
	for _, a := range []time.Duration{-time.Hour, grace} {
		if _, err := New(e.s, Options{Grace: grace, Abandon: a, Log: discard}); err == nil {
			t.Errorf("abandon %s: New succeeded, want an error", a)
		}
	}
	c, err := New(e.s, Options{Grace: grace, Log: discard})
	if err != nil || c.abandon != AbandonFactor*grace {
		t.Fatalf("default abandon %v (%v), want %s", c, err, AbandonFactor*grace)
	}

	n := name(t, "app")
	ds := e.firstPush(t, n, -6*time.Hour, -7*time.Hour)
	e.clk.set(-8 * time.Hour)
	c, err = New(e.s, Options{Grace: grace, Abandon: 5 * time.Hour, Now: e.clk.now, Log: discard})
	if err != nil {
		t.Fatal(err)
	}
	e.ran(t)
	e.clk.set(0)
	if rep := e.sweep(t, c); rep.Count(KindBlob) != len(ds) {
		t.Fatalf("report %+v, want %d blobs reaped past a 5h horizon", rep, len(ds))
	}
}

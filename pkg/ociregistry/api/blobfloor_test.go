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

package api

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// fromRecorder is a response that records what ReadFrom is handed, the type
// the standard library's sendfile path looks for.
type fromRecorder struct {
	*httptest.ResponseRecorder
	readers []io.Reader
}

func (r *fromRecorder) ReadFrom(src io.Reader) (int64, error) {
	r.readers = append(r.readers, src)
	return io.Copy(struct{ io.Writer }{r.ResponseRecorder}, src)
}

func TestFloorWriter(t *testing.T) {
	base := time.Unix(1000, 0)
	setup := func(end time.Time) (*floorWriter, *fromRecorder, *[]time.Time, *time.Time) {
		rec := &fromRecorder{ResponseRecorder: httptest.NewRecorder()}
		var set []time.Time
		now := base
		w := &floorWriter{
			ResponseWriter: rec,
			set:            func(_ http.ResponseWriter, dl time.Time) { set = append(set, dl) },
			now:            func() time.Time { return now },
			window:         time.Minute, chunk: 4, end: end,
		}
		return w, rec, &set, &now
	}

	t.Run("a limited file reaches the response as a limited file, chunk by chunk", func(t *testing.T) {
		p := filepath.Join(t.TempDir(), "blob")
		if err := os.WriteFile(p, []byte("0123456789"), 0o600); err != nil {
			t.Fatal(err)
		}
		f, err := os.Open(p)
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		w, rec, set, _ := setup(base.Add(time.Hour))
		src := &io.LimitedReader{R: f, N: 10}
		n, err := w.ReadFrom(src)
		if err != nil || n != 10 || src.N != 0 {
			t.Fatalf("ReadFrom = %d, %v, %d left", n, err, src.N)
		}
		if rec.Body.String() != "0123456789" {
			t.Fatalf("body %q", rec.Body.String())
		}
		if len(rec.readers) != 3 {
			t.Fatalf("%d copies; want one per chunk", len(rec.readers))
		}
		for _, r := range rec.readers {
			lr, ok := r.(*io.LimitedReader)
			if !ok {
				t.Fatalf("handed %T", r)
			}
			if _, ok := lr.R.(*os.File); !ok {
				t.Fatalf("the limit wraps %T, which the sendfile path cannot use", lr.R)
			}
		}
		if len(*set) != 3 {
			t.Fatalf("%d deadlines; want one per chunk", len(*set))
		}
	})
	t.Run("a source of unknown length ends at its EOF", func(t *testing.T) {
		w, rec, _, _ := setup(base.Add(time.Hour))
		n, err := w.ReadFrom(strings.NewReader("0123456789"))
		if err != nil || n != 10 || rec.Body.String() != "0123456789" {
			t.Fatalf("ReadFrom = %d, %v, body %q", n, err, rec.Body.String())
		}
	})
	t.Run("Write spans chunks and each deadline runs from when its chunk opens", func(t *testing.T) {
		w, rec, set, now := setup(base.Add(time.Hour))
		if n, err := w.Write([]byte("abc")); err != nil || n != 3 {
			t.Fatalf("Write = %d, %v", n, err)
		}
		*now = base.Add(10 * time.Second)
		if n, err := w.Write([]byte("defgh")); err != nil || n != 5 {
			t.Fatalf("Write = %d, %v", n, err)
		}
		if rec.Body.String() != "abcdefgh" {
			t.Fatalf("body %q", rec.Body.String())
		}
		if len(*set) != 2 || !(*set)[0].Equal(base.Add(time.Minute)) || !(*set)[1].Equal(base.Add(10*time.Second+time.Minute)) {
			t.Fatalf("deadlines %v", *set)
		}
	})
	t.Run("no deadline passes the blob's whole window", func(t *testing.T) {
		end := base.Add(30 * time.Second)
		w, _, set, _ := setup(end)
		if _, err := w.Write([]byte("a")); err != nil {
			t.Fatal(err)
		}
		if len(*set) != 1 || !(*set)[0].Equal(end) {
			t.Fatalf("deadlines %v, want the end %v", *set, end)
		}
	})
	t.Run("a small blob or a HEAD keeps the deadline it has", func(t *testing.T) {
		f := newFixture(t, func(c *Config) {
			c.ResponseTimeout = time.Minute
			c.MinWriteRate = 1 << 10
		})
		rec := httptest.NewRecorder()
		get := httptest.NewRequest(http.MethodGet, "/", nil)
		if got := f.srv.floored(rec, get, 60<<10, base); got != http.ResponseWriter(rec) {
			t.Errorf("a blob of one chunk got %T", got)
		}
		if got := f.srv.floored(rec, httptest.NewRequest(http.MethodHead, "/", nil), 1<<30, base); got != http.ResponseWriter(rec) {
			t.Errorf("a HEAD got %T", got)
		}
		if _, ok := f.srv.floored(rec, get, 61<<10, base).(*floorWriter); !ok {
			t.Error("a blob past one chunk has no floor")
		}
	})
}

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
	"time"
)

// floored returns where a blob response of size bytes is written. The write
// deadline a blob GET starts with allows the whole size at MinWriteRate, which
// on a large blob lets a reader that never reads hold a descriptor for hours.
// So a body larger than one ResponseTimeout at MinWriteRate goes through a
// floorWriter, which moves the deadline chunk by chunk. A smaller body, and a
// HEAD, keep the deadline they have: it is already that short.
func (s *Server) floored(w http.ResponseWriter, r *http.Request, size int64, end time.Time) http.ResponseWriter {
	chunk := max(int64(float64(s.minWriteRate)*s.respTimeout.Seconds()), 1)
	if r.Method != http.MethodGet || size <= chunk {
		return w
	}
	return &floorWriter{
		ResponseWriter: w, set: s.setWriteDeadline, now: s.now,
		window: s.respTimeout, chunk: chunk, end: end,
	}
}

// floorWriter is a minimum-progress response writer: each chunk bytes must be
// written within window, under a write deadline it moves at each chunk and
// never past end. A peer that stops reading is cut by the deadline, within
// window, and the handler returns and closes the blob. It keeps ReadFrom, and
// hands the response a limited *os.File as the standard library's copy does, so
// the response still sends the file with sendfile. It is used by one goroutine.
type floorWriter struct {
	http.ResponseWriter
	set    func(http.ResponseWriter, time.Time)
	now    func() time.Time
	window time.Duration
	chunk  int64
	end    time.Time
	// left is what the current deadline still has to carry.
	left int64
}

// renew opens the next chunk once the current one is written.
func (w *floorWriter) renew() {
	if w.left > 0 {
		return
	}
	dl := w.now().Add(w.window)
	if w.end.Before(dl) {
		dl = w.end
	}
	w.set(w.ResponseWriter, dl)
	w.left = w.chunk
}

// Write writes p across as many chunks as it spans.
func (w *floorWriter) Write(p []byte) (int, error) {
	total := 0
	for len(p) > 0 {
		w.renew()
		take := min(int64(len(p)), w.left)
		n, err := w.ResponseWriter.Write(p[:take])
		total += n
		w.left -= int64(n)
		p = p[n:]
		if err != nil {
			return total, err
		}
	}
	return total, nil
}

// ReadFrom copies src to the response across as many chunks as it spans.
func (w *floorWriter) ReadFrom(src io.Reader) (int64, error) {
	lr, limited := src.(*io.LimitedReader)
	var total int64
	for {
		w.renew()
		take, from := w.left, src
		if limited {
			if lr.N <= 0 {
				return total, nil
			}
			take, from = min(lr.N, w.left), lr.R
		}
		n, err := io.Copy(w.ResponseWriter, &io.LimitedReader{R: from, N: take})
		total += n
		w.left -= n
		if limited {
			lr.N -= n
		}
		if err != nil || n < take {
			return total, err
		}
	}
}

// Unwrap gives http.ResponseController the response underneath.
func (w *floorWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

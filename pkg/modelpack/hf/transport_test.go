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

package hf

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"sync"
)

// hostTransport is an in-process http.RoundTripper: it serves each request
// with the handler registered for the URL's host, streaming the response
// through a pipe so a handler can send headers and part of a body and then
// drop the "connection" (panic(http.ErrAbortHandler)). No socket is opened.
type hostTransport map[string]http.Handler

func (t hostTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	h, ok := t[req.URL.Host]
	if !ok {
		if req.Body != nil {
			req.Body.Close()
		}
		return nil, fmt.Errorf("dial %s: no such host in the test", req.URL.Host)
	}
	in := req.Clone(req.Context())
	in.Host = req.URL.Host
	in.RequestURI = req.URL.RequestURI()
	if in.Body == nil {
		in.Body = http.NoBody
	}
	pr, pw := io.Pipe()
	w := &pipeWriter{header: http.Header{}, pw: pw, pr: pr, req: req, ready: make(chan *http.Response, 1)}
	go func() {
		aborted := false
		defer func() {
			if r := recover(); r != nil {
				if r != http.ErrAbortHandler {
					panic(r)
				}
				aborted = true
			}
			w.WriteHeader(http.StatusOK)
			if aborted {
				pw.CloseWithError(io.ErrUnexpectedEOF)
			} else {
				pw.Close()
			}
			in.Body.Close()
		}()
		h.ServeHTTP(w, in)
	}()
	select {
	case resp := <-w.ready:
		return resp, nil
	case <-req.Context().Done():
		pr.CloseWithError(req.Context().Err())
		return nil, req.Context().Err()
	}
}

// pipeWriter is the http.ResponseWriter of a hostTransport request.
type pipeWriter struct {
	header http.Header
	pw     *io.PipeWriter
	pr     *io.PipeReader
	req    *http.Request
	ready  chan *http.Response

	once sync.Once
}

func (w *pipeWriter) Header() http.Header { return w.header }

func (w *pipeWriter) WriteHeader(code int) {
	w.once.Do(func() {
		cl := int64(-1)
		if v := w.header.Get("Content-Length"); v != "" {
			if n, err := strconv.ParseInt(v, 10, 64); err == nil {
				cl = n
			}
		}
		var body io.ReadCloser = w.pr
		if w.req.Method == http.MethodHead {
			body = http.NoBody
		}
		w.ready <- &http.Response{
			Status: strconv.Itoa(code) + " " + http.StatusText(code), StatusCode: code,
			Proto: "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1,
			Header: w.header.Clone(), Body: body, ContentLength: cl, Request: w.req,
		}
	})
}

func (w *pipeWriter) Write(b []byte) (int, error) {
	w.WriteHeader(http.StatusOK)
	if w.req.Method == http.MethodHead {
		return len(b), nil
	}
	n, err := w.pw.Write(b)
	if errors.Is(err, io.ErrClosedPipe) {
		return n, http.ErrAbortHandler
	}
	return n, err
}

func (w *pipeWriter) Flush() {}

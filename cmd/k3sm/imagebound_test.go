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
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"google.golang.org/grpc"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// boundTestIdle stands for requestIdleTimeout (2 m) in this gate.
const boundTestIdle = 300 * time.Millisecond

// TestImageCommandsBoundEachRequest is the gate for the image verbs' request
// bound. The verbs that move image content carry no overall deadline; each
// registry request, and the daemon's export stream, is abandoned only once it
// moves no byte for the idle window. So a slow transfer that keeps moving
// outlives the window many times over, a stalled one fails at the window
// rather than after a fixed half hour, and Ctrl-C still cancels.
func TestImageCommandsBoundEachRequest(t *testing.T) {
	t.Run("streaming verbs carry no overall deadline, only the request bound", func(t *testing.T) {
		for _, args := range [][]string{
			{"load", "app.tar"}, {"import", "app.tar"}, {"push", "dir", "example.test/app:v1"},
			{"pull", "example.test/app:v1"}, {"save", "example.test/app:v1", "-o", "app.tar"},
		} {
			o, err := parseImageArgs(args, io.Discard)
			if err != nil {
				t.Fatalf("parse %v: %v", args, err)
			}
			ctx, cancel := imageContext(t.Context(), o)
			if dl, ok := ctx.Deadline(); ok {
				t.Errorf("%s: deadline %v; want none (a slow transfer that keeps moving must not be cut)", args[0], time.Until(dl).Round(time.Minute))
			}
			if got := requestIdle(ctx); got != requestIdleTimeout {
				t.Errorf("%s: request idle window = %v; want %v", args[0], got, requestIdleTimeout)
			}
			cancel()
			explicit, err := parseImageArgs(append(args, "--timeout", "45s"), io.Discard)
			if err != nil {
				t.Fatalf("parse %v --timeout: %v", args, err)
			}
			ctx, cancel = imageContext(t.Context(), explicit)
			if _, ok := ctx.Deadline(); !ok {
				t.Errorf("%s --timeout 45s: no deadline; an explicit --timeout is still an overall deadline", args[0])
			}
			cancel()
		}
		o, err := parseImageArgs([]string{"ls"}, io.Discard)
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := imageContext(t.Context(), o)
		defer cancel()
		if _, ok := ctx.Deadline(); !ok {
			t.Error("ls: no deadline; a metadata verb keeps its overall deadline")
		}
		if got := requestIdle(ctx); got != 0 {
			t.Errorf("ls: request idle window = %v; want none", got)
		}
	})

	t.Run("a download that keeps moving outlives the window", func(t *testing.T) {
		h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			for i := 0; i < 6; i++ {
				_, _ = w.Write([]byte("chunk"))
				w.(http.Flusher).Flush()
				time.Sleep(boundTestIdle / 3)
			}
		})
		start := time.Now()
		body, err := boundGet(t, withRequestIdle(t.Context(), boundTestIdle), h)
		if err != nil {
			t.Fatalf("download failed after %v: %v; a transfer still moving bytes must not be cut", time.Since(start), err)
		}
		if body != strings.Repeat("chunk", 6) || time.Since(start) < 2*boundTestIdle {
			t.Errorf("body %q after %v; want six chunks over more than %v", body, time.Since(start), 2*boundTestIdle)
		}
	})

	t.Run("a download that stops moving is abandoned at the window", func(t *testing.T) {
		h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte("first"))
			w.(http.Flusher).Flush()
			<-r.Context().Done()
		})
		parent := withRequestIdle(t.Context(), boundTestIdle)
		start := time.Now()
		_, err := boundGet(t, parent, h)
		assertStalled(t, err, start)
		if parent.Err() != nil {
			t.Errorf("the command's context was cancelled (%v); only the stalled request is abandoned", parent.Err())
		}
	})

	t.Run("a response that never starts is abandoned at the window", func(t *testing.T) {
		h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			<-r.Context().Done()
		})
		start := time.Now()
		_, err := boundGet(t, withRequestIdle(t.Context(), boundTestIdle), h)
		assertStalled(t, err, start)
	})

	t.Run("an upload that keeps moving outlives the window", func(t *testing.T) {
		h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			n, _ := io.Copy(io.Discard, r.Body)
			if n != 6*5 {
				w.WriteHeader(http.StatusBadRequest)
			}
		})
		req, err := http.NewRequestWithContext(withRequestIdle(t.Context(), boundTestIdle), http.MethodPut, testRegistryURL, &slowReader{chunks: 6, gap: boundTestIdle / 3})
		if err != nil {
			t.Fatal(err)
		}
		resp, err := boundRequests(pipeTransport{h}).RoundTrip(req)
		if err != nil {
			t.Fatalf("upload failed: %v; an upload still sending bytes must not be cut", err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("status %d; the server did not receive the whole body", resp.StatusCode)
		}
	})

	t.Run("an upload the peer stops taking is abandoned at the window", func(t *testing.T) {
		// The handler never reads the body, so no byte of the upload moves.
		release := make(chan struct{})
		h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			<-release
		})
		defer close(release)
		req, err := http.NewRequestWithContext(withRequestIdle(t.Context(), boundTestIdle), http.MethodPut, testRegistryURL, io.LimitReader(zeroReader{}, 1<<30))
		if err != nil {
			t.Fatal(err)
		}
		start := time.Now()
		resp, err := boundRequests(pipeTransport{h}).RoundTrip(req)
		if err == nil {
			resp.Body.Close()
		}
		assertStalled(t, err, start)
	})

	t.Run("Ctrl-C cancels a request inside its window", func(t *testing.T) {
		h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			<-r.Context().Done()
		})
		parent, interrupt := context.WithCancel(withRequestIdle(t.Context(), time.Hour))
		time.AfterFunc(boundTestIdle/3, interrupt)
		start := time.Now()
		_, err := boundGet(t, parent, h)
		if !errors.Is(err, context.Canceled) || errors.Is(err, errNoProgress) {
			t.Fatalf("err = %v; want the interrupt's cancellation, not a stall", err)
		}
		if el := time.Since(start); el > 10*boundTestIdle {
			t.Errorf("cancellation took %v", el)
		}
	})

	t.Run("a request under no window is not bounded", func(t *testing.T) {
		h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			time.Sleep(boundTestIdle)
			_, _ = w.Write([]byte("late"))
		})
		body, err := boundGet(t, t.Context(), h)
		if err != nil || body != "late" {
			t.Errorf("body %q err %v; a context with no window passes through", body, err)
		}
	})

	t.Run("the push path's registry options carry the bound", func(t *testing.T) {
		t.Setenv(registryTokenEnv, "")
		t.Setenv("DOCKER_CONFIG", t.TempDir())
		h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			<-r.Context().Done()
		})
		prev := defaultRegistryTransport
		defaultRegistryTransport = pipeTransport{h}
		t.Cleanup(func() { defaultRegistryTransport = prev })
		ref, err := name.NewTag("registry.test/app:v1")
		if err != nil {
			t.Fatal(err)
		}
		opts, err := pushDest{}.options(withRequestIdle(t.Context(), boundTestIdle), ref)
		if err != nil {
			t.Fatalf("options: %v", err)
		}
		start := time.Now()
		_, err = remote.Head(ref, opts...)
		assertStalled(t, err, start)
	})

	t.Run("the daemon's export stream is abandoned when no frame arrives", func(t *testing.T) {
		start := time.Now()
		var sink strings.Builder
		_, err := streamSaveImage(withRequestIdle(t.Context(), boundTestIdle), stallingSaveDaemon{frames: 4, gap: boundTestIdle / 3}, &runtimev1.SaveImageRequest{Reference: "example.test/app:v1"}, &sink, "runtimed.sock")
		assertStalled(t, err, start)
		if sink.Len() != 4*len("frame") {
			t.Errorf("wrote %d bytes before the stall; want every frame that arrived inside its window", sink.Len())
		}
		if el := time.Since(start); el < boundTestIdle+boundTestIdle {
			t.Errorf("abandoned after %v; frames arriving inside the window must restart it", el)
		}
	})
}

// testRegistryURL is the address every in-process request names; nothing
// listens on it, pipeTransport answers.
const testRegistryURL = "http://registry.test/v2/"

// boundGet fetches through a boundRequests transport over h under ctx.
func boundGet(t *testing.T, ctx context.Context, h http.Handler) (string, error) {
	t.Helper()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, testRegistryURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := boundRequests(pipeTransport{h}).RoundTrip(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	return string(b), err
}

// assertStalled requires err to be the idle window's, reached near the window.
func assertStalled(t *testing.T, err error, start time.Time) {
	t.Helper()
	el := time.Since(start)
	if !errors.Is(err, errNoProgress) {
		t.Fatalf("err = %v after %v; want the no-progress bound", err, el)
	}
	if el > 10*boundTestIdle {
		t.Errorf("abandoned after %v; want near the %v window", el, boundTestIdle)
	}
}

// slowReader yields chunks of "chunk" with gap between them.
type slowReader struct {
	chunks int
	gap    time.Duration
	sent   int
}

func (r *slowReader) Read(p []byte) (int, error) {
	if r.sent == r.chunks {
		return 0, io.EOF
	}
	if r.sent > 0 {
		time.Sleep(r.gap)
	}
	r.sent++
	return copy(p, "chunk"), nil
}

// zeroReader yields zero bytes without end.
type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) {
	clear(p)
	return len(p), nil
}

// pipeTransport answers each request by running h in process with a response
// writer that streams through a pipe, so a handler that writes slowly, stalls,
// or never reads the request body behaves to the client as it would over a
// connection, with no socket. It returns once the handler writes its header or
// the request's context ends, and a context end fails any read still pending.
type pipeTransport struct{ h http.Handler }

func (t pipeTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	ctx := r.Context()
	pr, pw := io.Pipe()
	rw := &pipeResponse{header: http.Header{}, pw: pw, ready: make(chan struct{})}
	go func() {
		t.h.ServeHTTP(rw, r)
		rw.WriteHeader(http.StatusOK)
		// A handler that returned because the request was abandoned did not
		// finish its response: the client sees the abandonment, never an EOF.
		_ = pw.CloseWithError(ctx.Err())
	}()
	context.AfterFunc(ctx, func() { _ = pr.CloseWithError(ctx.Err()) })
	select {
	case <-rw.ready:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	return &http.Response{
		Status: http.StatusText(rw.status), StatusCode: rw.status, Proto: "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1,
		Header: rw.header, Body: pr, ContentLength: -1, Request: r,
	}, nil
}

// pipeResponse is the http.ResponseWriter pipeTransport hands a handler.
type pipeResponse struct {
	header http.Header
	pw     *io.PipeWriter
	once   sync.Once
	status int // set once, before ready closes
	ready  chan struct{}
}

func (w *pipeResponse) Header() http.Header { return w.header }

func (w *pipeResponse) WriteHeader(code int) {
	w.once.Do(func() {
		w.status = code
		close(w.ready)
	})
}

func (w *pipeResponse) Write(p []byte) (int, error) {
	w.WriteHeader(http.StatusOK)
	return w.pw.Write(p)
}

func (w *pipeResponse) Flush() { w.WriteHeader(http.StatusOK) }

// stallingSaveDaemon is an in-process ImagesClient whose export stream sends
// frames with gap between them and then goes silent until its context ends.
type stallingSaveDaemon struct {
	runtimev1.ImagesClient
	frames int
	gap    time.Duration
}

func (d stallingSaveDaemon) SaveImage(ctx context.Context, _ *runtimev1.SaveImageRequest, _ ...grpc.CallOption) (grpc.ServerStreamingClient[runtimev1.SaveImageResponse], error) {
	return &stallingSaveStream{ctx: ctx, d: d}, nil
}

type stallingSaveStream struct {
	grpc.ClientStream
	ctx  context.Context
	d    stallingSaveDaemon
	sent int
}

func (s *stallingSaveStream) Recv() (*runtimev1.SaveImageResponse, error) {
	if s.sent < s.d.frames {
		if s.sent > 0 {
			select {
			case <-time.After(s.d.gap):
			case <-s.ctx.Done():
				return nil, s.ctx.Err()
			}
		}
		s.sent++
		return &runtimev1.SaveImageResponse{Chunk: []byte("frame")}, nil
	}
	<-s.ctx.Done()
	return nil, s.ctx.Err()
}

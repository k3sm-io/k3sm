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

package socket

import (
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"testing"
	"testing/synctest"
	"time"
)

const helloV1 = `{"proto":"k3sm-keys","min":1,"max":1}`

// session is a Handler serving one end of an in-memory pipe.
type session struct {
	client net.Conn
	done   chan error
	start  time.Time
	ended  bool
	err    error
}

// wait returns Serve's result, waiting for it the first time.
func (s *session) wait() error {
	if !s.ended {
		s.err, s.ended = <-s.done, true
	}
	return s.err
}

// serve starts Serve on a pipe, inside the caller's synctest bubble.
func serve(t *testing.T, now func() time.Time) *session {
	t.Helper()
	h, err := NewHandler(now)
	if err != nil {
		t.Fatal(err)
	}
	return serveWith(t, h)
}

// testPeer is the admitted peer serveWith serves for.
var testPeer = Peer{UID: 501, PID: 4242}

// serveWith starts h's Serve on a pipe for testPeer, inside the caller's
// synctest bubble.
func serveWith(t *testing.T, h *Handler) *session {
	t.Helper()
	return serveAs(t, h, testPeer)
}

// serveAs starts h's Serve on a pipe for p, a fake admitted peer.
func serveAs(t *testing.T, h *Handler, p Peer) *session {
	t.Helper()
	client, server := net.Pipe()
	s := &session{client: client, done: make(chan error, 1), start: time.Now()}
	go func() {
		err := h.Serve(t.Context(), server, p)
		_ = server.Close() // the caller's close, as a listener would
		s.done <- err
	}()
	return s
}

func (s *session) send(t *testing.T, typ FrameType, header string, value []byte) {
	t.Helper()
	if err := WriteFrame(s.client, Frame{Type: typ, Header: []byte(header), Value: value}); err != nil {
		t.Fatalf("send: %v", err)
	}
}

func (s *session) recv(t *testing.T, want FrameType, header any) {
	t.Helper()
	f, err := ReadFrame(s.client)
	if err != nil {
		t.Fatalf("recv: %v", err)
	}
	if f.Type != want || f.Value != nil {
		t.Fatalf("recv type %#02x value %q, want type %#02x and no value", byte(f.Type), f.Value, byte(want))
	}
	if err := json.Unmarshal(f.Header, header); err != nil {
		t.Fatalf("recv header %q: %v", f.Header, err)
	}
}

func (s *session) recvCode(t *testing.T) Code {
	t.Helper()
	var eh errorHeader
	s.recv(t, TypeError, &eh)
	return eh.Code
}

// finish closes the client side and returns Serve's result.
func (s *session) finish() error {
	_ = s.client.Close() // the server may have closed first
	return s.wait()
}

// closed reports whether the server has closed its end.
func (s *session) closed(t *testing.T) {
	t.Helper()
	if _, err := ReadFrame(s.client); !errors.Is(err, io.EOF) {
		t.Fatalf("after the close, client read = %v, want EOF", err)
	}
}

func TestHelloReadDeadline(t *testing.T) {
	hello, err := AppendFrame(nil, Frame{Type: TypeHello, Header: []byte(helloV1)})
	if err != nil {
		t.Fatal(err)
	}
	request, err := AppendFrame(nil, Frame{Type: TypeRequest, Header: []byte(`{"op":"x"}`)})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name    string
		skew    time.Duration // the injected clock's offset from the bubble's
		send    []byte
		elapsed time.Duration
		want    func(error) bool
	}{
		{"nothing sent", 0, nil, RequestBound, func(err error) bool { return errors.Is(err, os.ErrDeadlineExceeded) }},
		{"half a HELLO", 0, hello[:len(hello)/2], RequestBound, func(err error) bool { return errors.Is(err, os.ErrDeadlineExceeded) }},
		{"deadline from the injected clock", -4 * time.Second, nil, RequestBound - 4*time.Second, func(err error) bool { return errors.Is(err, os.ErrDeadlineExceeded) }},
		// The server stops reading these after the first five bytes (a
		// HELLO with a value after nine), so the rest of the write meets
		// a closed pipe.
		{"request before HELLO", 0, request, 0, isProtocolError},
		{"reply type before HELLO", 0, cat(be(7), []byte{byte(TypeReply)}, be(2), []byte("{}")), 0, isProtocolError},
		{"HELLO with a value", 0, cat(be(uint32(5+len(helloV1)+5)), []byte{byte(TypeHello)}, be(uint32(len(helloV1))), []byte(helloV1), be(1), []byte("v")), 0, isProtocolError},
		{"HELLO for another protocol", 0, cat(be(5+22), []byte{byte(TypeHello)}, be(22), []byte(`{"proto":"x","max":1}`+" ")), 0, isProtocolError},
		{"HELLO header not JSON", 0, cat(be(5+3), []byte{byte(TypeHello)}, be(3), []byte("{{{")), 0, isProtocolError},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				s := serve(t, func() time.Time { return time.Now().Add(tc.skew) })
				if len(tc.send) > 0 {
					if _, err := s.client.Write(tc.send); err != nil && !errors.Is(err, io.ErrClosedPipe) {
						t.Fatalf("write: %v", err)
					}
				}
				err := s.wait()
				if got := time.Since(s.start); got != tc.elapsed {
					t.Errorf("Serve returned after %v, want %v", got, tc.elapsed)
				}
				if !tc.want(err) {
					t.Errorf("Serve = %v, not the expected kind", err)
				}
				s.closed(t)
				_ = s.finish()
			})
		})
	}
}

func TestUnknownHeaderFieldsIgnored(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s := serve(t, time.Now)
		s.send(t, TypeHello, `{"later":{"a":[1,2]},"proto":"k3sm-keys","min":1,"max":1,"caps":["x"]}`, nil)
		var reply HelloReply
		s.recv(t, TypeHello, &reply)
		if reply.Version != 1 {
			t.Fatalf("HELLO with unknown fields chose version %d", reply.Version)
		}
		s.send(t, TypeRequest, `{"op":"no-such-op","later":"field","n":3}`, nil)
		if c := s.recvCode(t); c != CodeUnknownOp {
			t.Fatalf("request with unknown fields answered %q", c)
		}
		if err := s.finish(); err != nil {
			t.Fatalf("Serve = %v", err)
		}
	})
}

func TestHelloVersionRange(t *testing.T) {
	for _, tc := range []struct {
		name                      string
		cmin, cmax, smin, smax, v int
		ok                        bool
	}{
		{"same single version", 1, 1, 1, 1, 1, true},
		{"client newer range", 1, 5, 1, 1, 1, true},
		{"client older floor", 0, 1, 1, 1, 1, true},
		{"highest common of wide ranges", 2, 5, 1, 3, 3, true},
		{"client ahead of server", 2, 9, 1, 1, 0, false},
		{"client behind server", 1, 2, 3, 4, 0, false},
		{"zero range", 0, 0, 1, 1, 0, false},
		{"inverted client range", 3, 1, 1, 3, 0, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v, ok := selectVersion(tc.cmin, tc.cmax, tc.smin, tc.smax)
			if v != tc.v || ok != tc.ok {
				t.Fatalf("selectVersion(%d, %d, %d, %d) = %d, %v; want %d, %v", tc.cmin, tc.cmax, tc.smin, tc.smax, v, ok, tc.v, tc.ok)
			}
		})
	}
	t.Run("served", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			s := serve(t, time.Now)
			s.send(t, TypeHello, `{"proto":"k3sm-keys","min":0,"max":7}`, nil)
			var reply HelloReply
			s.recv(t, TypeHello, &reply)
			if reply.Version != MaxVersion {
				t.Fatalf("version = %d, want %d", reply.Version, MaxVersion)
			}
			if err := s.finish(); err != nil {
				t.Fatalf("Serve = %v", err)
			}
		})
	})
}

func TestHelloReplyCarriesVersionAndMaxFrame(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s := serve(t, time.Now)
		s.send(t, TypeHello, helloV1, nil)
		f, err := ReadFrame(s.client)
		if err != nil {
			t.Fatal(err)
		}
		var got map[string]any
		if err := json.Unmarshal(f.Header, &got); err != nil {
			t.Fatal(err)
		}
		want := map[string]any{"proto": "k3sm-keys", "version": float64(1), "max_frame": float64(MaxFrame)}
		if f.Type != TypeHello || f.Value != nil || len(got) != len(want) {
			t.Fatalf("reply type %#02x value %q header %s", byte(f.Type), f.Value, f.Header)
		}
		for k, v := range want {
			if got[k] != v {
				t.Errorf("reply %q = %v, want %v", k, got[k], v)
			}
		}
		if err := s.finish(); err != nil {
			t.Fatalf("Serve = %v", err)
		}
	})
}

func TestHelloNoOverlapSendsUnsupportedVersion(t *testing.T) {
	for _, tc := range []struct{ name, hello string }{
		{"newer only", `{"proto":"k3sm-keys","min":2,"max":9}`},
		{"no range", `{"proto":"k3sm-keys"}`},
		{"inverted", `{"proto":"k3sm-keys","min":1,"max":0}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				s := serve(t, time.Now)
				s.send(t, TypeHello, tc.hello, nil)
				if c := s.recvCode(t); c != CodeUnsupportedVersion {
					t.Fatalf("code = %q, want %q", c, CodeUnsupportedVersion)
				}
				if err := s.wait(); !errors.Is(err, ErrUnsupportedVersion) {
					t.Fatalf("Serve = %v, want ErrUnsupportedVersion", err)
				}
				s.closed(t)
				_ = s.finish()
			})
		})
	}
}

func TestUnknownOpKeepsConnection(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s := serve(t, time.Now)
		s.send(t, TypeHello, helloV1, nil)
		var reply HelloReply
		s.recv(t, TypeHello, &reply)
		for _, rq := range []struct {
			header string
			value  []byte
		}{
			{`{"op":"no-such-op"}`, nil},
			{`{"op":"future-op"}`, []byte("a value")},
			{`{"op":"no-such-op"}`, []byte{}},
		} {
			s.send(t, TypeRequest, rq.header, rq.value)
			if c := s.recvCode(t); c != CodeUnknownOp {
				t.Fatalf("%s answered %q, want %q", rq.header, c, CodeUnknownOp)
			}
		}
		if err := s.finish(); err != nil {
			t.Fatalf("Serve after the client's close = %v, want nil", err)
		}
	})
}

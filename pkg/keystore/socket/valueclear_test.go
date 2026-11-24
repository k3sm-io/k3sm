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
	"bytes"
	"context"
	"errors"
	"io"
	"testing"
	"time"

	"k3sm.io/k3sm/pkg/keystore"
)

// secretValue is the request value the clearing tests look for.
var secretValue = []byte("SECRET-VALUE-BYTES")

// recordingConn is a Conn over in, which keeps every buffer it read into,
// so a test can see whether the value read into one was zeroed.
type recordingConn struct {
	in     *bytes.Reader
	bufs   [][]byte
	out    bytes.Buffer
	writes [][]byte // each buffer written from, as the server passed it
}

func (c *recordingConn) Read(p []byte) (int, error) {
	n, err := c.in.Read(p)
	c.bufs = append(c.bufs, p[:n])
	return n, err
}
func (c *recordingConn) Write(p []byte) (int, error) {
	c.writes = append(c.writes, p)
	return c.out.Write(p)
}
func (c *recordingConn) SetReadDeadline(time.Time) error  { return nil }
func (c *recordingConn) SetWriteDeadline(time.Time) error { return nil }

// leftover reports whether any buffer read into still holds secretValue
// or its first bytes.
func (c *recordingConn) leftover() bool {
	for _, b := range c.bufs {
		if bytes.Contains(b, secretValue[:6]) {
			return true
		}
	}
	return false
}

func frameBytes(t *testing.T, f Frame) []byte {
	t.Helper()
	b, err := AppendFrame(nil, f)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// Serve zeroes a request's value on every way out, not only after a
// reply: a frame after HELLO that is not a request, a header that does not
// parse, one naming no op, a value cut part way, and a panic out of the
// operation; readFrame zeroes a value it read only part of.
func TestServeClearsValueOnEveryExit(t *testing.T) {
	hello := frameBytes(t, Frame{Type: TypeHello, Header: []byte(helloV1)})
	full := func(typ FrameType, header string) []byte {
		return frameBytes(t, Frame{Type: typ, Header: []byte(header), Value: bytes.Clone(secretValue)})
	}
	cut := full(TypeRequest, `{"op":"put"}`)
	cut = cut[:len(cut)-4] // the value's last bytes never arrive
	h, err := NewHandler(time.Now,
		withOp("put", func(context.Context, Request) (Reply, error) { return Reply{}, nil }),
		withOp("boom", func(context.Context, Request) (Reply, error) { panic("an operation panics") }),
	)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name  string
		frame []byte
		panic bool
	}{
		{"not a request", full(TypeReply, `{}`), false},
		{"bad header", full(TypeRequest, `not json`), false},
		{"empty op", full(TypeRequest, `{}`), false},
		{"value cut part way", cut, false},
		{"operation panics", full(TypeRequest, `{"op":"boom"}`), true},
		{"served", full(TypeRequest, `{"op":"put"}`), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := &recordingConn{in: bytes.NewReader(append(bytes.Clone(hello), tc.frame...))}
			func() {
				defer func() {
					if r := recover(); (r != nil) != tc.panic {
						t.Fatalf("panic %v, want one %v", r, tc.panic)
					}
				}()
				err := h.Serve(t.Context(), c, Peer{UID: uidA})
				if tc.name == "served" && err != nil {
					t.Fatalf("Serve: %v", err)
				}
				if tc.name != "served" && err == nil {
					t.Fatal("Serve returned nil, want the frame's error")
				}
			}()
			if c.leftover() {
				t.Fatal("the request's value was left in its buffer")
			}
		})
	}
	// A real read-for-exec reply: the store's value is encoded into the
	// reply's frame and written; after the write, both the value the store
	// returned and the encoded buffer the server wrote from are zeroed.
	t.Run("read-for-exec reply", func(t *testing.T) {
		st := &execValueStore{value: bytes.Clone(secretValue)}
		oh, err := NewOpsHandler(time.Now, st)
		if err != nil {
			t.Fatal(err)
		}
		req := frameBytes(t, Frame{Type: TypeRequest, Header: []byte(`{"op":"read-for-exec","entry":"user/70001/a"}`)})
		c := &recordingConn{in: bytes.NewReader(append(bytes.Clone(hello), req...))}
		if err := oh.Serve(t.Context(), c, Peer{UID: uidA}); err != nil {
			t.Fatalf("Serve: %v", err)
		}
		hr, err := ReadReply(&c.out) // the HELLO reply
		if err != nil || hr.Type != TypeHello {
			t.Fatalf("the HELLO reply: %+v, %v", hr, err)
		}
		f, err := ReadReply(&c.out)
		if err != nil || f.Type != TypeReply || !bytes.Equal(f.Value, secretValue) {
			t.Fatalf("the read-for-exec reply: %+v, %v; want the value as its binary part", f, err)
		}
		if len(c.writes) != 2 {
			t.Fatalf("%d writes, want the HELLO reply and the read-for-exec reply", len(c.writes))
		}
		if w := c.writes[1]; !bytes.Equal(w, make([]byte, len(w))) {
			t.Fatalf("the reply's encoded buffer was not zeroed after the write: %q", w)
		}
		if !bytes.Equal(st.value, make([]byte, len(st.value))) {
			t.Fatalf("the value the store returned was not zeroed after the write: %q", st.value)
		}
	})
	// readFrame alone, on a value cut part way.
	c := &recordingConn{in: bytes.NewReader(cut)}
	if _, err := ReadFrame(c); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("ReadFrame of a cut value = %v, want io.ErrUnexpectedEOF", err)
	}
	if c.leftover() {
		t.Fatal("ReadFrame left a part-read value in its buffer")
	}
}

// execValueStore is a Store whose read-for-exec returns value, the
// slice itself, so a test can see whether the server zeroed it. Admit
// admits everything; no other call is made.
type execValueStore struct {
	Store
	value []byte
}

func (s *execValueStore) Admit(Peer, string) error                      { return nil }
func (s *execValueStore) Refused(context.Context, Peer, string, string) {}
func (s *execValueStore) ReadForExec(context.Context, Peer, string) (keystore.Version, []byte, error) {
	return keystore.Version{Version: 3}, s.value, nil
}

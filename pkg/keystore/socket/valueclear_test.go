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
)

// secretValue is the request value the clearing tests look for.
var secretValue = []byte("SECRET-VALUE-BYTES")

// recordingConn is a Conn over in, which keeps every buffer it read into,
// so a test can see whether the value read into one was zeroed.
type recordingConn struct {
	in   *bytes.Reader
	bufs [][]byte
	out  bytes.Buffer
}

func (c *recordingConn) Read(p []byte) (int, error) {
	n, err := c.in.Read(p)
	c.bufs = append(c.bufs, p[:n])
	return n, err
}
func (c *recordingConn) Write(p []byte) (int, error)      { return c.out.Write(p) }
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
	// readFrame alone, on a value cut part way.
	c := &recordingConn{in: bytes.NewReader(cut)}
	if _, err := ReadFrame(c); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("ReadFrame of a cut value = %v, want io.ErrUnexpectedEOF", err)
	}
	if c.leftover() {
		t.Fatal("ReadFrame left a part-read value in its buffer")
	}
}

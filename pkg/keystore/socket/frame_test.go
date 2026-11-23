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
	"encoding/binary"
	"errors"
	"io"
	"runtime"
	"testing"

	"k3sm.io/k3sm/pkg/keystore"
)

// be is a 4-byte big-endian length.
func be(n uint32) []byte { return binary.BigEndian.AppendUint32(nil, n) }

func cat(bs ...[]byte) []byte {
	var o []byte
	for _, b := range bs {
		o = append(o, b...)
	}
	return o
}

func isProtocolError(err error) bool {
	var pe *ProtocolError
	return errors.As(err, &pe)
}

// FuzzFrameReader reads frames from arbitrary bytes: it never panics, never
// holds a buffer past the caps, ends only on a protocol error or the end of
// the stream, and every frame it accepts re-encodes to the bytes it read.
func FuzzFrameReader(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		checkReadHello(t, data)
		r := bytes.NewReader(data)
		off := 0
		for {
			fr, err := ReadFrame(r)
			if err != nil {
				if !isProtocolError(err) && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
					t.Fatalf("ReadFrame error %v is neither a protocol error nor an end of stream", err)
				}
				return
			}
			if cap(fr.Header) > MaxHeader {
				t.Fatalf("header buffer cap %d over %d", cap(fr.Header), MaxHeader)
			}
			if cap(fr.Header)+cap(fr.Value) > MaxFrame-minFrame {
				t.Fatalf("buffers hold %d bytes, past the frame cap", cap(fr.Header)+cap(fr.Value))
			}
			end := len(data) - r.Len()
			enc, err := AppendFrame(nil, fr)
			if err != nil {
				t.Fatalf("re-encoding an accepted frame: %v", err)
			}
			if !bytes.Equal(enc, data[off:end]) {
				t.Fatalf("re-encoded frame differs:\n got %q\nwant %q", enc, data[off:end])
			}
			off = end
		}
	})
}

func TestFramingBounds(t *testing.T) {
	atCapValue := make([]byte, MaxFrame-FrameOverhead-2)
	headerAtCap := bytes.Repeat([]byte(" "), MaxHeader)
	for _, tc := range []struct {
		name    string
		in      []byte
		wantErr func(error) bool
	}{
		{"frame at the cap", cat(be(MaxFrame), []byte{byte(TypeRequest)}, be(2), []byte("{}"), be(uint32(len(atCapValue))), atCapValue), nil},
		{"frame one past the cap", cat(be(MaxFrame+1), []byte{byte(TypeRequest)}, be(2), []byte("{}")), isProtocolError},
		{"largest length", cat(be(0xffffffff), []byte{byte(TypeHello)}, be(0xffffffff)), isProtocolError},
		{"zero length", be(0), isProtocolError},
		{"under the minimum", cat(be(minFrame-1), []byte{byte(TypeHello), 0, 0, 0}), isProtocolError},
		{"header at the cap", cat(be(minFrame+MaxHeader), []byte{byte(TypeHello)}, be(MaxHeader), headerAtCap), nil},
		{"header one past the cap", cat(be(minFrame+MaxHeader+1), []byte{byte(TypeHello)}, be(MaxHeader+1), headerAtCap, []byte(" ")), isProtocolError},
		{"type zero", cat(be(7), []byte{0}, be(2), []byte("{}")), isProtocolError},
		{"type past the last", cat(be(7), []byte{byte(TypeError) + 1}, be(2), []byte("{}")), isProtocolError},
		{"type 0xff", cat(be(7), []byte{0xff}, be(2), []byte("{}")), isProtocolError},
		{"empty stream", nil, func(err error) bool { return err == io.EOF }},
		{"cut in the length", []byte{0, 0}, func(err error) bool { return errors.Is(err, io.ErrUnexpectedEOF) }},
		{"cut in the header", cat(be(7), []byte{byte(TypeHello)}, be(2), []byte("{")), func(err error) bool { return errors.Is(err, io.ErrUnexpectedEOF) }},
		{"cut in the value", cat(be(13), []byte{byte(TypeRequest)}, be(2), []byte("{}"), be(2), []byte("v")), func(err error) bool { return errors.Is(err, io.ErrUnexpectedEOF) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ReadFrame(bytes.NewReader(tc.in))
			switch {
			case tc.wantErr == nil && err != nil:
				t.Fatalf("ReadFrame: %v", err)
			case tc.wantErr != nil && !tc.wantErr(err):
				t.Fatalf("ReadFrame error = %v, not the expected kind", err)
			}
		})
	}

	t.Run("no allocation from a refused length", func(t *testing.T) {
		in := cat(be(0xffffffff), []byte{byte(TypeHello)}, be(0xffffffff))
		var before, after runtime.MemStats
		runtime.ReadMemStats(&before)
		_, err := ReadFrame(bytes.NewReader(in))
		runtime.ReadMemStats(&after)
		if !isProtocolError(err) {
			t.Fatalf("ReadFrame error = %v, want a protocol error", err)
		}
		if d := after.TotalAlloc - before.TotalAlloc; d > 1<<20 {
			t.Fatalf("refusing a 4 GiB length allocated %d bytes", d)
		}
	})

	for _, tc := range []struct {
		name string
		f    Frame
	}{
		{"writer refuses an unknown type", Frame{Type: 0, Header: []byte("{}")}},
		{"writer refuses a header past the cap", Frame{Type: TypeRequest, Header: make([]byte, MaxHeader+1)}},
		{"writer refuses a frame past the cap", Frame{Type: TypeRequest, Header: []byte("{}"), Value: make([]byte, MaxFrame)}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			if err := WriteFrame(&buf, tc.f); !isProtocolError(err) {
				t.Fatalf("WriteFrame error = %v, want a protocol error", err)
			}
			if buf.Len() != 0 {
				t.Fatalf("WriteFrame wrote %d bytes of a refused frame", buf.Len())
			}
		})
	}
}

func TestSubLengthsWithinFrame(t *testing.T) {
	req := []byte{byte(TypeRequest)}
	for _, tc := range []struct {
		name      string
		in        []byte
		ok        bool
		wantValue []byte // nil: no value
	}{
		{"header fills the frame", cat(be(7), req, be(2), []byte("{}")), true, nil},
		{"header past the frame", cat(be(7), req, be(3), []byte("{}x")), false, nil},
		{"header far past the frame", cat(be(7), req, be(MaxHeader), []byte("{}")), false, nil},
		{"empty value", cat(be(11), req, be(2), []byte("{}"), be(0)), true, []byte{}},
		{"value fills the frame", cat(be(14), req, be(2), []byte("{}"), be(3), []byte("abc")), true, []byte("abc")},
		{"value past the frame", cat(be(12), req, be(2), []byte("{}"), be(9), []byte("v")), false, nil},
		{"value short of the frame", cat(be(14), req, be(2), []byte("{}"), be(1), []byte("abc")), false, nil},
		{"one byte after the header", cat(be(8), req, be(2), []byte("{}"), []byte{0}), false, nil},
		{"three bytes after the header", cat(be(10), req, be(2), []byte("{}"), []byte{0, 0, 0}), false, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fr, err := ReadFrame(bytes.NewReader(tc.in))
			if !tc.ok {
				if !isProtocolError(err) {
					t.Fatalf("ReadFrame error = %v, want a protocol error", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("ReadFrame: %v", err)
			}
			if (fr.Value == nil) != (tc.wantValue == nil) || !bytes.Equal(fr.Value, tc.wantValue) {
				t.Fatalf("value = %q (nil %v), want %q (nil %v)", fr.Value, fr.Value == nil, tc.wantValue, tc.wantValue == nil)
			}
		})
	}

	t.Run("a frame reads no byte of the next", func(t *testing.T) {
		next := cat(be(7), []byte{byte(TypeHello)}, be(2), []byte("{}"))
		r := bytes.NewReader(cat(be(14), req, be(2), []byte("{}"), be(3), []byte("abc"), next))
		if _, err := ReadFrame(r); err != nil {
			t.Fatalf("first frame: %v", err)
		}
		if r.Len() != len(next) {
			t.Fatalf("%d bytes left after the first frame, want %d", r.Len(), len(next))
		}
		fr, err := ReadFrame(r)
		if err != nil || fr.Type != TypeHello {
			t.Fatalf("second frame = %+v, %v", fr, err)
		}
	})
}

func TestFrameCapCoversMaxValue(t *testing.T) {
	if need := keystore.MaxValueSize + MaxHeader + FrameOverhead; MaxFrame < need {
		t.Fatalf("frame cap %d under the largest request %d (value %d, header %d, framing %d)",
			MaxFrame, need, keystore.MaxValueSize, MaxHeader, FrameOverhead)
	}
	f := Frame{Type: TypeRequest, Header: bytes.Repeat([]byte(" "), MaxHeader), Value: make([]byte, keystore.MaxValueSize)}
	b, err := AppendFrame(nil, f)
	if err != nil {
		t.Fatalf("encoding the largest request: %v", err)
	}
	got, err := ReadFrame(bytes.NewReader(b))
	if err != nil {
		t.Fatalf("reading the largest request: %v", err)
	}
	if len(got.Header) != MaxHeader || len(got.Value) != keystore.MaxValueSize {
		t.Fatalf("largest request read back as header %d, value %d", len(got.Header), len(got.Value))
	}
}

// checkReadHello holds ReadHello to its contract on data: it returns a
// HELLO with no value, or a protocol error or an end of stream; and a frame
// that is not a HELLO is refused having read no more than its length and
// type, a HELLO with a value having read no more than its length, type and
// header length.
func checkReadHello(t *testing.T, data []byte) {
	t.Helper()
	r := bytes.NewReader(data)
	fr, err := ReadHello(r)
	read := len(data) - r.Len()
	if err != nil {
		if !isProtocolError(err) && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
			t.Fatalf("ReadHello error %v is neither a protocol error nor an end of stream", err)
		}
		if len(data) >= 5 && FrameType(data[4]) != TypeHello && read > 5 {
			t.Fatalf("ReadHello read %d bytes of a frame of type %#02x, want at most 5", read, data[4])
		}
		return
	}
	if fr.Type != TypeHello || fr.Value != nil {
		t.Fatalf("ReadHello accepted type %#02x with value %v", byte(fr.Type), fr.Value != nil)
	}
}

// TestReadHelloRefusesBeforeTheBody checks that before HELLO a frame of
// another type is refused after five bytes, whatever its header and value
// say, and that a HELLO carrying a value is refused before its header is
// read.
func TestReadHelloRefusesBeforeTheBody(t *testing.T) {
	req, err := AppendFrame(nil, Frame{Type: TypeRequest, Header: bytes.Repeat([]byte("h"), MaxHeader), Value: make([]byte, 1000)})
	if err != nil {
		t.Fatal(err)
	}
	r := bytes.NewReader(req)
	if _, err := ReadHello(r); !isProtocolError(err) {
		t.Fatalf("ReadHello on a request = %v, want a protocol error", err)
	}
	if read := len(req) - r.Len(); read != 5 {
		t.Fatalf("ReadHello read %d bytes of a request, want 5", read)
	}
	hv, err := AppendFrame(nil, Frame{Type: TypeHello, Header: []byte(helloV1), Value: []byte("v")})
	if err != nil {
		t.Fatal(err)
	}
	r = bytes.NewReader(hv)
	if _, err := ReadHello(r); !isProtocolError(err) {
		t.Fatalf("ReadHello on a HELLO with a value = %v, want a protocol error", err)
	}
	if read := len(hv) - r.Len(); read != 4+minFrame {
		t.Fatalf("ReadHello read %d bytes of a HELLO with a value, want %d", read, 4+minFrame)
	}
	ok, err := AppendFrame(nil, Frame{Type: TypeHello, Header: []byte(helloV1)})
	if err != nil {
		t.Fatal(err)
	}
	if f, err := ReadHello(bytes.NewReader(ok)); err != nil || string(f.Header) != helloV1 {
		t.Fatalf("ReadHello on a HELLO = %q, %v", f.Header, err)
	}
}

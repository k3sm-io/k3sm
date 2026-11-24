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
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"k3sm.io/k3sm/pkg/keystore"
)

const (
	// MaxFrame is the frame cap: the most a frame's length may say. It is
	// twice the store's value cap (128 KiB for a 64 KiB value), which covers
	// the largest request (the value, a full header and the framing) with
	// headroom for later header fields, and follows the value cap when it
	// changes.
	MaxFrame = 2 * keystore.MaxValueSize
	// MaxHeader is the header cap: the most a frame's JSON header may hold,
	// every frame but a reply.
	MaxHeader = 8 << 10
	// MaxReplyHeader is a reply's header cap: the worst-case list of a full
	// scope (keystore.MaxScopeEntries rows, each at maxListRow) with the
	// warning an outcome may add, so one list call names every entry. Only
	// a reply may carry a header past MaxHeader, and only a client's reader
	// (ReadReply) takes one.
	MaxReplyHeader = len(`{"entries":[]}`) + len(`,"warning":""`) + len(WarnAuditFailed) +
		keystore.MaxScopeEntries*maxListRow
	// FrameOverhead is the framing a frame carrying a value adds to its
	// header and value inside the frame length: the type byte and the
	// header's and the value's length prefixes.
	FrameOverhead = 1 + 4 + 4
	// minFrame is the shortest frame body: a type and a header length.
	minFrame = 1 + 4
)

// The frame cap must hold the largest value with a full header; this fails
// to compile (a negative untyped constant converted to uint) if it does not.
const _ uint = MaxFrame - (keystore.MaxValueSize + MaxHeader + FrameOverhead)

// The frame cap must hold the largest reply header too; this fails to
// compile if a full scope's list does not fit one frame.
const _ = uint(MaxFrame - (minFrame + MaxReplyHeader))

// FrameType is a frame's 1-byte type.
type FrameType byte

// The frame types of k3sm-keys/1. Any other byte is an unknown type, which
// closes the connection.
const (
	// TypeHello opens the connection: the client's version range, then the
	// server's chosen version and frame cap.
	TypeHello FrameType = 0x01
	// TypeRequest is a client request; its header names the op.
	TypeRequest FrameType = 0x02
	// TypeReply is the server's answer to a request that succeeded.
	TypeReply FrameType = 0x03
	// TypeError is the server's answer carrying an error code.
	TypeError FrameType = 0x04
)

func (t FrameType) known() bool { return t >= TypeHello && t <= TypeError }

// Frame is one decoded frame. Value is nil when the frame carries no value
// and non-nil (possibly empty) when it carries one, so a frame re-encodes to
// the bytes it was read from.
type Frame struct {
	Type   FrameType
	Header []byte
	Value  []byte
}

// ProtocolError is a frame or handshake that breaks the protocol. The
// connection that produced it is closed.
type ProtocolError struct {
	Reason string
}

func (e *ProtocolError) Error() string { return "keystore socket: " + e.Reason }

func protocolErrorf(format string, args ...any) error {
	return &ProtocolError{Reason: fmt.Sprintf(format, args...)}
}

// ReadFrame reads one frame from r. A clean end of stream before a frame
// starts is io.EOF; one inside a frame is io.ErrUnexpectedEOF. Every length
// is checked against its cap and against what remains of the frame before
// the buffer it sizes is allocated. Every header is held to MaxHeader: this
// is the server's reader.
func ReadFrame(r io.Reader) (Frame, error) { return readFrame(r, readAny) }

// ReadReply is the client's reader of the server's answers: as ReadFrame,
// but a reply's header may be up to MaxReplyHeader, the list of a full
// scope. Every other type is still held to MaxHeader.
func ReadReply(r io.Reader) (Frame, error) { return readFrame(r, readReply) }

// ReadHello reads a connection's first frame, which must be a HELLO with no
// value, as ReadFrame does but stricter: a frame of any other type is
// refused as soon as its length and type are read, before its header
// length, header or value is read or allocated, and a HELLO whose length
// leaves room for a value is refused before its header is read.
func ReadHello(r io.Reader) (Frame, error) { return readFrame(r, readHello) }

// readMode is which reader readFrame is.
type readMode int

const (
	readAny   readMode = iota // ReadFrame
	readHello                 // ReadHello
	readReply                 // ReadReply
)

// headerCap is the most a header of type t may hold.
func headerCap(t FrameType) uint32 {
	if t == TypeReply {
		return uint32(MaxReplyHeader)
	}
	return MaxHeader
}

func readFrame(r io.Reader, mode readMode) (Frame, error) {
	hello := mode == readHello
	var prefix [4 + minFrame]byte
	if _, err := io.ReadFull(r, prefix[:4]); err != nil {
		return Frame{}, err
	}
	n := binary.BigEndian.Uint32(prefix[:4])
	if n > MaxFrame {
		return Frame{}, protocolErrorf("frame length %d over the cap %d", n, MaxFrame)
	}
	if n < minFrame {
		return Frame{}, protocolErrorf("frame length %d under the minimum %d", n, minFrame)
	}
	if err := readBody(r, prefix[4:5]); err != nil {
		return Frame{}, err
	}
	f := Frame{Type: FrameType(prefix[4])}
	if !f.Type.known() {
		return Frame{}, protocolErrorf("unknown frame type %#02x", byte(f.Type))
	}
	if hello && f.Type != TypeHello {
		return Frame{}, protocolErrorf("first frame is type %#02x, not HELLO", byte(f.Type))
	}
	if err := readBody(r, prefix[5:]); err != nil {
		return Frame{}, err
	}
	rest := n - minFrame
	hl := binary.BigEndian.Uint32(prefix[5:])
	limit := uint32(MaxHeader)
	if mode == readReply {
		limit = headerCap(f.Type)
	}
	if hl > limit {
		return Frame{}, protocolErrorf("header length %d over the cap %d", hl, limit)
	}
	if hl > rest {
		return Frame{}, protocolErrorf("header length %d past the frame", hl)
	}
	if hello && hl != rest {
		return Frame{}, protocolErrorf("HELLO carries %d bytes after its header", rest-hl)
	}
	f.Header = make([]byte, hl)
	if err := readBody(r, f.Header); err != nil {
		return Frame{}, err
	}
	rest -= hl
	if rest == 0 {
		return f, nil
	}
	if rest < 4 {
		return Frame{}, protocolErrorf("%d bytes after the header, too few for a value length", rest)
	}
	var vp [4]byte
	if err := readBody(r, vp[:]); err != nil {
		return Frame{}, err
	}
	rest -= 4
	if vl := binary.BigEndian.Uint32(vp[:]); vl != rest {
		// Neither length is named: what is left of the frame is the
		// value's length.
		return Frame{}, protocolErrorf("the value length does not fill the bytes left in the frame")
	}
	f.Value = make([]byte, rest)
	if err := readBody(r, f.Value); err != nil {
		// A value cut part way is zeroed: its first bytes may be a
		// secret's.
		clear(f.Value)
		return Frame{}, err
	}
	return f, nil
}

// readBody reads inside a frame, where a clean end of stream is a cut frame.
func readBody(r io.Reader, b []byte) error {
	if _, err := io.ReadFull(r, b); err != nil {
		if errors.Is(err, io.EOF) {
			return io.ErrUnexpectedEOF
		}
		return err
	}
	return nil
}

// AppendFrame appends f's encoding to b. It refuses a frame ReadFrame would
// refuse, except that a reply's header may be up to MaxReplyHeader, as
// ReadReply takes it.
func AppendFrame(b []byte, f Frame) ([]byte, error) {
	if !f.Type.known() {
		return b, protocolErrorf("unknown frame type %#02x", byte(f.Type))
	}
	if limit := headerCap(f.Type); len(f.Header) > int(limit) {
		return b, protocolErrorf("header length %d over the cap %d", len(f.Header), limit)
	}
	n := minFrame + len(f.Header)
	if f.Value != nil {
		n += 4 + len(f.Value)
	}
	if n > MaxFrame {
		return b, protocolErrorf("frame length %d over the cap %d", n, MaxFrame)
	}
	b = binary.BigEndian.AppendUint32(b, uint32(n))
	b = append(b, byte(f.Type))
	b = binary.BigEndian.AppendUint32(b, uint32(len(f.Header)))
	b = append(b, f.Header...)
	if f.Value != nil {
		b = binary.BigEndian.AppendUint32(b, uint32(len(f.Value)))
		b = append(b, f.Value...)
	}
	return b, nil
}

// WriteFrame writes f to w in one Write.
func WriteFrame(w io.Writer, f Frame) error {
	b, err := AppendFrame(nil, f)
	if err != nil {
		return err
	}
	_, err = w.Write(b)
	return err
}

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
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"slices"
	"time"

	"k3sm.io/k3sm/pkg/keystore/internal/strictjson"
)

// RequestBound is how long the server waits for a complete HELLO from
// accept, and how long a request may take, from its first byte to the end of
// its reply's write; a request past it is cut by closing the connection.
const RequestBound = 10 * time.Second

// IdleBound is how long a connection may sit between frames: after the
// HELLO reply, and after each reply, the next request's first byte must
// arrive within it or the connection is closed.
const IdleBound = 30 * time.Second

// ErrUnsupportedVersion is returned by Serve after it answers a HELLO whose
// version range does not meet the server's with unsupported-version.
var ErrUnsupportedVersion = errors.New("keystore socket: no common protocol version")

// Conn is the connection Serve speaks on: a byte stream with deadlines.
type Conn interface {
	io.ReadWriter
	SetReadDeadline(t time.Time) error
	SetWriteDeadline(t time.Time) error
}

// Handler serves k3sm-keys/1 on one connection at a time.
type Handler struct {
	now func() time.Time
	ops map[string]opFunc // the operations; an op not here is unknown-op
	log *slog.Logger      // receives the store errors that are damage (logStoreError)
	dmg damageLimiter     // bounds those lines per uid, op and class
}

// Peer is the admitted peer of a connection, as the listener read it at
// accept: UID is the authority every operation acts for, PID is advisory,
// for an audit line. No request header field can change either.
type Peer struct {
	UID uint32
	PID int32
}

// Request is one request as an operation receives it: the connection's
// admitted peer, the op it names, its whole header (an operation decodes
// its own fields; unknown fields are ignored) and its value, nil when the
// frame carries none. The value is the server's to zero once the reply is
// written; an operation never keeps it.
type Request struct {
	Peer   Peer
	Op     string
	Header []byte
	Value  []byte
}

// Reply is an operation's answer: its header, marshalled as a JSON object
// (nil is {}), and an optional value, which Serve writes as the reply's
// binary part and then zeroes. A header never carries a value.
type Reply struct {
	Header any
	Value  []byte
}

// opFunc runs one operation. Its reply is written when the error maps to
// no code (outcomeOf: nil, or a change that committed), with the warning
// the error carries; any other error is answered with the TypeError its
// code maps to and the reply is dropped, its value zeroed. Either way the
// connection stays open.
type opFunc func(ctx context.Context, req Request) (Reply, error)

// HandlerOption configures a Handler at construction.
type HandlerOption func(*Handler)

// withOp registers op under name (NewOpsHandler registers the
// operations; a later registration of a name replaces the earlier).
func withOp(name string, op opFunc) HandlerOption {
	return func(h *Handler) {
		if h.ops == nil {
			h.ops = map[string]opFunc{}
		}
		h.ops[name] = op
	}
}

// NewHandler returns a Handler that takes its deadlines from now.
func NewHandler(now func() time.Time, opts ...HandlerOption) (*Handler, error) {
	if now == nil {
		return nil, errors.New("keystore socket: nil clock")
	}
	h := &Handler{now: now, log: slog.Default()}
	for _, o := range opts {
		o(h)
	}
	return h, nil
}

// decodeField decodes raw, a field strictjson.Object read, into dst; an absent
// field, or one set to null, leaves dst as it is.
func decodeField(raw json.RawMessage, dst any) error {
	if raw == nil || bytes.Equal(raw, []byte("null")) {
		return nil
	}
	return json.Unmarshal(raw, dst)
}

// requestKeys are the names of every request header field an operation
// reads, derived from requestFields over every request type
// (requestHeaders), so the two cannot drift: the dispatcher judges all of
// them, whichever op the request names.
var requestKeys = func() []string {
	var keys []string
	for _, dst := range requestHeaders() {
		fields, err := requestFields(dst)
		if err != nil {
			panic(err) // requestHeaders lists only the types requestFields reads
		}
		for k := range fields {
			if !slices.Contains(keys, k) {
				keys = append(keys, k)
			}
		}
	}
	slices.Sort(keys)
	return keys
}()

// requestOp is the op a request header names, read with the keystore's
// strict-object rule (strictjson.Object) over every request field: a
// header that is not an object, any key given twice in any case, a
// request field spelled in another case, an op that is not a string, and a
// missing or empty op all close the connection.
func requestOp(header []byte) (string, error) {
	fields, err := strictjson.Object(header, requestKeys...)
	if err != nil {
		return "", protocolErrorf("malformed request header: %v", err)
	}
	var op string
	if err := decodeField(fields["op"], &op); err != nil {
		return "", protocolErrorf("malformed request header: the op is not a string")
	}
	if op == "" {
		return "", protocolErrorf("request names no op")
	}
	return op, nil
}

// helloOf is the client's HELLO header, read with the strict-object rule
// (strictjson.Object): a header that is not an object, any key given
// twice, a known field spelled in another case or of the wrong type closes
// the connection.
func helloOf(header []byte) (helloRequest, error) {
	var hello helloRequest
	fields, err := strictjson.Object(header, "proto", "min", "max")
	if err != nil {
		return hello, protocolErrorf("malformed HELLO header: %v", err)
	}
	for name, dst := range map[string]any{"proto": &hello.Proto, "min": &hello.Min, "max": &hello.Max} {
		if err := decodeField(fields[name], dst); err != nil {
			return helloRequest{}, protocolErrorf("malformed HELLO header: the field %s has the wrong type", name)
		}
	}
	return hello, nil
}

// Serve runs one connection: HELLO within RequestBound of the call, then
// requests until the client closes, each starting within IdleBound of the
// previous reply and done within RequestBound of its first byte. It returns nil when the client closes
// between frames and an error otherwise (a *ProtocolError for a frame or
// handshake that breaks the protocol, ErrUnsupportedVersion after its
// reply); the caller closes c in every case. Cancelling ctx expires c's
// deadlines, so Serve returns. Every request is served for p, the peer the
// listener admitted.
func (h *Handler) Serve(ctx context.Context, c Conn, p Peer) error {
	expired := time.Unix(1, 0)
	stop := context.AfterFunc(ctx, func() {
		_ = c.SetReadDeadline(expired)  // best effort: the read fails either way
		_ = c.SetWriteDeadline(expired) // best effort: the write fails either way
	})
	defer stop()
	// Each deadline is set before ctx is checked, so a cancellation that
	// lands in between is caught by the check or expires the new deadline.
	if err := c.SetReadDeadline(h.now().Add(RequestBound)); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	// Before HELLO the type is judged on the first five bytes: nothing of
	// a frame of another type, or of a HELLO with a value, is read further.
	f, err := ReadHello(c)
	if err != nil {
		return err
	}
	hello, err := helloOf(f.Header)
	if err != nil {
		return err
	}
	if hello.Proto != Proto {
		return protocolErrorf("HELLO names protocol %q", hello.Proto)
	}
	v, ok := selectVersion(hello.Min, hello.Max, MinVersion, MaxVersion)
	if !ok {
		if err := h.write(ctx, c, h.now().Add(RequestBound), TypeError, errorHeader{Code: CodeUnsupportedVersion}, nil); err != nil {
			return err
		}
		return ErrUnsupportedVersion
	}
	// The idle wait starts as the reply goes out, never after it: a client
	// may close as soon as it has read the reply, and a closed conn refuses
	// deadlines. A reply's write is bounded too, so the idle wait is at most
	// IdleBound and never longer.
	if err := c.SetReadDeadline(h.now().Add(IdleBound)); err != nil {
		return err
	}
	if err := h.write(ctx, c, h.now().Add(RequestBound), TypeHello, HelloReply{Proto: Proto, Version: v, MaxFrame: MaxFrame}, nil); err != nil {
		return err
	}
	for {
		// Idle: the next request's first byte within IdleBound of the last
		// reply's start (the read deadline set before it).
		if err := ctx.Err(); err != nil {
			return err
		}
		var first [1]byte
		if _, err := io.ReadFull(c, first[:]); err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		if err := h.serveRequest(ctx, c, p, first[0]); err != nil {
			return err
		}
	}
}

// serveRequest reads and answers one request whose first byte is first:
// the rest of its frame and its reply within RequestBound of that byte.
// The request's value is zeroed on every way out, an early return and a
// panic out of the operation included, and so is the reply's encoding.
func (h *Handler) serveRequest(ctx context.Context, c Conn, p Peer, first byte) error {
	end := h.now().Add(RequestBound)
	if err := c.SetReadDeadline(end); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	f, err := ReadFrame(io.MultiReader(bytes.NewReader([]byte{first}), c))
	defer func() { clear(f.Value) }()
	if err != nil {
		return err
	}
	if f.Type != TypeRequest {
		return protocolErrorf("frame type %#02x after HELLO, not a request", byte(f.Type))
	}
	name, err := requestOp(f.Header)
	if err != nil {
		return err
	}
	// An op the server does not have is answered unknown-op, and the
	// connection stays open so a newer client can fall back.
	rt, header, value := TypeError, any(errorHeader{Code: CodeUnknownOp}), []byte(nil)
	if op, ok := h.ops[name]; ok {
		rep, oerr := op(ctx, Request{Peer: p, Op: name, Header: f.Header, Value: f.Value})
		h.logStoreError(name, p, f.Header, oerr)
		rt, header, value = answer(rep, oerr)
	}
	// A reply the server cannot encode (a header that does not marshal,
	// or one past its cap) is answered internal: the operation has run,
	// and the connection stays open for the next request.
	b, err := marshalFrame(rt, header, value)
	clear(value)
	if err != nil {
		b, err = marshalFrame(TypeError, errorHeader{Code: CodeInternal}, nil)
	}
	// The encoding holds a copy of the reply's value: it is zeroed too.
	defer clear(b)
	if err != nil {
		return err
	}
	if err := c.SetReadDeadline(h.now().Add(IdleBound)); err != nil {
		return err
	}
	return h.writeEncoded(ctx, c, end, b)
}

// answer is the frame an operation's result is answered with: its reply,
// with the warning its error carries, when the error maps to no code; the
// error's code otherwise, the reply's value zeroed.
func answer(reply Reply, err error) (FrameType, any, []byte) {
	code, warning := outcomeOf(err)
	if code != "" {
		clear(reply.Value)
		return TypeError, errorHeader{Code: code}, nil
	}
	return TypeReply, replyHeader{header: reply.Header, warning: warning}, reply.Value
}

// replyHeader is a reply's header with the warning an outcome adds.
type replyHeader struct {
	header  any
	warning string
}

// MarshalJSON writes the operation's header as an object, with "warning"
// set when there is one; a header that is not an object is refused.
func (r replyHeader) MarshalJSON() ([]byte, error) {
	if r.header == nil && r.warning == "" {
		return []byte("{}"), nil
	}
	fields := map[string]json.RawMessage{}
	if r.header != nil {
		b, err := json.Marshal(r.header)
		if err != nil {
			return nil, err
		}
		if err := json.Unmarshal(b, &fields); err != nil {
			return nil, fmt.Errorf("keystore socket: a reply header must be a JSON object: %w", err)
		}
		if fields == nil {
			fields = map[string]json.RawMessage{}
		}
	}
	if r.warning != "" {
		w, err := json.Marshal(r.warning)
		if err != nil {
			return nil, err
		}
		fields["warning"] = w
	}
	return json.Marshal(fields)
}

// write sends one frame, with value as its binary part when it is not nil,
// finishing by deadline.
func (h *Handler) write(ctx context.Context, c Conn, deadline time.Time, t FrameType, header any, value []byte) error {
	b, err := marshalFrame(t, header, value)
	if err != nil {
		return err
	}
	// The encoding holds a copy of the value: it is zeroed with it.
	defer clear(b)
	return h.writeEncoded(ctx, c, deadline, b)
}

// marshalFrame is the encoding of one frame, header marshalled as JSON and
// value as its binary part when it is not nil. It fails, encoding nothing,
// when the header does not marshal or the frame is past a cap.
func marshalFrame(t FrameType, header any, value []byte) ([]byte, error) {
	hb, err := json.Marshal(header)
	if err != nil {
		return nil, err
	}
	return AppendFrame(nil, Frame{Type: t, Header: hb, Value: value})
}

// writeEncoded writes b, one encoded frame, finishing by deadline.
func (h *Handler) writeEncoded(ctx context.Context, c Conn, deadline time.Time, b []byte) error {
	if err := c.SetWriteDeadline(deadline); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	_, err := c.Write(b)
	return err
}

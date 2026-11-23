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
	"context"
	"encoding/json"
	"errors"
	"io"
	"time"
)

// RequestBound is how long the server waits for a complete HELLO from
// accept, and how long it gives each reply's write.
const RequestBound = 10 * time.Second

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
}

// NewHandler returns a Handler that takes its deadlines from now.
func NewHandler(now func() time.Time) (*Handler, error) {
	if now == nil {
		return nil, errors.New("keystore socket: nil clock")
	}
	return &Handler{now: now}, nil
}

// requestHeader is the part of a request header the dispatcher reads.
type requestHeader struct {
	Op string `json:"op"`
}

// Serve runs one connection: HELLO within RequestBound of the call, then
// requests until the client closes. It returns nil when the client closes
// between frames and an error otherwise (a *ProtocolError for a frame or
// handshake that breaks the protocol, ErrUnsupportedVersion after its
// reply); the caller closes c in every case. Cancelling ctx expires c's
// deadlines, so Serve returns.
func (h *Handler) Serve(ctx context.Context, c Conn) error {
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
	f, err := ReadFrame(c)
	if err != nil {
		return err
	}
	if f.Type != TypeHello {
		return protocolErrorf("first frame is type %#02x, not HELLO", byte(f.Type))
	}
	var hello helloRequest
	if err := json.Unmarshal(f.Header, &hello); err != nil {
		return protocolErrorf("malformed HELLO header: %v", err)
	}
	if hello.Proto != Proto {
		return protocolErrorf("HELLO names protocol %q", hello.Proto)
	}
	v, ok := selectVersion(hello.Min, hello.Max, MinVersion, MaxVersion)
	if !ok {
		if err := h.write(ctx, c, TypeError, errorHeader{Code: CodeUnsupportedVersion}); err != nil {
			return err
		}
		return ErrUnsupportedVersion
	}
	// The HELLO deadline ends before the reply goes out: a client may close
	// as soon as it has read the reply, and a closed conn refuses deadlines.
	if err := c.SetReadDeadline(time.Time{}); err != nil {
		return err
	}
	if err := h.write(ctx, c, TypeHello, HelloReply{Proto: Proto, Version: v, MaxFrame: MaxFrame}); err != nil {
		return err
	}
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		f, err := ReadFrame(c)
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		if f.Type != TypeRequest {
			return protocolErrorf("frame type %#02x after HELLO, not a request", byte(f.Type))
		}
		var req requestHeader
		if err := json.Unmarshal(f.Header, &req); err != nil {
			return protocolErrorf("malformed request header: %v", err)
		}
		if req.Op == "" {
			return protocolErrorf("request names no op")
		}
		// No operation exists yet: every op is unknown, and the connection
		// stays open so a newer client can fall back.
		if err := h.write(ctx, c, TypeError, errorHeader{Code: CodeUnknownOp}); err != nil {
			return err
		}
	}
}

// write sends one header-only frame within RequestBound.
func (h *Handler) write(ctx context.Context, c Conn, t FrameType, header any) error {
	hb, err := json.Marshal(header)
	if err != nil {
		return err
	}
	if err := c.SetWriteDeadline(h.now().Add(RequestBound)); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return WriteFrame(c, Frame{Type: t, Header: hb})
}

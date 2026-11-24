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
	"time"

	keyentry "k3sm.io/apis/keystore/entry"
	"k3sm.io/k3sm/pkg/keystore"
)

// The operations' names, as a request's op carries them.
const (
	OpPut         = "put"
	OpRotate      = "rotate"
	OpList        = "list"
	OpRm          = "rm"
	OpReadForExec = "read-for-exec"
	OpDeliver     = "deliver"
	OpWithdraw    = "withdraw"
	OpDeliveries  = "deliveries"
)

// The wire shapes of the operations (docs/design/keystore.md § "The
// socket", "Operations on the wire"). An entry is named in the API grammar
// only, user/<uid>/<name>: no bare name and no short name reaches the
// socket, and the store parses it. Unknown header fields are ignored; a
// known field of the wrong JSON type refuses the request.

// PutRequest is put's header; the value is the request's binary part.
// Kind is "opaque", the only kind the socket stores, or absent.
type PutRequest struct {
	Op    string `json:"op"`
	Entry string `json:"entry"`
	Kind  string `json:"kind,omitempty"`
}

// RotateRequest is rotate's header: with no FromVersion, the value is the
// request's binary part; with FromVersion, that version's value is
// written forward and the request carries no value.
type RotateRequest struct {
	Op          string  `json:"op"`
	Entry       string  `json:"entry"`
	FromVersion *uint64 `json:"from_version,omitempty"`
}

// ListRequest is list's header: the peer's own scope, nothing to name.
type ListRequest struct {
	Op string `json:"op"`
}

// RmRequest is rm's header.
type RmRequest struct {
	Op    string `json:"op"`
	Entry string `json:"entry"`
}

// ReadForExecRequest is read-for-exec's header.
type ReadForExecRequest struct {
	Op    string `json:"op"`
	Entry string `json:"entry"`
}

// VersionReply is put's and rotate's reply: the version written and its
// fingerprint, which the store computes as it seals, never by reading the
// value back.
type VersionReply struct {
	Version     uint64 `json:"version"`
	Fingerprint string `json:"fingerprint,omitempty"`
}

// ListReply is list's reply: every entry of the peer's own scope, sorted
// by name; an empty scope, or none yet, is an empty list.
type ListReply struct {
	Entries []ListEntry `json:"entries"`
}

// ListEntry is one entry of a list, named as `k3sm keys list -o json`
// names the same fields. It carries metadata only, never a value or its
// length. Status is ok, corrupt (the entry fails to open as stored) or
// error (it could not be read); the error itself stays in the server.
type ListEntry struct {
	Name        string `json:"name"`
	Kind        string `json:"kind,omitempty"`
	Version     uint64 `json:"version,omitempty"`
	Versions    int    `json:"versions,omitempty"`
	Created     string `json:"created,omitempty"`
	Fingerprint string `json:"fingerprint,omitempty"`
	Status      string `json:"status"`
}

// RmReply is rm's reply: an empty object.
type RmReply struct{}

// ReadForExecReply is read-for-exec's reply header; the value is the
// reply's binary part.
type ReadForExecReply struct {
	Version uint64 `json:"version"`
}

// ErrRequestRefused is a request the server refuses as it stands: a known
// header field of the wrong type, a value missing, empty, oversize or
// where the operation takes none, a kind the socket does not store, or an
// operation not yet served. It is answered refused, and the connection
// stays open.
var ErrRequestRefused = errors.New("keystore socket: request refused")

// reasonDeliverySlice is why deliver, withdraw and deliveries are refused:
// they arrive with the delivery slice. Until then each answers refused, a
// stable code, rather than unknown-op.
const reasonDeliverySlice = "the delivery operations are not served yet"

func refusedf(format string, args ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{ErrRequestRefused}, args...)...)
}

// NewOpsHandler returns the Handler that serves the operations over store,
// taking its deadlines from now.
func NewOpsHandler(now func() time.Time, store Store, opts ...HandlerOption) (*Handler, error) {
	if store == nil {
		return nil, errors.New("keystore socket: nil store")
	}
	o := ops{store: store}
	all := append([]HandlerOption{
		withOp(OpPut, o.put),
		withOp(OpRotate, o.rotate),
		withOp(OpList, o.list),
		withOp(OpRm, o.rm),
		withOp(OpReadForExec, o.readForExec),
		withOp(OpDeliver, o.notServed(OpDeliver)),
		withOp(OpWithdraw, o.notServed(OpWithdraw)),
		withOp(OpDeliveries, o.notServed(OpDeliveries)),
	}, opts...)
	return NewHandler(now, all...)
}

// ops are the operations over one Store. Each acts for the request's
// admitted peer, never a header field.
type ops struct {
	store Store
}

func (o ops) put(ctx context.Context, req Request) (Reply, error) {
	var h PutRequest
	if err := decodeRequest(req.Header, &h); err != nil {
		return Reply{}, err
	}
	kind := keystore.KindOpaque
	if h.Kind != "" && h.Kind != keystore.KindOpaque.String() {
		return Reply{}, refusedf("the socket stores kind %s only", keystore.KindOpaque)
	}
	if err := checkValue(req.Value); err != nil {
		return Reply{}, err
	}
	if err := o.store.Admit(req.Peer, OpPut); err != nil {
		return Reply{}, err
	}
	v, err := o.store.Put(ctx, req.Peer, h.Entry, kind, req.Value)
	return Reply{Header: VersionReply{Version: v.Version, Fingerprint: v.Fingerprint}}, err
}

func (o ops) rotate(ctx context.Context, req Request) (Reply, error) {
	var h RotateRequest
	if err := decodeRequest(req.Header, &h); err != nil {
		return Reply{}, err
	}
	var (
		v   keystore.Version
		err error
	)
	if h.FromVersion != nil {
		if req.Value != nil {
			return Reply{}, refusedf("a rotate carries a value or from_version, not both")
		}
		if err := o.store.Admit(req.Peer, OpRotate); err != nil {
			return Reply{}, err
		}
		v, err = o.store.RotateFrom(ctx, req.Peer, h.Entry, *h.FromVersion)
	} else {
		if err := checkValue(req.Value); err != nil {
			return Reply{}, err
		}
		if err := o.store.Admit(req.Peer, OpRotate); err != nil {
			return Reply{}, err
		}
		v, err = o.store.Rotate(ctx, req.Peer, h.Entry, req.Value)
	}
	// A rotation that committed returns its version with its error; the
	// reply is written when the error maps to no code (outcomeOf).
	return Reply{Header: VersionReply{Version: v.Version, Fingerprint: v.Fingerprint}}, err
}

func (o ops) list(ctx context.Context, req Request) (Reply, error) {
	var h ListRequest
	if err := decodeRequest(req.Header, &h); err != nil {
		return Reply{}, err
	}
	if err := noValue(req.Value); err != nil {
		return Reply{}, err
	}
	if err := o.store.Admit(req.Peer, OpList); err != nil {
		return Reply{}, err
	}
	es, err := o.store.List(ctx, req.Peer)
	if errors.Is(err, keystore.ErrScopeAbsent) {
		// A uid with no scope yet holds nothing: an empty list, as an
		// empty scope gives (docs/design/keystore.md § "A read never
		// mints a scope"). The store has audited the list already: one
		// whose line failed is refused (keystore.AuditRefused), not this.
		es, err = nil, nil
	}
	if err != nil {
		return Reply{}, err
	}
	out := ListReply{Entries: make([]ListEntry, 0, len(es))}
	for _, e := range es {
		out.Entries = append(out.Entries, listEntryOf(req.Peer.UID, e))
	}
	return Reply{Header: out}, nil
}

// listEntryOf is e's list row, named in the API grammar within uid's scope.
func listEntryOf(uid uint32, e keystore.Entry) ListEntry {
	out := ListEntry{Name: keyentry.Entry{Scope: keyentry.ScopeUser, UID: uid, Name: e.Name}.String(), Status: "ok"}
	if e.Err != nil {
		out.Status = "error"
		if errors.Is(e.Err, keystore.ErrCorrupt) {
			out.Status = "corrupt"
		}
		return out
	}
	out.Kind = e.Current.Kind.String()
	out.Version = e.Current.Version
	out.Versions = len(e.Versions)
	out.Created = e.Current.Created.UTC().Format(time.RFC3339)
	out.Fingerprint = e.Current.Fingerprint
	return out
}

func (o ops) rm(ctx context.Context, req Request) (Reply, error) {
	var h RmRequest
	if err := decodeRequest(req.Header, &h); err != nil {
		return Reply{}, err
	}
	if err := noValue(req.Value); err != nil {
		return Reply{}, err
	}
	if err := o.store.Admit(req.Peer, OpRm); err != nil {
		return Reply{}, err
	}
	return Reply{Header: RmReply{}}, o.store.Remove(ctx, req.Peer, h.Entry)
}

func (o ops) readForExec(ctx context.Context, req Request) (Reply, error) {
	var h ReadForExecRequest
	if err := decodeRequest(req.Header, &h); err != nil {
		return Reply{}, err
	}
	if err := noValue(req.Value); err != nil {
		return Reply{}, err
	}
	if err := o.store.Admit(req.Peer, OpReadForExec); err != nil {
		return Reply{}, err
	}
	v, val, err := o.store.ReadForExec(ctx, req.Peer, h.Entry)
	if err != nil {
		clear(val)
		return Reply{}, err
	}
	return Reply{Header: ReadForExecReply{Version: v.Version}, Value: val}, nil
}

// notServed answers op, an operation of the delivery slice, refused, once
// the store admitted it: the placeholder keeps the limits and the
// fail-closed rule the operation will have.
func (o ops) notServed(op string) opFunc {
	return func(_ context.Context, req Request) (Reply, error) {
		if err := o.store.Admit(req.Peer, op); err != nil {
			return Reply{}, err
		}
		return Reply{}, refusedf("%s", reasonDeliverySlice)
	}
}

// checkValue refuses a value the store would not take, before the store
// is reached: none, empty, or over the store's value cap.
func checkValue(v []byte) error {
	switch {
	case len(v) == 0:
		return refusedf("the request carries no value")
	case len(v) > keystore.MaxValueSize:
		return refusedf("the value is over the %d-byte limit", keystore.MaxValueSize)
	}
	return nil
}

// noValue refuses a value on an operation that takes none.
func noValue(v []byte) error {
	if v != nil {
		return refusedf("the operation takes no value")
	}
	return nil
}

// requestFields are the header fields each request type reads, by their
// exact JSON names; every other field is ignored.
func requestFields(dst any) (map[string]any, error) {
	switch h := dst.(type) {
	case *PutRequest:
		return map[string]any{"op": &h.Op, "entry": &h.Entry, "kind": &h.Kind}, nil
	case *RotateRequest:
		return map[string]any{"op": &h.Op, "entry": &h.Entry, "from_version": &h.FromVersion}, nil
	case *ListRequest:
		return map[string]any{"op": &h.Op}, nil
	case *RmRequest:
		return map[string]any{"op": &h.Op, "entry": &h.Entry}, nil
	case *ReadForExecRequest:
		return map[string]any{"op": &h.Op, "entry": &h.Entry}, nil
	}
	return nil, fmt.Errorf("keystore socket: no request type %T", dst)
}

// decodeRequest decodes header into dst, one of the request types. A
// header over MaxHeader is refused before it is parsed; a header that is
// not a JSON object, or a known field of the wrong JSON type, refuses the
// request. Field names match exactly, never case-folded, and a field set
// to null is absent.
func decodeRequest(header []byte, dst any) error {
	fields, err := requestFields(dst)
	if err != nil {
		return err
	}
	if len(header) > MaxHeader {
		return refusedf("the header is over the %d-byte cap", MaxHeader)
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(header, &raw); err != nil || raw == nil {
		return refusedf("the header is not a JSON object")
	}
	for name, ptr := range fields {
		v, ok := raw[name]
		if !ok || bytes.Equal(v, []byte("null")) {
			continue
		}
		if err := json.Unmarshal(v, ptr); err != nil {
			return refusedf("the header field %s has the wrong type", name)
		}
	}
	return nil
}

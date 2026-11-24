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
	"errors"
	"fmt"
	"time"

	keyentry "k3sm.io/apis/keystore/entry"
	"k3sm.io/k3sm/pkg/keystore"
	"k3sm.io/k3sm/pkg/keystore/internal/strictjson"
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

// The widest each list row's fields can be, which size MaxReplyHeader. The
// name is in the API grammar (keyentry.MaxLength); the kind is a Kind's
// name, at most "ed25519" or "unknown"; the version a uint64 and versions an
// int in decimal; created is RFC 3339 in UTC of a time from int64 seconds,
// whose year has at most twelve digits and a sign; the fingerprint is at
// most the 64 hex digits of a SHA-256 (an ssh fingerprint is shorter); the
// status is ok, corrupt or error. No field holds a byte JSON escapes.
const (
	maxListKind        = len("ed25519")
	maxListUint64      = len("18446744073709551615")
	maxListInt         = len("-9223372036854775808")
	maxListCreated     = len("-292277026596-12-31T23:59:59Z")
	maxListFingerprint = 64
	maxListStatus      = len("corrupt")
	// maxListRow is the widest list row with its separating comma.
	maxListRow = len(`{"name":"","kind":"","version":,"versions":,"created":"","fingerprint":"","status":""},`) +
		keyentry.MaxLength + maxListKind + maxListUint64 + maxListInt + maxListCreated + maxListFingerprint + maxListStatus
)

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

// valueRefusedf is refusedf for a refusal of the request's value.
func valueRefusedf(format string, args ...any) error {
	return fmt.Errorf("%w: %w: "+format, append([]any{ErrRequestRefused, errBadValue}, args...)...)
}

// NewOpsHandler returns the Handler that serves the operations over store,
// taking its deadlines from now.
func NewOpsHandler(now func() time.Time, store Store, opts ...HandlerOption) (*Handler, error) {
	if store == nil {
		return nil, errors.New("keystore socket: nil store")
	}
	o := ops{store: store}
	all := append([]HandlerOption{
		o.serve(OpPut, o.put),
		o.serve(OpRotate, o.rotate),
		o.serve(OpList, o.list),
		o.serve(OpRm, o.rm),
		o.serve(OpReadForExec, o.readForExec),
		o.serve(OpDeliver, o.notServed(OpDeliver)),
		o.serve(OpWithdraw, o.notServed(OpWithdraw)),
		o.serve(OpDeliveries, o.notServed(OpDeliveries)),
	}, opts...)
	return NewHandler(now, all...)
}

// ops are the operations over one Store. Each acts for the request's
// admitted peer, never a header field.
type ops struct {
	store Store
}

// serve registers fn as op, recording each refusal the socket gives
// itself (refusalReason) as a post-frame refused line before the reply is
// written; a refusal the store gave, the store has audited.
func (o ops) serve(op string, fn opFunc) HandlerOption {
	return withOp(op, func(ctx context.Context, req Request) (Reply, error) {
		rep, err := fn(ctx, req)
		if reason := refusalReason(err); reason != "" {
			o.store.Refused(ctx, req.Peer, op, reason)
		}
		return rep, err
	})
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
			return Reply{}, valueRefusedf("a rotate carries a value or from_version, not both")
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
	if keystore.NoScopeKey(err) {
		// A uid with no scope yet holds nothing: an empty list, as an
		// empty scope gives (docs/design/keystore.md § "A read never
		// mints a scope"). The store has audited the list already: one
		// whose line failed is refused (keystore.AuditRefused), not this.
		// A scope that is there but damaged (a scope.key with no entries/
		// or no deliveries record) is not empty: it answers its own code.
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
	out.Versions = e.VersionCount
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
		return Reply{}, fmt.Errorf("%w: %w: %s", ErrRequestRefused, errNotServed, reasonDeliverySlice)
	}
}

// checkValue refuses a value the store would not take, before the store
// is reached: none, empty, or over the store's value cap.
func checkValue(v []byte) error {
	switch {
	case len(v) == 0:
		return valueRefusedf("the request carries no value")
	case len(v) > keystore.MaxValueSize:
		return valueRefusedf("the value is over the %d-byte limit", keystore.MaxValueSize)
	}
	return nil
}

// noValue refuses a value on an operation that takes none.
func noValue(v []byte) error {
	if v != nil {
		return valueRefusedf("the operation takes no value")
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
// request. Field names match exactly, never case-folded, under the
// keystore's strict-object rule (strictjson.Object), the one the
// dispatcher closes on first: a key given twice in any case, or a field
// spelled in another case, refuses it too. A field set to null is absent.
func decodeRequest(header []byte, dst any) error {
	fields, err := requestFields(dst)
	if err != nil {
		return err
	}
	if len(header) > MaxHeader {
		return refusedf("the header is over the %d-byte cap", MaxHeader)
	}
	names := make([]string, 0, len(fields))
	for name := range fields {
		names = append(names, name)
	}
	raw, err := strictjson.Object(header, names...)
	if err != nil {
		return refusedf("the header is not a strict JSON object")
	}
	for name, ptr := range fields {
		if err := decodeField(raw[name], ptr); err != nil {
			return refusedf("the header field %s has the wrong type", name)
		}
	}
	return nil
}

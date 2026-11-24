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
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	keyentry "k3sm.io/apis/keystore/entry"
	"k3sm.io/k3sm/pkg/keystore"
)

// maxName is the i-th distinct entry name at the store's name cap.
func maxName(i int) string {
	p := fmt.Sprintf("n%03d", i)
	return p + strings.Repeat("a", keyentry.MaxNameLength-len(p))
}

// A full scope, every entry at the name cap, lists in one call over a real
// framed connection: the reply header is past MaxHeader, inside
// MaxReplyHeader, and the connection stays open for the next request.
func TestListFullScopeOneReply(t *testing.T) {
	r := newOpsRig(t, nil)
	w := dialOps(t, r.ops, uidA)
	for i := range keystore.MaxScopeEntries {
		w.mustReply(t, hdr(t, OpPut, entryOf(uidA, maxName(i)), nil), []byte("v"), nil)
	}
	var l ListReply
	f := w.mustReply(t, hdr(t, OpList, "", nil), nil, &l)
	if len(f.Header) <= MaxHeader || len(f.Header) > MaxReplyHeader {
		t.Fatalf("the full list's header is %d bytes, want past MaxHeader %d and at most MaxReplyHeader %d", len(f.Header), MaxHeader, MaxReplyHeader)
	}
	if len(l.Entries) != keystore.MaxScopeEntries {
		t.Fatalf("list named %d entries, want %d", len(l.Entries), keystore.MaxScopeEntries)
	}
	for i, e := range l.Entries {
		if e.Name != entryOf(uidA, maxName(i)) || e.Status != "ok" || e.Version != 1 {
			t.Fatalf("entry %d is %+v, want %s at version 1", i, e, maxName(i))
		}
	}
	// The connection is still served.
	w.mustReply(t, hdr(t, OpRm, entryOf(uidA, maxName(0)), nil), nil, nil)
}

// worstListRow is a list row with every field at its widest.
func worstListRow(i int) ListEntry {
	return ListEntry{
		Name:        keyentry.Entry{Scope: keyentry.ScopeUser, UID: keyentry.MaxUID, Name: maxName(i)}.String(),
		Kind:        strings.Repeat("k", maxListKind),
		Version:     math.MaxUint64,
		Versions:    math.MinInt64,
		Created:     strings.Repeat("c", maxListCreated),
		Fingerprint: strings.Repeat("f", maxListFingerprint),
		Status:      strings.Repeat("s", maxListStatus),
	}
}

// MaxReplyHeader holds the worst-case list (a full scope, every field at
// its widest, with the warning) and the field widths hold what the store
// can put in them; a frame carrying it is under MaxFrame and reads back
// through ReadReply but not ReadFrame.
func TestReplyHeaderCapHoldsWorstList(t *testing.T) {
	out := ListReply{}
	for i := range keystore.MaxScopeEntries {
		out.Entries = append(out.Entries, worstListRow(i))
	}
	hb, err := json.Marshal(replyHeader{header: out, warning: WarnAuditFailed})
	if err != nil {
		t.Fatal(err)
	}
	if len(hb) > MaxReplyHeader {
		t.Fatalf("the worst-case list header is %d bytes, over MaxReplyHeader %d", len(hb), MaxReplyHeader)
	}
	b, err := AppendFrame(nil, Frame{Type: TypeReply, Header: hb})
	if err != nil {
		t.Fatalf("AppendFrame of the worst-case list: %v", err)
	}
	if f, err := ReadReply(strings.NewReader(string(b))); err != nil || len(f.Header) != len(hb) {
		t.Fatalf("ReadReply of the worst-case list: %v", err)
	}
	if _, err := ReadFrame(strings.NewReader(string(b))); !isProtocolError(err) {
		t.Fatalf("ReadFrame of a reply header past MaxHeader = %v, want a protocol error: only the client's reader takes it", err)
	}
	if _, err := AppendFrame(nil, Frame{Type: TypeRequest, Header: hb}); err == nil {
		t.Fatal("AppendFrame took a request header past MaxHeader")
	}
	for k := keystore.Kind(0); k < 16; k++ {
		if n := len(k.String()); n > maxListKind {
			t.Errorf("kind %d's name %q is over maxListKind %d", k, k, maxListKind)
		}
	}
	for _, s := range []int64{math.MinInt64, math.MaxInt64, math.MinInt64 / 2, math.MaxInt64 / 2, -62135596801, 253402300800, 0} {
		if c := time.Unix(s, 0).UTC().Format(time.RFC3339); len(c) > maxListCreated {
			t.Errorf("created %q is over maxListCreated %d", c, maxListCreated)
		}
	}
	if len(listEntryOf(keyentry.MaxUID, keystore.Entry{Name: maxName(0)}).Name) > keyentry.MaxLength {
		t.Error("a list row's name is over the API grammar's MaxLength")
	}
}

// A reply the server cannot encode, a header that does not marshal or one
// past its cap, is an error frame with code internal, and the connection
// stays open.
func TestUnencodableReplyIsInternal(t *testing.T) {
	huge := map[string]string{"x": strings.Repeat("a", MaxReplyHeader)}
	h, err := NewHandler(time.Now,
		withOp("bad", func(context.Context, Request) (Reply, error) {
			return Reply{Header: map[string]any{"f": func() {}}, Value: []byte("secret")}, nil
		}),
		withOp("huge", func(context.Context, Request) (Reply, error) { return Reply{Header: huge}, nil }),
		withOp("ok", func(context.Context, Request) (Reply, error) { return Reply{}, nil }),
	)
	if err != nil {
		t.Fatal(err)
	}
	w := dialOps(t, h, uidA)
	for _, op := range []string{"bad", "huge"} {
		f := w.call(t, `{"op":"`+op+`"}`, nil)
		if f.Type != TypeError || codeOf(t, f) != CodeInternal || f.Value != nil {
			t.Fatalf("%s: reply %#02x %s, want an error frame internal with no value", op, byte(f.Type), f.Header)
		}
	}
	w.mustReply(t, `{"op":"ok"}`, nil, nil)
}

// Only a uid with no scope key lists as empty: a scope whose scope.key is
// there but whose entries/ directory or deliveries record is gone is
// damage, and its list answers the store's code, never an empty list.
func TestListDamagedScopeIsNotEmpty(t *testing.T) {
	for _, gone := range []string{"entries", "deliveries"} {
		t.Run(gone, func(t *testing.T) {
			r := newOpsRig(t, nil)
			w := dialOps(t, r.ops, uidA)
			w.mustReply(t, hdr(t, OpPut, entryOf(uidA, "a"), nil), []byte("v"), nil)
			p := filepath.Join(r.data, "server", "keystore", ".user", strconv.FormatUint(uint64(uidA), 10), gone)
			if err := os.RemoveAll(p); err != nil {
				t.Fatal(err)
			}
			f := w.call(t, hdr(t, OpList, "", nil), nil)
			if code := codeOf(t, f); f.Type != TypeError || code != CodeNotFound {
				t.Fatalf("list of a scope with no %s replied %#02x %s, want the error frame not-found (ErrScopeAbsent)", gone, byte(f.Type), f.Header)
			}
			// The store's answer is the damage, ErrScopeAbsent, never the
			// no-scope-key absence a list serves as empty.
			if _, err := r.b.List(t.Context(), Peer{UID: uidA}); !errors.Is(err, keystore.ErrScopeAbsent) || keystore.NoScopeKey(err) {
				t.Fatalf("the store's list of a scope with no %s = %v, want ErrScopeAbsent that is not NoScopeKey", gone, err)
			}
		})
	}
}

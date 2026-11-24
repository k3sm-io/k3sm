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
	"io"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	keyentry "k3sm.io/apis/keystore/entry"
	"k3sm.io/k3sm/pkg/keystore"
)

// opsRig is a started real store with the production operations served
// over its bridge.
type opsRig struct {
	*bridgeRig
	ops *Handler
}

func newOpsRig(t *testing.T, tune func(*keystore.Config)) *opsRig {
	t.Helper()
	r := newStartedBridge(t, tune)
	h, err := NewOpsHandler(time.Now, r.b)
	if err != nil {
		t.Fatal(err)
	}
	return &opsRig{bridgeRig: r, ops: h}
}

// wire is one fake peer's connection to a handler, after HELLO.
type wire struct {
	s *session
}

func dialOps(t *testing.T, h *Handler, uid uint32) *wire {
	t.Helper()
	s := serveAs(t, h, Peer{UID: uid, PID: int32(uid % 1000)})
	s.hello(t)
	t.Cleanup(func() { _ = s.finish() })
	return &wire{s: s}
}

// call sends header (value as its binary part when not nil) and returns
// the reply frame.
func (w *wire) call(t *testing.T, header string, value []byte) Frame {
	t.Helper()
	w.s.send(t, TypeRequest, header, value)
	f, _ := w.s.recvFrame(t)
	return f
}

// codeOf is f's error code, "" for a reply.
func codeOf(t *testing.T, f Frame) Code {
	t.Helper()
	if f.Type == TypeReply {
		return ""
	}
	var eh errorHeader
	if err := json.Unmarshal(f.Header, &eh); err != nil {
		t.Fatalf("error reply %s: %v", f.Header, err)
	}
	return eh.Code
}

// mustReply is call, failing unless the reply is ok, decoding its header
// into out when out is not nil.
func (w *wire) mustReply(t *testing.T, header string, value []byte, out any) Frame {
	t.Helper()
	f := w.call(t, header, value)
	if f.Type != TypeReply {
		t.Fatalf("%s: reply %#02x %s, want ok", header, byte(f.Type), f.Header)
	}
	if out != nil {
		if err := json.Unmarshal(f.Header, out); err != nil {
			t.Fatalf("%s: reply header %s: %v", header, f.Header, err)
		}
	}
	return f
}

// hdr is a request header naming op and entry, with extra fields.
func hdr(t *testing.T, op, entry string, extra map[string]any) string {
	t.Helper()
	m := map[string]any{"op": op}
	if entry != "" {
		m["entry"] = entry
	}
	for k, v := range extra {
		m[k] = v
	}
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func keysOf(t *testing.T, f Frame) []string {
	t.Helper()
	var m map[string]json.RawMessage
	if err := json.Unmarshal(f.Header, &m); err != nil {
		t.Fatalf("header %s: %v", f.Header, err)
	}
	var ks []string
	for k := range m {
		ks = append(ks, k)
	}
	slices.Sort(ks)
	return ks
}

// The five operations answer in their wire shapes: put and rotate their
// version and fingerprint, read-for-exec its version with the value as the
// binary part, list its entries' metadata named in the API grammar, rm an
// empty object.
func TestOpsWireShapes(t *testing.T) {
	r := newOpsRig(t, nil)
	w := dialOps(t, r.ops, uidA)
	e := entryOf(uidA, "a")

	var put VersionReply
	f := w.mustReply(t, hdr(t, OpPut, e, map[string]any{"kind": "opaque"}), []byte("v1"), &put)
	if put.Version != 1 || put.Fingerprint == "" || f.Value != nil || !slices.Equal(keysOf(t, f), []string{"fingerprint", "version"}) {
		t.Fatalf("put replied %s value %q; want version 1 and a fingerprint, nothing else", f.Header, f.Value)
	}
	var rot VersionReply
	w.mustReply(t, hdr(t, OpRotate, e, nil), []byte("v2"), &rot)
	if rot.Version != 2 || rot.Fingerprint == "" || rot.Fingerprint == put.Fingerprint {
		t.Fatalf("rotate with a value replied %+v, want version 2 with a new fingerprint", rot)
	}
	var from VersionReply
	w.mustReply(t, hdr(t, OpRotate, e, map[string]any{"from_version": 1}), nil, &from)
	if from.Version != 3 || from.Fingerprint != put.Fingerprint {
		t.Fatalf("rotate from version 1 replied %+v, want version 3 with version 1's fingerprint %s", from, put.Fingerprint)
	}
	var rd ReadForExecReply
	f = w.mustReply(t, hdr(t, OpReadForExec, e, nil), nil, &rd)
	if rd.Version != 3 || string(f.Value) != "v1" || !slices.Equal(keysOf(t, f), []string{"version"}) {
		t.Fatalf("read-for-exec replied %s value %q; want version 3 and v1 as the binary part", f.Header, f.Value)
	}
	var ls ListReply
	f = w.mustReply(t, hdr(t, OpList, "", nil), nil, &ls)
	want := ListEntry{Name: e, Kind: "opaque", Version: 3, Versions: 3, Fingerprint: put.Fingerprint, Status: "ok"}
	if len(ls.Entries) != 1 || f.Value != nil {
		t.Fatalf("list replied %s value %q; want one entry", f.Header, f.Value)
	}
	got := ls.Entries[0]
	if _, err := time.Parse(time.RFC3339, got.Created); err != nil {
		t.Errorf("list's created %q is not RFC 3339: %v", got.Created, err)
	}
	got.Created = ""
	if got != want {
		t.Errorf("list's entry %+v, want %+v", got, want)
	}
	if bytes.Contains(f.Header, []byte("v1")) || bytes.Contains(f.Header, []byte(`"length"`)) {
		t.Errorf("list's reply %s carries a value or its length", f.Header)
	}
	f = w.mustReply(t, hdr(t, OpRm, e, nil), nil, nil)
	if string(f.Header) != "{}" || f.Value != nil {
		t.Fatalf("rm replied %s value %q, want {} and no value", f.Header, f.Value)
	}
	f = w.mustReply(t, hdr(t, OpList, "", nil), nil, nil)
	if string(f.Header) != `{"entries":[]}` {
		t.Fatalf("list of an emptied scope replied %s, want an empty list", f.Header)
	}
}

// countingStore is a Store that counts its calls and answers each ok.
type countingStore struct {
	mu      sync.Mutex
	calls   int
	refused []string
}

func (s *countingStore) hit() { s.mu.Lock(); s.calls++; s.mu.Unlock() }

func (s *countingStore) n() int { s.mu.Lock(); defer s.mu.Unlock(); return s.calls }

func (s *countingStore) Put(context.Context, Peer, string, keystore.Kind, []byte) (keystore.Version, error) {
	s.hit()
	return keystore.Version{Version: 1}, nil
}

func (s *countingStore) Rotate(context.Context, Peer, string, []byte) (keystore.Version, error) {
	s.hit()
	return keystore.Version{Version: 2}, nil
}

func (s *countingStore) RotateFrom(context.Context, Peer, string, uint64) (keystore.Version, error) {
	s.hit()
	return keystore.Version{Version: 2}, nil
}

func (s *countingStore) Remove(context.Context, Peer, string) error { s.hit(); return nil }

func (s *countingStore) List(context.Context, Peer) ([]keystore.Entry, error) {
	s.hit()
	return nil, nil
}

func (s *countingStore) Admit(Peer, string) error { return nil }

// Refused records the socket's own refusals by operation and reason; they
// are not store calls.
func (s *countingStore) Refused(_ context.Context, _ Peer, op, reason string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.refused = append(s.refused, op+" "+reason)
}

func (s *countingStore) refusals() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.refused...)
}

func (s *countingStore) ReadForExec(context.Context, Peer, string) (keystore.Version, []byte, error) {
	s.hit()
	return keystore.Version{Version: 1}, []byte("v"), nil
}

// A known field of the wrong type, a value missing, empty, oversize or
// where none belongs, both or neither of rotate's sources, and a kind the
// socket does not store are each refused before the store is reached, and
// the connection stays open; unknown fields are ignored.
func TestOpsRefuseMalformedRequests(t *testing.T) {
	st := &countingStore{}
	h, err := NewOpsHandler(time.Now, st)
	if err != nil {
		t.Fatal(err)
	}
	w := dialOps(t, h, uidA)
	e := entryOf(uidA, "a")
	big := make([]byte, keystore.MaxValueSize+1)
	for _, tc := range []struct {
		name   string
		header string
		value  []byte
	}{
		{"put entry a number", `{"op":"put","entry":7}`, []byte("v")},
		{"put entry an array", `{"op":"put","entry":["x"]}`, []byte("v")},
		{"put kind a number", `{"op":"put","entry":"` + e + `","kind":1}`, []byte("v")},
		{"put kind ed25519", `{"op":"put","entry":"` + e + `","kind":"ed25519"}`, []byte("v")},
		{"put kind token", `{"op":"put","entry":"` + e + `","kind":"token"}`, []byte("v")},
		{"put no value", `{"op":"put","entry":"` + e + `"}`, nil},
		{"put empty value", `{"op":"put","entry":"` + e + `"}`, []byte{}},
		{"put oversize value", `{"op":"put","entry":"` + e + `"}`, big},
		{"rotate no value no from_version", `{"op":"rotate","entry":"` + e + `"}`, nil},
		{"rotate empty value", `{"op":"rotate","entry":"` + e + `"}`, []byte{}},
		{"rotate oversize value", `{"op":"rotate","entry":"` + e + `"}`, big},
		{"rotate value and from_version", `{"op":"rotate","entry":"` + e + `","from_version":1}`, []byte("v")},
		{"rotate empty value and from_version", `{"op":"rotate","entry":"` + e + `","from_version":1}`, []byte{}},
		{"rotate from_version a string", `{"op":"rotate","entry":"` + e + `","from_version":"1"}`, nil},
		{"rotate from_version negative", `{"op":"rotate","entry":"` + e + `","from_version":-1}`, nil},
		{"rotate from_version a fraction", `{"op":"rotate","entry":"` + e + `","from_version":1.5}`, nil},
		{"rotate from_version past uint64", `{"op":"rotate","entry":"` + e + `","from_version":18446744073709551616}`, nil},
		{"rm entry a bool", `{"op":"rm","entry":true}`, nil},
		{"rm with a value", `{"op":"rm","entry":"` + e + `"}`, []byte("v")},
		{"read-for-exec entry an object", `{"op":"read-for-exec","entry":{}}`, nil},
		{"read-for-exec with a value", `{"op":"read-for-exec","entry":"` + e + `"}`, []byte("v")},
		{"list with a value", `{"op":"list"}`, []byte("v")},
		{"list with an empty value", `{"op":"list"}`, []byte{}},
	} {
		f := w.call(t, tc.header, tc.value)
		if code := codeOf(t, f); code != CodeRefused || f.Value != nil {
			t.Errorf("%s: code %q value %q, want refused and no value", tc.name, code, f.Value)
		}
	}
	if n := st.n(); n != 0 {
		t.Fatalf("refused requests reached the store %d times", n)
	}
	for _, r := range st.refusals() {
		if !strings.HasSuffix(r, " bad-header") && !strings.HasSuffix(r, " bad-value") {
			t.Errorf("a malformed request was recorded as %q, want bad-header or bad-value", r)
		}
	}
	if n := len(st.refusals()); n != 23 {
		t.Fatalf("%d refusals recorded for the 23 malformed requests", n)
	}
	for _, tc := range []struct{ name, header string }{
		{"unknown fields", `{"op":"rm","entry":"` + e + `","x":{"y":[1,2]},"from_version":"z"}`},
		{"null from_version is absent", `{"op":"rotate","entry":"` + e + `","from_version":null}`},
		{"a field another op reads", `{"op":"rotate","entry":"` + e + `","kind":7}`},
	} {
		value := []byte(nil)
		if strings.Contains(tc.header, "rotate") {
			value = []byte("v")
		}
		if code := codeOf(t, w.call(t, tc.header, value)); code != "" {
			t.Errorf("%s: code %q, want ok", tc.name, code)
		}
	}
	if st.n() != 3 {
		t.Fatalf("the tolerated requests reached the store %d times, want 3", st.n())
	}
}

// An entry is named in the API grammar on the wire: a bare name or a short
// name is refused by the store's parser, never resolved by the socket.
func TestOpsEntryNameForms(t *testing.T) {
	r := newOpsRig(t, nil)
	w := dialOps(t, r.ops, uidA)
	w.mustReply(t, hdr(t, OpPut, entryOf(uidA, "a"), nil), []byte("v"), nil)
	for _, name := range []string{"a", "user/alice/a", "user/0" + strconv.FormatUint(uint64(uidA), 10) + "/a", "", "user/" + strconv.FormatUint(uint64(uidA), 10)} {
		for _, op := range []string{OpReadForExec, OpRm} {
			if code := codeOf(t, w.call(t, hdr(t, op, name, nil), nil)); code != CodeRefused {
				t.Errorf("%s %q: code %q, want refused", op, name, code)
			}
		}
	}
	if f := w.mustReply(t, hdr(t, OpReadForExec, entryOf(uidA, "a"), nil), nil, nil); string(f.Value) != "v" {
		t.Fatalf("the qualified name read %q, want v", f.Value)
	}
}

// A list by a uid with no scope yet answers an empty list, not not-found;
// the store's own list line records it as scope-absent, under that uid.
func TestListWithoutScopeIsEmpty(t *testing.T) {
	r := newOpsRig(t, nil)
	w := dialOps(t, r.ops, uidB)
	f := w.mustReply(t, hdr(t, OpList, "", nil), nil, nil)
	if string(f.Header) != `{"entries":[]}` {
		t.Fatalf("list with no scope replied %s, want an empty list", f.Header)
	}
	lines := r.linesOf(t, uidB)
	if len(lines) != 1 || lines[0].Op != "list" || lines[0].Result != "scope-absent" || lines[0].Caller.UID != uidB {
		t.Fatalf("uid %d's lines are %+v, want the one list line, scope-absent", uidB, lines)
	}
	if _, err := os.Stat(filepath.Join(r.data, "server", "keystore", ".user", strconv.FormatUint(uint64(uidB), 10))); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("a list minted uid %d's scope: %v", uidB, err)
	}
}

// deliver, withdraw and deliveries are known operations answered refused
// until the delivery slice serves them: a stable code, never unknown-op;
// they reach no store, each is recorded as the socket's own refusal,
// not-served, and the connection stays open.
func TestDeliveryOpsRefusedUntilDeliverySlice(t *testing.T) {
	st := &countingStore{}
	h, err := NewOpsHandler(time.Now, st)
	if err != nil {
		t.Fatal(err)
	}
	w := dialOps(t, h, uidA)
	for _, op := range []string{OpDeliver, OpWithdraw, OpDeliveries} {
		if code := codeOf(t, w.call(t, hdr(t, op, entryOf(uidA, "a"), nil), nil)); code != CodeRefused {
			t.Errorf("%s: code %q, want refused", op, code)
		}
	}
	if code := codeOf(t, w.call(t, `{"op":"show"}`, nil)); code != CodeUnknownOp {
		t.Errorf("an op the server does not have: code %q, want unknown-op", code)
	}
	if st.n() != 0 {
		t.Fatalf("the delivery operations reached the store %d times", st.n())
	}
	if got := strings.Join(st.refusals(), ","); got != "deliver not-served,withdraw not-served,deliveries not-served" {
		t.Fatalf("the delivery operations' refusals are %s, want one not-served each", got)
	}
	if _, err := NewOpsHandler(time.Now, nil); err == nil {
		t.Fatal("NewOpsHandler took a nil store")
	}
}

// encodeFrame is f's exact encoding, for a byte-for-byte comparison.
func encodeFrame(t *testing.T, f Frame) []byte {
	t.Helper()
	b, err := AppendFrame(nil, f)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// namedCase is one request naming an entry, for the refusal tests: the
// header for a name, its value, and the store's op name in the audit line
// ("" for an operation that reaches no store).
type namedCase struct {
	op     string
	extra  map[string]any
	value  []byte
	lineOp string
}

// namedCases are U45's operations that take a name: read-for-exec, rotate
// (with a value and from_version), rm, deliver, withdraw and deliveries.
var namedCases = []namedCase{
	{OpReadForExec, nil, nil, "exec-read"},
	{OpRotate, nil, []byte("taken"), "rotate"},
	{OpRotate, map[string]any{"from_version": 1}, nil, "rotate"},
	{OpRm, nil, nil, "rm"},
	{OpDeliver, nil, nil, ""},
	{OpWithdraw, nil, nil, ""},
	{OpDeliveries, nil, nil, ""},
}

// refusalRig is uid A's scope holding a secret and uid B's holding one
// entry of its own, served by the production operations.
func refusalRig(t *testing.T) *opsRig {
	t.Helper()
	r := newOpsRig(t, nil)
	a := dialOps(t, r.ops, uidA)
	a.mustReply(t, hdr(t, OpPut, entryOf(uidA, "secret"), nil), []byte("a-value"), nil)
	a.mustReply(t, hdr(t, OpRotate, entryOf(uidA, "secret"), nil), []byte("a-value-2"), nil)
	dialOps(t, r.ops, uidB).mustReply(t, hdr(t, OpPut, entryOf(uidB, "mine"), nil), []byte("b-value"), nil)
	return r
}

// unreadable makes p unopenable until the test ends, so any open of it
// fails loudly instead of answering as an absent entry would.
func unreadable(t *testing.T, p string, restore os.FileMode) {
	t.Helper()
	if _, err := os.Stat(p); err != nil {
		t.Fatalf("the file to guard is not there: %v", err)
	}
	if err := os.Chmod(p, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(p, restore) })
}

// assertRefusedLikeAbsent asks, as uid B, every named operation for other
// and for B's own absent entry, and requires identical reply frames
// (not-found for the store's operations, refused for the delivery ones)
// with each refusal audited under B: the store's under the operation, the
// socket's own as a refused line.
func assertRefusedLikeAbsent(t *testing.T, r *opsRig, other string) {
	t.Helper()
	// A fresh minute for B's refused lines, so none is held back by their
	// rate limit.
	r.clock.advance(time.Minute)
	b := dialOps(t, r.ops, uidB)
	absent := entryOf(uidB, "absent")
	for _, c := range namedCases {
		before := len(r.linesOf(t, uidB))
		got := b.call(t, hdr(t, c.op, other, c.extra), c.value)
		lines := r.linesOf(t, uidB)
		want := b.call(t, hdr(t, c.op, absent, c.extra), c.value)
		if !bytes.Equal(encodeFrame(t, got), encodeFrame(t, want)) {
			t.Errorf("%s %v of %s answered %#02x %s, but B's own absent entry %#02x %s", c.op, c.extra, other, byte(got.Type), got.Header, byte(want.Type), want.Header)
		}
		wantCode := CodeNotFound
		if c.lineOp == "" {
			wantCode = CodeRefused
		}
		if code := codeOf(t, got); code != wantCode {
			t.Errorf("%s %v of %s: code %q, want %q", c.op, c.extra, other, code, wantCode)
		}
		if c.lineOp == "" {
			// The socket's own refusal: one refused line under B, naming
			// the operation and not the entry.
			if len(lines) != before+1 {
				t.Errorf("%s of %s wrote %d lines, want its one refused line", c.op, other, len(lines)-before)
				continue
			}
			if l := lines[len(lines)-1]; l.Op != "refused" || l.Request != c.op || l.Result != "not-served" || l.Name != "" || l.Caller.UID != uidB {
				t.Errorf("%s of %s was audited %+v, want refused %s not-served with caller %d", c.op, other, l, c.op, uidB)
			}
			continue
		}
		if len(lines) != before+1 {
			t.Fatalf("%s of %s left uid %d with %d new lines, want one", c.op, other, uidB, len(lines)-before)
		}
		l := lines[len(lines)-1]
		if l.Op != c.lineOp || l.Result != "not-found" || l.Caller.UID != uidB || l.Via != "socket" {
			t.Errorf("%s of %s was audited %+v, want %s not-found via socket with caller %d", c.op, other, l, c.lineOp, uidB)
		}
	}
	// list names no entry: a name in its header is an unknown field, and
	// B sees its own scope only.
	got := b.mustReply(t, hdr(t, OpList, other, nil), nil, nil)
	want := b.mustReply(t, hdr(t, OpList, "", nil), nil, nil)
	if !bytes.Equal(encodeFrame(t, got), encodeFrame(t, want)) {
		t.Errorf("list naming %s answered %s, but a plain list %s", other, got.Header, want.Header)
	}
	var ls ListReply
	if err := json.Unmarshal(got.Header, &ls); err != nil {
		t.Fatal(err)
	}
	if len(ls.Entries) != 1 || ls.Entries[0].Name != entryOf(uidB, "mine") {
		t.Errorf("B's list is %+v, want its one entry only", ls.Entries)
	}
}

// TestCrossUserRefusedFakePeerCred (U45): a peer with uid B, in its normal
// state (a started scope, under its rate limit and share), asks for
// read-for-exec, rotate (with a value and from_version) and rm of uid A's
// entry, and lists; every reply is byte for byte the reply for an absent
// entry of B's own, each store refusal is audited under B, list shows B's
// own scope only, and nothing of A's scope is opened or audited: A's scope
// key is unreadable throughout, so an open would answer otherwise, and A's
// value is unchanged after. (The delivery operations are also asked, but
// they are not served yet and answer refused to every caller alike, so
// they show nothing about cross-user refusal here.)
func TestCrossUserRefusedFakePeerCred(t *testing.T) {
	r := refusalRig(t)
	beforeA := r.linesOf(t, uidA)
	key := filepath.Join(r.data, "server", "keystore", ".user", strconv.FormatUint(uint64(uidA), 10), "scope.key")
	func() {
		unreadable(t, key, 0o600)
		assertRefusedLikeAbsent(t, r, entryOf(uidA, "secret"))
		if err := os.Chmod(key, 0o600); err != nil {
			t.Fatal(err)
		}
	}()
	if got := r.linesOf(t, uidA); !reflect.DeepEqual(got, beforeA) {
		t.Fatalf("uid %d's lines changed under B's requests: %+v, was %+v", uidA, got, beforeA)
	}
	lines, _ := readAudit(t, r.auditPath())
	for _, l := range lines[len(lines)-10:] {
		if l.Caller.UID == uidA && l.Scope != "user/"+strconv.FormatUint(uint64(uidA), 10) {
			t.Fatalf("a line names caller %d outside its scope: %+v", uidA, l)
		}
	}
	a := dialOps(t, r.ops, uidA)
	var rd ReadForExecReply
	if f := a.mustReply(t, hdr(t, OpReadForExec, entryOf(uidA, "secret"), nil), nil, &rd); string(f.Value) != "a-value-2" || rd.Version != 2 {
		t.Fatalf("A's entry after B's requests: version %d value %q, want version 2 a-value-2", rd.Version, f.Value)
	}
}

// TestCrossUserRefusedShareSpent (U45, the qualifier): once peer B's log
// share is spent, B's own absent name answers from B's own state,
// log-full, but another uid's name, and a system/ name, still answer
// not-found in every form, refused before any scope of theirs is opened:
// what B learns is about B's own state, never A's. A's lines and value
// are unchanged.
func TestCrossUserRefusedShareSpent(t *testing.T) {
	r := newOpsRig(t, func(c *keystore.Config) { c.LogUIDShare = testShare })
	a := dialOps(t, r.ops, uidA)
	a.mustReply(t, hdr(t, OpPut, entryOf(uidA, "secret"), nil), []byte("a-value"), nil)
	if err := r.spend(t, Peer{UID: uidB}); !keystore.LogShareRefused(err) {
		t.Fatalf("spending B's share ended with %v, want its own share refused", err)
	}
	beforeA := r.linesOf(t, uidA)
	b := dialOps(t, r.ops, uidB)
	forms := []struct {
		op    string
		value []byte
		extra map[string]any
	}{
		{OpReadForExec, nil, nil},
		{OpRm, nil, nil},
		{OpRotate, []byte("x"), nil},
		{OpRotate, nil, map[string]any{"from_version": 1}},
	}
	for _, tc := range []struct {
		entry string
		code  Code
	}{
		{entryOf(uidA, "secret"), CodeNotFound},
		{"system/seed", CodeNotFound},
		{entryOf(uidB, "absent"), CodeLogFull},
	} {
		for _, form := range forms {
			f := b.call(t, hdr(t, form.op, tc.entry, form.extra), form.value)
			if code := codeOf(t, f); f.Type != TypeError || code != tc.code {
				t.Errorf("with B's share spent, %s %v of %s answered %#02x %s, want %s", form.op, form.extra, tc.entry, byte(f.Type), f.Header, tc.code)
			}
		}
	}
	if got := r.linesOf(t, uidA); !reflect.DeepEqual(got, beforeA) {
		t.Fatalf("uid %d's lines changed under B's requests: %+v, was %+v", uidA, got, beforeA)
	}
	if f := a.mustReply(t, hdr(t, OpReadForExec, entryOf(uidA, "secret"), nil), nil, nil); string(f.Value) != "a-value" {
		t.Fatalf("A's value after B's requests is %q, want a-value", f.Value)
	}
}

// TestNonRootCannotNameSystemEntries (U45): a peer naming a system/ entry,
// one that exists, is answered as for an absent entry of its own, byte for
// byte, audited under its own uid; the system entry's directory is
// unreadable throughout, so an open would answer otherwise.
func TestNonRootCannotNameSystemEntries(t *testing.T) {
	r := refusalRig(t)
	sys := filepath.Join(r.data, "server", "keystore", "seed")
	systemLines := func() []auditEntry {
		ls, _ := readAudit(t, r.auditPath())
		var out []auditEntry
		for _, l := range ls {
			if !strings.HasPrefix(l.Scope, "user/") {
				out = append(out, l)
			}
		}
		return out
	}
	before := systemLines()
	unreadable(t, sys, 0o700)
	assertRefusedLikeAbsent(t, r, "system/seed")
	assertRefusedLikeAbsent(t, r, "system/never-made")
	if got := systemLines(); !reflect.DeepEqual(got, before) {
		t.Fatalf("a peer's requests wrote lines outside its scope: %+v, was %+v", got, before)
	}
}

// replyWatch is a server end that, as each reply or error frame's write
// begins, reads the audit log and hands its lines to the test.
type replyWatch struct {
	net.Conn
	read func() []auditEntry
	seen chan []auditEntry
}

func (c *replyWatch) Write(b []byte) (int, error) {
	if len(b) > 4 && (FrameType(b[4]) == TypeReply || FrameType(b[4]) == TypeError) {
		c.seen <- c.read()
	}
	return c.Conn.Write(b)
}

// TestAuditBeforeReply (U32): for put, rotate (with a value and with
// from_version), read-for-exec, list and rm, and for the store's own
// refusals among them (rm of an absent entry, put of an existing one,
// read-for-exec of another uid's), the request's one audit line, with its
// op, result and caller, is in the log when the reply's write begins. It
// checks the line's place before the reply only, not the order of the
// line against the operation's own writes.
func TestAuditBeforeReply(t *testing.T) {
	r := newOpsRig(t, nil)
	read := func() []auditEntry { ls, _ := readAudit(t, r.auditPath()); return ls }
	client, server := net.Pipe()
	watch := &replyWatch{Conn: server, read: read, seen: make(chan []auditEntry, 1)}
	s := &session{client: client, done: make(chan error, 1)}
	go func() {
		err := r.ops.Serve(t.Context(), watch, Peer{UID: uidA, PID: 7})
		_ = server.Close()
		s.done <- err
	}()
	t.Cleanup(func() { _ = s.finish() })
	s.send(t, TypeHello, helloV1, nil)
	var hr HelloReply
	s.recv(t, TypeHello, &hr)
	e := entryOf(uidA, "a")
	for _, c := range []struct {
		name, header string
		value        []byte
		op, result   string
	}{
		{"put", hdr(t, OpPut, e, nil), []byte("v1"), "put", "ok"},
		{"rotate", hdr(t, OpRotate, e, nil), []byte("v2"), "rotate", "ok"},
		{"rotate from_version", hdr(t, OpRotate, e, map[string]any{"from_version": 1}), nil, "rotate", "ok"},
		{"read-for-exec", hdr(t, OpReadForExec, e, nil), nil, "exec-read", "ok"},
		{"list", hdr(t, OpList, "", nil), nil, "list", "ok"},
		{"rm", hdr(t, OpRm, e, nil), nil, "rm", "ok"},
		{"rm absent", hdr(t, OpRm, e, nil), nil, "rm", "not-found"},
		{"put exists", hdr(t, OpPut, entryOf(uidA, "b"), nil), []byte("v"), "put", "ok"},
		{"put again", hdr(t, OpPut, entryOf(uidA, "b"), nil), []byte("v"), "put", "exists"},
		{"read-for-exec of another uid", hdr(t, OpReadForExec, entryOf(uidB, "a"), nil), nil, "exec-read", "not-found"},
	} {
		before := len(read())
		s.send(t, TypeRequest, c.header, c.value)
		atWrite := <-watch.seen
		if _, err := ReadFrame(client); err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if len(atWrite) != before+1 {
			t.Fatalf("%s: %d new lines when the reply's write began, want its one line", c.name, len(atWrite)-before)
		}
		l := atWrite[len(atWrite)-1]
		if l.Op != c.op || l.Result != c.result || l.Caller.UID != uidA {
			t.Errorf("%s: the line before the reply is %+v, want %s %s for uid %d", c.name, l, c.op, c.result, uidA)
		}
	}
}

// TestAuditFailureAfterCommitRepliesCommittedAuditFailed (U112, the
// socket's half): with appends failing, a rotate and an rm commit, then
// fail to append, and answer ok with their reply and the warning
// committed; audit failed, counted unaudited; a put, a grant, and a read,
// which append before they act or reply, are refused.
func TestAuditFailureAfterCommitRepliesCommittedAuditFailed(t *testing.T) {
	r := newOpsRig(t, nil)
	w := dialOps(t, r.ops, uidA)
	w.mustReply(t, hdr(t, OpPut, entryOf(uidA, "a"), nil), []byte("v1"), nil)
	w.mustReply(t, hdr(t, OpPut, entryOf(uidA, "b"), nil), []byte("v1"), nil)
	r.breakAudit(t)
	var rot struct {
		VersionReply
		Warning string `json:"warning"`
	}
	w.mustReply(t, hdr(t, OpRotate, entryOf(uidA, "a"), nil), []byte("v2"), &rot)
	if rot.Version != 2 || rot.Fingerprint == "" || rot.Warning != WarnAuditFailed {
		t.Fatalf("rotate with appends failing replied %+v, want version 2, its fingerprint and %q", rot, WarnAuditFailed)
	}
	f := w.mustReply(t, hdr(t, OpRm, entryOf(uidA, "b"), nil), nil, nil)
	if string(f.Header) != `{"warning":"committed; audit failed"}` {
		t.Fatalf("rm with appends failing replied %s, want only the warning", f.Header)
	}
	if n := r.fs.UnauditedOps(); n != 2 {
		t.Fatalf("UnauditedOps = %d after two committed, unaudited changes, want 2", n)
	}
	if code := codeOf(t, w.call(t, hdr(t, OpPut, entryOf(uidA, "c"), nil), []byte("v"))); code != CodeRefused {
		t.Errorf("a put with appends failing: code %q, want refused", code)
	}
	if code := codeOf(t, w.call(t, hdr(t, OpReadForExec, entryOf(uidA, "a"), nil), nil)); code != CodeRefused {
		t.Errorf("a read with appends failing: code %q, want refused", code)
	}
}

// requestTypes makes one zero request of each type decodeRequest reads.
var requestTypes = []func() any{
	func() any { return &PutRequest{} },
	func() any { return &RotateRequest{} },
	func() any { return &ListRequest{} },
	func() any { return &RmRequest{} },
	func() any { return &ReadForExecRequest{} },
}

// headerTokens is the fuzz oracle's own read of a header: each top-level
// key in order with its raw value, tokenized by encoding/json's Decoder,
// and false when the header is not one JSON object with nothing after it.
// Unlike json.Unmarshal into a map, which keeps the last of two equal keys,
// it keeps every key, so a duplicate the parser accepted is seen.
func headerTokens(header []byte) ([]string, []json.RawMessage, bool) {
	dec := json.NewDecoder(bytes.NewReader(header))
	if tok, err := dec.Token(); err != nil || tok != json.Delim('{') {
		return nil, nil, false
	}
	var (
		keys []string
		vals []json.RawMessage
	)
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return nil, nil, false
		}
		k, ok := tok.(string)
		if !ok {
			return nil, nil, false
		}
		var v json.RawMessage
		if err := dec.Decode(&v); err != nil {
			return nil, nil, false
		}
		keys, vals = append(keys, k), append(vals, v)
	}
	if _, err := dec.Token(); err != nil {
		return nil, nil, false
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, nil, false
	}
	return keys, vals, true
}

// duplicateKey reports whether two of keys are the same under
// encoding/json's case folding, which the strict rule refuses.
func duplicateKey(keys []string) bool {
	for i, a := range keys {
		for _, b := range keys[i+1:] {
			if strings.EqualFold(a, b) {
				return true
			}
		}
	}
	return false
}

// checkDuplicateRefused holds every reader of a header to the strict rule
// on the oracle's tokens: a header with any key given twice, in any case,
// is refused by the dispatcher, by every request type's decoder, by the
// HELLO reader and by the logged entry's reader.
func checkDuplicateRefused(t *testing.T, header []byte) {
	t.Helper()
	keys, _, ok := headerTokens(header)
	if !ok || !duplicateKey(keys) {
		return
	}
	if op, err := requestOp(header); err == nil {
		t.Fatalf("requestOp(%q) = %q, accepted a key given twice", header, op)
	}
	for _, mk := range requestTypes {
		if dst := mk(); decodeRequest(header, dst) == nil {
			t.Fatalf("decodeRequest(%q) into %T accepted a key given twice: %+v", header, dst, dst)
		}
	}
	if h, err := helloOf(header); err == nil {
		t.Fatalf("helloOf(%q) = %+v, accepted a key given twice", header, h)
	}
	if e, ok := requestEntry(header); ok {
		t.Fatalf("requestEntry(%q) = %q, accepted a key given twice", header, e)
	}
}

// checkHelloAgrees holds helloOf to the oracle: it accepts exactly the
// headers that are one object with no key given twice, whose keys folding
// to proto, min or max are spelled exactly, and whose fields of those
// names decode to their types (null is absent), and then reads the same
// fields.
func checkHelloAgrees(t *testing.T, header []byte) {
	t.Helper()
	got, err := helloOf(header)
	keys, vals, ok := headerTokens(header)
	want := helloRequest{}
	accept := ok && !duplicateKey(keys)
	for i := 0; accept && i < len(keys); i++ {
		var dst any
		switch keys[i] {
		case "proto":
			dst = &want.Proto
		case "min":
			dst = &want.Min
		case "max":
			dst = &want.Max
		default:
			for _, k := range []string{"proto", "min", "max"} {
				if strings.EqualFold(k, keys[i]) {
					accept = false
				}
			}
			continue
		}
		if !bytes.Equal(vals[i], []byte("null")) && json.Unmarshal(vals[i], dst) != nil {
			accept = false
		}
	}
	switch {
	case accept && err != nil:
		t.Fatalf("helloOf(%q) = %v, the oracle accepts it as %+v", header, err, want)
	case !accept && err == nil:
		t.Fatalf("helloOf(%q) = %+v, the oracle refuses it", header, got)
	case accept && got != want:
		t.Fatalf("helloOf(%q) = %+v, the oracle reads %+v", header, got, want)
	}
}

// checkRequestOp holds the dispatcher's read of a request's op to the
// exact-key rule: it never panics; it fails with a protocol error or
// names a non-empty op; it fails whenever a key other than "op" folds to
// it; and the op it names is the one both a case-insensitive, last-wins
// decoder and an exact-name decoder read, so no two decoders disagree.
func checkRequestOp(t *testing.T, header []byte) {
	t.Helper()
	op, err := requestOp(header)
	var raw map[string]json.RawMessage
	_ = json.Unmarshal(header, &raw) // nil when it is no object; then requestOp must fail
	folded := false
	for k := range raw {
		if k != "op" && strings.EqualFold(k, "op") {
			folded = true
		}
	}
	if err != nil {
		var pe *ProtocolError
		if !errors.As(err, &pe) || op != "" {
			t.Fatalf("requestOp(%q) = %q, %v; want a protocol error and no op", header, op, err)
		}
		return
	}
	if folded || raw == nil {
		t.Fatalf("requestOp(%q) = %q, want a close: a key folds to op, or no object", header, op)
	}
	var exact string
	if json.Unmarshal(raw["op"], &exact) != nil || exact != op || op == "" {
		t.Fatalf("requestOp(%q) = %q, the exact op field reads %q", header, op, exact)
	}
	var lenient struct {
		Op string `json:"op"`
	}
	if json.Unmarshal(header, &lenient) != nil || lenient.Op != op {
		t.Fatalf("requestOp(%q) = %q, a lenient decoder reads %q", header, op, lenient.Op)
	}
}

// checkHelloAndEntry holds the HELLO reader and the logged entry's reader
// to the same rule over any header: helloOf never panics and fails only
// with a protocol error; requestEntry names an entry only when the exact
// entry field is a valid name in the API grammar, and then that name.
func checkHelloAndEntry(t *testing.T, header []byte) {
	t.Helper()
	if _, err := helloOf(header); err != nil {
		var pe *ProtocolError
		if !errors.As(err, &pe) {
			t.Fatalf("helloOf(%q) = %v, want a protocol error", header, err)
		}
	}
	e, ok := requestEntry(header)
	if !ok {
		return
	}
	var raw map[string]json.RawMessage
	var s string
	if json.Unmarshal(header, &raw) != nil || json.Unmarshal(raw["entry"], &s) != nil {
		t.Fatalf("requestEntry(%q) = %q from a header with no entry string", header, e)
	}
	p, err := keyentry.Parse(s)
	if err != nil || p.String() != e {
		t.Fatalf("requestEntry(%q) = %q, the entry field %q parses to %v, %v", header, e, s, p, err)
	}
}

// FuzzRequestHeader: decoding a request header never panics; a header over
// the cap is refused before it is parsed; any other failure is a refusal;
// and a header that decodes re-encodes to an equivalent request. The
// dispatcher's read of its op keeps to the exact-key rule
// (checkRequestOp); a key given twice is refused by every reader, on the
// oracle's own tokens (checkDuplicateRefused); and the HELLO reader
// accepts exactly what the oracle does (checkHelloAgrees).
func FuzzRequestHeader(f *testing.F) {
	f.Fuzz(func(t *testing.T, header []byte) {
		checkRequestOp(t, header)
		checkHelloAndEntry(t, header)
		checkDuplicateRefused(t, header)
		checkHelloAgrees(t, header)
		for _, mk := range requestTypes {
			dst := mk()
			err := decodeRequest(header, dst)
			if len(header) > MaxHeader {
				if !errors.Is(err, ErrRequestRefused) || !reflect.DeepEqual(dst, mk()) {
					t.Fatalf("a %d-byte header was not refused before parsing: %v, %+v", len(header), err, dst)
				}
				continue
			}
			if err != nil {
				if !errors.Is(err, ErrRequestRefused) {
					t.Fatalf("decode %T: %v is not a refusal", dst, err)
				}
				continue
			}
			enc, err := json.Marshal(dst)
			if err != nil {
				t.Fatalf("re-encoding %+v: %v", dst, err)
			}
			again := mk()
			if err := decodeRequest(enc, again); err != nil {
				t.Fatalf("the re-encoded %s does not decode: %v", enc, err)
			}
			if !reflect.DeepEqual(dst, again) {
				t.Fatalf("%q decoded to %+v, re-encoded %s decodes to %+v", header, dst, enc, again)
			}
		}
	})
}

// A header past the cap is refused even when it is a valid object.
func TestRequestHeaderCap(t *testing.T) {
	pad := strings.Repeat(" ", MaxHeader)
	var h RmRequest
	if err := decodeRequest([]byte(`{"op":"rm","entry":"user/501/a"}`+pad), &h); !errors.Is(err, ErrRequestRefused) || h != (RmRequest{}) {
		t.Fatalf("a header over the cap decoded: %v, %+v", err, h)
	}
	if err := decodeRequest([]byte(`{"op":"rm","entry":"user/501/a"}`), &h); err != nil || h.Entry != "user/501/a" {
		t.Fatalf("a header under the cap: %v, %+v", err, h)
	}
}

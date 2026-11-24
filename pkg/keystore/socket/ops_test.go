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
	"net"
	"testing"
	"testing/synctest"
	"time"

	"k3sm.io/k3sm/pkg/keystore"
)

// recvFrame reads one frame and its header as JSON fields.
func (s *session) recvFrame(t *testing.T) (Frame, map[string]json.RawMessage) {
	t.Helper()
	f, err := ReadReply(s.client)
	if err != nil {
		t.Fatalf("recv: %v", err)
	}
	var h map[string]json.RawMessage
	if err := json.Unmarshal(f.Header, &h); err != nil {
		t.Fatalf("recv header %q: %v", f.Header, err)
	}
	return f, h
}

// hello sends the HELLO and reads its reply.
func (s *session) hello(t *testing.T) {
	t.Helper()
	s.send(t, TypeHello, helloV1, nil)
	var hr HelloReply
	s.recv(t, TypeHello, &hr)
}

// An operation receives the admitted peer, its op, its whole header and its
// value; its reply's header and value are written back, and an error is
// its code with no value.
func TestOpGetsRequestAndRepliesValue(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var got Request
		echo := func(_ context.Context, req Request) (Reply, error) {
			got = req
			got.Header, got.Value = bytes.Clone(req.Header), bytes.Clone(req.Value)
			return Reply{Header: map[string]any{"version": 3}, Value: []byte("out")}, nil
		}
		fails := func(context.Context, Request) (Reply, error) {
			return Reply{Header: map[string]any{"version": 9}, Value: []byte("never")}, keystore.ErrQuota
		}
		h, err := NewHandler(time.Now, withOp("echo", echo), withOp("fails", fails))
		if err != nil {
			t.Fatal(err)
		}
		peer := Peer{UID: 70001, PID: 321}
		s := serveAs(t, h, peer)
		s.hello(t)
		s.send(t, TypeRequest, `{"op":"echo","entry":"user/70001/a","extra":true}`, []byte("in"))
		f, hdr := s.recvFrame(t)
		if f.Type != TypeReply || string(f.Value) != "out" || string(hdr["version"]) != "3" || len(hdr) != 1 {
			t.Fatalf("reply type %#02x header %s value %q; want a reply {\"version\":3} with value out", byte(f.Type), f.Header, f.Value)
		}
		if got.Peer != peer || got.Op != "echo" || string(got.Value) != "in" || !bytes.Contains(got.Header, []byte(`"entry":"user/70001/a"`)) {
			t.Fatalf("the op got %+v (header %s), want peer %+v, op echo, value in and the whole header", got, got.Header, peer)
		}
		// A request with no value hands the op nil, not an empty value.
		s.send(t, TypeRequest, `{"op":"echo"}`, nil)
		s.recvFrame(t)
		if got.Value != nil {
			t.Fatalf("a request without a value gave the op %q, want nil", got.Value)
		}
		s.send(t, TypeRequest, `{"op":"fails"}`, nil)
		f, hdr = s.recvFrame(t)
		if f.Type != TypeError || f.Value != nil || string(hdr["code"]) != `"quota"` || len(hdr) != 1 {
			t.Fatalf("a failed op answered type %#02x header %s value %q; want the error {\"code\":\"quota\"} and no value", byte(f.Type), f.Header, f.Value)
		}
		if err := s.finish(); err != nil {
			t.Fatalf("Serve = %v, want nil after the client closes", err)
		}
	})
}

// A change that committed but whose audit line failed is answered ok, with
// the operation's header and the warning.
func TestCommittedAuditFailedReplyWarns(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		lost := auditLostErr(t)
		op := func(context.Context, Request) (Reply, error) {
			return Reply{Header: map[string]any{"version": 2}}, lost
		}
		h, err := NewHandler(time.Now, withOp("rotate", op))
		if err != nil {
			t.Fatal(err)
		}
		s := serveWith(t, h)
		s.hello(t)
		s.send(t, TypeRequest, `{"op":"rotate"}`, nil)
		f, hdr := s.recvFrame(t)
		if f.Type != TypeReply || string(hdr["version"]) != "2" || string(hdr["warning"]) != `"committed; audit failed"` {
			t.Fatalf("reply type %#02x header %s; want ok with version 2 and the warning", byte(f.Type), f.Header)
		}
		_ = s.finish()
	})
}

// Neither the request's value nor the reply's outlives the reply: each is
// zeroed once the reply is written, and a refused reply's value too.
func TestOpValuesZeroedAfterReply(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var in, out [][]byte
		op := func(_ context.Context, req Request) (Reply, error) {
			v := []byte("secret-out")
			in, out = append(in, req.Value), append(out, v)
			if bytes.Equal(req.Value, []byte("refuse")) {
				return Reply{Value: v}, keystore.ErrNotFound
			}
			return Reply{Value: v}, nil
		}
		h, err := NewHandler(time.Now, withOp("x", op))
		if err != nil {
			t.Fatal(err)
		}
		s := serveWith(t, h)
		s.hello(t)
		s.send(t, TypeRequest, `{"op":"x"}`, []byte("secret-in"))
		if f, _ := s.recvFrame(t); string(f.Value) != "secret-out" {
			t.Fatalf("reply value %q, want secret-out", f.Value)
		}
		s.send(t, TypeRequest, `{"op":"x"}`, []byte("refuse"))
		if f, _ := s.recvFrame(t); f.Type != TypeError || f.Value != nil {
			t.Fatalf("a refused op's reply carried %q", f.Value)
		}
		_ = s.finish()
		for i := range in {
			for _, b := range [][]byte{in[i], out[i]} {
				if !bytes.Equal(b, make([]byte, len(b))) {
					t.Errorf("request %d: a value %q was not zeroed after the reply", i, b)
				}
			}
		}
	})
}

// The listener serves each connection for the peer it admitted, the uid
// and pid read at accept.
func TestListenerPassesAdmittedPeer(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		seen := make(chan Peer, 4)
		op := func(_ context.Context, req Request) (Reply, error) {
			seen <- req.Peer
			return Reply{}, nil
		}
		r := &rig{
			ln:      newFakeListener(),
			creds:   &fakeCreds{peers: map[net.Conn]PeerCred{}, fail: map[net.Conn]bool{}},
			sandbox: &fakeSandbox{sandboxed: map[AuditToken]bool{}, fail: map[AuditToken]bool{}},
			audit:   &fakeAuditor{},
			done:    make(chan error, 1),
			hopts:   []HandlerOption{withOp("who", op)},
		}
		r.serve(t, serviceUID, r.audit)
		for _, uid := range []uint32{70001, 70002} {
			p := r.dial(uid)
			p.admitted(t)
			if err := WriteFrame(p.client, Frame{Type: TypeRequest, Header: []byte(`{"op":"who","uid":1}`)}); err != nil {
				t.Fatal(err)
			}
			if f, err := ReadFrame(p.client); err != nil || f.Type != TypeReply {
				t.Fatalf("reply %#02x, %v", byte(f.Type), err)
			}
			if got, want := <-seen, (Peer{UID: uid, PID: r.pid}); got != want {
				t.Fatalf("the op was served for %+v, want the admitted peer %+v", got, want)
			}
			p.close()
		}
		if err := r.stop(); err != nil {
			t.Fatal(err)
		}
	})
}

// auditLostErr is a real store's error for a committed change whose audit
// line failed: an rm after the audit log is made unwritable, which commits
// and then cannot append; it is returned wrapped, as an operation would.
func auditLostErr(t *testing.T) error {
	t.Helper()
	r := newStartedBridge(t, nil)
	p := Peer{UID: uidA, PID: 1}
	if _, err := r.b.Put(t.Context(), p, entryOf(uidA, "a"), keystore.KindOpaque, []byte("v")); err != nil {
		t.Fatal(err)
	}
	r.breakAudit(t)
	err := r.b.Remove(t.Context(), p, entryOf(uidA, "a"))
	if !keystore.AuditLost(err) {
		t.Fatalf("rm with the audit log broken = %v, want a committed change whose audit line was lost", err)
	}
	return fmt.Errorf("wrapped: %w", err)
}

// outcomeOf maps every store error the five operations return to one code
// of the closed set, as the design's table gives, and ok for a commit.
func TestOutcomeOfMapsStoreErrors(t *testing.T) {
	codes := map[Code]bool{}
	for _, c := range []Code{CodeNotFound, CodeQuota, CodeBusy, CodeLogFull, CodeScopeOwnerChanged, CodeScopeOwnerUnknown,
		CodeUserScopeOff, CodeRateLimited, CodeRefused, CodeUnsupportedVersion, CodeUnknownOp, CodeInternal} {
		codes[c] = true
	}
	wrap := func(err error) error { return fmt.Errorf("user scope put: %w", err) }
	for _, tc := range []struct {
		name string
		err  error
		code Code
	}{
		{"nil", nil, ""},
		{"committed", fmt.Errorf("%w: the floor line was not written", keystore.ErrCommitted), ""},
		{"socket busy", ErrBusy, CodeBusy},
		{"rate limited", ErrRateLimited, CodeRateLimited},
		{"request refused", refusedf("x"), CodeRefused},
		{"log full", wrap(keystore.ErrLogFull), CodeLogFull},
		{"not found", wrap(keystore.ErrNotFound), CodeNotFound},
		{"version not found", wrap(keystore.ErrVersionNotFound), CodeNotFound},
		{"scope absent", wrap(keystore.ErrScopeAbsent), CodeNotFound},
		{"quota", wrap(keystore.ErrQuota), CodeQuota},
		{"owner changed", wrap(keystore.ErrScopeOwnerChanged), CodeScopeOwnerChanged},
		{"owner unknown", wrap(keystore.ErrScopeOwnerUnknown), CodeScopeOwnerUnknown},
		{"exists", wrap(keystore.ErrExists), CodeRefused},
		{"invalid name", wrap(keystore.ErrInvalidName), CodeRefused},
		{"kind mismatch", wrap(keystore.ErrKindMismatch), CodeRefused},
		{"typed credential", wrap(keystore.ErrTypedCredential), CodeRefused},
		{"rewrap in progress", wrap(keystore.ErrRewrapInProgress), CodeRefused},
		{"corrupt", wrap(keystore.ErrCorrupt), CodeInternal},
		{"orphan version", wrap(fmt.Errorf("%w: %w", keystore.ErrCorrupt, keystore.ErrOrphanVersion)), CodeRefused},
		{"master missing", wrap(keystore.ErrMasterMissing), CodeInternal},
		{"master untrusted", wrap(keystore.ErrMasterUntrusted), CodeInternal},
		{"kind unsupported", wrap(keystore.ErrKindUnsupported), CodeInternal},
		{"cancelled", context.Canceled, CodeInternal},
		{"unknown", errors.New("x"), CodeInternal},
	} {
		code, warn := outcomeOf(tc.err)
		if code != tc.code || warn != "" {
			t.Errorf("%s: outcomeOf(%v) = %q, %q; want %q and no warning", tc.name, tc.err, code, warn, tc.code)
		}
		if code != "" && !codes[code] {
			t.Errorf("%s: code %q is outside the closed set", tc.name, code)
		}
	}
}

// A value the store refuses for its kind, an Ed25519 key of the wrong
// length or with a foreign public half, is the caller's to change: the
// socket answers it refused, never internal.
func TestEd25519ValueRefusedNotInternal(t *testing.T) {
	r := newStartedBridge(t, nil)
	seed := bytes.Repeat([]byte{7}, 32)
	mismatched := append(bytes.Clone(seed), bytes.Repeat([]byte{9}, 32)...)
	for i, v := range [][]byte{seed[:31], mismatched} {
		_, err := r.b.Put(t.Context(), Peer{UID: uidA}, entryOf(uidA, fmt.Sprintf("k%d", i)), keystore.KindEd25519, v)
		if code, _ := outcomeOf(err); code != CodeRefused || !keystore.InvalidValue(err) {
			t.Errorf("a put of a %d-byte Ed25519 value = %v, code %q; want refused", len(v), err, code)
		}
	}
}

// The store's own states, made by the real store: its busy lock, the user
// scope not started, a uid's spent share, and a committed change whose
// audit line failed.
func TestOutcomeOfRealStoreStates(t *testing.T) {
	ctx := t.Context()
	unstarted := newStoreRigWith(t, bridgeConfig(0, 0))
	b, err := NewFileStoreBridge(unstarted.fs, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	_, err = b.Put(ctx, Peer{UID: uidA}, entryOf(uidA, "a"), keystore.KindOpaque, []byte("v"))
	if code, _ := outcomeOf(err); code != CodeUserScopeOff || !keystore.UserScopeOff(err) {
		t.Errorf("a put before the start step = %v, code %q; want user-scope-off", err, code)
	}
	if code, warn := outcomeOf(auditLostErr(t)); code != "" || warn != WarnAuditFailed {
		t.Errorf("a committed rm whose audit failed = %q, %q; want ok with %q", code, warn, WarnAuditFailed)
	}
	r := newStartedBridge(t, func(c *keystore.Config) { c.LogUIDShare = testShare })
	err = r.spend(t, Peer{UID: uidA})
	if code, _ := outcomeOf(err); code != CodeLogFull || !keystore.LogShareRefused(err) {
		t.Errorf("a put past the share = %v, code %q; want log-full from the uid's own share", err, code)
	}
	if code, _ := outcomeOf(r.lockedPut(t)); code != CodeBusy {
		t.Errorf("a put while the store lock is held past its wait = code %q, want busy", code)
	}
}

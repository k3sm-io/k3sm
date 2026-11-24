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

package keystore

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"k3sm.io/k3sm/pkg/keystore/typed"
)

// typedNow is the clock the typed tests stamp from.
var typedNow = time.Date(2026, 11, 22, 10, 0, 0, 0, time.UTC)

func tokenEnvelope(value string) typed.Envelope {
	return typed.Envelope{Credential: typed.Credential{Value: []byte(value), ExpiresAt: typedNow.Add(time.Hour)}}
}

func oauthEnvelope(access, refresh string) typed.Envelope {
	return typed.Envelope{
		Credential: typed.Credential{
			AccessToken:     []byte(access),
			AccessExpiresAt: typedNow.Add(time.Hour),
			RefreshOwner:    "local",
		},
		RefreshToken: []byte(refresh),
	}
}

func newTypedStore(t *testing.T) (*FileStore, string) {
	t.Helper()
	s, server := newTestStore(t)
	s.now = func() time.Time { return typedNow }
	return s, server
}

func mustPutCredential(t *testing.T, s *FileStore, name string, kind Kind, e typed.Envelope) Version {
	t.Helper()
	v, err := s.PutCredential(context.Background(), name, kind, e)
	if err != nil {
		t.Fatalf("PutCredential %s: %v", name, err)
	}
	return v
}

func mustRotateCredential(t *testing.T, s *FileStore, name string, kind Kind, e typed.Envelope) Version {
	t.Helper()
	v, err := s.RotateCredential(context.Background(), name, kind, e)
	if err != nil {
		t.Fatalf("RotateCredential %s: %v", name, err)
	}
	return v
}

func mustCredential(t *testing.T, s *FileStore, name string) (Version, typed.Credential) {
	t.Helper()
	v, c, err := s.CurrentCredential(context.Background(), name)
	if err != nil {
		t.Fatalf("CurrentCredential %s: %v", name, err)
	}
	return v, c
}

// TestTypedIssuedAtStampedAndSealed is U144: a token's issuedAt and an oauth
// pair's accessIssuedAt come from the store's clock at put and rotate,
// whatever the caller passed.
func TestTypedIssuedAtStampedAndSealed(t *testing.T) {
	s, _ := newTypedStore(t)
	e := tokenEnvelope("t1")
	e.Credential.IssuedAt = time.Unix(1, 0) // the caller's is ignored
	mustPutCredential(t, s, "tok", KindToken, e)
	if _, c := mustCredential(t, s, "tok"); !c.IssuedAt.Equal(typedNow) {
		t.Fatalf("token issuedAt %v, want the clock's %v", c.IssuedAt, typedNow)
	}
	o := oauthEnvelope("a1", "r1")
	o.Credential.AccessIssuedAt = time.Unix(1, 0)
	mustPutCredential(t, s, "pair", KindOAuth, o)
	if _, c := mustCredential(t, s, "pair"); !c.AccessIssuedAt.Equal(typedNow) {
		t.Fatalf("oauth accessIssuedAt %v, want the clock's %v", c.AccessIssuedAt, typedNow)
	}
	later := typedNow.Add(90 * time.Minute)
	s.now = func() time.Time { return later }
	t2 := tokenEnvelope("t2")
	t2.Credential.ExpiresAt = later.Add(time.Hour) // a token sealed already expired is refused
	mustRotateCredential(t, s, "tok", KindToken, t2)
	if _, c := mustCredential(t, s, "tok"); !c.IssuedAt.Equal(later) {
		t.Fatalf("rotated token issuedAt %v, want %v", c.IssuedAt, later)
	}
	read, _ := mustCredential(t, s, "pair")
	o2 := oauthEnvelope("a2", "r2")
	o2.Credential.AccessExpiresAt = later.Add(time.Hour) // an access token sealed already expired is refused
	if _, err := s.RotateIf(context.Background(), "pair", KindOAuth, read, o2); err != nil {
		t.Fatal(err)
	}
	if _, c := mustCredential(t, s, "pair"); !c.AccessIssuedAt.Equal(later) {
		t.Fatalf("refreshed accessIssuedAt %v, want %v", c.AccessIssuedAt, later)
	}
}

// TestCreatedHeaderEditChangesNoTypedTime is U144: the record's created
// header is unauthenticated display metadata, so editing it moves Created
// and no sealed time.
func TestCreatedHeaderEditChangesNoTypedTime(t *testing.T) {
	s, server := newTypedStore(t)
	mustPutCredential(t, s, "tok", KindToken, tokenEnvelope("t1"))
	p := entryPath(server, "tok", "v1")
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	off := 4 + len("tok") + 8 + generationSize
	binary.BigEndian.PutUint64(b[off:], uint64(time.Unix(1, 0).Unix()))
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	v, c := mustCredential(t, s, "tok")
	if v.Created.Unix() != 1 {
		t.Fatalf("Created %v: the edit did not reach the header", v.Created)
	}
	if !c.IssuedAt.Equal(typedNow) || !c.ExpiresAt.Equal(typedNow.Add(time.Hour)) {
		t.Fatalf("typed times moved with the header: issued %v, expires %v", c.IssuedAt, c.ExpiresAt)
	}
}

// TestListShowsUnsupportedKind is U145's store half: an entry holding a
// record of an unassigned kind lists with ErrKindUnsupported, not
// ErrCorrupt, which the CLI shows as unsupported.
func TestListShowsUnsupportedKind(t *testing.T) {
	s, server := newTypedStore(t)
	mustPut(t, s, "newer", KindOpaque, []byte("one"))
	mustPutCredential(t, s, "tok", KindToken, tokenEnvelope("t"))
	if err := os.WriteFile(entryPath(server, "newer", "v1"), []byte{recordFormat, 0x10, 0, 0}, 0o600); err != nil {
		t.Fatal(err)
	}
	list, err := s.List(context.Background())
	if err != nil || len(list) != 2 {
		t.Fatalf("List = %+v, %v", list, err)
	}
	if err := list[0].Err; !errors.Is(err, ErrKindUnsupported) || errors.Is(err, ErrCorrupt) {
		t.Fatalf("the newer entry lists with %v, want ErrKindUnsupported and not ErrCorrupt", err)
	}
	if list[1].Err != nil || list[1].Current.Kind != KindToken {
		t.Fatalf("the token entry lists as %+v", list[1])
	}
}

// TestRotateAndPutCannotChangeKind is U146.
func TestRotateAndPutCannotChangeKind(t *testing.T) {
	ctx := context.Background()
	s, _ := newTypedStore(t)
	mustPut(t, s, "raw", KindOpaque, []byte("v"))
	tok := mustPutCredential(t, s, "tok", KindToken, tokenEnvelope("t"))
	mustPutCredential(t, s, "pair", KindOAuth, oauthEnvelope("a", "r"))
	checks := []struct {
		name string
		fn   func() error
	}{
		{"put token over opaque", func() error { _, err := s.PutCredential(ctx, "raw", KindToken, tokenEnvelope("t")); return err }},
		{"put opaque over token", func() error { _, err := s.Put(ctx, "tok", KindOpaque, []byte("v")); return err }},
		{"put oauth over token", func() error { _, err := s.PutCredential(ctx, "tok", KindOAuth, oauthEnvelope("a", "r")); return err }},
		{"rotate opaque as token", func() error { _, err := s.RotateCredential(ctx, "raw", KindToken, tokenEnvelope("t")); return err }},
		{"rotate token with a raw value", func() error { _, err := s.Rotate(ctx, "tok", []byte("v")); return err }},
		{"rotate oauth as token", func() error { _, err := s.RotateCredential(ctx, "pair", KindToken, tokenEnvelope("t")); return err }},
		{"rotateIf token as oauth", func() error { _, err := s.RotateIf(ctx, "tok", KindOAuth, tok, oauthEnvelope("a", "r")); return err }},
		{"raw put of a typed kind", func() error { _, err := s.Put(ctx, "fresh", KindToken, []byte("v")); return err }},
	}
	for _, c := range checks {
		if err := c.fn(); !errors.Is(err, ErrKindMismatch) {
			t.Errorf("%s: %v, want ErrKindMismatch", c.name, err)
		}
	}
	if _, err := s.PutCredential(ctx, "tok", KindToken, tokenEnvelope("t")); !errors.Is(err, ErrExists) || errors.Is(err, ErrKindMismatch) {
		t.Errorf("put of the same kind over an entry: %v, want ErrExists", err)
	}
	for _, n := range []string{"raw", "tok", "pair"} {
		if v, _, err := s.Get(ctx, n, 2); !errors.Is(err, ErrVersionNotFound) {
			t.Errorf("%s gained a version: %+v, %v", n, v, err)
		}
	}
}

// TestTypedPutValidation is U147.
func TestTypedPutValidation(t *testing.T) {
	ctx := context.Background()
	s, _ := newTypedStore(t)
	noExpiry := tokenEnvelope("t")
	noExpiry.Credential.ExpiresAt = time.Time{}
	without := func(f func(*typed.Envelope)) typed.Envelope {
		e := oauthEnvelope("a", "r")
		f(&e)
		return e
	}
	refused := []struct {
		name string
		kind Kind
		e    typed.Envelope
	}{
		{"token without expiresAt", KindToken, noExpiry},
		{"token without a value", KindToken, typed.Envelope{Credential: typed.Credential{ExpiresAt: typedNow.Add(time.Hour)}}},
		{"token expiring at its issue time", KindToken, typed.Envelope{Credential: typed.Credential{Value: []byte("t"), ExpiresAt: typedNow}}},
		{"token expiring before its issue time", KindToken, typed.Envelope{Credential: typed.Credential{Value: []byte("t"), ExpiresAt: typedNow.Add(-time.Second)}}},
		{"token claiming a later issue time", KindToken, typed.Envelope{Credential: typed.Credential{Value: []byte("t"), ExpiresAt: typedNow.Add(-time.Minute), IssuedAt: typedNow.Add(-time.Hour)}}},
		{"oauth without the access token", KindOAuth, without(func(e *typed.Envelope) { e.Credential.AccessToken = nil })},
		{"oauth without the access expiry", KindOAuth, without(func(e *typed.Envelope) { e.Credential.AccessExpiresAt = time.Time{} })},
		{"oauth without the refresh token", KindOAuth, without(func(e *typed.Envelope) { e.RefreshToken = nil })},
		{"oauth without an owner", KindOAuth, without(func(e *typed.Envelope) { e.Credential.RefreshOwner = "" })},
		{"oauth with an owner outside the grammar", KindOAuth, without(func(e *typed.Envelope) { e.Credential.RefreshOwner = "Not An Owner!" })},
		{"a token field on oauth", KindOAuth, without(func(e *typed.Envelope) { e.Credential.Value = []byte("v") })},
		{"ssh with a short seed", KindSSH, typed.Envelope{Credential: typed.Credential{Algorithm: typed.SSHAlgorithmEd25519, Seed: make([]byte, 31)}}},
	}
	for i, r := range refused {
		name := fmt.Sprintf("e%d", i)
		if _, err := s.PutCredential(ctx, name, r.kind, r.e); !errors.Is(err, typed.ErrInvalidCredential) {
			t.Errorf("%s: %v, want ErrInvalidCredential", r.name, err)
		}
		if _, err := s.RotateCredential(ctx, name, r.kind, r.e); !errors.Is(err, typed.ErrInvalidCredential) {
			t.Errorf("rotate %s: %v, want ErrInvalidCredential", r.name, err)
		}
	}
	if list, err := s.List(ctx); err != nil || len(list) != 0 {
		t.Fatalf("a refused put stored something: %+v, %v", list, err)
	}
	if _, err := s.PutCredential(ctx, "ok", KindOpaque, tokenEnvelope("t")); !errors.Is(err, ErrKindMismatch) {
		t.Errorf("PutCredential of opaque: %v, want ErrKindMismatch", err)
	}
}

// TestStoreGenerateSSHUsesRandomSeam is U148's store half: the seed comes
// from the store's random seam, and only the public key comes back.
func TestStoreGenerateSSHUsesRandomSeam(t *testing.T) {
	s, _ := newTypedStore(t)
	seed := bytes.Repeat([]byte{0x42}, 32)
	s.rand = io.MultiReader(bytes.NewReader(seed), rand.Reader)
	v, line, err := s.GenerateSSH(context.Background(), "deploy", "ci@k3sm")
	if err != nil {
		t.Fatal(err)
	}
	want, _ := typed.SSHAuthorizedKey(seed, "ci@k3sm")
	fp, _ := typed.SSHFingerprint(seed)
	if line != want || v.Fingerprint != fp || v.Kind != KindSSH {
		t.Fatalf("GenerateSSH = %+v, %q; want the seam's key %q, %s", v, line, want, fp)
	}
	if _, c := mustCredential(t, s, "deploy"); !bytes.Equal(c.Seed, seed) || c.Comment != "ci@k3sm" {
		t.Fatalf("stored ssh credential %+v", c)
	}
}

// encodings are the forms U149 scans every result for.
func encodings(secret []byte) []string {
	return []string{
		string(secret),
		hex.EncodeToString(secret),
		base64.StdEncoding.EncodeToString(secret),
		base64.RawStdEncoding.EncodeToString(secret),
		base64.URLEncoding.EncodeToString(secret),
		base64.RawURLEncoding.EncodeToString(secret),
		url.QueryEscape(string(secret)),
		url.PathEscape(string(secret)),
	}
}

// leaks reports which encoding of secret appears in any rendering of vals.
func leaks(secret []byte, vals ...any) string {
	var b strings.Builder
	for _, v := range vals {
		fmt.Fprintf(&b, "%v|%+v|%#v|%s|%x|%q\n", v, v, v, v, v, v)
		if bs, ok := v.([]byte); ok {
			b.Write(bs)
		}
	}
	out := b.String()
	for _, enc := range encodings(secret) {
		if strings.Contains(out, enc) {
			return enc
		}
	}
	return ""
}

// TestPlantedRefreshTokenNeverReturned is U149: a planted refresh token
// appears in no result, value or error of any exported method of *FileStore
// or *UserScope, nor in any audit or user-scope floor line they wrote. Every
// exported method is enumerated by reflection, so a new
// one cannot escape: it must be called by hand below (each check names the
// method it called first), be callable with arguments reflection builds, or
// be allowlisted with the reason it returns no secret data.
func TestPlantedRefreshTokenNeverReturned(t *testing.T) {
	ctx := context.Background()
	s, server := newTypedStore(t)
	fakeGUIDs(t, map[uint32][generationSize]byte{1001: guid(0xA1)})
	planted := []byte("planted-refresh+token/7f3a9c==")
	second := []byte("second-refresh+token/0b1d2e==")
	covered := map[string]bool{}
	check := func(what string, vals ...any) {
		t.Helper()
		method, _, _ := strings.Cut(what, " ")
		if !strings.Contains(method, ".") {
			method = "FileStore." + method
		}
		covered[method] = true
		for _, sec := range [][]byte{planted, second} {
			if enc := leaks(sec, vals...); enc != "" {
				t.Errorf("%s returned the refresh token as %q", what, enc)
			}
		}
	}
	v, err := s.PutCredential(ctx, "pair", KindOAuth, oauthEnvelope("access-1", string(planted)))
	check("PutCredential", v, err)
	if err != nil {
		t.Fatal(err)
	}
	v, raw, err := s.Current(ctx, "pair")
	check("Current", v, raw, err)
	v, raw, err = s.Get(ctx, "pair", 1)
	check("Get", v, raw, err)
	list, err := s.List(ctx)
	check("List", list, err)
	v, c, err := s.CurrentCredential(ctx, "pair")
	check("CurrentCredential", v, c, err)
	v, c, err = s.GetCredential(ctx, "pair", 1)
	check("GetCredential", v, c, err)
	v, err = s.RotateFrom(ctx, "pair", 1)
	check("RotateFrom", v, err)
	v, err = s.Rotate(ctx, "pair", planted)
	check("Rotate", v, err)
	stale := v
	v, err = s.RotateIf(ctx, "pair", KindOAuth, Version{Name: "pair", Version: 9}, oauthEnvelope("access-x", string(second)))
	check("RotateIf (unread)", v, err)
	v, err = s.RotateIf(ctx, "pair", KindOAuth, stale, oauthEnvelope("access-x", string(second)))
	check("RotateIf (stale)", v, err)
	v, err = s.RotateCredential(ctx, "pair", KindOAuth, oauthEnvelope("access-2", string(second)))
	check("RotateCredential", v, err)
	read, _, err := s.CurrentCredential(ctx, "pair")
	check("CurrentCredential (2)", read, err)
	v, err = s.RotateIf(ctx, "pair", KindOAuth, read, oauthEnvelope("access-3", string(second)))
	check("RotateIf", v, err)
	// A crashed rotation leaves the planted token in an orphan above the
	// pointer: the refusals that name it, Orphan and Adopt return none of it.
	crashAfterVersionWrite(t, s, server, "pair", func() error {
		_, err := s.RotateCredential(ctx, "pair", KindOAuth, oauthEnvelope("access-o", string(planted)))
		return err
	})
	v, c, err = s.CurrentCredential(ctx, "pair")
	check("CurrentCredential (orphan)", v, c, err)
	v, err = s.RotateCredential(ctx, "pair", KindOAuth, oauthEnvelope("access-y", string(second)))
	check("RotateCredential (orphan)", v, err)
	info, err := s.Orphan(ctx, "pair")
	check("Orphan", info, err)
	if err != nil {
		t.Fatal(err)
	}
	v, err = s.Adopt(ctx, "pair", info.Orphan)
	check("Adopt", v, err)
	v, err = s.PutCredential(ctx, "pair", KindOAuth, oauthEnvelope("access-4", string(planted)))
	check("PutCredential (exists)", v, err)
	err = s.RaiseFloor(ctx)
	check("RaiseFloor", err)
	err = s.Rewrap(ctx, rewrapKey(7))
	check("Rewrap", err)
	for n := uint64(0); n <= 4; n++ {
		v, c, err = s.GetCredential(ctx, "pair", n)
		check(fmt.Sprintf("GetCredential %d", n), v, c, err)
		v, raw, err = s.Get(ctx, "pair", n)
		check(fmt.Sprintf("Get %d", n), v, raw, err)
	}
	list, err = s.List(ctx)
	check("List after rewrap", list, err)

	// The rest of the store's surface, with the pair still planted.
	v, line, err := s.GenerateSSH(ctx, "deploy", "ci")
	check("GenerateSSH", v, line, err)
	v, err = s.Put(ctx, "raw", KindOpaque, planted)
	check("Put (an opaque value, not the pair)", v, err)
	fp, ok, err := s.InterruptedRewrap(ctx)
	check("InterruptedRewrap", fp, ok, err)
	ok, err = s.RecordsSealedUnder(ctx, rewrapKey(7))
	check("RecordsSealedUnder", ok, err)
	ok, err = s.UserScopesExist(ctx)
	check("UserScopesExist", ok, err)

	// A user scope holding a planted pair, read through every UserScope
	// method, the deliveries path included, twice: through the view as
	// UserScope returns it, and through the socket's view of the same scope
	// (WithOrigin(SocketOrigin)), whose operations are the socket's path.
	// Each view walks its own pair, deleted at the end of its walk.
	startScopes(t, s)
	u, err := s.UserScope(1001)
	check("UserScope", u, err)
	if err != nil {
		t.Fatal(err)
	}
	walkUser := func(label string, view *UserScope) {
		t.Helper()
		const pair, opaque = "user/1001/pair", "user/1001/opaque"
		v, err := view.Put(ctx, pair, KindOpaque, []byte("placeholder"))
		check(label+".Put", v, err)
		if err != nil {
			t.Fatal(err)
		}
		plantUserTyped(t, view, pair, KindOAuth, oauthEnvelope("access-u", string(planted)))
		v, raw, err := view.Current(ctx, pair)
		check(label+".Current", v, raw, err)
		if !errors.Is(err, ErrTypedCredential) {
			t.Errorf("%s.Current of the planted pair: %v, want ErrTypedCredential", label, err)
		}
		v, raw, err = view.ReadForExec(ctx, pair)
		check(label+".ReadForExec", v, raw, err)
		if !errors.Is(err, ErrTypedCredential) || raw != nil {
			t.Errorf("%s.ReadForExec of the planted pair: %d bytes, %v; want none and ErrTypedCredential", label, len(raw), err)
		}
		list, err := view.List(ctx)
		check(label+".List", list, err)
		if len(list) != 1 || list[0].Err != nil || list[0].Current.Kind != KindOAuth {
			t.Errorf("%s.List = %+v, want the planted oauth pair", label, list)
		}
		// A user entry is never typed, so Rotate of a raw value over the
		// planted pair is refused; RotateFrom carries the pair's envelope
		// forward as its next version. Neither returns any of it.
		v, err = view.Rotate(ctx, pair, planted)
		check(label+".Rotate", v, err)
		if !errors.Is(err, ErrKindMismatch) {
			t.Errorf("%s.Rotate of a raw value over the planted pair: %v, want ErrKindMismatch", label, err)
		}
		v, err = view.RotateFrom(ctx, pair, 1)
		check(label+".RotateFrom", v, err)
		v, raw, err = view.ReadForExec(ctx, pair)
		check(label+".ReadForExec (rotated pair)", v, raw, err)
		w := view.WithOrigin(SocketOrigin(7))
		check(label+".WithOrigin", w)
		if w == view {
			t.Errorf("%s.WithOrigin returned the view itself, want a copy", label)
		}

		// The socket stores opaque values only, so a user scope cannot hold
		// a typed pair in this release but by planting. The token is planted
		// a second way, as an opaque user value, and every method is called
		// on it: only the value reads return it, ReadForExec (the socket's
		// read for exec, the one way a user reaches its own value) and
		// Current (this package's own read, which no socket operation
		// calls). Every other result, and their versions and errors beside
		// the value, must carry none of it.
		value := func(what string, v Version, raw []byte, err error) {
			t.Helper()
			check(what, v, err)
			if err != nil || !bytes.Equal(raw, planted) {
				t.Errorf("%s of the opaque token: %d bytes, %v; want the token", what, len(raw), err)
			}
		}
		v, err = view.Put(ctx, opaque, KindOpaque, planted)
		check(label+".Put (the opaque token)", v, err)
		if err != nil {
			t.Fatal(err)
		}
		v, raw, err = view.ReadForExec(ctx, opaque)
		value(label+".ReadForExec (opaque)", v, raw, err)
		v, raw, err = view.Current(ctx, opaque)
		value(label+".Current (opaque)", v, raw, err)
		list, err = view.List(ctx)
		check(label+".List (opaque)", list, err)
		v, err = view.Rotate(ctx, opaque, planted)
		check(label+".Rotate (opaque)", v, err)
		if err != nil {
			t.Errorf("%s.Rotate of the opaque token: %v", label, err)
		}
		v, err = view.RotateFrom(ctx, opaque, 1)
		check(label+".RotateFrom (opaque)", v, err)
		if err != nil {
			t.Errorf("%s.RotateFrom of the opaque token: %v", label, err)
		}
		v, err = view.RotateFrom(ctx, opaque, 9)
		check(label+".RotateFrom (opaque, no such version)", v, err)
		v, err = view.Rotate(ctx, opaque, nil)
		check(label+".Rotate (opaque, empty)", v, err)
		list, err = view.List(ctx)
		check(label+".List (rotated)", list, err)

		err = view.Refused(ctx, "exec-read", RefusedBadValue)
		check(label+".Refused", err)
		err = view.RefusedDropped(ctx, 1)
		check(label+".RefusedDropped", err)
		d := exportDelivery(testDelivery(1))
		d.Entry = pair
		d.Items = nil
		err = view.Deliver(ctx, d)
		check(label+".Deliver", err)
		got, err := view.Delivery(ctx, d.UID)
		check(label+".Delivery", got, err)
		err = view.Withdraw(ctx, d.UID)
		check(label+".Withdraw", err)
		err = view.Delete(ctx, opaque)
		check(label+".Delete (opaque)", err)
		err = view.Delete(ctx, pair)
		check(label+".Delete", err)
	}
	walkUser("UserScope", u)
	socketView := u.WithOrigin(SocketOrigin(4242))
	walkUser("SocketView", socketView)

	// MergeFloor takes an options struct reflection cannot build: a dry
	// run, which writes nothing, is called by hand.
	mr, err := s.MergeFloor(ctx, MergeOptions{DryRun: true})
	check("MergeFloor", mr, err)

	// RefusedIneligible takes a pid reflection does not build: the
	// socket's refused line for a uid with no user scope, by hand.
	err = s.RefusedIneligible(ctx, 100, 4242, "list")
	check("RefusedIneligible", err)

	err = s.Delete(ctx, "pair")
	check("Delete", err)

	// The audit sink and the user-scope floor saw every user-scope write
	// above; no line carries the token.
	floorLog, audit := userLogs(s)
	lines := audit.all()
	if len(lines) == 0 {
		t.Fatal("the audit sink recorded no line: the user-scope writes above were not audited")
	}
	for _, sec := range [][]byte{planted, second} {
		if enc := leaks(sec, lines, floorLog.lines); enc != "" {
			t.Errorf("the audit sink or the user-scope floor carries the refresh token as %q", enc)
		}
	}
	viaSocket := false
	for _, l := range lines {
		viaSocket = viaSocket || l.via == auditViaSocket
	}
	if !viaSocket {
		t.Error("no audit line came by the socket: the socket view's operations were not walked")
	}

	// The root maintenance verbs take a file-attribute writer reflection
	// cannot build: each is called by hand with a recording one, last, as
	// they rewrite the logs read above. Whether it succeeds or refuses, its
	// report and its error must not carry the token.
	rb, err := s.RebuildFloor(ctx, &attrRecorder{})
	check("RebuildFloor", rb, err)
	ra, err := s.RotateAudit(ctx, &attrRecorder{}, false)
	check("RotateAudit", ra, err)

	// allow lists the methods that return no secret data and are not
	// called above, each with its reason. It is empty: every method is
	// called.
	allow := map[string]string{}
	// The socket view is walked as a receiver of its own: a method called
	// on the plain view does not cover it on the socket's path.
	for _, r := range []struct {
		label string
		recv  any
	}{{"FileStore", s}, {"UserScope", u}, {"SocketView", socketView}} {
		recv := r.recv
		rt := reflect.TypeOf(recv)
		for i := 0; i < rt.NumMethod(); i++ {
			m := rt.Method(i)
			key := r.label + "." + m.Name
			if covered[key] || allow[key] != "" {
				continue
			}
			args, ok := reflectArgs(ctx, m.Type)
			if !ok {
				t.Errorf("%s: reflection cannot build its arguments; call it by hand in this test, or allowlist it with the reason it returns no secret data", key)
				continue
			}
			out := reflect.ValueOf(recv).Method(i).Call(args)
			vals := make([]any, len(out))
			for j := range out {
				vals[j] = out[j].Interface()
			}
			check(key+" (by reflection)", vals...)
		}
	}
}

// reflectArgs builds arguments for a method of type mt (receiver first)
// from the kinds of parameter a store method takes: a context, an entry
// name, a version or a uid. Any other parameter type is not built.
func reflectArgs(ctx context.Context, mt reflect.Type) ([]reflect.Value, bool) {
	var args []reflect.Value
	for i := 1; i < mt.NumIn(); i++ {
		switch in := mt.In(i); {
		case in == reflect.TypeFor[context.Context]():
			args = append(args, reflect.ValueOf(ctx))
		case in.Kind() == reflect.String:
			args = append(args, reflect.ValueOf("pair").Convert(in))
		case in.Kind() == reflect.Uint64, in.Kind() == reflect.Uint32:
			args = append(args, reflect.ValueOf(uint64(1)).Convert(in))
		default:
			return nil, false
		}
	}
	return args, true
}

// plantUserTyped replaces version 1 of u's entry input, an opaque entry,
// with a record of the typed kind kind sealing e, under the scope's keys:
// a user scope has no typed put yet, and U149 reads a typed pair through
// every UserScope method.
func plantUserTyped(t *testing.T, u *UserScope, input string, kind Kind, e typed.Envelope) {
	t.Helper()
	name, err := u.own("current", input)
	if err != nil {
		t.Fatal(err)
	}
	ck, _ := credentialKind(kind)
	e.Credential.AccessIssuedAt = typedNow
	env, err := typed.Encode(ck, e)
	if err != nil {
		t.Fatal(err)
	}
	err = u.read(context.Background(), func(entries *os.Root, uk keys) error {
		en, err := openUserEntry(entries, name)
		if err != nil {
			return err
		}
		defer en.close()
		rec := record{kind: byte(kind), name: name, version: 1, generation: en.generation, created: typedNow.Unix()}
		if err := rec.seal(uk.seal, uk.scope, env, rand.Reader); err != nil {
			return err
		}
		f, err := en.root.OpenFile(versionName(1), os.O_WRONLY|os.O_TRUNC, 0)
		if err != nil {
			return err
		}
		if _, err := f.Write(rec.marshal()); err != nil {
			f.Close()
			return err
		}
		return f.Close()
	})
	if err != nil {
		t.Fatalf("plant %s: %v", input, err)
	}
}

// TestGetReturnsRedactedCredential is U149: a typed entry reads back as a
// typed.Credential, which has no field a refresh token could fill, and the
// raw reads refuse it.
func TestGetReturnsRedactedCredential(t *testing.T) {
	ctx := context.Background()
	s, _ := newTypedStore(t)
	mustPutCredential(t, s, "pair", KindOAuth, oauthEnvelope("access-1", "refresh-1"))
	mustPutCredential(t, s, "tok", KindToken, tokenEnvelope("t1"))
	mustPut(t, s, "raw", KindOpaque, []byte("v"))
	ct := reflect.TypeFor[typed.Credential]()
	for i := 0; i < ct.NumField(); i++ {
		if strings.Contains(strings.ToLower(ct.Field(i).Name), "refreshtoken") {
			t.Fatalf("typed.Credential has a refresh-token field %s", ct.Field(i).Name)
		}
	}
	for _, n := range []string{"pair", "tok"} {
		if _, val, err := s.Current(ctx, n); !errors.Is(err, ErrTypedCredential) || val != nil {
			t.Errorf("Current %s: %q, %v, want ErrTypedCredential", n, val, err)
		}
		if _, val, err := s.Get(ctx, n, 1); !errors.Is(err, ErrTypedCredential) || val != nil {
			t.Errorf("Get %s: %q, %v, want ErrTypedCredential", n, val, err)
		}
	}
	v, c, err := s.GetCredential(ctx, "pair", 1)
	if err != nil || v.Kind != KindOAuth || string(c.AccessToken) != "access-1" || c.RefreshOwner != "local" || c.TokenTypeOrDefault() != "Bearer" {
		t.Fatalf("GetCredential = %+v, %+v, %v", v, c, err)
	}
	if _, _, err := s.CurrentCredential(ctx, "raw"); !errors.Is(err, ErrKindMismatch) {
		t.Errorf("CurrentCredential of opaque: %v, want ErrKindMismatch", err)
	}
	if _, _, err := s.GetCredential(ctx, "pair", 2); !errors.Is(err, ErrVersionNotFound) {
		t.Errorf("GetCredential of an uncommitted version: %v", err)
	}
}

// TestRotateIfStaleVersionRefused is U150.
func TestRotateIfStaleVersionRefused(t *testing.T) {
	ctx := context.Background()
	s, _ := newTypedStore(t)
	mustPutCredential(t, s, "pair", KindOAuth, oauthEnvelope("a1", "r1"))
	v1, _ := mustCredential(t, s, "pair")
	mustRotateCredential(t, s, "pair", KindOAuth, oauthEnvelope("a2", "r2"))
	v2, _ := mustCredential(t, s, "pair")
	for _, stale := range []Version{
		{},
		v1,
		{Name: "pair", Version: 2}, // built, not read: no identity
		{Name: "pair", Version: 3},
	} {
		if _, err := s.RotateIf(ctx, "pair", KindOAuth, stale, oauthEnvelope("ax", "rx")); !errors.Is(err, ErrVersionStale) {
			t.Errorf("RotateIf at %d: %v, want ErrVersionStale", stale.Version, err)
		}
	}
	if v, c := mustCredential(t, s, "pair"); v.Version != 2 || string(c.AccessToken) != "a2" {
		t.Fatalf("a stale RotateIf wrote: %+v %q", v, c.AccessToken)
	}
	v, err := s.RotateIf(ctx, "pair", KindOAuth, v2, oauthEnvelope("a3", "r3"))
	if err != nil || v.Version != 3 {
		t.Fatalf("RotateIf at the current version: %+v, %v", v, err)
	}
	if _, err := s.RotateIf(ctx, "absent", KindOAuth, v1, oauthEnvelope("a", "r")); !errors.Is(err, ErrNotFound) {
		t.Errorf("RotateIf of a missing entry: %v", err)
	}
}

// TestRotateIfRefusesVersionBuiltOutside is U150's limit of the identity: a
// caller outside the package can set only a Version's exported fields, so
// even a copy of every exported field of the current version, as read, has
// no identity and is refused as stale. Only the Version a read returned is
// accepted.
func TestRotateIfRefusesVersionBuiltOutside(t *testing.T) {
	ctx := context.Background()
	s, _ := newTypedStore(t)
	mustPutCredential(t, s, "pair", KindOAuth, oauthEnvelope("a1", "r1"))
	read, _ := mustCredential(t, s, "pair")
	var built Version
	rv, bv := reflect.ValueOf(read), reflect.ValueOf(&built).Elem()
	for i := 0; i < rv.NumField(); i++ {
		if rv.Type().Field(i).IsExported() {
			bv.Field(i).Set(rv.Field(i))
		}
	}
	if built.Version != read.Version || built.Fingerprint != read.Fingerprint || built == read {
		t.Fatalf("the copy %+v is not every exported field of %+v and nothing else", built, read)
	}
	if _, err := s.RotateIf(ctx, "pair", KindOAuth, built, oauthEnvelope("a2", "r2")); !errors.Is(err, ErrVersionStale) {
		t.Fatalf("RotateIf with a Version built from the exported fields: %v, want ErrVersionStale", err)
	}
	if v, err := s.RotateIf(ctx, "pair", KindOAuth, read, oauthEnvelope("a2", "r2")); err != nil || v.Version != 2 {
		t.Fatalf("RotateIf with the Version read = %+v, %v", v, err)
	}
}

// TestRotateIfRefusesRecreatedEntry is U150: an entry deleted and put again
// restarts at version 1, so a refresher holding a version of the old entry
// whose number the new one reaches again is refused; the identity of a
// version read from the new entry is accepted. The clock is fixed and the
// values repeat, so the fingerprints of the two lives are equal too: only
// the identity tells them apart.
func TestRotateIfRefusesRecreatedEntry(t *testing.T) {
	ctx := context.Background()
	s, _ := newTypedStore(t)
	mustPutCredential(t, s, "pair", KindOAuth, oauthEnvelope("a1", "r1"))
	mustRotateCredential(t, s, "pair", KindOAuth, oauthEnvelope("a2", "r2"))
	old, _ := mustCredential(t, s, "pair")
	if err := s.Delete(ctx, "pair"); err != nil {
		t.Fatal(err)
	}
	mustPutCredential(t, s, "pair", KindOAuth, oauthEnvelope("a1", "r1"))
	mustRotateCredential(t, s, "pair", KindOAuth, oauthEnvelope("a2", "r2"))
	fresh, _ := mustCredential(t, s, "pair")
	if fresh.Version != old.Version || fresh.Fingerprint != old.Fingerprint {
		t.Fatalf("the two lives differ before the identity: %+v, %+v", old, fresh)
	}
	if _, err := s.RotateIf(ctx, "pair", KindOAuth, old, oauthEnvelope("stale", "stale")); !errors.Is(err, ErrVersionStale) {
		t.Fatalf("RotateIf holding the deleted entry's version: %v, want ErrVersionStale", err)
	}
	if v, c := mustCredential(t, s, "pair"); v.Version != 2 || string(c.AccessToken) != "a2" {
		t.Fatalf("the refused RotateIf wrote: %+v %q", v, c.AccessToken)
	}
	if v, err := s.RotateIf(ctx, "pair", KindOAuth, fresh, oauthEnvelope("a3", "r3")); err != nil || v.Version != 3 {
		t.Fatalf("RotateIf holding the new entry's version: %+v, %v", v, err)
	}
	// List and GetCredential hand out the same identity as CurrentCredential.
	got, _, err := s.GetCredential(ctx, "pair", 3)
	if err != nil {
		t.Fatal(err)
	}
	list, err := s.List(ctx)
	if err != nil || len(list) != 1 || list[0].Current != got {
		t.Fatalf("List current %+v, GetCredential %+v, %v", list, got, err)
	}
}

// pointerBytes is the size of name's pointer plaintext, from its file.
func pointerBytes(t *testing.T, server, name string) int {
	t.Helper()
	fi, err := os.Stat(entryPath(server, name, currentName))
	if err != nil {
		t.Fatal(err)
	}
	return int(fi.Size()) - headerSize - len(name) - tagSize
}

// versionFiles lists the version files of name on disk.
func versionFiles(t *testing.T, server, name string) []uint64 {
	t.Helper()
	des, err := os.ReadDir(entryPath(server, name, ""))
	if err != nil {
		t.Fatal(err)
	}
	var out []uint64
	for _, de := range des {
		if v, ok := parseVersionName(de.Name()); ok {
			out = append(out, v)
		}
	}
	return out
}

// prunedPair stores an oauth entry rotated twice: v2 and v3 retained, v1
// pruned, low = 2.
func prunedPair(t *testing.T) (*FileStore, string) {
	t.Helper()
	s, server := newTypedStore(t)
	mustPutCredential(t, s, "pair", KindOAuth, oauthEnvelope("a1", "r1"))
	mustRotateCredential(t, s, "pair", KindOAuth, oauthEnvelope("a2", "r2"))
	mustRotateCredential(t, s, "pair", KindOAuth, oauthEnvelope("a3", "r3"))
	return s, server
}

// TestOAuthPruneKeepsTwo is U151: oauth keeps the current version and one
// previous; token and ssh keep every version.
func TestOAuthPruneKeepsTwo(t *testing.T) {
	s, server := prunedPair(t)
	if got := versionFiles(t, server, "pair"); fmt.Sprint(got) != "[2 3]" {
		t.Fatalf("oauth versions on disk %v, want [2 3]", got)
	}
	mustRotateCredential(t, s, "pair", KindOAuth, oauthEnvelope("a4", "r4"))
	if got := versionFiles(t, server, "pair"); fmt.Sprint(got) != "[3 4]" {
		t.Fatalf("oauth versions on disk %v, want [3 4]", got)
	}
	if _, _, err := s.GetCredential(context.Background(), "pair", 2); !errors.Is(err, ErrVersionNotFound) {
		t.Errorf("a pruned version reads: %v", err)
	}
	if _, c, err := s.GetCredential(context.Background(), "pair", 3); err != nil || string(c.AccessToken) != "a3" {
		t.Errorf("the previous version: %v", err)
	}
	mustPutCredential(t, s, "tok", KindToken, tokenEnvelope("t1"))
	for i := 2; i <= 4; i++ {
		mustRotateCredential(t, s, "tok", KindToken, tokenEnvelope(fmt.Sprintf("t%d", i)))
	}
	if got := versionFiles(t, server, "tok"); fmt.Sprint(got) != "[1 2 3 4]" {
		t.Fatalf("token versions %v, want all four", got)
	}
}

// TestPointerLowWaterMark is U151: a pointer is 16 bytes until a prune and
// 24 bytes, carrying low, after one; a sealed low out of range is corrupt.
func TestPointerLowWaterMark(t *testing.T) {
	s, server := newTypedStore(t)
	mustPutCredential(t, s, "pair", KindOAuth, oauthEnvelope("a1", "r1"))
	mustRotateCredential(t, s, "pair", KindOAuth, oauthEnvelope("a2", "r2"))
	if n := pointerBytes(t, server, "pair"); n != pointerSize {
		t.Fatalf("pointer before any prune is %d bytes, want %d", n, pointerSize)
	}
	mustRotateCredential(t, s, "pair", KindOAuth, oauthEnvelope("a3", "r3"))
	if n := pointerBytes(t, server, "pair"); n != prunedPointerSize {
		t.Fatalf("pointer after a prune is %d bytes, want %d", n, prunedPointerSize)
	}
	if got := rangePlaintext(5, 9, 1); len(got) != pointerSize || !bytes.Equal(got, pointerPlaintext(5, 9)) {
		t.Fatalf("low = 1 does not encode as the 16-byte pointer: %x", got)
	}
	// A pointer sealed with a low outside 1..version, or of another size,
	// is corrupt.
	k, err := s.loadMaster()
	if err != nil {
		t.Fatal(err)
	}
	gen, err := hex.DecodeString(strings.TrimSpace(readString(t, entryPath(server, "pair", generationName))))
	if err != nil {
		t.Fatal(err)
	}
	for _, pt := range [][]byte{
		binary.BigEndian.AppendUint64(pointerPlaintext(3, 3), 0),
		binary.BigEndian.AppendUint64(pointerPlaintext(3, 3), 4),
		append(pointerPlaintext(3, 3), 1, 2, 3),
	} {
		ptr := record{kind: kindPointer, name: "pair", created: 1}
		copy(ptr.generation[:], gen)
		if err := ptr.seal(k.seal, k.scope, pt, rand.Reader); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(entryPath(server, "pair", currentName), ptr.marshal(), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, _, err := s.CurrentCredential(context.Background(), "pair"); !errors.Is(err, ErrCorrupt) {
			t.Errorf("pointer plaintext %x: %v, want ErrCorrupt", pt, err)
		}
	}
}

func readString(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// TestListPrunedOAuthEntryNotCorrupt is U152: a pruned entry lists healthy,
// with its committed range only, even with a leftover below low.
func TestListPrunedOAuthEntryNotCorrupt(t *testing.T) {
	s, server := prunedPair(t)
	copyFile(t, entryPath(server, "pair", "v2"), entryPath(server, "pair", "v1"))
	list, err := s.List(context.Background())
	if err != nil || len(list) != 1 || list[0].Err != nil {
		t.Fatalf("List = %+v, %v", list, err)
	}
	if e := list[0]; e.Current.Version != 3 || len(e.Versions) != 2 || e.Versions[0].Version != 2 {
		t.Fatalf("pruned entry lists as %+v, want versions 2 and 3", e)
	}
}

// TestRewrapHandlesPrunedOAuth is U152: Rewrap re-seals low..current and
// unlinks a leftover below low.
func TestRewrapHandlesPrunedOAuth(t *testing.T) {
	s, server := prunedPair(t)
	copyFile(t, entryPath(server, "pair", "v2"), entryPath(server, "pair", "v1"))
	if err := s.Rewrap(context.Background(), rewrapKey(3)); err != nil {
		t.Fatal(err)
	}
	if got := versionFiles(t, server, "pair"); fmt.Sprint(got) != "[2 3]" {
		t.Fatalf("versions after rewrap %v, want [2 3]", got)
	}
	for n, want := range map[uint64]string{2: "a2", 3: "a3"} {
		if _, c, err := s.GetCredential(context.Background(), "pair", n); err != nil || string(c.AccessToken) != want {
			t.Errorf("version %d after rewrap: %q, %v", n, c.AccessToken, err)
		}
	}
	if n := pointerBytes(t, server, "pair"); n != prunedPointerSize {
		t.Errorf("rewrap lost the mark: pointer is %d bytes", n)
	}
}

// TestDeletePrunedOAuthEntry is U152: Delete removes a pruned entry and its
// leftovers.
func TestDeletePrunedOAuthEntry(t *testing.T) {
	s, server := prunedPair(t)
	copyFile(t, entryPath(server, "pair", "v2"), entryPath(server, "pair", "v1"))
	if err := s.Delete(context.Background(), "pair"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(entryPath(server, "pair", "")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the entry directory survived Delete: %v", err)
	}
	if _, _, err := s.CurrentCredential(context.Background(), "pair"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("after Delete: %v", err)
	}
}

// TestGapInsideCommittedRangeIsCorrupt is U152: a version missing inside
// low..current is damage.
func TestGapInsideCommittedRangeIsCorrupt(t *testing.T) {
	s, server := prunedPair(t)
	remove(t, entryPath(server, "pair", "v2"))
	list, err := s.List(context.Background())
	if err != nil || len(list) != 1 || !errors.Is(list[0].Err, ErrCorrupt) {
		t.Fatalf("List with a gap = %+v, %v; want the entry corrupt", list, err)
	}
	if err := s.Rewrap(context.Background(), rewrapKey(4)); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("Rewrap with a gap: %v, want ErrCorrupt", err)
	}
}

// TestCopyBackAcrossPruneCaught is U152: a pointer copied back from before a
// prune fails the floor's sequence check.
func TestCopyBackAcrossPruneCaught(t *testing.T) {
	s, server := newTypedStore(t)
	mustPutCredential(t, s, "pair", KindOAuth, oauthEnvelope("a1", "r1"))
	mustRotateCredential(t, s, "pair", KindOAuth, oauthEnvelope("a2", "r2"))
	saved := readString(t, entryPath(server, "pair", currentName))
	mustRotateCredential(t, s, "pair", KindOAuth, oauthEnvelope("a3", "r3"))
	writeFile(t, entryPath(server, "pair", currentName), saved)
	if _, _, err := s.CurrentCredential(context.Background(), "pair"); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("a copied-back pointer read: %v, want ErrCorrupt", err)
	}
	list, err := s.List(context.Background())
	if err != nil || len(list) != 1 || !errors.Is(list[0].Err, ErrCorrupt) {
		t.Fatalf("List with a copied-back pointer = %+v, %v", list, err)
	}
}

// TestFromVersionRefusedForOAuth is U153; token keeps the rollback.
func TestFromVersionRefusedForOAuth(t *testing.T) {
	ctx := context.Background()
	s, _ := newTypedStore(t)
	mustPutCredential(t, s, "pair", KindOAuth, oauthEnvelope("a1", "r1"))
	mustRotateCredential(t, s, "pair", KindOAuth, oauthEnvelope("a2", "r2"))
	if _, err := s.RotateFrom(ctx, "pair", 1); !errors.Is(err, ErrFromVersionOAuth) {
		t.Fatalf("RotateFrom oauth: %v, want ErrFromVersionOAuth", err)
	}
	if v, _ := mustCredential(t, s, "pair"); v.Version != 2 {
		t.Fatalf("a refused RotateFrom wrote version %d", v.Version)
	}
	mustPutCredential(t, s, "tok", KindToken, tokenEnvelope("t1"))
	mustRotateCredential(t, s, "tok", KindToken, tokenEnvelope("t2"))
	v, err := s.RotateFrom(ctx, "tok", 1)
	if err != nil || v.Version != 3 {
		t.Fatalf("RotateFrom token: %+v, %v", v, err)
	}
	if _, c := mustCredential(t, s, "tok"); string(c.Value) != "t1" {
		t.Fatalf("RotateFrom token wrote %q, want t1", c.Value)
	}
	if _, err := s.RotateFrom(ctx, "tok", 9); !errors.Is(err, ErrVersionNotFound) {
		t.Fatalf("RotateFrom an uncommitted version: %v", err)
	}
}

// TestRefreshOwnerFixedPerEntry: an oauth entry's refresh owner is fixed
// when it is put. RotateCredential and RotateIf refuse an envelope naming
// another owner, in both directions, with ErrRefreshOwnerFixed, and write
// nothing. RotateFrom is refused for oauth before any owner is compared.
func TestRefreshOwnerFixedPerEntry(t *testing.T) {
	ctx := context.Background()
	owned := func(access, owner string) typed.Envelope {
		e := oauthEnvelope(access, "r-"+access)
		e.Credential.RefreshOwner = owner
		return e
	}
	for _, flip := range [][2]string{{"local", "server/x"}, {"server/x", "local"}, {"server/x", "server/y"}} {
		t.Run(flip[0]+" to "+flip[1], func(t *testing.T) {
			s, _ := newTypedStore(t)
			mustPutCredential(t, s, "pair", KindOAuth, owned("a1", flip[0]))
			read, _ := mustCredential(t, s, "pair")
			if _, err := s.RotateCredential(ctx, "pair", KindOAuth, owned("a2", flip[1])); !errors.Is(err, ErrRefreshOwnerFixed) {
				t.Errorf("RotateCredential to owner %s: %v, want ErrRefreshOwnerFixed", flip[1], err)
			}
			if _, err := s.RotateIf(ctx, "pair", KindOAuth, read, owned("a2", flip[1])); !errors.Is(err, ErrRefreshOwnerFixed) {
				t.Errorf("RotateIf to owner %s: %v, want ErrRefreshOwnerFixed", flip[1], err)
			}
			if v, c := mustCredential(t, s, "pair"); v.Version != 1 || c.RefreshOwner != flip[0] {
				t.Fatalf("a refused owner change wrote: %+v %q", v, c.RefreshOwner)
			}
			if _, err := s.RotateFrom(ctx, "pair", 1); !errors.Is(err, ErrFromVersionOAuth) {
				t.Errorf("RotateFrom: %v, want ErrFromVersionOAuth", err)
			}
			// The same owner still rotates.
			if v, err := s.RotateIf(ctx, "pair", KindOAuth, read, owned("a2", flip[0])); err != nil || v.Version != 2 {
				t.Fatalf("RotateIf keeping owner %s: %+v, %v", flip[0], v, err)
			}
		})
	}
}

// sealPointer replaces name's current pointer with one sealing pt.
func sealPointer(t *testing.T, s *FileStore, server, name string, pt []byte) {
	t.Helper()
	k, err := s.loadMaster()
	if err != nil {
		t.Fatal(err)
	}
	gen, err := hex.DecodeString(strings.TrimSpace(readString(t, entryPath(server, name, generationName))))
	if err != nil {
		t.Fatal(err)
	}
	ptr := record{kind: kindPointer, name: name, created: 1}
	copy(ptr.generation[:], gen)
	if err := ptr.seal(k.seal, k.scope, pt, rand.Reader); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(entryPath(server, name, currentName), ptr.marshal(), 0o600); err != nil {
		t.Fatal(err)
	}
}

// TestPointerCanonicalForm is U151: the low-water mark has one encoding. A
// 24-byte pointer recording low = 1, which the 16-byte form says, and a
// 24-byte pointer over an entry that is not oauth, which never prunes, are
// corrupt, at the sequence the floor records.
func TestPointerCanonicalForm(t *testing.T) {
	ctx := context.Background()
	s, server := newTypedStore(t)
	mustPutCredential(t, s, "pair", KindOAuth, oauthEnvelope("a1", "r1"))
	mustRotateCredential(t, s, "pair", KindOAuth, oauthEnvelope("a2", "r2"))
	mustPutCredential(t, s, "tok", KindToken, tokenEnvelope("t1"))
	mustRotateCredential(t, s, "tok", KindToken, tokenEnvelope("t2"))
	mustPut(t, s, "raw", KindOpaque, []byte("one"))
	mustRotate(t, s, "raw", "two")

	sealPointer(t, s, server, "pair", binary.BigEndian.AppendUint64(pointerPlaintext(2, 2), 1))
	if _, _, err := s.CurrentCredential(ctx, "pair"); !errors.Is(err, ErrCorrupt) {
		t.Errorf("a 24-byte oauth pointer with low 1: %v, want ErrCorrupt", err)
	}
	// At version 2 the writer records low 1, so the 16-byte form is the
	// only one (TestOAuthRetentionWindowOnRead).
	sealPointer(t, s, server, "pair", binary.BigEndian.AppendUint64(pointerPlaintext(2, 2), 2))
	if _, _, err := s.CurrentCredential(ctx, "pair"); !errors.Is(err, ErrCorrupt) {
		t.Errorf("a 24-byte oauth pointer with low 2 at version 2: %v, want ErrCorrupt", err)
	}
	sealPointer(t, s, server, "tok", binary.BigEndian.AppendUint64(pointerPlaintext(2, 2), 2))
	if _, _, err := s.CurrentCredential(ctx, "tok"); !errors.Is(err, ErrCorrupt) {
		t.Errorf("a 24-byte token pointer: %v, want ErrCorrupt", err)
	}
	sealPointer(t, s, server, "raw", binary.BigEndian.AppendUint64(pointerPlaintext(2, 2), 2))
	if _, _, err := s.Current(ctx, "raw"); !errors.Is(err, ErrCorrupt) {
		t.Errorf("a 24-byte opaque pointer: %v, want ErrCorrupt", err)
	}
	list, err := s.List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range list {
		if (e.Name == "tok" || e.Name == "raw") && !errors.Is(e.Err, ErrCorrupt) {
			t.Errorf("List %s with a 24-byte pointer: %+v, want ErrCorrupt", e.Name, e)
		}
	}
}

// TestOAuthRetentionWindowOnRead is U151's read half of the retention
// window: an oauth pointer reads only in the form a rotation writes, low =
// version-1 in the 24-byte form from version 3, and the 16-byte form only at
// versions 1 and 2. A pointer widening or narrowing the window is ErrCorrupt
// on read, not only once List opens a missing version.
func TestOAuthRetentionWindowOnRead(t *testing.T) {
	ctx := context.Background()
	s, server := newTypedStore(t)
	mustPutCredential(t, s, "pair", KindOAuth, oauthEnvelope("a1", "r1"))
	for i := 2; i <= 4; i++ {
		mustRotateCredential(t, s, "pair", KindOAuth, oauthEnvelope(fmt.Sprintf("a%d", i), fmt.Sprintf("r%d", i)))
	}
	written := readString(t, entryPath(server, "pair", currentName))
	for _, c := range []struct {
		name string
		pt   []byte
		ok   bool
	}{
		{"the writer's form, low 3", rangePlaintext(4, 4, 3), true},
		{"the 16-byte form at version 4", pointerPlaintext(4, 4), false},
		{"low 2 at version 4", rangePlaintext(4, 4, 2), false},
		{"low 4 at version 4", rangePlaintext(4, 4, 4), false},
	} {
		sealPointer(t, s, server, "pair", c.pt)
		v, _, err := s.CurrentCredential(ctx, "pair")
		if c.ok && (err != nil || v.Version != 4) {
			t.Errorf("%s: %+v, %v; want version 4", c.name, v, err)
		}
		if !c.ok && !errors.Is(err, ErrCorrupt) {
			t.Errorf("%s: %+v, %v; want ErrCorrupt", c.name, v, err)
		}
	}
	writeFile(t, entryPath(server, "pair", currentName), written)
	if v, _ := mustCredential(t, s, "pair"); v.Version != 4 {
		t.Fatalf("the written pointer reads version %d", v.Version)
	}
}

// sealVersion writes a record of kind sealing pt as version of name, under
// the store's master and the entry's generation, as only a master holder
// could.
func sealVersion(t *testing.T, s *FileStore, server, name string, version uint64, kind Kind, pt []byte) {
	t.Helper()
	k, err := s.loadMaster()
	if err != nil {
		t.Fatal(err)
	}
	gen, err := hex.DecodeString(strings.TrimSpace(readString(t, entryPath(server, name, generationName))))
	if err != nil {
		t.Fatal(err)
	}
	r := record{kind: byte(kind), name: name, version: version, created: 1}
	copy(r.generation[:], gen)
	if err := r.seal(k.seal, k.scope, pt, rand.Reader); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(entryPath(server, name, versionName(version)), r.marshal(), 0o600); err != nil {
		t.Fatal(err)
	}
}

// TestRotateFromRefusesOtherKind is U146's rollback case: RotateFrom refuses,
// with ErrKindMismatch, a source version whose kind is not the entry's
// current kind, and writes nothing.
func TestRotateFromRefusesOtherKind(t *testing.T) {
	ctx := context.Background()
	s, server := newTypedStore(t)
	mustPutCredential(t, s, "tok", KindToken, tokenEnvelope("t1"))
	mustRotateCredential(t, s, "tok", KindToken, tokenEnvelope("t2"))
	sealVersion(t, s, server, "tok", 1, KindOpaque, []byte("raw bytes"))
	if v, err := s.RotateFrom(ctx, "tok", 1); !errors.Is(err, ErrKindMismatch) || v != (Version{}) {
		t.Fatalf("RotateFrom an opaque version of a token entry = %+v, %v; want ErrKindMismatch", v, err)
	}
	if got := fmt.Sprint(versionFiles(t, server, "tok")); got != "[1 2]" {
		t.Fatalf("versions after the refusal %s, want [1 2]", got)
	}
	if v, c := mustCredential(t, s, "tok"); v.Version != 2 || string(c.Value) != "t2" {
		t.Fatalf("current after the refusal: %d %q", v.Version, c.Value)
	}
}

// TestTypedPlaintextZeroedAfterSeal is the zeroing rule: every typed
// plaintext buffer the store owns (the encoded envelope a typed put or
// rotation seals, and the access token sameRefreshOwner decodes) is zero
// once the call returns, and a raw Put or Rotate leaves the caller's slice
// as it was.
func TestTypedPlaintextZeroedAfterSeal(t *testing.T) {
	ctx := context.Background()
	s, _ := newTypedStore(t)
	var owned [][]byte
	s.owned = func(b []byte) { owned = append(owned, b) }
	check := func(op string, want int) {
		t.Helper()
		if len(owned) < want {
			t.Fatalf("%s handed %d store-owned buffers, want at least %d", op, len(owned), want)
		}
		for i, b := range owned {
			if len(b) == 0 {
				t.Fatalf("%s: buffer %d is empty", op, i)
			}
			if !bytes.Equal(b, make([]byte, len(b))) {
				t.Fatalf("%s: store-owned buffer %d is not zero after the call: %q", op, i, b)
			}
		}
		owned = nil
	}
	mustPutCredential(t, s, "o", KindOAuth, oauthEnvelope("a1", "r1"))
	check("PutCredential", 1)
	read := mustRotateCredential(t, s, "o", KindOAuth, oauthEnvelope("a2", "r2"))
	check("RotateCredential", 2) // the envelope and the decoded access token
	if _, err := s.RotateIf(ctx, "o", KindOAuth, read, oauthEnvelope("a3", "r3")); err != nil {
		t.Fatal(err)
	}
	check("RotateIf", 2)

	raw := []byte("caller's value")
	mustPut(t, s, "r", KindOpaque, raw)
	if string(raw) != "caller's value" {
		t.Fatalf("Put changed the caller's slice to %q", raw)
	}
	raw2 := []byte("caller's next value")
	if _, err := s.Rotate(ctx, "r", raw2); err != nil {
		t.Fatal(err)
	}
	if string(raw2) != "caller's next value" {
		t.Fatalf("Rotate changed the caller's slice to %q", raw2)
	}
	e := oauthEnvelope("a4", "r4")
	if _, err := s.RotateCredential(ctx, "o", KindOAuth, e); err != nil {
		t.Fatal(err)
	}
	if string(e.Credential.AccessToken) != "a4" || string(e.RefreshToken) != "r4" {
		t.Fatalf("RotateCredential changed the caller's envelope: %q %q", e.Credential.AccessToken, e.RefreshToken)
	}
}

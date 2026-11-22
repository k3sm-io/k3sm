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
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"k3sm.io/apis/keystore/credential"
)

// newDeliveryScope returns a mastered store and uid 1001's view of it, with
// the scope minted by a put of user/1001/token.
func newDeliveryScope(t *testing.T) (*FileStore, string, *UserScope) {
	t.Helper()
	s, server := newMasteredStore(t)
	fakeGUIDs(t, map[uint32][generationSize]byte{1001: guid(0xA1)})
	u := userScope(t, s, 1001)
	userPut(t, u, "user/1001/token", "a value")
	return s, server, u
}

// testDelivery is a delivery of user/1001/token numbered n.
func testDelivery(n int) delivery {
	return delivery{
		uid:         fmt.Sprintf("00000000-0000-0000-0000-%012d", n),
		name:        fmt.Sprintf("kd-%d", n),
		entry:       "user/1001/token",
		namespace:   "team-a",
		secretName:  fmt.Sprintf("token-%d", n),
		items:       []credential.Item{{Field: credential.FieldValue, Key: "token"}, {Field: credential.FieldExpiresAt, Key: "expires_at"}},
		requestedBy: "k3sm:local:1001",
	}
}

// openDeliveriesFile opens uid 1001's deliveries file under the store's
// keys, returning the record and its plaintext.
func openDeliveriesFile(t *testing.T, s *FileStore, server string) (record, []byte) {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(scopeDir(server, "1001"), deliveriesName))
	if err != nil {
		t.Fatal(err)
	}
	r, err := parseDeliveriesRecord(b)
	if err != nil {
		t.Fatal(err)
	}
	k, err := s.loadMaster()
	if err != nil {
		t.Fatal(err)
	}
	sk, err := os.ReadFile(filepath.Join(scopeDir(server, "1001"), scopeKeyName))
	if err != nil {
		t.Fatal(err)
	}
	skr, err := parseScopeKey(sk)
	if err != nil {
		t.Fatal(err)
	}
	ku, err := skr.open(k.wrap, "user/1001")
	if err != nil {
		t.Fatal(err)
	}
	pt, err := r.open(hmacSHA256(ku, []byte(deliveriesKeyLabel+"\x00user/1001")), "user/1001")
	if err != nil {
		t.Fatalf("the deliveries record does not open under HMAC(K_u, label ‖ 0 ‖ scope): %v", err)
	}
	return r, pt
}

// U14: add, look up and withdraw round-trip under the floor; the record
// keeps the UID, the KeyDelivery's name, the full target tuple and the
// digest under its seal, re-sealed at the next sequence on every write; a
// copied-back older record is refused against the floor.
func TestDeliveryRecordDigestRoundTrip(t *testing.T) {
	ctx := context.Background()
	s, server, u := newDeliveryScope(t)
	fl, audit := userLogs(s)
	d := testDelivery(1)
	if err := u.Deliver(ctx, exportDelivery(d)); err != nil {
		t.Fatalf("Deliver: %v", err)
	}
	exported, err := u.Delivery(ctx, d.uid)
	if err != nil {
		t.Fatalf("Delivery: %v", err)
	}
	got := exported.internal()
	want := deliveryDigest(d.entry, d.namespace, d.secretName, d.items)
	if got.uid != d.uid || got.name != d.name || got.entry != d.entry || got.namespace != d.namespace || got.secretName != d.secretName || got.requestedBy != d.requestedBy || got.withdrawn || got.digest != want {
		t.Fatalf("looked up %+v, want %+v with digest %x", got, d, want)
	}
	if len(got.items) != 2 || got.items[0].Key != "expires_at" || got.items[1].Key != "token" {
		t.Fatalf("items %+v, want both, sorted by key", got.items)
	}
	// Under seal: no field of the tuple is in the file's bytes.
	raw, err := os.ReadFile(filepath.Join(scopeDir(server, "1001"), deliveriesName))
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{d.uid, d.name, d.namespace, d.secretName, d.requestedBy, "user/1001/token"} {
		if bytes.Contains(raw, []byte(f)) {
			t.Errorf("the deliveries file holds %q in the clear", f)
		}
	}
	r, _ := openDeliveriesFile(t, s, server)
	if r.kind != kindDeliveries || r.name != deliveriesName || r.version != 2 || r.generation != guid(0xA1) {
		t.Fatalf("record kind %#x name %q seq %d generation %x; want 0xfd, deliveries, 2, the GeneratedUID", r.kind, r.name, r.version, r.generation)
	}
	older := raw
	if err := u.Withdraw(ctx, d.uid); err != nil {
		t.Fatalf("Withdraw: %v", err)
	}
	if got, err := u.Delivery(ctx, d.uid); err != nil || !got.Withdrawn || got.Digest != want {
		t.Fatalf("after withdraw: %+v, %v; want the tombstone with its digest", got, err)
	}
	if err := u.Withdraw(ctx, d.uid); err != nil {
		t.Fatalf("a second withdraw: %v, want no change", err)
	}
	if _, err := u.Delivery(ctx, "absent"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("lookup of an unrecorded UID: %v, want ErrNotFound", err)
	}
	if err := u.Withdraw(ctx, "absent"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("withdraw of an unrecorded UID: %v, want ErrNotFound", err)
	}
	if err := u.Deliver(ctx, exportDelivery(d)); !errors.Is(err, ErrExists) {
		t.Fatalf("a second add of one UID: %v, want ErrExists", err)
	}
	if seq, _ := fl.floor("user/1001", deliveriesFloorName, guid(0xA1)); seq != 3 {
		t.Fatalf("floor sequence %d, want 3 (the mint, the add, the withdraw)", seq)
	}
	ops := ""
	for _, l := range audit.all() {
		ops += l.op + "=" + l.result + " "
		if l.scope != "user/1001" {
			t.Errorf("audit line %+v is not for user/1001", l)
		}
	}
	if ops != "put=ok deliver=ok withdraw=ok withdraw=ok withdraw=not-found deliver=exists " {
		t.Fatalf("audit lines %q", ops)
	}
	// A copied-back older record, which still lists the UID live, is
	// refused against the floor.
	if err := os.WriteFile(filepath.Join(scopeDir(server, "1001"), deliveriesName), older, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := u.Delivery(ctx, d.uid); !errors.Is(err, ErrCorrupt) || !strings.Contains(err.Error(), "matched set") {
		t.Fatalf("lookup over a copied-back record: %v, want ErrCorrupt with the user-scope floor message", err)
	}
	// Another scope's entry, or a requester that is not the caller, is
	// refused before anything is written.
	other := testDelivery(2)
	other.entry = "user/1002/token"
	if err := u.Deliver(ctx, exportDelivery(other)); !errors.Is(err, ErrNotFound) {
		t.Fatalf("add of another scope's entry: %v, want ErrNotFound", err)
	}
	other = testDelivery(3)
	other.requestedBy = "k3sm:local:1002"
	if err := u.Deliver(ctx, exportDelivery(other)); err == nil {
		t.Fatal("add with another uid as requester succeeded")
	}
}

// U14: the plaintext starts with the format version byte (1), the digest
// is sha256 under the k3sm-keystore-delivery-target/v1 label, and a record
// version this build does not know is refused, never read as empty.
func TestDeliveryRecordVersionByteAndDigestLabel(t *testing.T) {
	ctx := context.Background()
	s, server, u := newDeliveryScope(t)
	_, pt := openDeliveriesFile(t, s, server)
	if !bytes.Equal(pt, []byte{deliveriesFormat, 0, 0, 0, 0}) {
		t.Fatalf("the minted record's plaintext is %x, want the version byte and a zero count", pt)
	}
	d := testDelivery(1)
	if err := u.addDelivery(ctx, d); err != nil {
		t.Fatal(err)
	}
	_, pt = openDeliveriesFile(t, s, server)
	if pt[0] != 1 {
		t.Fatalf("plaintext version byte %d, want 1", pt[0])
	}
	lp := func(b []byte, v string) []byte {
		b = binary.BigEndian.AppendUint32(b, uint32(len(v)))
		return append(b, v...)
	}
	var items []byte
	items = lp(items, "expiresAt")
	items = lp(items, "expires_at")
	items = lp(items, "value")
	items = lp(items, "token")
	msg := []byte("k3sm-keystore-delivery-target/v1")
	msg = lp(msg, "user/1001/token")
	msg = lp(msg, "team-a")
	msg = lp(msg, "token-1")
	msg = lp(msg, string(items))
	if got := deliveryDigest(d.entry, d.namespace, d.secretName, d.items); got != sha256.Sum256(msg) {
		t.Fatalf("digest %x, want sha256(label ‖ LP(entry) ‖ LP(namespace) ‖ LP(secretName) ‖ LP(items))", got)
	}
	bumped := append([]byte{2}, pt[1:]...)
	if _, err := parseDeliveries(bumped); !errors.Is(err, errDeliveriesFormat) || !errors.Is(err, ErrCorrupt) {
		t.Fatalf("a record version 2: %v, want the unknown-version refusal", err)
	}
	// parseRecord, every other reader's, refuses kind 0xFD.
	b, err := os.ReadFile(filepath.Join(scopeDir(server, "1001"), deliveriesName))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := parseRecord(b); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("parseRecord on a 0xFD record: %v, want ErrCorrupt", err)
	}
}

// U14: the digest covers entry, namespace, secretName and the key-sorted
// items; a reorder of items leaves it unchanged, and requestedBy is not in
// it.
func TestDeliveryDigestCoversTargetAndItems(t *testing.T) {
	d := testDelivery(1)
	base := deliveryDigest(d.entry, d.namespace, d.secretName, d.items)
	reordered := []credential.Item{d.items[1], d.items[0]}
	if deliveryDigest(d.entry, d.namespace, d.secretName, reordered) != base {
		t.Fatal("a reorder of items changed the digest")
	}
	for name, got := range map[string][sha256.Size]byte{
		"entry":      deliveryDigest("user/1001/other", d.namespace, d.secretName, d.items),
		"namespace":  deliveryDigest(d.entry, "team-b", d.secretName, d.items),
		"secretName": deliveryDigest(d.entry, d.namespace, "token-2", d.items),
		"item field": deliveryDigest(d.entry, d.namespace, d.secretName, []credential.Item{{Field: credential.FieldValue, Key: "token"}, {Field: credential.FieldValue, Key: "expires_at"}}),
		"item key":   deliveryDigest(d.entry, d.namespace, d.secretName, []credential.Item{{Field: credential.FieldValue, Key: "tok"}, {Field: credential.FieldExpiresAt, Key: "expires_at"}}),
		"item count": deliveryDigest(d.entry, d.namespace, d.secretName, d.items[:1]),
		// Length-prefixing: moving a byte between neighbours changes it.
		"a shifted boundary": deliveryDigest(d.entry, d.namespace+"t", d.secretName[1:], d.items),
	} {
		if got == base {
			t.Errorf("a changed %s left the digest unchanged", name)
		}
	}
}

// A scope whose scope.key opens and whose deliveries record is missing is
// incomplete, ErrScopeAbsent, never an empty record; and the mint writes the
// record, and its floor line, before scope.key.
func TestScopeWithoutDeliveriesIsAbsent(t *testing.T) {
	ctx := context.Background()
	s, server := newMasteredStore(t)
	fakeGUIDs(t, map[uint32][generationSize]byte{1001: guid(0xA1)})
	u := userScope(t, s, 1001)
	var steps []string
	s.step = func(name string) error { steps = append(steps, name); return nil }
	userPut(t, u, "user/1001/token", "a value")
	s.step = func(string) error { return nil }
	var writes []string
	for _, st := range steps {
		if strings.HasPrefix(st, "write ") {
			writes = append(writes, st)
		}
	}
	if len(writes) < 2 || writes[0] != "write "+deliveriesName || writes[1] != "write "+scopeKeyName {
		t.Fatalf("mint steps %v, want the deliveries record written before scope.key, and both first", steps)
	}
	if err := os.Remove(filepath.Join(scopeDir(server, "1001"), deliveriesName)); err != nil {
		t.Fatal(err)
	}
	if _, err := u.lookupDelivery(ctx, "x"); !errors.Is(err, ErrScopeAbsent) || errors.Is(err, ErrNotFound) {
		t.Fatalf("lookup with no deliveries record: %v, want ErrScopeAbsent", err)
	}
	if _, err := u.List(ctx); !errors.Is(err, ErrScopeAbsent) {
		t.Fatalf("List with no deliveries record: %v, want ErrScopeAbsent", err)
	}
	if err := u.withdrawDelivery(ctx, "x"); !errors.Is(err, ErrScopeAbsent) {
		t.Fatalf("withdraw with no deliveries record: %v, want ErrScopeAbsent", err)
	}
	if err := u.addDelivery(ctx, testDelivery(1)); !errors.Is(err, ErrScopeAbsent) {
		t.Fatalf("add with no deliveries record: %v, want ErrScopeAbsent, never a re-mint", err)
	}
}

// U13: the 65th live delivery answers ErrQuota to deliver; withdraw still
// works at the bound, and frees a live place; at 320 entries in all,
// tombstones included, deliver is ErrQuota too.
func TestDeliveryRecordQuota(t *testing.T) {
	ctx := context.Background()
	_, _, u := newDeliveryScope(t)
	for i := 0; i < maxLiveDeliveries; i++ {
		if err := u.addDelivery(ctx, testDelivery(i)); err != nil {
			t.Fatalf("delivery %d: %v", i+1, err)
		}
	}
	if err := u.addDelivery(ctx, testDelivery(maxLiveDeliveries)); !errors.Is(err, ErrQuota) {
		t.Fatalf("the 65th live delivery: %v, want ErrQuota", err)
	}
	if err := u.withdrawDelivery(ctx, testDelivery(0).uid); err != nil {
		t.Fatalf("withdraw at the bound: %v", err)
	}
	if err := u.addDelivery(ctx, testDelivery(maxLiveDeliveries)); err != nil {
		t.Fatalf("deliver after a withdraw freed a place: %v", err)
	}
	// Fill to 320 in all: withdraw one, add one.
	n := maxLiveDeliveries + 1
	for w := 1; n < maxDeliveries; w, n = w+1, n+1 {
		if err := u.withdrawDelivery(ctx, testDelivery(w).uid); err != nil {
			t.Fatal(err)
		}
		if err := u.addDelivery(ctx, testDelivery(n)); err != nil {
			t.Fatalf("delivery %d of %d in all: %v", n+1, maxDeliveries, err)
		}
	}
	if err := u.withdrawDelivery(ctx, testDelivery(n-1).uid); err != nil {
		t.Fatalf("withdraw at 320 in all: %v", err)
	}
	if err := u.addDelivery(ctx, testDelivery(n)); !errors.Is(err, ErrQuota) {
		t.Fatalf("delivery %d in all: %v, want ErrQuota", n+1, err)
	}
}

// U13: the 257th entry and the byte budget answer ErrQuota to put; rm still
// works at either bound and makes room.
func TestUserScopeQuota(t *testing.T) {
	ctx := context.Background()
	t.Run("entries", func(t *testing.T) {
		_, _, u := newDeliveryScope(t)
		for i := 1; i < maxScopeEntries; i++ {
			userPut(t, u, fmt.Sprintf("user/1001/e%d", i), "v")
		}
		if _, err := u.Put(ctx, "user/1001/one-more", KindOpaque, []byte("v")); !errors.Is(err, ErrQuota) {
			t.Fatalf("the 257th entry: %v, want ErrQuota", err)
		}
		// An existing name at the bound is ErrExists, as it is below it:
		// the count bounds new names only.
		if _, err := u.Put(ctx, "user/1001/e1", KindOpaque, []byte("v")); !errors.Is(err, ErrExists) || errors.Is(err, ErrQuota) {
			t.Fatalf("put of an existing name at the bound: %v, want ErrExists", err)
		}
		if err := checkScopeQuotaAt(t, u, "e1"); err != nil {
			t.Fatalf("checkScopeQuota of an existing name at the bound: %v, want nil", err)
		}
		if err := u.Delete(ctx, "user/1001/e1"); err != nil {
			t.Fatalf("rm at the bound: %v", err)
		}
		userPut(t, u, "user/1001/one-more", "v")
	})
	t.Run("bytes", func(t *testing.T) {
		s, _ := newMasteredStore(t)
		fakeGUIDs(t, map[uint32][generationSize]byte{1001: guid(0xA1)})
		u := userScope(t, s, 1001)
		big := bytes.Repeat([]byte{7}, MaxValueSize)
		var err error
		i := 1
		for ; i <= maxScopeEntries; i++ {
			if _, err = u.Put(ctx, fmt.Sprintf("user/1001/b%d", i), KindOpaque, big); err != nil {
				break
			}
		}
		// 255 entries of 64 KiB hold about 16.75 MB of sealed records, so
		// the 256th passes 16 MiB before it reaches the entry bound.
		if !errors.Is(err, ErrQuota) || !strings.Contains(err.Error(), "sealed records would be") {
			t.Fatalf("put %d of 64 KiB values: %v, want ErrQuota from the byte budget", i, err)
		}
		if err := u.Delete(ctx, "user/1001/b1"); err != nil {
			t.Fatalf("rm at the byte budget: %v", err)
		}
		if _, err := u.Put(ctx, fmt.Sprintf("user/1001/b%d", i), KindOpaque, big); err != nil {
			t.Fatalf("put after rm made room: %v", err)
		}
		if err := u.Delete(ctx, "user/1001/absent"); !errors.Is(err, ErrNotFound) {
			t.Fatalf("rm of an absent entry: %v, want ErrNotFound", err)
		}
	})
}

// FuzzParseDeliveries holds the delivery record's plaintext parser to its
// contract on any bytes: it never panics, any refusal matches ErrCorrupt,
// and anything it accepts is within the bounds and re-encodes to its input.
func FuzzParseDeliveries(f *testing.F) {
	f.Add(marshalDeliveries(nil))
	one := testDelivery(1)
	one.items = []credential.Item{one.items[1], one.items[0]}
	one.digest = deliveryDigest(one.entry, one.namespace, one.secretName, one.items)
	f.Add(marshalDeliveries([]delivery{one}))
	two := testDelivery(2)
	two.withdrawn, two.delivered = true, 7
	two.items = two.items[:1]
	two.digest = deliveryDigest(two.entry, two.namespace, two.secretName, two.items)
	f.Add(marshalDeliveries([]delivery{one, two}))
	f.Add([]byte{})
	f.Add([]byte{2, 0, 0, 0, 0})
	f.Fuzz(func(t *testing.T, b []byte) {
		ds, err := parseDeliveries(b)
		if err != nil {
			if !errors.Is(err, ErrCorrupt) {
				t.Fatalf("parse error %v is not ErrCorrupt", err)
			}
			return
		}
		live := 0
		for _, d := range ds {
			if !d.withdrawn {
				live++
			}
			if len(d.items) == 0 || len(d.items) > maxDeliveryItems {
				t.Fatalf("accepted %d items", len(d.items))
			}
		}
		if len(ds) > maxDeliveries || live > maxLiveDeliveries {
			t.Fatalf("accepted %d entries, %d live", len(ds), live)
		}
		if !bytes.Equal(marshalDeliveries(ds), b) {
			t.Fatal("an accepted record does not re-encode to its input")
		}
	})
}

// FuzzParseDeliveriesRecord holds the sealed delivery record's parser to its
// contract: it never panics, refuses with ErrCorrupt, and accepts only a
// kind-0xFD record named deliveries that re-encodes to its input.
func FuzzParseDeliveriesRecord(f *testing.F) {
	r := record{kind: kindDeliveries, name: deliveriesName, version: 1, generation: guid(0xA1)}
	if err := r.seal(testKey, "user/501", marshalDeliveries(nil), rand.Reader); err != nil {
		f.Fatal(err)
	}
	f.Add(r.marshal())
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, b []byte) {
		got, err := parseDeliveriesRecord(b)
		if err != nil {
			if !errors.Is(err, ErrCorrupt) {
				t.Fatalf("parse error %v is not ErrCorrupt", err)
			}
			return
		}
		if got.kind != kindDeliveries || got.name != deliveriesName || got.version == 0 {
			t.Fatalf("accepted kind %#x name %q version %d", got.kind, got.name, got.version)
		}
		if !bytes.Equal(got.marshal(), b) {
			t.Fatal("an accepted record does not re-encode to its input")
		}
	})
}

// checkScopeQuotaAt runs checkScopeQuota for name in uid 1001's entries.
func checkScopeQuotaAt(t *testing.T, u *UserScope, name string) error {
	t.Helper()
	root, err := os.OpenRoot(filepath.Join(scopeDir(filepath.Dir(u.s.dir), "1001"), scopeEntriesName))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	return checkScopeQuota(root, name, []byte("v"), 0)
}

// scopeFileBytes sums the regular files under uid 1001's entries/.
func scopeFileBytes(t *testing.T, server string) int64 {
	t.Helper()
	var total int64
	err := filepath.WalkDir(filepath.Join(scopeDir(server, "1001"), scopeEntriesName), func(_ string, d fs.DirEntry, err error) error {
		if err != nil || !d.Type().IsRegular() {
			return err
		}
		fi, err := d.Info()
		total += fi.Size()
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return total
}

// U13: the byte budget counts the deliveries record and the new entry's
// generation file, not only its version record and pointer: a put that fits
// only without them is ErrQuota, and the refusal does not claim a withdraw
// frees room.
func TestUserScopeQuotaCountsDeliveriesAndGeneration(t *testing.T) {
	ctx := context.Background()
	_, server, u := newDeliveryScope(t)
	for n := 1; n <= 3; n++ {
		if err := u.addDelivery(ctx, testDelivery(n)); err != nil {
			t.Fatal(err)
		}
	}
	const name, value = "fits", "v"
	add := int64(headerSize+len(name)+len(value)+tagSize) + int64(headerSize+len(currentName)+pointerSize+tagSize)
	// Pad token's entry directory so the entries and the two records fill
	// the budget exactly.
	pad := filepath.Join(scopeDir(server, "1001"), scopeEntriesName, "token", "pad")
	if err := os.WriteFile(pad, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Truncate(pad, maxScopeBytes-add-scopeFileBytes(t, server)); err != nil {
		t.Fatal(err)
	}
	_, err := u.Put(ctx, "user/1001/"+name, KindOpaque, []byte(value))
	if !errors.Is(err, ErrQuota) || !strings.Contains(err.Error(), "sealed records would be") {
		t.Fatalf("put that fits only without the deliveries record and generation file: %v, want ErrQuota", err)
	}
	if strings.Contains(err.Error(), "withdraw a delivery to make room") {
		t.Fatalf("refusal %q claims a withdraw frees room", err)
	}
	if !strings.Contains(err.Error(), "once their Secret is gone") {
		t.Fatalf("refusal %q does not say when withdrawn deliveries are reclaimed", err)
	}
}

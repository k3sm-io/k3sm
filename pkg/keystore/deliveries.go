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
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"math"
	"os"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"

	"k3sm.io/apis/keystore/credential"
	keyentry "k3sm.io/apis/keystore/entry"
)

// This file is a user scope's sealed delivery record: docs/design/
// keystore.md § "User scope", "Key hierarchy", "Quotas" and "KeyDelivery".
// .user/<uid>/deliveries is a kind-0xFD record in the Phase A encoding, AAD
// scope user/<uid>, name "deliveries", generation the scope's bound
// GeneratedUID and version the record's sequence, sealed under
// HMAC(K_u, "k3sm-keystore-deliveries-v1" ‖ 0x00 ‖ "user/<uid>"). Every
// write re-seals the whole record at the previous sequence plus 1, then
// appends its floor line (user/<uid>, .deliveries, generation, seq); a read
// refuses a sequence below the floor's.
//
// The plaintext is
//
//	0  1  format version (deliveriesFormat)
//	1  4  entry count (big-endian uint32), at most maxDeliveries
//	5  …  the entries
//
// and each entry is LP(uid) ‖ LP(name) ‖ LP(entry) ‖ LP(namespace) ‖
// LP(secretName) ‖ LP(requestedBy) ‖ LP(items) ‖ digest (32) ‖ last
// delivered version (8, big-endian) ‖ state (1): seven 4-byte length
// prefixes, as "Quotas" counts them. items is the blob the digest covers:
// the items sorted by key bytewise, each LP(field) ‖ LP(key).

const (
	// kindDeliveries is the delivery record's kind byte; only
	// parseDeliveriesRecord accepts it.
	kindDeliveries = 0xFD
	// deliveriesName is the record's file in the scope directory, and also
	// its record name (the AAD name).
	deliveriesName = "deliveries"
	// deliveriesFloorName is the record's name in the user-scope floor: no
	// valid entry name (a leading dot is an empty label), so it never
	// collides with an entry named deliveries.
	deliveriesFloorName = ".deliveries"
	// deliveriesFormat is the plaintext's format version byte.
	deliveriesFormat = 1
	// deliveriesKeyLabel derives the delivery-record key from K_u.
	deliveriesKeyLabel = "k3sm-keystore-deliveries-v1"
	// deliveryDigestLabel is the target digest's domain label.
	deliveryDigestLabel = "k3sm-keystore-delivery-target/v1"

	// maxLiveDeliveries and maxDeliveries bound the record: 64 live entries,
	// 320 in all with the withdrawn tombstones.
	maxLiveDeliveries = 64
	maxDeliveries     = 320
	// maxDeliveriesRecordSize bounds the sealed record a read or a write
	// accepts (1,056 KiB), and maxDeliveriesPlaintext its plaintext (1,040
	// KiB and a 16-byte header).
	maxDeliveriesRecordSize = 1056 << 10
	maxDeliveriesPlaintext  = 1040<<10 + 16

	// The field bounds of one entry ("Quotas").
	maxDeliveryUIDLen   = 36
	maxObjectNameLen    = 253
	maxDeliveryEntryLen = 269
	maxNamespaceLen     = 63
	maxSecretNameLen    = 253
	maxRequestedByLen   = 21
	maxDeliveryItems    = 8
	maxItemKeyLen       = 253
	maxItemsBlobLen     = maxDeliveryItems * (8 + credential.MaxFieldLength + maxItemKeyLen)

	// The entry states.
	deliveryLive      = 1
	deliveryWithdrawn = 2

	// requestedByPrefix begins a user delivery's requester: k3sm:local:<uid>.
	requestedByPrefix = "k3sm:local:"
)

// delivery is one entry of the record: a KeyDelivery's UID and name, its
// target tuple, the target digest, the last delivered version and whether
// it is withdrawn.
type delivery struct {
	uid         string
	name        string
	entry       string
	namespace   string
	secretName  string
	items       []credential.Item
	requestedBy string
	digest      [sha256.Size]byte
	delivered   uint64
	withdrawn   bool
}

// itemsBlob is the items as the digest and the record carry them: sorted by
// key bytewise, each LP(field) ‖ LP(key).
func itemsBlob(items []credential.Item) []byte {
	sorted := append([]credential.Item(nil), items...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Key < sorted[j].Key })
	var b []byte
	for _, it := range sorted {
		b = appendLP(b, []byte(it.Field))
		b = appendLP(b, []byte(it.Key))
	}
	return b
}

// deliveryDigest is the target digest: sha256(label ‖ LP(entry) ‖
// LP(namespace) ‖ LP(secretName) ‖ LP(items)). requestedBy is not in it.
func deliveryDigest(entry, namespace, secretName string, items []credential.Item) [sha256.Size]byte {
	b := []byte(deliveryDigestLabel)
	b = appendLP(b, []byte(entry))
	b = appendLP(b, []byte(namespace))
	b = appendLP(b, []byte(secretName))
	b = appendLP(b, itemsBlob(items))
	return sha256.Sum256(b)
}

// appendLP appends v with its 4-byte big-endian length.
func appendLP(b, v []byte) []byte {
	b = binary.BigEndian.AppendUint32(b, uint32(len(v)))
	return append(b, v...)
}

// errDeliveriesFormat is a plaintext whose format version this build does
// not know: refused, and a reader treats it as indeterminate, never as an
// empty record.
var errDeliveriesFormat = fmt.Errorf("%w: the deliveries record has a format version this build of k3sm does not know", ErrCorrupt)

// marshalDeliveries encodes ds as the record's plaintext.
func marshalDeliveries(ds []delivery) []byte {
	b := []byte{deliveriesFormat}
	b = binary.BigEndian.AppendUint32(b, uint32(len(ds)))
	for _, d := range ds {
		for _, f := range []string{d.uid, d.name, d.entry, d.namespace, d.secretName, d.requestedBy} {
			b = appendLP(b, []byte(f))
		}
		b = appendLP(b, itemsBlob(d.items))
		b = append(b, d.digest[:]...)
		b = binary.BigEndian.AppendUint64(b, d.delivered)
		state := byte(deliveryLive)
		if d.withdrawn {
			state = deliveryWithdrawn
		}
		b = append(b, state)
	}
	return b
}

// lpReader reads length-prefixed fields off a bounded plaintext.
type lpReader struct {
	b   []byte
	err error
}

// field reads one LP field of 1 to max bytes.
func (r *lpReader) field(what string, max int) []byte {
	if r.err != nil {
		return nil
	}
	if len(r.b) < 4 {
		r.err = fmt.Errorf("%w: the deliveries record ends inside %s's length", ErrCorrupt, what)
		return nil
	}
	n := binary.BigEndian.Uint32(r.b)
	if n == 0 || n > uint32(max) || uint64(n) > uint64(len(r.b)-4) {
		r.err = fmt.Errorf("%w: the deliveries record's %s is %d bytes, want 1 to %d within the record", ErrCorrupt, what, n, max)
		return nil
	}
	v := r.b[4 : 4+n]
	r.b = r.b[4+n:]
	return v
}

// fixed reads n bytes.
func (r *lpReader) fixed(what string, n int) []byte {
	if r.err != nil {
		return nil
	}
	if len(r.b) < n {
		r.err = fmt.Errorf("%w: the deliveries record ends inside %s", ErrCorrupt, what)
		return nil
	}
	v := r.b[:n]
	r.b = r.b[n:]
	return v
}

// parseDeliveries decodes the record's plaintext. It is bounded and strict:
// the format version must be deliveriesFormat (else errDeliveriesFormat),
// the count at most maxDeliveries with at most maxLiveDeliveries live, every
// field within its bound, every entry a valid user entry, the items 1 to 8
// with unique keys in their sorted order, each stored digest the digest of
// its tuple, no UID twice, a known state byte, and no trailing bytes. Any
// other refusal is ErrCorrupt.
func parseDeliveries(pt []byte) ([]delivery, error) {
	if len(pt) > maxDeliveriesPlaintext {
		return nil, fmt.Errorf("%w: the deliveries record is %d bytes, over %d", ErrCorrupt, len(pt), maxDeliveriesPlaintext)
	}
	if len(pt) < 5 {
		return nil, fmt.Errorf("%w: the deliveries record is %d bytes, shorter than its header", ErrCorrupt, len(pt))
	}
	if pt[0] != deliveriesFormat {
		return nil, fmt.Errorf("%w (version %d, want %d)", errDeliveriesFormat, pt[0], deliveriesFormat)
	}
	n := binary.BigEndian.Uint32(pt[1:5])
	if n > maxDeliveries {
		return nil, fmt.Errorf("%w: the deliveries record holds %d entries, over %d", ErrCorrupt, n, maxDeliveries)
	}
	r := &lpReader{b: pt[5:]}
	out := make([]delivery, 0, n)
	seen := map[string]bool{}
	live := 0
	for i := uint32(0); i < n; i++ {
		var d delivery
		d.uid = string(r.field("uid", maxDeliveryUIDLen))
		d.name = string(r.field("name", maxObjectNameLen))
		d.entry = string(r.field("entry", maxDeliveryEntryLen))
		d.namespace = string(r.field("namespace", maxNamespaceLen))
		d.secretName = string(r.field("secretName", maxSecretNameLen))
		d.requestedBy = string(r.field("requestedBy", maxRequestedByLen))
		blob := r.field("items", maxItemsBlobLen)
		digest := r.fixed("digest", sha256.Size)
		ver := r.fixed("delivered version", 8)
		state := r.fixed("state", 1)
		if r.err != nil {
			return nil, r.err
		}
		var err error
		if d.items, err = parseItemsBlob(blob); err != nil {
			return nil, err
		}
		if err := checkDeliveryFields(d); err != nil {
			return nil, fmt.Errorf("%w: a deliveries record entry: %w", ErrCorrupt, err)
		}
		copy(d.digest[:], digest)
		if d.digest != deliveryDigest(d.entry, d.namespace, d.secretName, d.items) {
			return nil, fmt.Errorf("%w: a deliveries record entry's digest is not its target's", ErrCorrupt)
		}
		d.delivered = binary.BigEndian.Uint64(ver)
		switch state[0] {
		case deliveryLive:
			live++
		case deliveryWithdrawn:
			d.withdrawn = true
		default:
			return nil, fmt.Errorf("%w: a deliveries record entry has state %d", ErrCorrupt, state[0])
		}
		if seen[d.uid] {
			return nil, fmt.Errorf("%w: the deliveries record names one UID twice", ErrCorrupt)
		}
		seen[d.uid] = true
		out = append(out, d)
	}
	if len(r.b) != 0 {
		return nil, fmt.Errorf("%w: %d bytes follow the deliveries record's last entry", ErrCorrupt, len(r.b))
	}
	if live > maxLiveDeliveries {
		return nil, fmt.Errorf("%w: the deliveries record holds %d live entries, over %d", ErrCorrupt, live, maxLiveDeliveries)
	}
	return out, nil
}

// parseItemsBlob decodes an items blob: 1 to 8 items, each a field of 1 to
// 32 bytes and a key of 1 to 253, keys strictly increasing bytewise (so
// unique, and in the order itemsBlob writes).
func parseItemsBlob(blob []byte) ([]credential.Item, error) {
	r := &lpReader{b: blob}
	var items []credential.Item
	for len(r.b) > 0 {
		if len(items) == maxDeliveryItems {
			return nil, fmt.Errorf("%w: a deliveries record entry has more than %d items", ErrCorrupt, maxDeliveryItems)
		}
		f := r.field("item field", credential.MaxFieldLength)
		k := r.field("item key", maxItemKeyLen)
		if r.err != nil {
			return nil, r.err
		}
		if n := len(items); n > 0 && items[n-1].Key >= string(k) {
			return nil, fmt.Errorf("%w: a deliveries record entry's item keys are not unique and sorted", ErrCorrupt)
		}
		items = append(items, credential.Item{Field: credential.Field(f), Key: string(k)})
	}
	if len(items) == 0 {
		return nil, fmt.Errorf("%w: a deliveries record entry has no items", ErrCorrupt)
	}
	return items, nil
}

// parseDeliveriesRecord decodes a deliveries file: a record of kind 0xFD
// named "deliveries", within the record bound. Anything else is ErrCorrupt.
// parseRecord, which every other reader uses, still refuses kind 0xFD.
func parseDeliveriesRecord(b []byte) (record, error) {
	if len(b) > maxDeliveriesRecordSize {
		return record{}, fmt.Errorf("%w: %s is %d bytes, over %d", ErrCorrupt, deliveriesName, len(b), maxDeliveriesRecordSize)
	}
	r, err := parseRecordOf(b, func(kind byte) bool { return kind == kindDeliveries })
	if err != nil {
		return record{}, fmt.Errorf("%s: %w", deliveriesName, err)
	}
	if r.name != deliveriesName || r.version == 0 {
		return record{}, fmt.Errorf("%w: %s does not hold this scope's delivery record", ErrCorrupt, deliveriesName)
	}
	return r, nil
}

// checkDelivery validates a delivery the caller adds: the entry in the
// caller's own scope (else notFound, as any other scope's name), then every
// field's grammar (checkDeliveryFields), which ties requestedBy to the
// caller's own principal. No error carries a field's value.
func (u *UserScope) checkDelivery(op string, d delivery) error {
	if _, err := u.own(op, d.entry); err != nil {
		return err
	}
	if err := checkDeliveryFields(d); err != nil {
		return fmt.Errorf("user scope %s: %w", op, err)
	}
	if _, err := parseItemsBlob(itemsBlob(d.items)); err != nil {
		return fmt.Errorf("user scope %s: the delivery's items: %w", op, err)
	}
	return nil
}

// errDeliveryField is a delivery field outside its grammar, at add and at
// parse alike.
var errDeliveryField = errors.New("a delivery field is outside its grammar")

// requestedByRE is the KeyDelivery's spec.requestedBy grammar.
var requestedByRE = regexp.MustCompile(keyentry.RequestedByPattern)

// checkDeliveryFields checks each field of d against the grammar its
// KeyDelivery field has, so an add and a parse refuse the same records:
// uid UUID-shaped; name a DNS-1123 subdomain (the entry name grammar);
// entry a user entry; namespace a DNS-1123 label of at most 63 bytes;
// secretName a DNS-1123 subdomain of at most 253; requestedBy matching
// RequestedByPattern and equal to k3sm:local:<the entry's uid>; each item's
// field in the credential Fields table and its key a ConfigMap key. The
// error names the field, never its value.
func checkDeliveryFields(d delivery) error {
	bad := func(what string) error { return fmt.Errorf("%w: %s", errDeliveryField, what) }
	if !uuidShaped(d.uid) {
		return bad("uid (want a lowercase UUID)")
	}
	if checkName(d.name) != nil {
		return bad("name (want a DNS-1123 subdomain)")
	}
	e, err := ParseEntry(d.entry)
	if err != nil || e.Scope != keyentry.ScopeUser {
		return bad("entry (want a user entry)")
	}
	if len(d.namespace) > maxNamespaceLen || !dnsLabel(d.namespace) {
		return bad("namespace (want a DNS-1123 label of at most 63 characters)")
	}
	if len(d.secretName) > maxSecretNameLen || checkName(d.secretName) != nil {
		return bad("secretName (want a DNS-1123 subdomain of at most 253 characters)")
	}
	if !requestedByRE.MatchString(d.requestedBy) || d.requestedBy != requestedByPrefix+strconv.FormatUint(uint64(e.UID), 10) {
		return bad("requestedBy (want k3sm:local:<the entry's uid>)")
	}
	for _, it := range d.items {
		if !slices.Contains(credential.Fields(), it.Field) {
			return bad("item field (want a credential field)")
		}
		if !configMapKey(it.Key) {
			return bad("item key (want a Secret data key)")
		}
	}
	return nil
}

// uuidShaped reports whether s is 8-4-4-4-12 lowercase hex digits.
func uuidShaped(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch i {
		case 8, 13, 18, 23:
			if c != '-' {
				return false
			}
		default:
			if !('0' <= c && c <= '9' || 'a' <= c && c <= 'f') {
				return false
			}
		}
	}
	return true
}

// configMapKey is the Kubernetes ConfigMap and Secret data-key rule, the
// one pkg/keystore/deliver applies through apimachinery (this package
// imports no Kubernetes package): 1 to 253 bytes of letters, digits, '-',
// '_' and '.', not "." or "..", and not beginning "..".
func configMapKey(k string) bool {
	if k == "" || len(k) > maxItemKeyLen || k == "." || strings.HasPrefix(k, "..") {
		return false
	}
	for i := 0; i < len(k); i++ {
		c := k[i]
		if !('a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || '0' <= c && c <= '9' || c == '-' || c == '_' || c == '.') {
			return false
		}
	}
	return true
}

// openedScope is an opened user scope: the scope directory, its derived
// keys, the delivery-record key and the bound generation.
type openedScope struct {
	dir *os.Root
	uk  keys
	key []byte
	gen [generationSize]byte
}

// close clears the delivery-record key and closes the scope directory; the
// derived keys stay with whoever copied them.
func (o *openedScope) close() {
	clear(o.key)
	_ = o.dir.Close() // writes are fsynced by writeFile
}

// readDeliveries reads, checks and opens the scope's delivery record, and
// returns its entries and sequence. A missing record is ErrScopeAbsent,
// never an empty record. The record must be the service user's, at most
// 0600, of kind 0xFD named deliveries, at the scope's bound generation, and
// at or above the floor's sequence for that generation.
func (u *UserScope) readDeliveries(o *openedScope) ([]delivery, uint64, error) {
	r, err := u.readDeliveriesFloor(o, false)
	return r.ds, r.seq, err
}

// deliveriesRead is what readDeliveriesFloor read: the record's entries and
// sequence, and the floor's sequence for it, or, for a revocation that went
// ahead without the floor, why the floor could not be checked.
type deliveriesRead struct {
	ds         []delivery
	seq, floor uint64
	// unverified is the floor's error when the record was not checked
	// against it; nil when it was.
	unverified error
}

// readDeliveriesFloor is readDeliveries. With revoke set, a floor that
// is absent or cannot be read skips the floor check rather than refuse,
// but a floor whose bytes do not parse (matching ErrCorrupt) refuses: it is
// damage, which root repairs with floor --rebuild. It always checks the
// record against the larger of the floor and the highest sequence this
// process has read or written, and without the floor against that mark
// alone, reporting the floor's error as unverified: a withdraw then
// seals nothing (errWithdrawUnsealed; docs/design/keystore.md § "Quotas",
// "Revocation always succeeds"). A record below a floor that can be read is
// refused, revoke or not.
func (u *UserScope) readDeliveriesFloor(o *openedScope, revoke bool) (deliveriesRead, error) {
	b, fi, err := readFile(o.dir, deliveriesName, maxDeliveriesRecordSize)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return deliveriesRead{}, fmt.Errorf("%w: the scope has a scope key and no %s record", ErrScopeAbsent, deliveriesName)
	case errors.Is(err, errBadFile):
		return deliveriesRead{}, fmt.Errorf("%w: %s: %w", ErrCorrupt, deliveriesName, err)
	case err != nil:
		return deliveriesRead{}, fmt.Errorf("read %s: %w", deliveriesName, err)
	}
	if err := u.s.checkOwned(fi, fileMode); err != nil {
		return deliveriesRead{}, fmt.Errorf("%w: %s: %w", ErrCorrupt, deliveriesName, err)
	}
	r, err := parseDeliveriesRecord(b)
	if err != nil {
		return deliveriesRead{}, err
	}
	if r.generation != o.gen {
		return deliveriesRead{}, fmt.Errorf("%w: %s is not bound to this scope's owner", ErrCorrupt, deliveriesName)
	}
	fl, flErr := u.s.userFloor.floor(u.scope, deliveriesFloorName, o.gen)
	if flErr != nil && (!revoke || errors.Is(flErr, ErrCorrupt)) {
		return deliveriesRead{}, flErr
	}
	// A floor whose damage could name the record (errFloorDegraded) still
	// reports the highest sequence its whole lines hold: a withdraw checks
	// the record against it, so a copy put back below what the floor still
	// knows is refused under the taint too.
	degraded := errors.Is(flErr, errFloorDegraded)
	// The record is checked against the larger of the floor and the
	// sequence this process last read or wrote, always: a withdraw whose
	// floor line failed leaves the floor one behind the record, and a copy
	// put back at the floor must still not be re-sealed at a later sequence
	// with a tombstone lost. With no floor to read the mark stands alone.
	seen := deliveriesSeen.high(u.s.dir, u.scope, o.gen)
	if (flErr == nil || degraded) && r.version < fl {
		return deliveriesRead{}, fmt.Errorf("%w: the %s record (sequence %d) is older than the user-scope floor (sequence %d); an older copy was put back. For a deliberate restore, "+restoreRemedy, ErrCorrupt, deliveriesName, r.version, fl)
	}
	if r.version < seen {
		why := "the user-scope floor is behind it"
		if flErr != nil {
			why = fmt.Sprintf("the user-scope floor cannot be read (%v)", flErr)
		}
		return deliveriesRead{}, fmt.Errorf("%w: the %s record (sequence %d) is older than one this process has already read or written (sequence %d), and %s; an older copy was put back. For a deliberate restore, "+restoreRemedy, ErrCorrupt, deliveriesName, r.version, seen, why)
	}
	pt, err := r.open(o.key, u.scope)
	if err != nil {
		return deliveriesRead{}, fmt.Errorf("%s: %w", deliveriesName, err)
	}
	ds, err := parseDeliveries(pt)
	if err != nil {
		return deliveriesRead{}, err
	}
	for _, d := range ds {
		if e, _ := ParseEntry(d.entry); e.UID != u.uid {
			return deliveriesRead{}, fmt.Errorf("%w: %s names another scope's entry", ErrCorrupt, deliveriesName)
		}
	}
	deliveriesSeen.note(u.s.dir, u.scope, o.gen, r.version)
	return deliveriesRead{ds: ds, seq: r.version, floor: fl, unverified: flErr}, nil
}

// deliverySeqs is the highest delivery-record sequence the process has read
// or written, per scope and generation, in memory. A withdraw that cannot
// read the floor refuses a record below it: the process's own high-water
// mark is the floor it can still trust. It is keyed by the keystore
// directory too, so every FileStore on one keystore shares a mark, and two
// keystores do not.
type deliverySeqs struct {
	mu sync.Mutex
	m  map[string]uint64
}

// deliveriesSeen is the process-wide mark, shared by every FileStore in the
// process (docs/design/keystore.md § "Quotas").
var deliveriesSeen deliverySeqs

func deliverySeqKey(dir, scope string, gen [generationSize]byte) string {
	return dir + "\x00" + scope + "\x00" + string(gen[:])
}

// note raises the mark for dir, scope and gen to seq.
func (d *deliverySeqs) note(dir, scope string, gen [generationSize]byte, seq uint64) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.m == nil {
		d.m = map[string]uint64{}
	}
	if k := deliverySeqKey(dir, scope, gen); seq > d.m[k] {
		d.m[k] = seq
	}
}

// high returns the mark for dir, scope and gen, 0 when none.
func (d *deliverySeqs) high(dir, scope string, gen [generationSize]byte) uint64 {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.m[deliverySeqKey(dir, scope, gen)]
}

// writeDeliveries seals ds at seq and writes the record, then its floor
// line: a crash between the two leaves the floor one behind, which a read
// accepts.
func (u *UserScope) writeDeliveries(dir *os.Root, key []byte, gen [generationSize]byte, ds []delivery, seq uint64, revoke bool) error {
	pt := marshalDeliveries(ds)
	if len(pt) > maxDeliveriesPlaintext {
		return fmt.Errorf("the deliveries record would be %d bytes, over %d", len(pt), maxDeliveriesPlaintext)
	}
	rec := record{kind: kindDeliveries, name: deliveriesName, version: seq, generation: gen, created: u.s.now().Unix()}
	if err := rec.seal(key, u.scope, pt, u.s.rand); err != nil {
		return err
	}
	b := rec.marshal()
	if len(b) > maxDeliveriesRecordSize {
		return fmt.Errorf("the deliveries record would be %d bytes, over %d", len(b), maxDeliveriesRecordSize)
	}
	if err := u.s.writeFile(dir, deliveriesName, b); err != nil {
		return err
	}
	deliveriesSeen.note(u.s.dir, u.scope, gen, seq)
	if err := u.s.userFloor.append(u.scope, deliveriesFloorName, gen, seq, revoke); err != nil {
		return fmt.Errorf("%w, and its floor line was not written: %w", errCommitted, err)
	}
	return nil
}

// errDeliveriesLastSeq refuses a change to a delivery record already at the
// last sequence, before anything is written: the next would wrap to 0, as
// Rotate refuses a pointer at the last sequence.
var errDeliveriesLastSeq = fmt.Errorf("%w: the %s record is at the last sequence, so no change to it can be sealed", ErrCorrupt, deliveriesName)

// errWithdrawUnsealed refuses a withdrawal of a live delivery while the
// user-scope floor cannot be verified (absent, untrusted, unflagged or
// unreadable): the record on disk may be an older copy put back, and
// re-sealing it at a fresh sequence would make that copy authentic. Nothing
// was sealed, so the delivery stays live in the record; the reconciler
// deletes the delivered Secret anyway, as for any withdrawal that errors.
var errWithdrawUnsealed = errors.New("the user-scope floor cannot be verified, so the withdrawal was not sealed into the delivery record, which may be an older copy put back; delete the delivered Secret anyway; root must " + restoreRemedy + ", then withdraw again")

// errCommitted marks an error after a change was committed: the change
// stands, and what follows it (a floor line, an audit line) was not
// written.
var errCommitted = errors.New("the change was made")

// Committed reports whether err followed a change that was committed and
// stands, such as a Delete whose entry was deleted though its floor write
// evicted tombstones (ErrTombstoneEvicted).
func Committed(err error) bool { return errors.Is(err, errCommitted) }

// deliveriesKey derives the delivery-record key from K_u.
func deliveriesKey(ku []byte, scope string) []byte {
	return hmacSHA256(ku, scopedLabel(deliveriesKeyLabel, scope))
}

// Delivery is one KeyDelivery as a user scope records it: its UID and
// name, its target tuple (Entry, Namespace, SecretName, Items) and its
// requester; and, as recorded, the target digest, the last delivered
// version and whether it is withdrawn. Deliver ignores Digest, Delivered
// and Withdrawn: it computes the digest and records the delivery live and
// never delivered.
type Delivery struct {
	UID         string
	Name        string
	Entry       string
	Namespace   string
	SecretName  string
	Items       []credential.Item
	RequestedBy string
	Digest      [sha256.Size]byte
	Delivered   uint64
	Withdrawn   bool
}

// exportDelivery is d as a Delivery.
func exportDelivery(d delivery) Delivery {
	return Delivery{
		UID: d.uid, Name: d.name, Entry: d.entry, Namespace: d.namespace,
		SecretName: d.secretName, Items: d.items, RequestedBy: d.requestedBy,
		Digest: d.digest, Delivered: d.delivered, Withdrawn: d.withdrawn,
	}
}

// internal is d as the record's entry.
func (d Delivery) internal() delivery {
	return delivery{
		uid: d.UID, name: d.Name, entry: d.Entry, namespace: d.Namespace,
		secretName: d.SecretName, items: d.Items, requestedBy: d.RequestedBy,
		digest: d.Digest, delivered: d.Delivered, withdrawn: d.Withdrawn,
	}
}

// Deliver records d, live, in the caller's delivery record, minting the
// scope on its first mutating operation (addDelivery). A UID already
// recorded is ErrExists; a record with 64 live entries, or 320 in all, is
// ErrQuota. Its audit line is appended before anything is written: a
// failed append refuses it, and nothing is written.
func (u *UserScope) Deliver(ctx context.Context, d Delivery) error {
	return u.addDelivery(ctx, d.internal())
}

// Delivery returns the recorded delivery with uid, live or withdrawn
// (lookupDelivery). A UID absent from a record that opened is ErrNotFound;
// a scope or record that is not there is ErrScopeAbsent. It never mints.
func (u *UserScope) Delivery(ctx context.Context, uid string) (Delivery, error) {
	d, err := u.lookupDelivery(ctx, uid)
	if err != nil {
		return Delivery{}, err
	}
	return exportDelivery(d), nil
}

// Withdraw turns the live delivery uid into a tombstone in place
// (withdrawDelivery). It is never refused for a quota and runs while a
// Rewrap is half done. An already withdrawn UID is no change; an absent one
// is ErrNotFound. It commits first and audits after: a failed append is
// reported and the tombstone stands.
func (u *UserScope) Withdraw(ctx context.Context, uid string) error {
	return u.withdrawDelivery(ctx, uid)
}

// addDelivery records d, live, in the caller's delivery record, minting the
// scope on its first mutating operation. A UID already recorded is
// ErrExists; a record with 64 live entries, or 320 in all, is ErrQuota. It
// is a grant, so its audit line is appended before anything is written: a
// failed append refuses it, and nothing is written (the mint included).
func (u *UserScope) addDelivery(ctx context.Context, d delivery) error {
	if err := u.checkDelivery("deliver", d); err != nil {
		// A refused add audits the placeholder: its fields are not known
		// to be in their grammar.
		u.auditBriefly(ctx, auditLine{op: "deliver", name: auditPlaceholder, namespace: auditPlaceholder}, err)
		return fail("deliver", err)
	}
	e, _ := ParseEntry(d.entry) // checked by checkDelivery
	g := u.grant("deliver", e.Name, d.namespace)
	if err := u.quarantineErr(); err != nil {
		g.refusedBriefly(ctx, err)
		return fail("deliver", err)
	}
	if err := u.addDeliveryLocked(ctx, d, g); err != nil {
		return fail("deliver", err)
	}
	return nil
}

func (u *UserScope) addDeliveryLocked(ctx context.Context, d delivery, g *grantAudit) error {
	if err := u.s.checkConfig(); err != nil {
		return err
	}
	grant := g.take
	return u.grantLocked(ctx, g, func(o *openedScope) error {
		rd, err := u.readDeliveriesFloor(o, false)
		if err != nil {
			return err
		}
		u.catchUpDeliveries(o.gen, rd)
		ds, seq := rd.ds, rd.seq
		live := 0
		for _, x := range ds {
			if x.uid == d.uid {
				return fmt.Errorf("%w: the delivery UID is already recorded", ErrExists)
			}
			if !x.withdrawn {
				live++
			}
		}
		if live >= maxLiveDeliveries || len(ds) >= maxDeliveries {
			return fmt.Errorf("%w: the scope has %d live deliveries and %d in all (at most %d and %d)", ErrQuota, live, len(ds), maxLiveDeliveries, maxDeliveries)
		}
		d.items = append([]credential.Item(nil), d.items...)
		sort.Slice(d.items, func(i, j int) bool { return d.items[i].Key < d.items[j].Key })
		d.digest = deliveryDigest(d.entry, d.namespace, d.secretName, d.items)
		d.withdrawn, d.delivered = false, 0
		if seq == math.MaxUint64 {
			return errDeliveriesLastSeq
		}
		// Refuse, before the grant's first write, a deliver whose floor line
		// would be refused after its commit, as put does.
		if err := u.s.floorDeliverRoom(u.scope, o.gen); err != nil {
			return err
		}
		if err := grant(); err != nil {
			return err
		}
		return u.writeDeliveries(o.dir, o.key, o.gen, append(ds, d), seq+1, false)
	})
}

// lookupDelivery returns the recorded delivery with uid, live or withdrawn.
// A UID absent from a record that opened is ErrNotFound; a scope or record
// that is not there is ErrScopeAbsent. A read never mints.
func (u *UserScope) lookupDelivery(ctx context.Context, uid string) (delivery, error) {
	if err := u.quarantineErr(); err != nil {
		return delivery{}, fail("look up a delivery", err)
	}
	var out delivery
	err := u.readScope(ctx, func(_ *os.Root, o *openedScope) error {
		ds, _, err := u.readDeliveries(o)
		if err != nil {
			return err
		}
		for _, d := range ds {
			if d.uid == uid {
				out = d
				return nil
			}
		}
		return ErrNotFound
	})
	if err != nil {
		return delivery{}, fail("look up a delivery", err)
	}
	return out, nil
}

// withdrawDelivery turns the live delivery uid into a tombstone in place. It
// never adds an entry, so it is never refused for a quota, and it runs while
// a Rewrap is half done. It is refused for a record put back below the
// floor, or, with the floor unreadable, below the highest sequence this store
// has read or written, and with the floor unverifiable it seals nothing
// (errWithdrawUnsealed) (docs/design/keystore.md § "Quotas", the residuals of
// "Revocation always succeeds"). An already withdrawn UID is no change; an absent one is ErrNotFound. As a revocation it
// commits first and audits after: a failed append is reported (errCommitted)
// and the tombstone stands.
//
// Its audit line names the delivery UID (auditPlaceholder for one outside
// the grammar) and the namespace the record holds for it, when found.
func (u *UserScope) withdrawDelivery(ctx context.Context, uid string) error {
	if err := u.withdrawLocked(ctx, uid); err != nil {
		return fail("withdraw", err)
	}
	return nil
}

// withdrawLocked needs no owner's live GeneratedUID and runs with
// master.next present (openScopeForRevoke); over a floor it cannot verify it
// seals nothing (errWithdrawUnsealed). An
// already withdrawn UID re-appends the record's floor line when the floor
// is below the record's sequence, in case the withdraw that wrote the
// tombstone could not, and appends nothing when the floor already holds it. It commits, then appends its audit
// line, which names the namespace of the delivery it found, before it
// releases the store lock (auditSink).
func (u *UserScope) withdrawLocked(ctx context.Context, uid string) (err error) {
	if err := u.s.checkConfig(); err != nil {
		return err
	}
	root, done, err := u.s.openLocked(ctx, false, true)
	if errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("%w: the keystore directory is missing", ErrScopeAbsent)
	}
	if err != nil {
		return err
	}
	defer done()
	id := auditPlaceholder
	if uuidShaped(uid) {
		id = uid
	}
	var (
		ns      string
		revoked bool
		sealed  []delivery
	)
	defer func() { // before done: the line is appended under the lock
		// A revocation is a withdraw that wrote its tombstone or a catch-up
		// line, whether or not its floor line then failed (errCommitted); a
		// no-op repeat that wrote neither is not, as for rm.
		revoke := revoked && (err == nil || errors.Is(err, errCommitted))
		l := auditLine{op: "withdraw", namespace: ns, delivery: id, revoke: revoke}
		aerr := u.appendAudit(l, err)
		if revoke && len(sealed) > 0 {
			aerr = errors.Join(aerr, u.auditSealed(sealed, err))
		}
		err = u.keepAuditFailure("withdraw", err, aerr)
	}()
	ns, revoked, sealed, err = u.withdrawBody(root, uid)
	return err
}

// auditSealed appends the audit line of each delivery a mass seal under a
// delivery-record taint withdrew besides the one named, in the revocation
// class: it attempts every line, keeps going past a failure, and reports
// how many it wrote alongside every failure (errCommitted).
func (u *UserScope) auditSealed(sealed []delivery, err error) error {
	var errs []error
	for _, d := range sealed {
		if aerr := u.appendAudit(auditLine{op: "withdraw", namespace: d.namespace, delivery: d.uid, revoke: true}, err); aerr != nil {
			errs = append(errs, aerr)
		}
	}
	if len(errs) == 0 {
		return nil
	}
	return fmt.Errorf("the audit lines of the deliveries the withdraw sealed: %d of %d written: %w", len(sealed)-len(errs), len(sealed), errors.Join(errs...))
}

// withdrawBody is withdrawLocked's work under the lock. It returns the
// recorded namespace of the delivery it found, for the audit line, whether
// it went on to revoke: seal the tombstone or append a catch-up line, and
// the other deliveries a seal under a delivery-record taint withdrew, each
// of which is audited too.
func (u *UserScope) withdrawBody(root *os.Root, uid string) (string, bool, []delivery, error) {
	k, err := u.s.loadMaster()
	if err != nil {
		return "", false, nil, err
	}
	o, err := u.openScopeForRevoke(root, k)
	if err != nil {
		return "", false, nil, err
	}
	defer o.close()
	u.catchUpLostEntries(o)
	rd, err := u.readDeliveriesFloor(o, true)
	if err != nil {
		return "", false, nil, err
	}
	ds, seq := rd.ds, rd.seq
	for i := range ds {
		if ds[i].uid != uid {
			continue
		}
		ns := ds[i].namespace
		var sealed []delivery
		if !ds[i].withdrawn && rd.unverified != nil && !errors.Is(rd.unverified, errFloorDegraded) {
			// The record was not checked against the floor, so it may be an
			// older copy put back; sealing it at a fresh sequence would make
			// that copy authentic. Nothing is sealed. A floor that read but
			// holds damage naming the record (errFloorDegraded) did check it
			// against every line it has (readDeliveriesFloor): the withdraw
			// only removes, so it seals and writes its floor line.
			return ns, false, nil, fmt.Errorf("%w: %w", errWithdrawUnsealed, rd.unverified)
		}
		// Only a withdraw that revokes is in the revocation class, and a
		// repeat that catches the floor up to the record, which finishes the
		// revocation whose floor line failed; any other repeat changes
		// nothing and is refused past the hard cap like any other operation.
		catchUp := ds[i].withdrawn && rd.unverified == nil && rd.floor < seq
		if err := u.s.admit(u.uid, !ds[i].withdrawn || catchUp); err != nil {
			return ns, false, nil, err
		}
		if ds[i].withdrawn {
			if !catchUp {
				// The floor already holds the record's sequence, or cannot
				// be read to take it: nothing changed, and nothing is
				// appended.
				return ns, false, nil, nil
			}
			// The same catch-up as catchUpDeliveryLine's, liveRefused
			// included: a live line the floor's damage refuses is not
			// written, and the withdrawn record changes nothing.
			if err := u.catchUpDeliveryLine(o.gen, rd); errors.Is(err, errFloorDegraded) {
				return ns, false, nil, nil
			} else if err != nil {
				return ns, true, nil, err
			}
			return ns, true, nil, nil
		}
		if errors.Is(rd.unverified, errFloorDegraded) {
			// The floor's damage could name the record, so a line above
			// what its whole lines hold may be lost, and this copy may be
			// older than it: any delivery live here could have been
			// withdrawn by it. Resealing one live would undo that withdraw,
			// so every delivery is sealed withdrawn (a withdraw keeps none
			// live), above both the record's and the floor's sequence.
			seq = max(seq, rd.floor)
			for j := range ds {
				if j != i && !ds[j].withdrawn {
					sealed = append(sealed, ds[j])
				}
				ds[j].withdrawn = true
			}
			// Every delivery it seals is audited, each on its own line
			// after the withdraw's own: the audit log must hold all of
			// them, whole appends, before anything is sealed.
			if err := u.s.auditRevokeRoom(u.uid, int64(1+len(sealed))*maxAppendLine); err != nil {
				return ns, false, nil, err
			}
		}
		if seq == math.MaxUint64 {
			return ns, false, nil, errDeliveriesLastSeq
		}
		ds[i].withdrawn = true
		return ns, true, sealed, u.writeDeliveries(o.dir, o.key, o.gen, ds, seq+1, true)
	}
	// The catch-up line is a revocation's: admitted as one before it is
	// appended. Without one the unknown UID is admitted as any other
	// operation.
	revoked := false
	if rd.unverified == nil && rd.seq > rd.floor {
		if err := u.s.admit(u.uid, true); err != nil {
			return "", false, nil, err
		}
		revoked = u.catchUpDeliveries(o.gen, rd)
	}
	if !revoked {
		if err := u.s.admit(u.uid, false); err != nil {
			return "", false, nil, err
		}
	}
	return "", revoked, nil, ErrNotFound
}

// catchUpDeliveries appends, for an operation that holds the exclusive store
// lock and read rd, the authenticated delivery record at gen, against a
// floor it could read, the record's floor line when the floor is behind it:
// a revocation-class line, so it lands past the hard cap on the uid's
// revocation budget and in the floor's revocation headroom, and is durable
// across a restart, where the process's own mark (deliveriesSeen) is not. It
// runs before the operation serves, and is best effort: a line the floor
// refuses leaves the floor behind, as before, and the operation's own floor
// line meets the same floor. It reports whether it appended the line; a
// line the floor refused is logged at Warn, never dropped unseen.
func (u *UserScope) catchUpDeliveries(gen [generationSize]byte, rd deliveriesRead) bool {
	if rd.unverified != nil || rd.seq <= rd.floor {
		return false
	}
	return u.catchUpDeliveryLine(gen, rd) == nil
}

// catchUpDeliveryLine is catchUpDeliveries' append, with its reason: nil
// for a line appended or none owed, errFloorDegraded for one the floor's
// damage refuses (a tainted delivery record, which only that damage can
// lift), and any other error for one the floor did not take for a
// transient reason (ErrLogFull, errLogNoSpace, an I/O error), which the
// next operation on the scope tries again.
func (u *UserScope) catchUpDeliveryLine(gen [generationSize]byte, rd deliveriesRead) error {
	if rd.unverified != nil || rd.seq <= rd.floor {
		return nil
	}
	if ff, ok := u.s.userFloor.(*fileFloorLog); ok {
		// A catch-up writes no live line for a tainted key, nor for a
		// generation the floor has no line for while unattributable damage
		// counts.
		refused, err := ff.liveRefused(floorKey{u.scope, deliveriesFloorName, gen})
		if err == nil && refused {
			err = errFloorDegraded
		}
		if err != nil {
			slog.Warn("the user-scope floor holds damage that could name the delivery record, or cannot be read, so its catch-up line is not written", "scope", u.scope, "err", err)
			return err
		}
	}
	if err := u.s.userFloor.append(u.scope, deliveriesFloorName, gen, rd.seq, true); err != nil {
		slog.Warn("the user-scope floor did not take the delivery record's catch-up line; the floor stays behind the record", "scope", u.scope, "err", err)
		return err
	}
	return nil
}

// startUserScopes is the server's user-scope start step, owed before the
// listener serves: CheckLogBounds, then catchUpUser, in that order. Once
// both have run it marks the user scope started, and only then does
// UserScope build one (errUserScopesNotStarted). A refused CheckLogBounds
// (it fails closed: a log missing, untrusted, unflagged or unreadable is
// refused), or a catch-up that could not run at all (no lock, no master),
// leaves it unstarted and returns the error. A scope whose live catch-up
// line the floor refused (errCatchUpRefused: a tainted key, or a generation
// with no line while unattributable damage counts, errFloorDegraded) is
// quarantined, never served over a floor behind its authenticated tree:
// UserScope refuses that uid with errFloorDegraded, every other scope
// starts, and the refusal is named in the returned error. Unattributable
// damage so quarantines only the scopes that have something to catch up. A
// scope the catch-up could not open at all has no line to write: it is
// logged and named in the returned error, and it still starts.
//
//lint:ignore U1000 the server start calls it once the socket lands; until then TestUserScopeIsUnexported holds the user scope in this package.
func (s *FileStore) startUserScopes(ctx context.Context) error {
	if s.userScopesStarted == nil {
		return fmt.Errorf("%w: the store was not made by New", errInvalidConfig)
	}
	damage, spent, err := s.CheckLogBounds(ctx)
	if err != nil {
		return err
	}
	if damage > 0 {
		slog.Warn("the keystore append-only logs hold damaged lines, which are skipped", "damaged", damage)
	}
	if spent > 0 {
		slog.Warn("uids have spent their revocation budgets past the hard cap; only their revocations are refused", "uids", spent)
	}
	quarantined, scopeErrs, err := s.catchUpUser(ctx)
	if err != nil {
		return errors.Join(err, scopeErrs)
	}
	if len(quarantined) > 0 {
		slog.Warn("the user-scope floor refused live catch-up lines; those scopes are quarantined and every other scope starts", "quarantined", len(quarantined))
	}
	s.quarantined.Store(&quarantined)
	s.userScopesStarted.Store(true)
	return scopeErrs
}

// errScopeQuarantined marks a uid whose scope the start step quarantined
// (startUserScopes); it wraps errFloorDegraded.
var errScopeQuarantined = errors.New("the user-scope floor refused this scope's catch-up line at the server's start, so the scope is quarantined")

// scopeQuarantined reports whether the start step quarantined uid's scope.
func (s *FileStore) scopeQuarantined(uid uint32) bool {
	if s.quarantined == nil {
		return false
	}
	m := s.quarantined.Load()
	return m != nil && (*m)[uid]
}

// errCatchUpRefused marks a live catch-up line the floor did not take,
// which quarantines its scope at the start step (startUserScopes).
var errCatchUpRefused = errors.New("the user-scope floor did not take a live catch-up line, so the scope is quarantined")

// errUserScopesNotStarted refuses a user scope before the server's start
// step (startUserScopes) has run.
var errUserScopesNotStarted = errors.New("the user scope is not started: the server's start step (the log bounds check, then the delivery catch-up) has not run")

// catchUpUser appends, under the exclusive store lock, the catch-up floor
// line of every user scope whose authenticated delivery record sits above
// its floor line (catchUpDeliveries): what a withdraw whose floor line
// failed left behind, and which the process's own mark no longer covers
// after a restart. The server's start step (startUserScopes) runs it, after
// CheckLogBounds, before the listener serves (docs/design/keystore.md §
// "The user-scope floor"); it is unexported, so nothing outside the package
// reaches it. It opens each scope.key under W with no GeneratedUID check, as
// a revocation does. It is best effort per scope: a scope that does not
// open, or whose floor does not take the line, is logged at Warn and named
// in scopeErrs, and the rest are still caught up; err is a catch-up that
// could not run at all. A keystore with no directory or no user scope has
// nothing to catch up.
//
// Before the catch-up, still under the lock, it seals the torn tail of
// both user-scope logs, the floor and the audit log (sealUserLogTails), so
// no foreign append, now or across a later restart, can complete the
// fragment into a line that parses.
//
// quarantined is the uids whose live catch-up line the floor refused
// (errCatchUpRefused): the scopes the start step quarantines.
func (s *FileStore) catchUpUser(ctx context.Context) (quarantined map[uint32]bool, scopeErrs, err error) {
	quarantined = map[uint32]bool{}
	if err := s.checkConfig(); err != nil {
		return quarantined, nil, err
	}
	root, done, err := s.openLocked(ctx, false, true)
	if errors.Is(err, fs.ErrNotExist) {
		return quarantined, nil, nil
	}
	if err != nil {
		return quarantined, nil, err
	}
	defer done()
	s.sealUserLogTails()
	return s.catchUpUserLocked(ctx, root)
}

// sealUserLogTails seals the torn tail of the floor and of the audit log
// (appendLog.sealTail), at the start step, under the exclusive store lock
// the caller holds. The newline it writes is the leading newline the next
// append would write: it closes a torn line, which stays counted damage,
// and never makes it parse. A seal that fails is logged at Warn, and this
// process reads that tail frozen, as before (docs/design/keystore.md §
// "A torn tail").
func (s *FileStore) sealUserLogTails() {
	var logs []*appendLog
	if ff, ok := s.userFloor.(*fileFloorLog); ok {
		logs = append(logs, ff.log)
	}
	if fa, ok := s.auditSink.(*fileAuditLog); ok {
		logs = append(logs, fa.log)
	}
	for _, l := range logs {
		if err := l.sealTail(); err != nil {
			slog.Warn("a keystore append-only log's torn tail could not be sealed at the start step; this process still reads it frozen", "log", l.name, "err", err)
		}
	}
}

// catchUpUserLocked is catchUpUser under the exclusive store lock the
// caller holds on root.
func (s *FileStore) catchUpUserLocked(ctx context.Context, root *os.Root) (quarantined map[uint32]bool, scopeErrs, err error) {
	quarantined = map[uint32]bool{}
	if exists, err := rootHasUserScopes(root); err != nil || !exists {
		return quarantined, nil, err
	}
	k, err := s.loadMaster()
	if err != nil {
		return quarantined, nil, err
	}
	var errs []error
	err = s.eachScopeDir(ctx, root, func(name string, _ *os.Root) error {
		id, _ := strconv.ParseUint(name, 10, 32) // eachScopeDir passes only decimal uids
		u := &UserScope{s: s, uid: uint32(id), scope: userScopeOf(uint32(id))}
		if err := u.catchUpScope(root, k); err != nil {
			slog.Warn("the user-scope delivery catch-up did not run for a scope", "scope", u.scope, "err", err)
			errs = append(errs, fmt.Errorf("%s: %w", u.scope, err))
			if errors.Is(err, errCatchUpRefused) {
				quarantined[u.uid] = true
			}
		}
		return nil
	})
	joined := errors.Join(errs...)
	if n := countCatchUpRefused(joined); n > 0 {
		slog.Warn("the user-scope floor refused live catch-up lines; none was written", "refused", n)
	}
	return quarantined, joined, err
}

// countCatchUpRefused counts the errCatchUpRefused leaves in err, a tree of
// joined errors.
func countCatchUpRefused(err error) int {
	if err == nil {
		return 0
	}
	if j, ok := err.(interface{ Unwrap() []error }); ok {
		n := 0
		for _, e := range j.Unwrap() {
			n += countCatchUpRefused(e)
		}
		if n > 0 || !errors.Is(err, errCatchUpRefused) {
			return n
		}
	}
	if errors.Is(err, errCatchUpRefused) {
		return 1
	}
	return 0
}

// catchUpScope runs catchUpDeliveries, then catchUpEntries, for u's scope,
// opened for a revocation. A scope with no delivery record has no delivery
// line to catch up; its entries are still caught up.
func (u *UserScope) catchUpScope(root *os.Root, k keys) error {
	o, err := u.openScopeForRevoke(root, k)
	if err != nil {
		return err
	}
	defer o.close()
	return errors.Join(u.catchUpScopeDeliveries(o), u.catchUpEntries(o))
}

// catchUpScopeDeliveries is catchUpScope's delivery-record half.
func (u *UserScope) catchUpScopeDeliveries(o *openedScope) error {
	rd, err := u.readDeliveriesFloor(o, true)
	if errors.Is(err, ErrScopeAbsent) {
		return nil
	}
	if err != nil {
		return err
	}
	switch err := u.catchUpDeliveryLine(o.gen, rd); {
	case errors.Is(err, errFloorDegraded):
		return fmt.Errorf("%w: the delivery record's: %w", errCatchUpRefused, err)
	case err != nil:
		// Transient: the scope is not quarantined, and the next operation
		// on it runs this catch-up again (catchUpDeliveries).
		return fmt.Errorf("the delivery record's catch-up line: %w", err)
	}
	return nil
}

// catchUpEntries appends the floor line a put lost after its commit (a
// crash between the pointer and the floor line, or a floor that refused
// the line): for every entry of o's scope whose pointer authenticates under
// K_u and whose authenticated generation has no floor line, a live line at
// the pointer's sequence. Without it the entry's generation rests only on
// the tree's word, which a tree-writer can rewrite before the user runs rm.
// A generation a tombstone buries is never given a live line: that tree is
// a copy put back after rm. An entry whose pointer does not authenticate
// has nothing to catch up. It is best effort: each line the floor does not
// take is logged at Warn and named in the joined error, and the rest are
// still appended.
func (u *UserScope) catchUpEntries(o *openedScope) error {
	entries, err := u.s.openSubdir(o.dir, scopeEntriesName, false)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("%w: %s: %w", ErrCorrupt, scopeEntriesName, err)
	}
	defer func() { _ = entries.Close() }() // nothing is written in entries/
	names, err := readDirNames(entries, maxDirNames)
	if err != nil {
		return fmt.Errorf("list %s: %w", scopeEntriesName, err)
	}
	var errs []error
	for _, name := range names {
		e, err := openEntryDirRaw(entries, name)
		if err != nil {
			continue // no entry directory the store wrote
		}
		gen, seq, ok := authenticatedPointer(e, o.uk)
		e.close()
		if !ok {
			continue
		}
		if err := u.catchUpEntry(name, gen, seq); err != nil {
			slog.Warn("the user-scope floor did not take an entry's catch-up line; the entry's generation rests on its tree alone", "scope", u.scope, "err", err)
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// catchUpEntry appends name's live floor line at gen and seq unless the
// floor already holds one for gen or buries it. The line is in the
// revocation class: it is what lets a later rm bury the entry's real
// generation, so past the hard cap it draws on the uid's revocation budget.
// While the floor holds damage that could name gen it writes nothing
// (errFloorDegraded): the skipped line could be the tombstone that buries
// gen. Only that refusal is errCatchUpRefused, which quarantines the scope
// at the start step; a transient error is returned as it is.
func (u *UserScope) catchUpEntry(name string, gen [generationSize]byte, seq uint64) error {
	live, err := u.s.userFloor.liveGens(u.scope, name)
	if err != nil {
		return fmt.Errorf("read the floor's generations for an entry: %w", err)
	}
	if slices.Contains(live, gen) {
		return nil
	}
	if _, err := u.s.userFloor.floor(u.scope, name, gen); errors.Is(err, errFloorBuried) {
		return nil
	} else if errors.Is(err, errFloorDegraded) {
		return fmt.Errorf("%w: an entry's catch-up line: %w", errCatchUpRefused, err)
	} else if err != nil {
		return fmt.Errorf("read the floor for an entry: %w", err)
	}
	if err := u.s.userFloor.append(u.scope, name, gen, seq, true); errors.Is(err, errFloorDegraded) {
		return fmt.Errorf("%w: an entry's catch-up line: %w", errCatchUpRefused, err)
	} else if err != nil {
		// Transient (ErrLogFull, errLogNoSpace, an I/O error): the scope is
		// not quarantined, and the next operation on it runs this catch-up
		// again (catchUpScope at the next start).
		return fmt.Errorf("an entry's catch-up line: %w", err)
	}
	return nil
}

// authenticatedPointer opens e's current pointer under uk at the
// generation its header names, and returns that generation and the
// pointer's sequence when the pointer authenticates: a generation K_u
// vouches for, unlike the generation file's or a header read without a
// key.
func authenticatedPointer(e *entry, uk keys) ([generationSize]byte, uint64, bool) {
	g, ok := headerGeneration(e.root, currentName, e.name, true)
	if !ok {
		return g, 0, false
	}
	e.generation = g
	_, seq, err := e.pointer(uk)
	if err != nil {
		return g, 0, false
	}
	return g, seq, true
}

// rootHasUserScopes reports whether root holds a .user name.
func rootHasUserScopes(root *os.Root) (bool, error) {
	_, err := root.Lstat(userScopesName)
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("check for keystore/%s: %w", userScopesName, err)
	}
	return true, nil
}

// grantLocked runs fn on the opened scope under the exclusive lock, minting
// the scope first when it has none. It never mints the master and refuses
// while a Rewrap is half done, as Put does. grant appends the operation's
// audit line; it is called before the mint's first write, and fn calls it
// before its own first write, so a failed append writes nothing. It
// appends at most once.
func (u *UserScope) grantLocked(ctx context.Context, g *grantAudit, fn func(*openedScope) error) (err error) {
	root, done, err := u.s.openLocked(ctx, false, true)
	if errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("%w: the keystore directory is missing; a root put creates the keystore", ErrMasterMissing)
	}
	if err != nil {
		return err
	}
	defer done()
	defer func() { // before done: the refusal's line is appended under the lock
		if err != nil {
			g.refused(err)
		}
	}()
	if err := u.s.admit(u.uid, false); err != nil {
		return err
	}
	grant := g.take
	k, err := u.masterForWrite()
	if err != nil {
		return err
	}
	o, entries, err := u.openScopeFull(root, func() (keys, error) { return k, nil })
	if errors.Is(err, errNoScopeKey) {
		// The mint and then fn each append a floor line for the delivery
		// record: one new key, preflighted before the mint's first write.
		if err := u.s.floorGrantRoomKeys(u.scope, []string{deliveriesFloorName, deliveriesFloorName}, 0, func(*logState) int { return 1 }, func(st *logState) bool {
			// The mint's floor read refuses a tainted generation itself.
			return st.nameTainted(u.scope, deliveriesFloorName)
		}); err != nil {
			return err
		}
		_, entries, err = u.mint(root, k.wrap, grant)
		if err == nil {
			_ = entries.Close() // nothing written through it here
			o, entries, err = u.openScopeFull(root, func() (keys, error) { return k, nil })
		}
	}
	if err != nil {
		return err
	}
	_ = entries.Close() // not written through here
	defer o.close()
	u.catchUpLostEntries(o)
	return fn(o)
}

// grantAudit is a grant's audit line: appended once, before the grant's
// first write, with result ok; a refusal before it is audited with the
// refusal's result instead, and a failure after it with a second line.
type grantAudit struct {
	u               *UserScope
	op, name, ns    string
	appended, tried bool
}

// grant returns op's grant audit line over the validated name and
// namespace.
func (u *UserScope) grant(op, name, namespace string) *grantAudit {
	return &grantAudit{u: u, op: op, name: name, ns: namespace}
}

// take judges the user-scope floor, then appends the line once. Its error
// refuses the grant, which has written nothing: a floor that is absent,
// untrusted, unflagged, unreadable or past the reader's bound refuses before the ok line,
// and the refusal is audited in its place (refused).
func (g *grantAudit) take() error {
	if g.tried {
		if !g.appended {
			return errAuditRefused
		}
		return nil
	}
	if err := g.u.s.userFloor.check(); err != nil {
		return fmt.Errorf("the user-scope floor: %w", err)
	}
	g.tried = true
	if err := g.u.s.auditSink.append(auditLine{op: g.op, scope: g.u.scope, name: g.name, namespace: g.ns, result: "ok"}); err != nil {
		return fmt.Errorf("%w: %w", errAuditRefused, err)
	}
	g.appended = true
	return nil
}

// refused audits err, the grant's refusal, best effort: as the refusal when
// no line was appended (an append that itself failed is not retried), as a
// second line after the ok one otherwise.
func (g *grantAudit) refused(err error) {
	if g.tried && !g.appended {
		return
	}
	_ = g.u.s.auditSink.append(auditLine{op: g.op, scope: g.u.scope, name: g.name, namespace: g.ns, result: auditResult(err)}) // already refused
}

// refusedBriefly audits err, a refusal before the grant took the store
// lock, under the lock taken briefly (auditBriefly).
func (g *grantAudit) refusedBriefly(ctx context.Context, err error) {
	g.u.auditBriefly(ctx, auditLine{op: g.op, name: g.name, namespace: g.ns}, err)
}

// auditBriefly appends l, the audit line of a refusal that came before its
// operation took the store lock, under the exclusive lock taken for the
// append alone (auditSink). A refusal for which the lock cannot be had is
// not audited: a store whose configuration is invalid, a keystore directory
// that is missing (no lock file and no log to append to), a lock held past
// its wait, or a done context. Appending such a line without the lock is
// what the contract forbids, and a refusal line is best effort.
func (u *UserScope) auditBriefly(ctx context.Context, l auditLine, err error) {
	if u.s.checkConfig() != nil {
		return
	}
	_, done, lerr := u.s.openLocked(ctx, false, true)
	if lerr != nil {
		return
	}
	defer done()
	_ = u.appendAudit(l, err) // already refused
}

// errAuditRefused is a grant refused because its audit line could not be
// appended.
var errAuditRefused = errors.New("the audit line could not be written, so nothing was changed")

// appendAudit appends l to the audit sink, setting its scope and its
// result, "ok" or the refusal's name; its name and namespace must already
// be validated (or auditPlaceholder), and never a value. It is the
// revocations' order: commit, then audit. Its error, after a change was
// made, matches errCommitted.
func (u *UserScope) appendAudit(l auditLine, err error) error {
	l.scope, l.result = u.scope, auditResult(err)
	if aerr := u.s.auditSink.append(l); aerr != nil {
		return fmt.Errorf("%w, and its audit line was not written: %w", errCommitted, aerr)
	}
	return nil
}

// auditPlaceholder stands in an audit line for a field that failed its
// grammar: a line carries only validated fields.
const auditPlaceholder = "-"

// The results of a change that committed: whole (auditResultOK), or part
// way, a revocation reported after its commit (auditResultCommitted). Any
// other result names the sentinel the operation was refused with.
const (
	auditResultOK        = "ok"
	auditResultCommitted = "committed"
)

// keepAuditFailure is the result of a committed operation (err) whose audit
// append returned aerr: aerr when err is nil; both joined when err is
// already a partial commit, so the result stays errCommitted, logged at Warn
// with the scope and verb only; otherwise err.
func (u *UserScope) keepAuditFailure(op string, err, aerr error) error {
	if aerr == nil {
		return err
	}
	if err == nil {
		return aerr
	}
	if errors.Is(err, errCommitted) {
		slog.Warn("the audit line of a change committed in part was not written", "scope", u.scope, "op", op)
		return errors.Join(err, aerr)
	}
	return err
}

// auditResult names an operation's outcome for its audit line.
func auditResult(err error) string {
	switch {
	case err == nil:
		return auditResultOK
	case errors.Is(err, errCommitted):
		return auditResultCommitted
	case errors.Is(err, ErrQuota):
		return "quota"
	case errors.Is(err, ErrNotFound):
		return "not-found"
	case errors.Is(err, ErrExists):
		return "exists"
	case errors.Is(err, ErrScopeAbsent):
		return "scope-absent"
	case errors.Is(err, ErrCorrupt):
		return "corrupt"
	case errors.Is(err, ErrLogFull):
		return "log-full"
	}
	return "error"
}

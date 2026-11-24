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

package typed

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	"k3sm.io/apis/keystore/credential"
)

// EnvelopeVersion is the envelope version this build writes and reads: the
// envelope's first byte.
const EnvelopeVersion = 1

// The envelope's bounds. docs/design/keystore.md § "Record kinds, the typed
// envelope and retention" sets them.
const (
	// MaxEnvelopeSize is the largest envelope, the keystore's MaxValueSize.
	MaxEnvelopeSize = 64 << 10
	// MaxTokenValue bounds a token's value.
	MaxTokenValue = 16 << 10
	// MaxAccessToken bounds an oauth access token.
	MaxAccessToken = 32 << 10
	// MaxRefreshToken bounds an oauth refresh token.
	MaxRefreshToken = 8 << 10
	// MaxComment bounds an ssh key's comment, printable ASCII.
	MaxComment = 255
	// MaxTokenType bounds an oauth token type, ASCII letters.
	MaxTokenType = 32
	// MaxTime is the latest time an envelope holds, 9999-12-31T23:59:59Z in
	// Unix seconds: the last second RFC 3339 can render. The earliest is the
	// Unix epoch.
	MaxTime = 253402300799
)

// SSHAlgorithmEd25519 is the ssh envelope's algorithm byte for an ed25519
// key, the only algorithm this release stores.
const SSHAlgorithmEd25519 = 1

// DefaultTokenType is an oauth pair's token type when the envelope names none.
const DefaultTokenType = "Bearer"

// The envelope's tags, per kind. Each kind's set is closed.
const (
	tagValue     = 0x10
	tagExpiresAt = 0x11
	tagIssuedAt  = 0x12

	tagAlgorithm = 0x20
	tagSeed      = 0x21
	tagComment   = 0x22

	tagAccessToken      = 0x30
	tagAccessExpiresAt  = 0x31
	tagAccessIssuedAt   = 0x32
	tagRefreshToken     = 0x33
	tagRefreshExpiresAt = 0x34
	tagTokenType        = 0x35
	tagRefreshOwner     = 0x36
)

var (
	// ErrCorrupt reports an envelope that does not decode: an unknown,
	// repeated or out-of-order tag, a missing field, a value out of its
	// bounds, or a truncated or oversized envelope. No build writes one.
	ErrCorrupt = errors.New("the typed credential envelope is corrupt")
	// ErrKindUnsupported reports a credential this build cannot read: a
	// record kind or an envelope version from a newer k3sm, or a file
	// altered so that it reads as one (a single flipped byte can). Its text
	// names both remedies, so an alteration never steers an operator to
	// upgrade alone.
	ErrKindUnsupported = errors.New("the keystore entry was written by a newer k3sm, in a kind or envelope version this build cannot read, or the file was altered; upgrade k3sm, or, if this k3sm is current, restore it from backup")
	// ErrInvalidCredential reports a credential Encode or an SSH import
	// refuses: a missing field, a value out of its bounds, or a field of
	// another kind.
	ErrInvalidCredential = errors.New("invalid typed credential")
)

// Credential is a typed credential's value, as a store hands it to every
// consumer: a renderer, a socket handler, a reconciler. It has no field for
// an oauth refresh token, by design. Only the fields of the entry's kind are
// set; a time that is absent is the zero time.Time. Times are whole UTC
// seconds.
type Credential struct {
	// Value is a token's bytes (token).
	Value []byte
	// ExpiresAt is when a token expires (token).
	ExpiresAt time.Time
	// IssuedAt is when the store took the token, from its clock (token).
	IssuedAt time.Time

	// Algorithm is the ssh key's algorithm, SSHAlgorithmEd25519 (ssh).
	Algorithm byte
	// Seed is the ssh key's 32-byte ed25519 seed (ssh).
	Seed []byte
	// Comment is the ssh key's comment, empty for none (ssh).
	Comment string

	// AccessToken is an oauth pair's access token (oauth).
	AccessToken []byte
	// AccessExpiresAt is when the access token expires (oauth).
	AccessExpiresAt time.Time
	// AccessIssuedAt is when the store took the access token, from its
	// clock (oauth).
	AccessIssuedAt time.Time
	// RefreshExpiresAt is when the refresh token expires, the zero time when
	// unknown (oauth).
	RefreshExpiresAt time.Time
	// TokenType is the access token's type, empty when the envelope names
	// none; TokenTypeOrDefault applies the default (oauth).
	TokenType string
	// RefreshOwner names who refreshes the pair, in the refresh-owner
	// grammar (oauth).
	RefreshOwner string
}

// TokenTypeOrDefault returns c's token type, or DefaultTokenType when c
// names none.
func (c Credential) TokenTypeOrDefault() string {
	if c.TokenType == "" {
		return DefaultTokenType
	}
	return c.TokenType
}

// Envelope is the whole sealed plaintext of a typed record: the Credential
// and, for oauth, the refresh token that Credential deliberately lacks.
type Envelope struct {
	// Credential is everything but the refresh token.
	Credential Credential
	// RefreshToken is an oauth pair's refresh token (oauth).
	RefreshToken []byte
}

// field is one envelope field: its tag, its bounds and where it lives in an
// Envelope.
type field struct {
	tag      byte
	name     string
	optional bool
	// min and max bound the value's length.
	min, max int
	// valid, when set, checks the value beyond its length.
	valid func([]byte) bool
	// get returns the field's encoded value and whether it is present.
	get func(*Envelope) ([]byte, bool)
	// set stores a decoded, valid value.
	set func(*Envelope, []byte)
}

func bytesField(tag byte, name string, max int, p func(*Envelope) *[]byte) field {
	return field{
		tag: tag, name: name, min: 1, max: max,
		get: func(e *Envelope) ([]byte, bool) { v := *p(e); return v, len(v) > 0 },
		set: func(e *Envelope, v []byte) { *p(e) = bytes.Clone(v) },
	}
}

func stringField(tag byte, name string, max int, valid func([]byte) bool, p func(*Envelope) *string) field {
	return field{
		tag: tag, name: name, min: 1, max: max, valid: valid,
		get: func(e *Envelope) ([]byte, bool) { v := *p(e); return []byte(v), v != "" },
		set: func(e *Envelope, v []byte) { *p(e) = string(v) },
	}
}

func timeField(tag byte, name string, p func(*Envelope) *time.Time) field {
	return field{
		tag: tag, name: name, min: 8, max: 8,
		valid: func(v []byte) bool {
			s := int64(binary.BigEndian.Uint64(v))
			return s >= 0 && s <= MaxTime
		},
		get: func(e *Envelope) ([]byte, bool) {
			t := *p(e)
			if t.IsZero() {
				return nil, false
			}
			return binary.BigEndian.AppendUint64(nil, uint64(t.Unix())), true
		},
		set: func(e *Envelope, v []byte) { *p(e) = time.Unix(int64(binary.BigEndian.Uint64(v)), 0).UTC() },
	}
}

func optional(f field) field { f.optional = true; return f }

// fields is each typed kind's field table, in tag order.
var fields = map[credential.Kind][]field{
	credential.KindToken: {
		bytesField(tagValue, "value", MaxTokenValue, func(e *Envelope) *[]byte { return &e.Credential.Value }),
		timeField(tagExpiresAt, "expiresAt", func(e *Envelope) *time.Time { return &e.Credential.ExpiresAt }),
		timeField(tagIssuedAt, "issuedAt", func(e *Envelope) *time.Time { return &e.Credential.IssuedAt }),
	},
	credential.KindSSH: {
		{
			tag: tagAlgorithm, name: "algorithm", min: 1, max: 1,
			valid: func(v []byte) bool { return v[0] == SSHAlgorithmEd25519 },
			get: func(e *Envelope) ([]byte, bool) {
				a := e.Credential.Algorithm
				return []byte{a}, a != 0
			},
			set: func(e *Envelope, v []byte) { e.Credential.Algorithm = v[0] },
		},
		func() field {
			f := bytesField(tagSeed, "seed", seedSize, func(e *Envelope) *[]byte { return &e.Credential.Seed })
			f.min = seedSize
			return f
		}(),
		optional(stringField(tagComment, "comment", MaxComment, printableASCII, func(e *Envelope) *string { return &e.Credential.Comment })),
	},
	credential.KindOAuth: {
		bytesField(tagAccessToken, "accessToken", MaxAccessToken, func(e *Envelope) *[]byte { return &e.Credential.AccessToken }),
		timeField(tagAccessExpiresAt, "accessExpiresAt", func(e *Envelope) *time.Time { return &e.Credential.AccessExpiresAt }),
		timeField(tagAccessIssuedAt, "accessIssuedAt", func(e *Envelope) *time.Time { return &e.Credential.AccessIssuedAt }),
		bytesField(tagRefreshToken, "refreshToken", MaxRefreshToken, func(e *Envelope) *[]byte { return &e.RefreshToken }),
		optional(timeField(tagRefreshExpiresAt, "refreshExpiresAt", func(e *Envelope) *time.Time { return &e.Credential.RefreshExpiresAt })),
		optional(stringField(tagTokenType, "tokenType", MaxTokenType, letters, func(e *Envelope) *string { return &e.Credential.TokenType })),
		stringField(tagRefreshOwner, "refreshOwner", credential.MaxRefreshOwnerLength, refreshOwner, func(e *Envelope) *string { return &e.Credential.RefreshOwner }),
	},
}

func printableASCII(v []byte) bool {
	for _, c := range v {
		if c < 0x20 || c > 0x7e {
			return false
		}
	}
	return true
}

func letters(v []byte) bool {
	for _, c := range v {
		if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') {
			return false
		}
	}
	return true
}

func refreshOwner(v []byte) bool {
	_, err := credential.ParseRefreshOwner(string(v))
	return err == nil
}

// HasEnvelope reports whether kind seals an envelope: token, ssh and oauth.
func HasEnvelope(kind credential.Kind) bool {
	_, ok := fields[kind]
	return ok
}

// check reports why value v is not a valid f, or nil. The reason names the
// field and its bounds only, never the value's bytes or its length.
func (f *field) check(v []byte) error {
	if len(v) < f.min || len(v) > f.max {
		return fmt.Errorf("%s is outside its %d to %d bytes", f.name, f.min, f.max)
	}
	if f.valid != nil && !f.valid(v) {
		return fmt.Errorf("%s is outside its grammar", f.name)
	}
	return nil
}

// Encode returns the envelope of e for kind, the one encoding Decode accepts
// for it. It refuses, with ErrInvalidCredential, a kind without an envelope,
// a missing required field, a value out of its bounds, and a set field that
// belongs to another kind. Times are encoded in whole seconds.
func Encode(kind credential.Kind, e Envelope) ([]byte, error) {
	fs, ok := fields[kind]
	if !ok {
		return nil, fmt.Errorf("%w: kind %q has no envelope", ErrInvalidCredential, kind)
	}
	for k, other := range fields {
		if k == kind {
			continue
		}
		for i := range other {
			if _, present := other[i].get(&e); present {
				return nil, fmt.Errorf("%w: %s is not a field of kind %s", ErrInvalidCredential, other[i].name, kind)
			}
		}
	}
	b := []byte{EnvelopeVersion}
	for i := range fs {
		f := &fs[i]
		v, present := f.get(&e)
		if !present {
			if f.optional {
				continue
			}
			return nil, fmt.Errorf("%w: kind %s needs %s", ErrInvalidCredential, kind, f.name)
		}
		if err := f.check(v); err != nil {
			return nil, fmt.Errorf("%w: %w", ErrInvalidCredential, err)
		}
		b = append(b, f.tag)
		b = binary.BigEndian.AppendUint16(b, uint16(len(v)))
		b = append(b, v...)
	}
	if len(b) > MaxEnvelopeSize {
		return nil, fmt.Errorf("%w: the envelope is over %d bytes", ErrInvalidCredential, MaxEnvelopeSize)
	}
	if err := checkExpiryOrder(kind, &e); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidCredential, err)
	}
	return b, nil
}

// checkExpiryOrder refuses a token whose expiresAt is not after its
// issuedAt, and an oauth pair whose accessExpiresAt is not after its
// accessIssuedAt, compared as the envelope holds them: in whole seconds.
// Encode and Decode both apply it, so they accept the same envelopes.
func checkExpiryOrder(kind credential.Kind, e *Envelope) error {
	c := &e.Credential
	switch kind {
	case credential.KindToken:
		if c.ExpiresAt.Unix() <= c.IssuedAt.Unix() {
			return errors.New("expiresAt is not after issuedAt")
		}
	case credential.KindOAuth:
		if c.AccessExpiresAt.Unix() <= c.AccessIssuedAt.Unix() {
			return errors.New("accessExpiresAt is not after accessIssuedAt")
		}
	}
	return nil
}

// decodeRefused is called with the partly decoded envelope of a refused
// Decode, before its clones are cleared, where a test records them.
var decodeRefused = func(*Envelope) {}

// wipe clears every secret field of e in place: RefreshToken, Value, Seed
// and AccessToken.
func (e *Envelope) wipe() {
	clear(e.RefreshToken)
	clear(e.Credential.Value)
	clear(e.Credential.Seed)
	clear(e.Credential.AccessToken)
}

// Decode parses the envelope b of kind. It accepts exactly what Encode
// writes: anything else is ErrCorrupt, except an envelope version other than
// EnvelopeVersion, which is ErrKindUnsupported. Its errors carry the kind,
// field names and fixed bounds only, never a byte, tag or length read from
// the envelope, which is a decrypted value. A refusal clears the
// field values it had already copied out of b.
func Decode(kind credential.Kind, b []byte) (Envelope, error) {
	var e Envelope
	fs, ok := fields[kind]
	if !ok {
		return e, fmt.Errorf("%w: kind %q has no envelope", ErrCorrupt, kind)
	}
	if len(b) == 0 {
		return e, fmt.Errorf("%w: empty", ErrCorrupt)
	}
	if len(b) > MaxEnvelopeSize {
		return e, fmt.Errorf("%w: the envelope is over %d bytes", ErrCorrupt, MaxEnvelopeSize)
	}
	if b[0] != EnvelopeVersion {
		return e, fmt.Errorf("%w: the envelope's version is not %d, the one this build reads", ErrKindUnsupported, EnvelopeVersion)
	}
	// A refusal after a field was set clears the clones made so far: they
	// may hold a secret and the caller never sees them.
	refuse := func(err error) (Envelope, error) {
		decodeRefused(&e)
		e.wipe()
		return Envelope{}, err
	}
	rest := b[1:]
	next := 0 // the index in fs of the first field not yet passed
	for len(rest) > 0 {
		if len(rest) < 3 {
			return refuse(fmt.Errorf("%w: a field header is truncated", ErrCorrupt))
		}
		tag, n := rest[0], int(binary.BigEndian.Uint16(rest[1:3]))
		if len(rest)-3 < n {
			return refuse(fmt.Errorf("%w: a field claims bytes past the end", ErrCorrupt))
		}
		v := rest[3 : 3+n]
		rest = rest[3+n:]
		i := next
		for i < len(fs) && fs[i].tag < tag {
			if !fs[i].optional {
				return refuse(fmt.Errorf("%w: kind %s is missing %s", ErrCorrupt, kind, fs[i].name))
			}
			i++
		}
		if i == len(fs) || fs[i].tag != tag {
			return refuse(fmt.Errorf("%w: a field's tag is unknown, repeated or out of order for kind %s", ErrCorrupt, kind))
		}
		f := &fs[i]
		if err := f.check(v); err != nil {
			return refuse(fmt.Errorf("%w: %w", ErrCorrupt, err))
		}
		f.set(&e, v)
		next = i + 1
	}
	for ; next < len(fs); next++ {
		if !fs[next].optional {
			return refuse(fmt.Errorf("%w: kind %s is missing %s", ErrCorrupt, kind, fs[next].name))
		}
	}
	if err := checkExpiryOrder(kind, &e); err != nil {
		return refuse(fmt.Errorf("%w: %w", ErrCorrupt, err))
	}
	return e, nil
}

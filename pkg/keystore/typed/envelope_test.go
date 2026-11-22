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
	"encoding/hex"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"k3sm.io/apis/keystore/credential"
)

// readHexVector reads an annotated hex file: '#' starts a comment, and every
// other non-space character is a hex digit.
func readHexVector(t testing.TB, name string) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "envelope", name+".hex"))
	if err != nil {
		t.Fatal(err)
	}
	var digits strings.Builder
	for line := range strings.SplitSeq(string(raw), "\n") {
		line, _, _ = strings.Cut(line, "#")
		digits.WriteString(strings.Join(strings.Fields(line), ""))
	}
	b, err := hex.DecodeString(digits.String())
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return b
}

func unix(s int64) time.Time { return time.Unix(s, 0).UTC() }

func seq(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i)
	}
	return b
}

// goldenVectors are the envelopes under testdata/envelope, each assembled by
// hand from the design rather than written by Encode, so the test compares
// the codec with the specification and not with itself.
var goldenVectors = []struct {
	file string
	kind credential.Kind
	env  Envelope
}{
	{"token", credential.KindToken, Envelope{Credential: Credential{
		Value: []byte("ghp_k3smTestToken"), ExpiresAt: unix(1800000000), IssuedAt: unix(1790000000),
	}}},
	{"ssh", credential.KindSSH, Envelope{Credential: Credential{
		Algorithm: SSHAlgorithmEd25519, Seed: seq(32), Comment: "ci-bot@k3sm",
	}}},
	{"ssh-no-comment", credential.KindSSH, Envelope{Credential: Credential{
		Algorithm: SSHAlgorithmEd25519, Seed: seq(32),
	}}},
	{"oauth", credential.KindOAuth, Envelope{
		Credential: Credential{
			AccessToken: []byte("gho_access"), AccessExpiresAt: unix(1790003600), AccessIssuedAt: unix(1790000000),
			RefreshExpiresAt: unix(1805552000), TokenType: "Bearer", RefreshOwner: "server/github",
		},
		RefreshToken: []byte("ghr_refresh"),
	}},
	{"oauth-minimal", credential.KindOAuth, Envelope{
		Credential: Credential{
			AccessToken: []byte("gho_access"), AccessExpiresAt: unix(1790003600), AccessIssuedAt: unix(1790000000),
			RefreshOwner: "local",
		},
		RefreshToken: []byte("ghr_refresh"),
	}},
}

func TestEnvelopeGoldenVectors(t *testing.T) {
	for _, gv := range goldenVectors {
		t.Run(gv.file, func(t *testing.T) {
			want := readHexVector(t, gv.file)
			got, err := Encode(gv.kind, gv.env)
			if err != nil {
				t.Fatalf("encode: %v", err)
			}
			if !bytes.Equal(got, want) {
				t.Fatalf("encode:\n got %x\nwant %x", got, want)
			}
			dec, err := Decode(gv.kind, want)
			if err != nil {
				t.Fatalf("decode: %v", err)
			}
			if !reflect.DeepEqual(dec, gv.env) {
				t.Fatalf("decode:\n got %+v\nwant %+v", dec, gv.env)
			}
		})
	}
}

// TestEnvelopeVectorsCoverEveryKind keeps a golden vector for each kind that
// has an envelope.
func TestEnvelopeVectorsCoverEveryKind(t *testing.T) {
	seen := map[credential.Kind]bool{}
	for _, gv := range goldenVectors {
		seen[gv.kind] = true
	}
	for _, k := range credential.Kinds() {
		if HasEnvelope(k) != seen[k] {
			t.Errorf("kind %s: HasEnvelope %v, golden vector %v", k, HasEnvelope(k), seen[k])
		}
	}
}

func TestTokenTypeOrDefault(t *testing.T) {
	if got := (Credential{}).TokenTypeOrDefault(); got != "Bearer" {
		t.Errorf("default token type %q, want Bearer", got)
	}
	if got := (Credential{TokenType: "MAC"}).TokenTypeOrDefault(); got != "MAC" {
		t.Errorf("token type %q, want MAC", got)
	}
}

// tlv is one encoded field.
func tlv(tag byte, v []byte) []byte {
	b := []byte{tag}
	b = binary.BigEndian.AppendUint16(b, uint16(len(v)))
	return append(b, v...)
}

func be(s int64) []byte { return binary.BigEndian.AppendUint64(nil, uint64(s)) }

func cat(parts ...[]byte) []byte { return bytes.Join(parts, nil) }

func TestEnvelopeRejectsUnknownTagDuplicateAndOrder(t *testing.T) {
	v := []byte{EnvelopeVersion}
	value := tlv(0x10, []byte("tok"))
	exp := tlv(0x11, be(1800000000))
	iss := tlv(0x12, be(1790000000))
	alg := tlv(0x20, []byte{1})
	seed := tlv(0x21, seq(32))
	at := tlv(0x30, []byte("a"))
	aexp := tlv(0x31, be(1790003600))
	aiss := tlv(0x32, be(1790000000))
	rt := tlv(0x33, []byte("r"))
	owner := tlv(0x36, []byte("local"))
	// Each base decodes; every case below is one defect away from it.
	bases := map[credential.Kind][]byte{
		credential.KindToken: cat(v, value, exp, iss),
		credential.KindSSH:   cat(v, alg, seed),
		credential.KindOAuth: cat(v, at, aexp, aiss, rt, owner),
	}
	for k, b := range bases {
		if _, err := Decode(k, b); err != nil {
			t.Fatalf("base %s: %v", k, err)
		}
	}
	tests := []struct {
		name string
		kind credential.Kind
		b    []byte
	}{
		{"empty", credential.KindToken, nil},
		{"version only", credential.KindToken, v},
		{"unknown tag", credential.KindToken, cat(v, value, exp, iss, tlv(0x13, []byte{0}))},
		{"unknown tag 0", credential.KindToken, cat(v, tlv(0, nil), value, exp, iss)},
		{"another kind's tag", credential.KindToken, cat(v, value, exp, iss, tlv(0x22, []byte("c")))},
		{"refresh tag in a token", credential.KindToken, cat(v, value, exp, iss, tlv(0x33, []byte("r")))},
		{"duplicate", credential.KindToken, cat(v, value, value, exp, iss)},
		{"duplicate last", credential.KindToken, cat(v, value, exp, iss, iss)},
		{"out of order", credential.KindToken, cat(v, exp, value, iss)},
		{"out of order optional", credential.KindOAuth, cat(v, at, aexp, aiss, rt, tlv(0x35, []byte("Bearer")), tlv(0x34, be(1)), owner)},
		{"missing value", credential.KindToken, cat(v, exp, iss)},
		{"missing expiresAt", credential.KindToken, cat(v, value, iss)},
		{"missing issuedAt", credential.KindToken, cat(v, value, exp)},
		{"missing seed", credential.KindSSH, cat(v, alg)},
		{"missing refresh token", credential.KindOAuth, cat(v, at, aexp, aiss, owner)},
		{"missing refresh owner", credential.KindOAuth, cat(v, at, aexp, aiss, rt)},
		{"empty value", credential.KindToken, cat(v, tlv(0x10, nil), exp, iss)},
		{"token value over 16 KiB", credential.KindToken, cat(v, tlv(0x10, make([]byte, MaxTokenValue+1)), exp, iss)},
		{"access token over 32 KiB", credential.KindOAuth, cat(v, tlv(0x30, make([]byte, MaxAccessToken+1)), aexp, aiss, rt, owner)},
		{"refresh token over 8 KiB", credential.KindOAuth, cat(v, at, aexp, aiss, tlv(0x33, make([]byte, MaxRefreshToken+1)), owner)},
		{"short time", credential.KindToken, cat(v, value, tlv(0x11, be(1)[1:]), iss)},
		{"negative time", credential.KindToken, cat(v, value, tlv(0x11, be(-1)), iss)},
		{"time past 9999", credential.KindToken, cat(v, value, tlv(0x11, be(MaxTime+1)), iss)},
		{"algorithm 2", credential.KindSSH, cat(v, tlv(0x20, []byte{2}), seed)},
		{"algorithm 0", credential.KindSSH, cat(v, tlv(0x20, []byte{0}), seed)},
		{"short seed", credential.KindSSH, cat(v, alg, tlv(0x21, seq(31)))},
		{"long seed", credential.KindSSH, cat(v, alg, tlv(0x21, seq(33)))},
		{"empty comment", credential.KindSSH, cat(v, alg, seed, tlv(0x22, nil))},
		{"comment with a newline", credential.KindSSH, cat(v, alg, seed, tlv(0x22, []byte("a\nb")))},
		{"comment over 255", credential.KindSSH, cat(v, alg, seed, tlv(0x22, bytes.Repeat([]byte("a"), 256)))},
		{"token type with a digit", credential.KindOAuth, cat(v, at, aexp, aiss, rt, tlv(0x35, []byte("Bearer1")), owner)},
		{"token type over 32", credential.KindOAuth, cat(v, at, aexp, aiss, rt, tlv(0x35, bytes.Repeat([]byte("a"), 33)), owner)},
		{"refresh owner outside the grammar", credential.KindOAuth, cat(v, at, aexp, aiss, rt, tlv(0x36, []byte("server/")))},
		{"refresh owner over 70", credential.KindOAuth, cat(v, at, aexp, aiss, rt, tlv(0x36, []byte("server/"+strings.Repeat("a", 64))))},
		{"truncated header", credential.KindToken, cat(v, value, exp, iss, []byte{0x13, 0})},
		{"length past the end", credential.KindToken, cat(v, value, exp, iss[:len(iss)-1])},
		{"trailing byte", credential.KindToken, cat(v, value, exp, iss, []byte{0})},
		{"over 64 KiB", credential.KindOAuth, append(cat(v, at, aexp, aiss, rt, owner), make([]byte, MaxEnvelopeSize)...)},
		{"not an envelope kind", credential.KindOpaque, bases[credential.KindToken]},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Decode(tt.kind, tt.b)
			if !errors.Is(err, ErrCorrupt) {
				t.Fatalf("decode: %v, want ErrCorrupt", err)
			}
			if errors.Is(err, ErrKindUnsupported) {
				t.Fatalf("decode: %v is also ErrKindUnsupported", err)
			}
		})
	}
}

// TestEnvelopeUnknownVersionUnsupported: an envelope version this build does
// not know is a newer k3sm's record, not a damaged one.
func TestEnvelopeUnknownVersionUnsupported(t *testing.T) {
	good := readHexVector(t, "token")
	for _, ver := range []byte{0, 2, 0xFF} {
		b := bytes.Clone(good)
		b[0] = ver
		_, err := Decode(credential.KindToken, b)
		if !errors.Is(err, ErrKindUnsupported) || errors.Is(err, ErrCorrupt) {
			t.Errorf("version %d: %v, want ErrKindUnsupported alone", ver, err)
		}
	}
}

func TestEncodeRefusesInvalid(t *testing.T) {
	good := goldenVectors[0].env.Credential
	tests := []struct {
		name string
		kind credential.Kind
		env  Envelope
	}{
		{"opaque has no envelope", credential.KindOpaque, Envelope{Credential: good}},
		{"token without expiresAt", credential.KindToken, Envelope{Credential: Credential{Value: []byte("x"), IssuedAt: unix(1)}}},
		{"token with a refresh token", credential.KindToken, Envelope{Credential: good, RefreshToken: []byte("r")}},
		{"token with a seed", credential.KindToken, func() Envelope { c := good; c.Seed = seq(32); return Envelope{Credential: c} }()},
		{"token before the epoch", credential.KindToken, func() Envelope { c := good; c.ExpiresAt = unix(-5); return Envelope{Credential: c} }()},
		{"ssh without algorithm", credential.KindSSH, Envelope{Credential: Credential{Seed: seq(32)}}},
		{"oauth with a bad owner", credential.KindOAuth, func() Envelope {
			e := goldenVectors[3].env
			e.Credential.RefreshOwner = "pod/x"
			return e
		}()},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := Encode(tt.kind, tt.env); !errors.Is(err, ErrInvalidCredential) {
				t.Fatalf("encode: %v, want ErrInvalidCredential", err)
			}
		})
	}
}

var fuzzKinds = []credential.Kind{credential.KindToken, credential.KindSSH, credential.KindOAuth}

// FuzzEnvelopeParse: the first byte picks the kind, the rest is the
// envelope. Decode never panics; an accepted envelope re-encodes to its
// input byte for byte; a refusal is ErrCorrupt or ErrKindUnsupported and
// its message never carries the input.
func FuzzEnvelopeParse(f *testing.F) {
	for i, gv := range goldenVectors {
		for j, k := range fuzzKinds {
			if k == gv.kind {
				f.Add(append([]byte{byte(j)}, readHexVector(f, goldenVectors[i].file)...))
			}
		}
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) == 0 {
			return
		}
		kind := fuzzKinds[int(b[0])%len(fuzzKinds)]
		in := b[1:]
		e, err := Decode(kind, in)
		if err != nil {
			if !errors.Is(err, ErrCorrupt) && !errors.Is(err, ErrKindUnsupported) {
				t.Fatalf("decode error %v is neither ErrCorrupt nor ErrKindUnsupported", err)
			}
			// The sentinels' fixed texts are not the input's; what is left of
			// the message must not carry leakWindow input bytes in a row,
			// anywhere in the input.
			msg := err.Error()
			for _, s := range []error{ErrCorrupt, ErrKindUnsupported} {
				msg = strings.ReplaceAll(msg, s.Error(), "")
			}
			if at, ok := windowLeak(msg, in); ok {
				t.Fatalf("decode error carries input bytes %d to %d: %v", at, at+leakWindow, err)
			}
			return
		}
		out, err := Encode(kind, e)
		if err != nil {
			t.Fatalf("an accepted envelope does not re-encode: %v", err)
		}
		if !bytes.Equal(out, in) {
			t.Fatalf("encode(decode(b)) != b:\n got %x\nwant %x", out, in)
		}
	})
}

// leakWindow is the run of input bytes an error must never carry.
const leakWindow = 8

// fixedText is every string literal of the package's non-test files, each
// cut at its format verbs, longest first, with the credential kind names:
// the text an error carries that is the package's, not the input's.
var fixedText = sync.OnceValues(func() ([]string, error) {
	pieces := []string{string(credential.KindToken), string(credential.KindSSH), string(credential.KindOAuth)}
	files, err := filepath.Glob("*.go")
	if err != nil {
		return nil, err
	}
	verb := regexp.MustCompile(`%[-+# 0-9.]*[a-zA-Z]`)
	fset := token.NewFileSet()
	for _, n := range files {
		if strings.HasSuffix(n, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, n, nil, parser.SkipObjectResolution)
		if err != nil {
			return nil, err
		}
		ast.Inspect(f, func(node ast.Node) bool {
			lit, ok := node.(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				return true
			}
			v, err := strconv.Unquote(lit.Value)
			if err == nil {
				pieces = append(pieces, verb.Split(v, -1)...)
			}
			return true
		})
	}
	sort.Slice(pieces, func(i, j int) bool { return len(pieces[i]) > len(pieces[j]) })
	return pieces, nil
})

// windowLeak reports the offset of the first leakWindow-byte window of in
// that appears in msg once the package's own text (fixedText) is cut out of
// it, so that an input which happens to spell a field name is not a leak.
func windowLeak(msg string, in []byte) (int, bool) {
	pieces, err := fixedText()
	if err != nil {
		panic(err) // the package's own source does not parse
	}
	for _, p := range pieces {
		if len(p) > 1 {
			msg = strings.ReplaceAll(msg, p, "\x00")
		}
	}
	for i := 0; i+leakWindow <= len(in); i++ {
		if strings.Contains(msg, string(in[i:i+leakWindow])) {
			return i, true
		}
	}
	return 0, false
}

// TestEnvelopeRefusalsNeverCarryRefreshToken plants a marker refresh token in
// an oauth envelope, breaks the envelope around it in every way Decode
// refuses, and checks that no refusal's text carries the marker, nor any
// leakWindow bytes of the input in a row.
func TestEnvelopeRefusalsNeverCarryRefreshToken(t *testing.T) {
	refusalsHideRefreshToken(t, []byte("MARKER-refresh-token-5f0c1e9a7b3d"))
}

// TestShortSecretNeverInRefusals is the same check with a 4-byte refresh
// token, below the leak window, so only the marker check can catch it, and
// with a 4-byte secret in every secret field of an envelope Encode refuses:
// no refusal on any path carries it, raw or hex-encoded.
func TestShortSecretNeverInRefusals(t *testing.T) {
	marker := []byte("Zq9X")
	refusalsHideRefreshToken(t, marker)
	at := time.Date(2026, 11, 22, 10, 0, 0, 0, time.UTC)
	refused := map[string]Envelope{
		"oauth without an owner":       {Credential: Credential{AccessToken: marker, AccessExpiresAt: at, AccessIssuedAt: at}, RefreshToken: marker},
		"oauth with a bad owner":       {Credential: Credential{AccessToken: marker, AccessExpiresAt: at, AccessIssuedAt: at, RefreshOwner: string(marker)}, RefreshToken: marker},
		"oauth with a token's field":   {Credential: Credential{AccessToken: marker, AccessExpiresAt: at, AccessIssuedAt: at, RefreshOwner: "local", Value: marker}, RefreshToken: marker},
		"oauth over its access bound":  {Credential: Credential{AccessToken: bytes.Repeat(marker, MaxEnvelopeSize), AccessExpiresAt: at, AccessIssuedAt: at, RefreshOwner: "local"}, RefreshToken: marker},
		"token without an expiry":      {Credential: Credential{Value: marker, IssuedAt: at}},
		"token with oauth's field":     {Credential: Credential{Value: marker, IssuedAt: at, ExpiresAt: at, AccessToken: marker}},
		"ssh with a short seed":        {Credential: Credential{Algorithm: SSHAlgorithmEd25519, Seed: marker}},
		"ssh with a bad algorithm":     {Credential: Credential{Algorithm: 9, Seed: bytes.Repeat(marker, 8)}},
		"ssh with a token's field":     {Credential: Credential{Algorithm: SSHAlgorithmEd25519, Seed: bytes.Repeat(marker, 8), Value: marker}},
		"oauth with the comment field": {Credential: Credential{AccessToken: marker, AccessExpiresAt: at, AccessIssuedAt: at, RefreshOwner: "local", Comment: string(marker)}, RefreshToken: marker},
	}
	for name, e := range refused {
		for _, kind := range fuzzKinds {
			_, err := Encode(kind, e)
			if err == nil {
				continue // valid for another kind's reading; nothing to check
			}
			msg := err.Error()
			if strings.Contains(msg, string(marker)) || strings.Contains(msg, hex.EncodeToString(marker)) {
				t.Errorf("Encode %s as %s: the refusal carries the 4-byte secret: %v", name, kind, err)
			}
		}
	}
	if _, err := ImportSSH(append([]byte("Zq9X"), marker...)); err == nil || strings.Contains(err.Error(), string(marker)) {
		t.Errorf("ImportSSH of a short input: %v", err)
	}
}

// refusalsHideRefreshToken plants marker as the refresh token of an oauth
// envelope, breaks the envelope around it in every way Decode refuses, and
// checks no refusal carries the marker, raw or hex, nor leakWindow input
// bytes in a row.
func refusalsHideRefreshToken(t *testing.T, marker []byte) {
	t.Helper()
	at := time.Date(2026, 11, 22, 10, 0, 0, 0, time.UTC)
	good, err := Encode(credential.KindOAuth, Envelope{
		Credential: Credential{
			AccessToken:     []byte("access"),
			AccessExpiresAt: at.Add(time.Hour),
			AccessIssuedAt:  at,
			RefreshOwner:    "local",
		},
		RefreshToken: marker,
	})
	if err != nil {
		t.Fatal(err)
	}
	refresh := bytes.Index(good, marker) - 3 // the refresh token's field header
	if refresh < 1 || good[refresh] != tagRefreshToken {
		t.Fatalf("the marker is not the refresh token field in %x", good)
	}
	field := func(tag byte, v []byte) []byte {
		return append(binary.BigEndian.AppendUint16([]byte{tag}, uint16(len(v))), v...)
	}
	splice := func(parts ...[]byte) []byte { return bytes.Join(parts, nil) }
	head, tail := good[:refresh], good[refresh+3+len(marker):]
	big := bytes.Repeat(marker, MaxRefreshToken/len(marker)+1)
	cases := map[string][]byte{
		"envelope version 0":           splice([]byte{0}, good[1:]),
		"envelope version 2":           splice([]byte{2}, good[1:]),
		"oversized":                    splice(good, bytes.Repeat(marker, MaxEnvelopeSize/len(marker)+1)),
		"truncated inside the token":   good[:refresh+3+len(marker)/2],
		"truncated field header":       splice(good, []byte{0x40, 0}),
		"length past the end":          splice(head, []byte{tagRefreshToken, 0xff, 0xff}, marker),
		"refresh token over its bound": splice(head, field(tagRefreshToken, big), tail),
		"empty refresh token":          splice(head, field(tagRefreshToken, nil), tail),
		"refresh token missing":        splice(head, tail),
		"refresh token repeated":       splice(head, field(tagRefreshToken, marker), field(tagRefreshToken, marker), tail),
		"refresh token out of order":   splice(good[:1], field(tagRefreshToken, marker), good[1:refresh], tail),
		"unknown tag carrying it":      splice(head, field(0x3f, marker), tail),
		"another kind's tag":           splice(head, field(tagValue, marker), tail),
		"trailing field after owner":   splice(good, field(0x37, marker)),
		"refresh owner is the marker":  splice(head, field(tagRefreshToken, marker), good[bytes.LastIndexByte(good, tagRefreshOwner):bytes.LastIndexByte(good, tagRefreshOwner)+1], binary.BigEndian.AppendUint16(nil, uint16(len(marker))), marker),
	}
	for name, in := range cases {
		for _, kind := range fuzzKinds {
			_, err := Decode(kind, in)
			if err == nil {
				t.Errorf("%s as %s: decoded", name, kind)
				continue
			}
			msg := err.Error()
			if bytes.Contains([]byte(msg), marker) || strings.Contains(msg, hex.EncodeToString(marker)) {
				t.Errorf("%s as %s: the refusal carries the marker: %v", name, kind, err)
			}
			for _, s := range []error{ErrCorrupt, ErrKindUnsupported} {
				msg = strings.ReplaceAll(msg, s.Error(), "")
			}
			if at, ok := windowLeak(msg, in); ok {
				t.Errorf("%s as %s: the refusal carries input bytes %d to %d: %v", name, kind, at, at+leakWindow, err)
			}
		}
	}
}

// TestKindUnsupportedNamesAlteration: a single flipped byte can make an
// envelope version read as unknown, so the refusal names alteration and a
// restore beside an upgrade, and never steers an operator only to upgrade.
func TestKindUnsupportedNamesAlteration(t *testing.T) {
	msg := ErrKindUnsupported.Error()
	for _, want := range []string{"upgrade k3sm", "or the file was altered", "if this k3sm is current, restore it from backup"} {
		if !strings.Contains(msg, want) {
			t.Errorf("ErrKindUnsupported %q does not say %q", msg, want)
		}
	}
}

// TestFieldTablesSortedByTag is U143's table invariant: each kind's field
// table is strictly increasing by tag, the order Decode walks it in.
func TestFieldTablesSortedByTag(t *testing.T) {
	for kind, fs := range fields {
		for i := 1; i < len(fs); i++ {
			if fs[i].tag <= fs[i-1].tag {
				t.Errorf("kind %s: %s (tag %#02x) does not follow %s (tag %#02x)", kind, fs[i].name, fs[i].tag, fs[i-1].name, fs[i-1].tag)
			}
		}
	}
}

// TestDecodeRefusalClearsClones is the zeroing rule's Decode half: a Decode
// refused after it copied fields out clears those copies, which the caller
// never sees, before it returns.
func TestDecodeRefusalClearsClones(t *testing.T) {
	good, err := Encode(credential.KindOAuth, Envelope{
		Credential: Credential{
			AccessToken:     []byte("ACCESSmarker"),
			AccessExpiresAt: time.Unix(1_800_000_000, 0),
			AccessIssuedAt:  time.Unix(1_799_990_000, 0),
			RefreshOwner:    "local",
		},
		RefreshToken: []byte("REFRESHmarker"),
	})
	if err != nil {
		t.Fatal(err)
	}
	var seen []Envelope
	decodeRefused = func(e *Envelope) { seen = append(seen, *e) }
	t.Cleanup(func() { decodeRefused = func(*Envelope) {} })
	// A truncated field header after every field: refused once all are set.
	if _, err := Decode(credential.KindOAuth, append(bytes.Clone(good), 0x40)); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("Decode of a trailing truncated header: %v, want ErrCorrupt", err)
	}
	if len(seen) != 1 {
		t.Fatalf("decodeRefused called %d times, want 1", len(seen))
	}
	e := seen[0]
	for name, b := range map[string][]byte{"accessToken": e.Credential.AccessToken, "refreshToken": e.RefreshToken} {
		if len(b) == 0 {
			t.Fatalf("the refused Decode had not copied %s", name)
		}
		if !bytes.Equal(b, make([]byte, len(b))) {
			t.Fatalf("the refused Decode left its copy of %s: %q", name, b)
		}
	}
}

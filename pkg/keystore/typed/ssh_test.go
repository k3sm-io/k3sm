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
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/iotest"

	"golang.org/x/crypto/ssh"
)

// fixtureSeed is the seed of the ed25519 key testdata/ssh/ed25519.pub holds
// the public half of. No private key is committed: each private fixture is
// built here, so the repository carries no PEM private-key block.
var fixtureSeed = sha256.Sum256([]byte("k3sm-typed-test ed25519 fixture"))

// fixtureComment is the comment ed25519.pub carries.
const fixtureComment = "k3sm-typed-test"

// sshPEM encodes key as an OpenSSH private key, encrypted under passphrase
// when it is not empty.
func sshPEM(t testing.TB, key crypto.PrivateKey, passphrase string) []byte {
	t.Helper()
	var (
		blk *pem.Block
		err error
	)
	if passphrase == "" {
		blk, err = ssh.MarshalPrivateKey(key, fixtureComment)
	} else {
		blk, err = ssh.MarshalPrivateKeyWithPassphrase(key, fixtureComment, []byte(passphrase))
	}
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(blk)
}

// sshFixtures returns the private-key fixtures: the ed25519 key of
// fixtureSeed, unencrypted and encrypted, and an RSA and an ECDSA key.
func sshFixtures(t testing.TB) (ed, encrypted, rsaKey, ecdsaKey []byte) {
	t.Helper()
	priv := ed25519.NewKeyFromSeed(fixtureSeed[:])
	r, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	// A fixed scalar: the ECDSA fixture needs no randomness at all.
	scalar := sha256.Sum256([]byte("k3sm-typed-test ecdsa fixture"))
	ec, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), scalar[:])
	if err != nil {
		t.Fatal(err)
	}
	return sshPEM(t, priv, ""), sshPEM(t, priv, "k3sm-test-passphrase"), sshPEM(t, r, ""), sshPEM(t, ec, "")
}

func readSSH(t testing.TB, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "ssh", name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestSSHGenerateAndImport(t *testing.T) {
	t.Run("generate draws the seed from the random seam", func(t *testing.T) {
		seed, err := GenerateSSH(bytes.NewReader(seq(40)))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(seed, seq(32)) {
			t.Fatalf("seed %x, want the first 32 bytes the seam gave", seed)
		}
		if _, err := GenerateSSH(bytes.NewReader(seq(31))); err == nil {
			t.Fatal("a short read of the seam gave a seed")
		}
		if _, err := GenerateSSH(iotest.ErrReader(errors.New("boom"))); err == nil {
			t.Fatal("a failed read of the seam gave a seed")
		}
	})

	key, encrypted, rsaKey, ecdsaKey := sshFixtures(t)
	t.Run("an unencrypted OpenSSH ed25519 key imports", func(t *testing.T) {
		seed, err := ImportSSH(key)
		if err != nil {
			t.Fatal(err)
		}
		// The committed public half, whose ssh-keygen fingerprint is
		// committed too, is the seed's.
		if !bytes.Equal(seed, fixtureSeed[:]) {
			t.Fatalf("seed %x, want the fixture's", seed)
		}
		line, err := SSHAuthorizedKey(seed, fixtureComment)
		if err != nil {
			t.Fatal(err)
		}
		if want := strings.TrimSpace(string(readSSH(t, "ed25519.pub"))); line != want {
			t.Fatalf("authorized key %q, want %q", line, want)
		}
		// Surrounding whitespace is not content.
		if again, err := ImportSSH(append(append([]byte("\n  "), key...), "\n\n"...)); err != nil || !bytes.Equal(again, seed) {
			t.Fatalf("import with whitespace: %v", err)
		}
	})

	pkcs8, err := x509.MarshalPKCS8PrivateKey(ed25519.NewKeyFromSeed(seq(32)))
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(ed25519.NewKeyFromSeed(seq(32)))
	if err != nil {
		t.Fatal(err)
	}
	mismatched := func() []byte {
		priv := ed25519.NewKeyFromSeed(seq(32))
		other := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{9}, 32))
		copy(priv[32:], other[32:])
		blk, err := ssh.MarshalPrivateKey(priv, "")
		if err != nil {
			t.Fatal(err)
		}
		return pem.EncodeToMemory(blk)
	}()
	headered := pem.EncodeToMemory(&pem.Block{Type: "OPENSSH PRIVATE KEY", Headers: map[string]string{"Proc-Type": "4,ENCRYPTED"}, Bytes: []byte("x")})
	refused := []struct {
		name string
		b    []byte
	}{
		{"empty", nil},
		{"encrypted", encrypted},
		{"rsa", rsaKey},
		{"ecdsa", ecdsaKey},
		{"an ssh certificate", readSSH(t, "ed25519-cert.pub")},
		{"a public key", readSSH(t, "ed25519.pub")},
		{"pkcs8 ed25519", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8})},
		{"the raw seed", seq(32)},
		{"the authorized key line", ssh.MarshalAuthorizedKey(signer.PublicKey())},
		{"text before the block", append([]byte("junk\n"), key...)},
		{"a second block after it", append(bytes.Clone(key), key...)},
		{"text after the block", append(bytes.Clone(key), "junk"...)},
		{"pem headers", headered},
		{"a public half that is not the seed's", mismatched},
		{"truncated", key[:len(key)/2]},
		{"over the size bound", append(bytes.Clone(key), bytes.Repeat([]byte(" "), MaxSSHImport)...)},
	}
	for _, tt := range refused {
		t.Run("refuses "+tt.name, func(t *testing.T) {
			seed, err := ImportSSH(tt.b)
			if !errors.Is(err, ErrInvalidCredential) || seed != nil {
				t.Fatalf("import: %x, %v, want ErrInvalidCredential", seed, err)
			}
		})
	}
}

// TestSSHFingerprintMatchesOpenSSH checks the fingerprint against ssh-keygen's
// own output for the committed public key, not against the library it is
// built on: importing the private key of the same seed yields that string.
func TestSSHFingerprintMatchesOpenSSH(t *testing.T) {
	out := strings.Fields(string(readSSH(t, "ed25519.ssh-keygen-l")))
	if len(out) < 2 || !strings.HasPrefix(out[1], "SHA256:") {
		t.Fatalf("ssh-keygen output %q does not parse", out)
	}
	seed, err := ImportSSH(sshPEM(t, ed25519.NewKeyFromSeed(fixtureSeed[:]), ""))
	if err != nil {
		t.Fatal(err)
	}
	got, err := SSHFingerprint(seed)
	if err != nil {
		t.Fatal(err)
	}
	if got != out[1] {
		t.Fatalf("fingerprint %s, ssh-keygen -l says %s", got, out[1])
	}
	if _, err := SSHFingerprint(seq(31)); !errors.Is(err, ErrInvalidCredential) {
		t.Fatalf("a 31-byte seed: %v, want ErrInvalidCredential", err)
	}
}

func TestSSHAuthorizedKeyComment(t *testing.T) {
	line, err := SSHAuthorizedKey(seq(32), "")
	if err != nil || strings.Count(line, " ") != 1 || strings.HasSuffix(line, "\n") {
		t.Fatalf("no comment: %q, %v", line, err)
	}
	for _, c := range []string{"a\nb", strings.Repeat("a", MaxComment+1), "é"} {
		if _, err := SSHAuthorizedKey(seq(32), c); !errors.Is(err, ErrInvalidCredential) {
			t.Errorf("comment %q: %v, want ErrInvalidCredential", c, err)
		}
	}
}

// opensshKey is an OpenSSH private-key file built field by field
// (openssh-key-v1, PROTOCOL.key), so a test can make the malformed shapes no
// encoder writes. Each of keys is a seed; check2 is XORed into the second
// check int; pad replaces the padding when it is not nil.
type opensshKey struct {
	cipher, kdf string
	kdfOpts     []byte
	keys        [][32]byte
	check2      uint32
	comment     string
	pad         []byte
}

// pem returns k encoded, the PEM header built from the block type rather
// than written out, so no private-key header is a literal in the source.
func (k opensshKey) pem() []byte {
	str := func(b []byte) []byte { return append(binary.BigEndian.AppendUint32(nil, uint32(len(b))), b...) }
	u32 := func(v uint32) []byte { return binary.BigEndian.AppendUint32(nil, v) }
	var pub, priv []byte
	priv = append(priv, u32(0x5eed1234)...)
	priv = append(priv, u32(0x5eed1234^k.check2)...)
	for _, seed := range k.keys {
		sk := ed25519.NewKeyFromSeed(seed[:])
		pk := sk.Public().(ed25519.PublicKey)
		blob := append(str([]byte(ssh.KeyAlgoED25519)), str(pk)...)
		pub = append(pub, str(blob)...)
		priv = append(priv, str([]byte(ssh.KeyAlgoED25519))...)
		priv = append(priv, str(pk)...)
		priv = append(priv, str(sk)...)
		priv = append(priv, str([]byte(k.comment))...)
	}
	pad := k.pad
	if pad == nil {
		for i := 1; (len(priv)+len(pad))%8 != 0; i++ {
			pad = append(pad, byte(i))
		}
	}
	priv = append(priv, pad...)
	body := []byte("openssh-key-v1\x00")
	body = append(body, str([]byte(k.cipher))...)
	body = append(body, str([]byte(k.kdf))...)
	body = append(body, str(k.kdfOpts)...)
	body = append(body, u32(uint32(len(k.keys)))...)
	body = append(body, pub...)
	body = append(body, str(priv)...)
	return pem.EncodeToMemory(&pem.Block{Type: openSSHBlockType, Bytes: body})
}

// malformedSSH are the shapes ImportSSH must refuse, built in the test.
func malformedSSH() map[string][]byte {
	one := [][32]byte{fixtureSeed}
	return map[string][]byte{
		"two keys in one file":    opensshKey{cipher: "none", kdf: "none", keys: [][32]byte{fixtureSeed, sha256.Sum256([]byte("second"))}}.pem(),
		"mismatched check ints":   opensshKey{cipher: "none", kdf: "none", keys: one, check2: 1}.pem(),
		"kdf bcrypt, cipher none": opensshKey{cipher: "none", kdf: "bcrypt", kdfOpts: append(binary.BigEndian.AppendUint32(nil, 16), make([]byte, 20)...), keys: one}.pem(),
		"bad padding":             opensshKey{cipher: "none", kdf: "none", keys: one, pad: []byte{1, 2, 4, 4, 5, 6, 7}}.pem(),
		"no keys":                 opensshKey{cipher: "none", kdf: "none"}.pem(),
	}
}

// TestSSHImportRefusesMalformed: each malformed shape is refused with the
// one fixed reason, and the builder itself is sound: its well-formed key,
// with an oversized comment, imports as the seed (the comment is not
// imported).
func TestSSHImportRefusesMalformed(t *testing.T) {
	for name, b := range malformedSSH() {
		if _, err := ImportSSH(b); err != errSSHRefused {
			t.Errorf("%s: %v, want the fixed refusal", name, err)
		}
	}
	good := opensshKey{cipher: "none", kdf: "none", keys: [][32]byte{fixtureSeed}, comment: strings.Repeat("c", 4*MaxComment)}.pem()
	seed, err := ImportSSH(good)
	if err != nil || !bytes.Equal(seed, fixtureSeed[:]) {
		t.Fatalf("the builder's well-formed key with an oversized comment: %x, %v", seed, err)
	}
}

// FuzzSSHImport: the import never panics, refuses with the one fixed reason
// (so no input byte reaches a message), and what it accepts is a seed whose
// key round-trips through OpenSSH's encoding to the same seed.
func FuzzSSHImport(f *testing.F) {
	ed, encrypted, rsaKey, ecdsaKey := sshFixtures(f)
	for _, b := range [][]byte{ed, encrypted, rsaKey, ecdsaKey, readSSH(f, "ed25519-cert.pub")} {
		f.Add(b)
	}
	for _, b := range malformedSSH() {
		f.Add(b)
	}
	f.Add(opensshKey{cipher: "none", kdf: "none", keys: [][32]byte{fixtureSeed}, comment: strings.Repeat("c", 4*MaxComment)}.pem())
	f.Fuzz(func(t *testing.T, b []byte) {
		seed, err := ImportSSH(b)
		if err != nil {
			if err != errSSHRefused {
				t.Fatalf("refusal %v is not the fixed reason", err)
			}
			// The refusal never carries leakWindow bytes of the input in a row.
			if at, ok := windowLeak(err.Error(), b); ok {
				t.Fatalf("the refusal carries input bytes %d to %d: %v", at, at+leakWindow, err)
			}
			return
		}
		if len(seed) != ed25519.SeedSize {
			t.Fatalf("accepted a %d-byte seed", len(seed))
		}
		blk, err := ssh.MarshalPrivateKey(ed25519.NewKeyFromSeed(seed), "")
		if err != nil {
			t.Fatal(err)
		}
		again, err := ImportSSH(pem.EncodeToMemory(blk))
		if err != nil || !bytes.Equal(again, seed) {
			t.Fatalf("the accepted key does not round-trip: %v", err)
		}
	})
}

// TestSSHSeedLengthError names the length wanted, never the seed's own:
// a seed's length is part of a secret's shape.
func TestSSHSeedLengthError(t *testing.T) {
	_, err := SSHFingerprint(make([]byte, 31))
	if err == nil || !strings.Contains(err.Error(), "an ssh seed is not 32 bytes") || strings.Contains(err.Error(), "31") {
		t.Fatalf("SSHFingerprint of a 31-byte seed: %v, want it to name 32 bytes and not 31", err)
	}
}

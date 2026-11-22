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
	"crypto/ed25519"
	"encoding/pem"
	"fmt"
	"io"
	"strings"

	"golang.org/x/crypto/ssh"
)

// seedSize is an ed25519 seed's size, the ssh envelope's seed length.
const seedSize = ed25519.SeedSize

// MaxSSHImport bounds what ImportSSH reads. An unencrypted OpenSSH ed25519
// key with a 255-byte comment is under 1 KiB of PEM; the bound leaves room
// and keeps the parser off anything large, such as a big RSA key.
const MaxSSHImport = 4 << 10

// openSSHBlockType is the PEM type of an OpenSSH private key.
const openSSHBlockType = "OPENSSH PRIVATE KEY"

// errSSHRefused is the one reason an import is refused. It names no input
// byte: the parser's own messages can quote the input (a PEM type, a curve
// name), so none of them is passed on.
var errSSHRefused = fmt.Errorf("%w: the ssh key must be an unencrypted OpenSSH ed25519 private key", ErrInvalidCredential)

// GenerateSSH returns a fresh ed25519 seed read from random, the store's
// random seam. A short or failed read is an error, never a partial seed.
func GenerateSSH(random io.Reader) ([]byte, error) {
	seed := make([]byte, seedSize)
	if _, err := io.ReadFull(random, seed); err != nil {
		return nil, fmt.Errorf("read an ssh seed: %w", err)
	}
	return seed, nil
}

// ImportSSH returns the ed25519 seed of an unencrypted OpenSSH private key:
// one PEM block of type OPENSSH PRIVATE KEY, nothing but whitespace around
// it, at most MaxSSHImport bytes. It refuses everything else with
// ErrInvalidCredential and one fixed reason: an encrypted key, an RSA, ECDSA
// or other key, an SSH certificate, a PKCS#8 or other PEM type, and a key
// whose private half does not belong to its seed. The OpenSSH parsing is
// golang.org/x/crypto/ssh's; the comment in the file is not kept.
func ImportSSH(pemBytes []byte) ([]byte, error) {
	if len(pemBytes) > MaxSSHImport {
		return nil, errSSHRefused
	}
	trimmed := bytes.TrimLeft(pemBytes, " \t\r\n")
	if !bytes.HasPrefix(trimmed, []byte("-----BEGIN "+openSSHBlockType+"-----")) {
		return nil, errSSHRefused
	}
	block, rest := pem.Decode(trimmed)
	if block != nil {
		// The decoded body holds the private key; only the shape check
		// below reads it, and the parser decodes the PEM again itself.
		defer clear(block.Bytes)
	}
	if block == nil || block.Type != openSSHBlockType || len(block.Headers) != 0 || len(bytes.TrimSpace(rest)) != 0 {
		return nil, errSSHRefused
	}
	raw, err := ssh.ParseRawPrivateKey(trimmed)
	if err != nil {
		return nil, errSSHRefused
	}
	key, ok := raw.(*ed25519.PrivateKey)
	if !ok {
		clearRawKey(raw)
		return nil, errSSHRefused
	}
	defer clear(*key)
	if len(*key) != ed25519.PrivateKeySize {
		return nil, errSSHRefused
	}
	seed := key.Seed() // a copy, which the caller owns
	// The parser checks the private half's length, not that its public half
	// belongs to the seed; a key that disagrees with itself is refused.
	again := ed25519.NewKeyFromSeed(seed)
	defer clear(again)
	if !bytes.Equal(again, *key) {
		clear(seed)
		return nil, errSSHRefused
	}
	return seed, nil
}

// clearRawKey zeroes what of a refused parsed key is a byte slice in our
// hands: an ed25519 key by value. The parser's RSA and ECDSA keys hold
// big.Int values, which cannot be zeroed through their API.
func clearRawKey(raw any) {
	if k, ok := raw.(ed25519.PrivateKey); ok {
		clear(k)
	}
}

// sshPublicKey returns the SSH public key of an ed25519 seed.
func sshPublicKey(seed []byte) (ssh.PublicKey, error) {
	if len(seed) != seedSize {
		return nil, fmt.Errorf("%w: an ssh seed is %d bytes, not %d", ErrInvalidCredential, len(seed), seedSize)
	}
	pub, err := ssh.NewPublicKey(ed25519.NewKeyFromSeed(seed).Public())
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidCredential, err)
	}
	return pub, nil
}

// SSHFingerprint returns the OpenSSH SHA256 fingerprint of an ed25519 seed's
// public key, SHA256:<unpadded base64>, the string ssh-keygen -l and a forge
// show.
func SSHFingerprint(seed []byte) (string, error) {
	pub, err := sshPublicKey(seed)
	if err != nil {
		return "", err
	}
	return ssh.FingerprintSHA256(pub), nil
}

// SSHAuthorizedKey returns the authorized_keys line of an ed25519 seed's
// public key, with comment appended when it is not empty, and no trailing
// newline. A comment must be printable ASCII of at most MaxComment bytes.
func SSHAuthorizedKey(seed []byte, comment string) (string, error) {
	if len(comment) > MaxComment || !printableASCII([]byte(comment)) {
		return "", fmt.Errorf("%w: the comment must be at most %d bytes of printable ASCII", ErrInvalidCredential, MaxComment)
	}
	pub, err := sshPublicKey(seed)
	if err != nil {
		return "", err
	}
	line := strings.TrimSuffix(string(ssh.MarshalAuthorizedKey(pub)), "\n")
	if comment != "" {
		line += " " + comment
	}
	return line, nil
}

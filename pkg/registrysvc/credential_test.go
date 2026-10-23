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

package registrysvc

import (
	"errors"
	"os"
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

// TestGenerateCredential pins the two properties a per-boot secret must have:
// it is different every time, and it survives an htpasswd line, a URL and a shell
// word without escaping.
func TestGenerateCredential(t *testing.T) {
	a, err := generateCredential("127.0.0.1:6450")
	if err != nil {
		t.Fatalf("generateCredential: %v", err)
	}
	b, err := generateCredential("127.0.0.1:6450")
	if err != nil {
		t.Fatalf("generateCredential: %v", err)
	}
	if a.Password == b.Password {
		t.Fatal("two credentials share a password; the secret is not being generated per call")
	}
	if a.Username != pushUser {
		t.Errorf("username = %q, want %q", a.Username, pushUser)
	}
	if a.Address != "127.0.0.1:6450" {
		t.Errorf("address = %q, want the bind it was minted for", a.Address)
	}
	if strings.ContainsAny(a.Password, ":/+= \t\n") {
		t.Errorf("password %q contains a character that needs escaping in an htpasswd line or a URL", a.Password)
	}
	if len(a.Password) < 40 {
		t.Errorf("password is %d characters, far short of %d bytes of entropy", len(a.Password), pushSecretBytes)
	}
}

// TestWriteCredential pins the whole on-disk credential contract: the bcrypt hash
// zot will verify against, the plaintext file `k3sm image push` reads back, and
// 0600 on both — a world-readable push credential is a world-writable image store.
func TestWriteCredential(t *testing.T) {
	work := t.TempDir()
	if err := os.MkdirAll(StateDir(work), 0o700); err != nil {
		t.Fatalf("create the state dir: %v", err)
	}
	cred, err := generateCredential("127.0.0.1:6450")
	if err != nil {
		t.Fatalf("generateCredential: %v", err)
	}
	if err := WriteCredential(work, cred); err != nil {
		t.Fatalf("WriteCredential: %v", err)
	}

	t.Run("the htpasswd hash verifies against the plaintext password", func(t *testing.T) {
		b, err := os.ReadFile(HTPasswdPath(work))
		if err != nil {
			t.Fatalf("read htpasswd: %v", err)
		}
		user, hash, ok := strings.Cut(strings.TrimSpace(string(b)), ":")
		if !ok {
			t.Fatalf("htpasswd line %q is not user:hash", b)
		}
		if user != cred.Username {
			t.Errorf("htpasswd user = %q, want %q", user, cred.Username)
		}
		// zot accepts $2a/$2b/$2y bcrypt; anything else is silently unauthenticable.
		if !strings.HasPrefix(hash, "$2a$") && !strings.HasPrefix(hash, "$2b$") && !strings.HasPrefix(hash, "$2y$") {
			t.Fatalf("htpasswd hash %q is not a bcrypt hash zot accepts", hash)
		}
		if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(cred.Password)); err != nil {
			t.Fatalf("the htpasswd hash does not verify the password it was minted from: %v", err)
		}
		if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(cred.Password+"x")); err == nil {
			t.Fatal("the htpasswd hash verifies a wrong password")
		}
	})

	t.Run("the plaintext credential round-trips", func(t *testing.T) {
		got, err := ReadCredential(work)
		if err != nil {
			t.Fatalf("ReadCredential: %v", err)
		}
		if got != cred {
			t.Errorf("ReadCredential = %+v, want %+v", got, cred)
		}
	})

	t.Run("both files are 0600", func(t *testing.T) {
		for _, p := range []string{HTPasswdPath(work), CredentialPath(work)} {
			fi, err := os.Stat(p)
			if err != nil {
				t.Fatalf("stat %s: %v", p, err)
			}
			if fi.Mode().Perm() != 0o600 {
				t.Errorf("%s mode = %o, want 600", p, fi.Mode().Perm())
			}
		}
	})

	t.Run("a rewrite replaces the credential wholesale", func(t *testing.T) {
		next, err := generateCredential("127.0.0.1:6450")
		if err != nil {
			t.Fatalf("generateCredential: %v", err)
		}
		if err := WriteCredential(work, next); err != nil {
			t.Fatalf("WriteCredential: %v", err)
		}
		got, err := ReadCredential(work)
		if err != nil {
			t.Fatalf("ReadCredential: %v", err)
		}
		if got.Password != next.Password {
			t.Errorf("password after rewrite = %q, want the new one", got.Password)
		}
		b, err := os.ReadFile(HTPasswdPath(work))
		if err != nil {
			t.Fatalf("read htpasswd: %v", err)
		}
		_, hash, _ := strings.Cut(strings.TrimSpace(string(b)), ":")
		if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(next.Password)); err != nil {
			t.Fatalf("the rewritten htpasswd does not match the rewritten password: %v", err)
		}
	})
}

// TestReadCredentialFailures pins the two shapes a caller distinguishes: absent
// (the registry is disabled — an ordinary answer) versus unusable (a real fault).
func TestReadCredentialFailures(t *testing.T) {
	t.Run("absent yields ErrNoCredential", func(t *testing.T) {
		_, err := ReadCredential(t.TempDir())
		if !errors.Is(err, ErrNoCredential) {
			t.Fatalf("ReadCredential on an empty work dir = %v, want ErrNoCredential", err)
		}
	})

	cases := []struct {
		name string
		body string
	}{
		{"not JSON", "not json at all"},
		{"empty object", "{}"},
		{"no password", `{"address":"127.0.0.1:6450","username":"k3sm"}`},
		{"no address", `{"username":"k3sm","password":"s"}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			work := t.TempDir()
			if err := os.MkdirAll(StateDir(work), 0o700); err != nil {
				t.Fatalf("create the state dir: %v", err)
			}
			if err := os.WriteFile(CredentialPath(work), []byte(tc.body), 0o600); err != nil {
				t.Fatalf("write: %v", err)
			}
			_, err := ReadCredential(work)
			if err == nil {
				t.Fatalf("ReadCredential(%q) = nil, want an error", tc.body)
			}
			if errors.Is(err, ErrNoCredential) {
				t.Errorf("a malformed credential reported as absent; the two must stay distinguishable")
			}
		})
	}
}

// TestCredentialMatchesRegistry pins which push targets the local credential is
// presented to. It is the whole containment of the secret: a match sends the
// password to this node's own registry, and every non-match must leave it on disk.
func TestCredentialMatchesRegistry(t *testing.T) {
	cred := Credential{Address: "127.0.0.1:6450", Username: pushUser, Password: "s"}
	cases := []struct {
		registry string
		want     bool
	}{
		{"127.0.0.1:6450", true},
		{"localhost:6450", true},
		{"LOCALHOST:6450", true},
		{"[::1]:6450", true},
		{"127.0.0.1:6451", false},
		{"localhost:5000", false},
		{"localhost", false},
		{"", false},
		{"ghcr.io", false},
		{"registry.example.com:6450", false},
		{"192.168.1.5:6450", false},
		{"127.0.0.1.example.com:6450", false},
	}
	for _, tc := range cases {
		t.Run(tc.registry, func(t *testing.T) {
			if got := cred.MatchesRegistry(tc.registry); got != tc.want {
				t.Errorf("MatchesRegistry(%q) = %v, want %v", tc.registry, got, tc.want)
			}
		})
	}
}

// TestCredentialWithoutAddressMatchesNothing pins the fail-closed direction: a
// credential file that lost its address must not become a credential for every
// loopback port on the machine.
func TestCredentialWithoutAddressMatchesNothing(t *testing.T) {
	cred := Credential{Username: pushUser, Password: "s"}
	for _, reg := range []string{"localhost:6450", "127.0.0.1:6450", ""} {
		if cred.MatchesRegistry(reg) {
			t.Errorf("an address-less credential matched %q", reg)
		}
	}
}

// TestWriteCredentialGateUser pins the push gate's credential on disk: its
// bcrypt line sits in the htpasswd file beside the local CLI's, and its
// plaintext password appears in no file at all, because the gate holds it in
// memory and nothing else ever presents it.
func TestWriteCredentialGateUser(t *testing.T) {
	work := t.TempDir()
	if err := os.MkdirAll(StateDir(work), 0o700); err != nil {
		t.Fatalf("create the state dir: %v", err)
	}
	cred, err := generateCredential("127.0.0.1:6450")
	if err != nil {
		t.Fatalf("generateCredential: %v", err)
	}
	gate, err := generateGateCredential("127.0.0.1:6450")
	if err != nil {
		t.Fatalf("generateGateCredential: %v", err)
	}
	if gate.Username != gateUser || gate.Password == cred.Password {
		t.Fatalf("gate credential = %+v, want user %q with its own password", gate, gateUser)
	}
	if err := WriteCredential(work, cred, gate); err != nil {
		t.Fatalf("WriteCredential: %v", err)
	}
	b, err := os.ReadFile(HTPasswdPath(work))
	if err != nil {
		t.Fatalf("read htpasswd: %v", err)
	}
	hashes := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		user, hash, _ := strings.Cut(line, ":")
		hashes[user] = hash
	}
	for _, c := range []Credential{cred, gate} {
		if err := bcrypt.CompareHashAndPassword([]byte(hashes[c.Username]), []byte(c.Password)); err != nil {
			t.Errorf("htpasswd line for %q does not verify its password: %v", c.Username, err)
		}
	}
	got, err := ReadCredential(work)
	if err != nil {
		t.Fatalf("ReadCredential: %v", err)
	}
	if got != cred {
		t.Errorf("the plaintext file holds %+v, want the local CLI's credential only", got)
	}
	entries, err := os.ReadDir(StateDir(work))
	if err != nil {
		t.Fatalf("read the state dir: %v", err)
	}
	for _, e := range entries {
		body, err := os.ReadFile(StateDir(work) + "/" + e.Name())
		if err != nil {
			continue
		}
		if strings.Contains(string(body), gate.Password) {
			t.Errorf("%s holds the gate's plaintext password", e.Name())
		}
	}
}

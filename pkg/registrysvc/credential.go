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
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

// pushUser is the single identity the registry admits a write from. It is a
// constant rather than a generated name because the SECRET is the password: a
// random username would add no entropy an attacker cannot enumerate off a 401,
// while a stable one keeps the htpasswd file and the failure messages readable.
const pushUser = "k3sm"

// pushSecretBytes is the entropy behind the generated password. 32 bytes of
// crypto/rand is far past any brute-force reachable through zot's authentication
// path, which is rate-limited by a fail delay and by bcrypt's own cost.
const pushSecretBytes = 32

// ErrNoCredential is returned when no credential file exists at the named path.
// It is a sentinel because "the registry is not running / not enabled" and "the
// credential is unreadable" call for different responses from a caller, and a
// caller that has to match message text will eventually match the wrong one.
var ErrNoCredential = errors.New("no local registry credential")

// Credential is the username/password pair the registry admits a push from, plus
// the loopback address it is valid at.
//
// Address is carried WITH the secret on purpose: `k3sm image push` decides
// whether to present this credential by comparing the push target's registry to
// it, and a credential that did not know its own address would either have to be
// presented to every loopback port (leaking it to whatever else is listening) or
// be paired with a second source of truth for the port.
type Credential struct {
	Address  string `json:"address"`
	Username string `json:"username"`
	Password string `json:"password"`
}

// StateDir returns the registry state root for a control-plane work dir.
func StateDir(workDir string) string { return filepath.Join(workDir, "registry") }

// ConfigPath returns the rendered zot config path for a work dir.
func ConfigPath(workDir string) string { return filepath.Join(StateDir(workDir), "config.json") }

// HTPasswdPath returns the bcrypt credential file zot authenticates against.
func HTPasswdPath(workDir string) string { return filepath.Join(StateDir(workDir), "htpasswd") }

// CredentialPath returns the plaintext push credential for a work dir —
// <work-dir>/registry/push-credential.json, mode 0600.
//
// This is the contract `k3sm image push` reads. It is a FUNCTION, not a string
// callers join themselves, so the pusher and the server can never disagree about
// where the credential lives.
func CredentialPath(workDir string) string {
	return filepath.Join(StateDir(workDir), "push-credential.json")
}

// LogPath returns the registry child's log file for a work dir. It sits beside
// the control plane's other component logs rather than inside the state dir,
// matching pkg/executor's <work-dir>/<component>.log convention.
func LogPath(workDir string) string { return filepath.Join(workDir, "registry.log") }

// generateCredential mints a fresh push credential for addr. A new password is
// generated on every call — the credential is per-boot, so nothing an earlier
// boot leaked is still valid.
func generateCredential(addr string) (Credential, error) {
	buf := make([]byte, pushSecretBytes)
	if _, err := rand.Read(buf); err != nil {
		return Credential{}, fmt.Errorf("generate the registry push password: %w", err)
	}
	return Credential{
		Address:  addr,
		Username: pushUser,
		// RawURL encoding: no padding and no '/' or '+', so the value survives a
		// URL, a shell word and an htpasswd line without quoting or escaping.
		Password: base64.RawURLEncoding.EncodeToString(buf),
	}, nil
}

// htpasswdLine renders the bcrypt htpasswd entry zot loads. zot accepts $2a/$2b/
// $2y bcrypt and $5$/$6$ SHA-crypt; bcrypt is what x/crypto can produce without a
// C library, so it is what k3sm writes.
func htpasswdLine(c Credential) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(c.Password), bcrypt.DefaultCost)
	if err != nil {
		return "", fmt.Errorf("hash the registry push password: %w", err)
	}
	return c.Username + ":" + string(hash) + "\n", nil
}

// WriteCredential writes both halves of the credential for workDir: the bcrypt
// htpasswd file zot authenticates against, and the plaintext file `k3sm image
// push` reads. Both are 0600.
//
// The plaintext file is written LAST, so a caller that finds it can rely on the
// htpasswd file beside it already vouching for the same password. Both are
// written through a temp name + rename, because a reader racing a rewrite must
// see one whole credential or the other, never a truncated one.
func WriteCredential(workDir string, c Credential) error {
	line, err := htpasswdLine(c)
	if err != nil {
		return err
	}
	if err := writeSecretFile(HTPasswdPath(workDir), []byte(line)); err != nil {
		return fmt.Errorf("write the registry htpasswd: %w", err)
	}
	body, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return fmt.Errorf("render the registry push credential: %w", err)
	}
	if err := writeSecretFile(CredentialPath(workDir), append(body, '\n')); err != nil {
		return fmt.Errorf("write the registry push credential: %w", err)
	}
	return nil
}

// ReadCredential loads the push credential written for workDir. A missing file
// yields ErrNoCredential — the ordinary answer on a node whose registry is
// disabled, which a caller reports as "no local credential" rather than as a
// failure.
func ReadCredential(workDir string) (Credential, error) {
	b, err := os.ReadFile(CredentialPath(workDir))
	if err != nil {
		if os.IsNotExist(err) {
			return Credential{}, fmt.Errorf("%w at %s", ErrNoCredential, CredentialPath(workDir))
		}
		return Credential{}, fmt.Errorf("read the registry push credential: %w", err)
	}
	var c Credential
	if err := json.Unmarshal(b, &c); err != nil {
		return Credential{}, fmt.Errorf("parse the registry push credential %s: %w", CredentialPath(workDir), err)
	}
	if c.Address == "" || c.Username == "" || c.Password == "" {
		return Credential{}, fmt.Errorf("registry push credential %s is incomplete (address/username/password)", CredentialPath(workDir))
	}
	return c, nil
}

// MatchesRegistry reports whether c is the credential for the registry named by
// a reference's registry component ("localhost:6450", "127.0.0.1:6450").
//
// The host is compared by NAME after normalising the loopback spellings, not by
// resolving it: a resolver answer is a runtime fact that can change, while the
// question here is whether the operator asked for THIS node's own registry. The
// port must match exactly, so a credential for one instance is never presented to
// another instance listening on a different loopback port.
func (c Credential) MatchesRegistry(registry string) bool {
	want, wantPort, ok := splitLoopback(c.Address)
	if !ok {
		return false
	}
	got, gotPort, ok := splitLoopback(registry)
	if !ok {
		return false
	}
	return want == got && wantPort == gotPort
}

// splitLoopback splits "host:port" and reports whether host is a loopback
// spelling, normalising every accepted spelling to "localhost" so the two sides
// of a comparison agree. Anything else — a hostname, a routable address, a
// missing port — is not a loopback registry and reports false.
func splitLoopback(hostPort string) (host, port string, ok bool) {
	i := strings.LastIndex(hostPort, ":")
	if i < 0 || i == len(hostPort)-1 {
		return "", "", false
	}
	host, port = hostPort[:i], hostPort[i+1:]
	switch strings.ToLower(strings.Trim(host, "[]")) {
	case "localhost", "127.0.0.1", "::1":
		return "localhost", port, true
	}
	return "", "", false
}

// writeSecretFile writes b to path at 0600 through a temp file in the same
// directory, so a reader never observes a partially written secret and an
// interrupted write never leaves a truncated one in place.
func writeSecretFile(path string, b []byte) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

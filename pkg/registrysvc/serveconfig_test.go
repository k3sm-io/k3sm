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
	"bytes"
	"os"
	"strings"
	"testing"

	"k3sm.io/k3sm/pkg/ociregistry/auth"
)

// TestServeConfig checks that the daemon writes both per-boot principals'
// SHA-256 secret hashes into the serve config, 0600 in a 0700 state dir
// outside the store root, with no plaintext secret, that the hashes match the
// credentials it minted, that a rewrite replaces them, and that the reader
// refuses anything it does not recognise.
func TestServeConfig(t *testing.T) {
	work := t.TempDir()
	s, err := New(Config{WorkDir: work, Port: 6450})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.provision(); err != nil {
		t.Fatal(err)
	}
	path := ServeConfigPath(work)
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("serve config mode %#o, want 0600", fi.Mode().Perm())
	}
	di, err := os.Stat(ServeStateDir(work))
	if err != nil {
		t.Fatal(err)
	}
	if di.Mode().Perm() != 0o700 {
		t.Errorf("state dir mode %#o, want 0700", di.Mode().Perm())
	}
	if strings.HasPrefix(ServeStateDir(work), StateDir(work)+string(os.PathSeparator)) {
		t.Errorf("state dir %s is inside the store root %s", ServeStateDir(work), StateDir(work))
	}
	push, err := ReadCredential(work)
	if err != nil {
		t.Fatal(err)
	}
	gate := s.GateCredential()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{push.Password, gate.Password} {
		if bytes.Contains(raw, []byte(secret)) {
			t.Errorf("the serve config carries a plaintext secret: %s", raw)
		}
	}
	cfg, err := ReadServeConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	want := []auth.Principal{
		{User: auth.UserPush, SecretSHA256: auth.HashSecret(push.Password)},
		{User: auth.UserGate, SecretSHA256: auth.HashSecret(gate.Password)},
	}
	if len(cfg.Principals) != 2 || cfg.Principals[0] != want[0] || cfg.Principals[1] != want[1] {
		t.Errorf("principals = %+v, want %+v", cfg.Principals, want)
	}

	// Each attempt mints new secrets, and the serve config follows them.
	if err := s.provision(); err != nil {
		t.Fatal(err)
	}
	again, err := ReadServeConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if again.Principals[0] == cfg.Principals[0] || again.Principals[1] == cfg.Principals[1] {
		t.Error("a second provision kept a principal's hash")
	}
	if push2, _ := ReadCredential(work); auth.HashSecret(push2.Password) != again.Principals[0].SecretSHA256 {
		t.Error("the serve config does not match the rewritten push credential")
	}

	refuse := []struct {
		name  string
		body  string
		mode  os.FileMode
		setup func(p string) error
	}{
		{"group-readable", string(raw), 0o640, nil},
		{"world-readable", string(raw), 0o604, nil},
		{"an unknown field", `{"principals":[],"htpasswd":"/x"}`, 0o600, nil},
		{"trailing data", string(raw) + `{}`, 0o600, nil},
		{"one principal", `{"principals":[{"user":"k3sm","secretSHA256":"` + want[0].SecretSHA256 + `"}]}`, 0o600, nil},
		{"a bcrypt hash", `{"principals":[{"user":"k3sm","secretSHA256":"$2a$10$abc"},{"user":"k3sm-gate","secretSHA256":"` + want[1].SecretSHA256 + `"}]}`, 0o600, nil},
		{"too large", `{"principals":[]` + strings.Repeat(" ", maxServeConfigBytes) + `}`, 0o600, nil},
		{"a symlink", "", 0, func(p string) error { return os.Symlink(path, p) }},
		{"a directory", "", 0, func(p string) error { return os.Mkdir(p, 0o700) }},
	}
	for _, tc := range refuse {
		t.Run("refuses "+tc.name, func(t *testing.T) {
			p := t.TempDir() + "/serve.json"
			if tc.setup != nil {
				if err := tc.setup(p); err != nil {
					t.Fatal(err)
				}
			} else {
				if err := os.WriteFile(p, []byte(tc.body), 0o600); err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(p, tc.mode); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := ReadServeConfig(p); err == nil {
				t.Fatal("ReadServeConfig accepted it")
			}
		})
	}
	t.Run("refuses credentials of the wrong users", func(t *testing.T) {
		if _, err := renderServeConfig(gate, push); err == nil {
			t.Fatal("renderServeConfig accepted swapped credentials")
		}
		if _, err := renderServeConfig(push, Credential{Username: gateUser}); err == nil {
			t.Fatal("renderServeConfig accepted an empty secret")
		}
	})
	t.Run("a stale temp file is replaced", func(t *testing.T) {
		tmp := path + ".tmp"
		if err := os.WriteFile(tmp, []byte("stale"), 0o666); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(tmp, 0o666); err != nil {
			t.Fatal(err)
		}
		if err := s.provision(); err != nil {
			t.Fatal(err)
		}
		if _, err := os.Stat(tmp); !os.IsNotExist(err) {
			t.Errorf("the temp file survived: %v", err)
		}
		if _, err := ReadServeConfig(path); err != nil {
			t.Fatal(err)
		}
	})
}

// TestServeStateDirHardening checks that writeServeConfig refuses a state dir
// that is a symlink or not a directory, and corrects the mode of one that is
// this user's own real directory.
func TestServeStateDirHardening(t *testing.T) {
	body := []byte("{}\n")
	t.Run("refuses a symlinked state dir", func(t *testing.T) {
		work := t.TempDir()
		target := t.TempDir()
		if err := os.Chmod(target, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, ServeStateDir(work)); err != nil {
			t.Fatal(err)
		}
		if err := writeServeConfig(work, body); err == nil {
			t.Fatal("writeServeConfig wrote through a symlinked state dir")
		}
		if _, err := os.Lstat(target + "/serve.json"); !os.IsNotExist(err) {
			t.Errorf("a serve config landed in the symlink target: %v", err)
		}
	})
	t.Run("refuses a state dir that is a file", func(t *testing.T) {
		work := t.TempDir()
		if err := os.WriteFile(ServeStateDir(work), nil, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := writeServeConfig(work, body); err == nil {
			t.Fatal("writeServeConfig accepted a regular file as the state dir")
		}
	})
	t.Run("corrects the mode of its own directory", func(t *testing.T) {
		work := t.TempDir()
		if err := os.Mkdir(ServeStateDir(work), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(ServeStateDir(work), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := writeServeConfig(work, body); err != nil {
			t.Fatal(err)
		}
		fi, err := os.Lstat(ServeStateDir(work))
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode().Perm() != 0o700 {
			t.Errorf("state dir mode %#o, want 0700", fi.Mode().Perm())
		}
	})
}

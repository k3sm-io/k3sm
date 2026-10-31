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
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"

	"k3sm.io/k3sm/pkg/ociregistry/auth"
)

// maxServeConfigBytes bounds the serve config a reader accepts.
const maxServeConfigBytes = 64 << 10

// ServeConfig is the k3sm registry server's configuration, written by the
// daemon on every boot. It carries only the SHA-256 hashes of the two
// per-boot secrets: the plaintext of the k3sm principal stays in
// push-credential.json, and the gate's in the daemon's memory.
type ServeConfig struct {
	Principals []auth.Principal `json:"principals"`
}

// ServeStateDir returns the registry server's state dir for a work dir:
// <work-dir>/registry-state, outside the store root.
func ServeStateDir(workDir string) string { return filepath.Join(workDir, "registry-state") }

// ServeConfigPath returns the serve config path for a work dir,
// <work-dir>/registry-state/serve.json, mode 0600.
func ServeConfigPath(workDir string) string {
	return filepath.Join(ServeStateDir(workDir), "serve.json")
}

// renderServeConfig renders the serve config for the push and gate
// credentials. It is pure.
func renderServeConfig(push, gate Credential) ([]byte, error) {
	if push.Username != pushUser || gate.Username != gateUser || push.Password == "" || gate.Password == "" {
		return nil, errors.New("render the registry serve config: the push and gate credentials are required")
	}
	cfg := ServeConfig{Principals: []auth.Principal{
		{User: auth.UserPush, SecretSHA256: auth.HashSecret(push.Password)},
		{User: auth.UserGate, SecretSHA256: auth.HashSecret(gate.Password)},
	}}
	b, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("render the registry serve config: %w", err)
	}
	return append(b, '\n'), nil
}

// writeServeConfig writes the serve config for workDir: the state dir at 0700,
// the file at 0600 through a fresh temp file and a rename, owned by this
// process's user (the service user the daemon runs as).
func writeServeConfig(workDir string, body []byte) error {
	dir := ServeStateDir(workDir)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create the registry state dir: %w", err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return fmt.Errorf("restrict the registry state dir: %w", err)
	}
	path := ServeConfigPath(workDir)
	tmp := path + ".tmp"
	// A leftover temp file from an interrupted write may have any mode; it is
	// replaced, never reused.
	if err := os.Remove(tmp); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("write the registry serve config: %w", err)
	}
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_EXCL|os.O_WRONLY|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return fmt.Errorf("write the registry serve config: %w", err)
	}
	_, werr := f.Write(body)
	if werr == nil {
		werr = f.Sync()
	}
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	if werr == nil {
		werr = os.Rename(tmp, path)
	}
	if werr != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("write the registry serve config: %w", werr)
	}
	return nil
}

// ReadServeConfig reads and validates the serve config at path. It refuses a
// file that is not a regular file owned by this process's user with no group
// or other permission bits, one larger than 64 KiB, an unknown field or
// trailing data, and principals auth.New would refuse.
func ReadServeConfig(path string) (ServeConfig, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return ServeConfig{}, fmt.Errorf("read the registry serve config: %w", err)
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return ServeConfig{}, fmt.Errorf("read the registry serve config: %w", err)
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	switch {
	case !fi.Mode().IsRegular():
		return ServeConfig{}, fmt.Errorf("registry serve config %s is not a regular file", path)
	case fi.Mode().Perm()&0o077 != 0:
		return ServeConfig{}, fmt.Errorf("registry serve config %s has mode %#o, want 0600", path, fi.Mode().Perm())
	case !ok || int(st.Uid) != os.Geteuid():
		return ServeConfig{}, fmt.Errorf("registry serve config %s is not owned by this user", path)
	}
	b, err := io.ReadAll(io.LimitReader(f, maxServeConfigBytes+1))
	if err != nil {
		return ServeConfig{}, fmt.Errorf("read the registry serve config: %w", err)
	}
	if len(b) > maxServeConfigBytes {
		return ServeConfig{}, fmt.Errorf("registry serve config %s is larger than %d bytes", path, maxServeConfigBytes)
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	var cfg ServeConfig
	if err := dec.Decode(&cfg); err != nil {
		return ServeConfig{}, fmt.Errorf("parse the registry serve config %s: %w", path, err)
	}
	if dec.More() {
		return ServeConfig{}, fmt.Errorf("parse the registry serve config %s: trailing data", path)
	}
	if _, err := auth.New(auth.Config{Principals: cfg.Principals}); err != nil {
		return ServeConfig{}, fmt.Errorf("registry serve config %s: %w", path, err)
	}
	return cfg, nil
}

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

	"golang.org/x/sys/unix"

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
// the file at 0600 through writeFileInDir, owned by this process's user (the
// service user the daemon runs as).
func writeServeConfig(workDir string, body []byte) error {
	d, err := openStateDir(ServeStateDir(workDir))
	if err != nil {
		return err
	}
	defer d.Close()
	if err := writeFileInDir(d, ServeConfigPath(workDir), body); err != nil {
		return fmt.Errorf("write the registry serve config: %w", err)
	}
	return nil
}

// writeFileInDir writes body to path at 0600 through a fresh temp file and a
// rename, then syncs d, the open directory path sits in, so the new file
// survives a crash. path must name a file directly inside the directory d was
// opened at. Every step (removing a leftover temp file, creating the temp
// file, the rename) is made relative to d's descriptor with base names only,
// so it lands in the directory openStateDir checked even if that directory's
// path is swapped for a symlink afterwards. The temp file is created
// O_EXCL|O_NOFOLLOW: a leftover from an interrupted write may have any mode or
// be a symlink, so it is removed and replaced, never reused or followed. A
// reader sees the old whole file or the new one, never a partial write.
func writeFileInDir(d *os.File, path string, body []byte) error {
	if filepath.Clean(filepath.Dir(path)) != filepath.Clean(d.Name()) {
		return fmt.Errorf("%s is not inside the open directory %s", path, d.Name())
	}
	dfd := int(d.Fd())
	name := filepath.Base(path)
	tmp := name + ".tmp"
	if err := unix.Unlinkat(dfd, tmp, 0); err != nil && !errors.Is(err, unix.ENOENT) {
		return fmt.Errorf("remove the stale temp file %s: %w", tmp, err)
	}
	fd, err := unix.Openat(dfd, tmp, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return fmt.Errorf("create the temp file %s: %w", tmp, err)
	}
	f := os.NewFile(uintptr(fd), filepath.Join(d.Name(), tmp))
	_, werr := f.Write(body)
	if werr == nil {
		werr = f.Sync()
	}
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	if werr == nil {
		werr = unix.Renameat(dfd, tmp, dfd, name)
	}
	if werr != nil {
		_ = unix.Unlinkat(dfd, tmp, 0) // best effort: the write already failed
		return werr
	}
	if err := d.Sync(); err != nil {
		return fmt.Errorf("sync %s: %w", d.Name(), err)
	}
	return nil
}

// openStateDir creates a registry state dir (the serve state dir, or the
// registry dir that holds the push credential and the htpasswd file) at 0700
// if it is missing and returns it open. It refuses, fail-closed, a path that is a symlink or not a directory,
// and a directory another user owns. A directory of this user's own with a
// wider mode is corrected to 0700, through the open descriptor, so the chmod
// never follows a symlink. Only the last component is checked: the work dir
// above it belongs to the service user.
func openStateDir(dir string) (*os.File, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create the registry state dir: %w", err)
	}
	fi, err := os.Lstat(dir)
	if err != nil {
		return nil, fmt.Errorf("check the registry state dir: %w", err)
	}
	if err := checkStateDir(dir, fi); err != nil {
		return nil, err
	}
	d, err := os.OpenFile(dir, os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, fmt.Errorf("open the registry state dir: %w", err)
	}
	// The open descriptor is what is checked and changed from here on; it must
	// be the directory the Lstat saw.
	dfi, err := d.Stat()
	if err == nil && !os.SameFile(fi, dfi) {
		err = fmt.Errorf("registry state dir %s changed while it was checked", dir)
	}
	if err == nil {
		err = checkStateDir(dir, dfi)
	}
	if err == nil && dfi.Mode().Perm() != 0o700 {
		if cerr := d.Chmod(0o700); cerr != nil {
			err = fmt.Errorf("restrict the registry state dir: %w", cerr)
		}
	}
	if err != nil {
		_ = d.Close()
		return nil, err
	}
	return d, nil
}

// checkStateDir refuses a state dir that is a symlink, not a directory, or
// not owned by this process's user.
func checkStateDir(dir string, fi os.FileInfo) error {
	st, ok := fi.Sys().(*syscall.Stat_t)
	switch {
	case fi.Mode()&os.ModeSymlink != 0:
		return fmt.Errorf("registry state dir %s is a symlink", dir)
	case !fi.IsDir():
		return fmt.Errorf("registry state dir %s is not a directory", dir)
	case !ok || int(st.Uid) != os.Geteuid():
		return fmt.Errorf("registry state dir %s is not owned by this user", dir)
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

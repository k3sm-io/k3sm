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

package deliver

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"

	"k8s.io/apimachinery/pkg/util/validation"

	"k3sm.io/k3sm/pkg/addons"
	"k3sm.io/k3sm/pkg/keystore"
)

// FileName is the delivery declaration's name in the data root
// (/var/lib/k3sm/keystore-delivery.json). It is the literal here because the
// data root's keystore path names have no shared home yet; the keystore's
// floor beside it (keystore-floor.json) is named the same way, in
// pkg/keystore.
const FileName = "keystore-delivery.json"

// FileMode is the declaration's mode: root:wheel 0644. World-readable, because
// it names no value, only which entry goes to which Secret; root-only to
// write, because it decides which namespace the admin client writes into.
const FileMode os.FileMode = 0o644

// SchemaVersion is the only declaration version this build reads or writes.
const SchemaVersion = 1

// DefaultDataKey is the Secret data key a target without one is delivered
// under.
const DefaultDataKey = "value"

// Bounds on a declaration. A file over MaxFileBytes, or one naming more than
// MaxTargets targets, is refused whole: the reconciler reads it on every
// sweep, so an unbounded file would be an unbounded read and an unbounded
// number of apiserver calls.
const (
	MaxFileBytes = 64 << 10
	MaxTargets   = 256
)

// Target is one declared delivery: the current version of keystore entry
// Name, as Secret SecretName in Namespace, under data key DataKey.
type Target struct {
	Name       string `json:"name"`
	Namespace  string `json:"namespace"`
	SecretName string `json:"secretName,omitempty"`
	DataKey    string `json:"dataKey,omitempty"`
}

// Secret is the Secret's name: SecretName, or the entry name by default.
func (t Target) Secret() string {
	if t.SecretName != "" {
		return t.SecretName
	}
	return t.Name
}

// Key is the data key: DataKey, or DefaultDataKey by default.
func (t Target) Key() string {
	if t.DataKey != "" {
		return t.DataKey
	}
	return DefaultDataKey
}

// Check refuses a target the reconciler could not deliver. Its errors name the
// field, never its value: a declaration is root's, but the CLI that builds a
// target from flags must not echo a value typed in the wrong place.
func (t Target) Check() error {
	if keystore.CheckName(t.Name) != nil {
		return errors.New("name is not a valid keystore entry name")
	}
	// The ownership label carries the entry name, and a label value is at most
	// 63 bytes, so a longer entry name cannot be delivered.
	if len(validation.IsValidLabelValue(t.Name)) != 0 {
		return fmt.Errorf("name is longer than the %d bytes a label value holds, so it cannot be delivered", validation.LabelValueMaxLength)
	}
	if len(validation.IsDNS1123Label(t.Namespace)) != 0 {
		return errors.New("namespace is not a valid namespace name (DNS-1123 label)")
	}
	if len(validation.IsDNS1123Subdomain(t.Secret())) != 0 {
		return errors.New("secretName is not a valid Secret name (DNS-1123 subdomain)")
	}
	if len(validation.IsConfigMapKey(t.Key())) != 0 {
		return errors.New("dataKey is not a valid Secret data key")
	}
	return nil
}

// Declaration is the file's content.
type Declaration struct {
	Version int      `json:"version"`
	Targets []Target `json:"targets"`
}

// Parse decodes a declaration strictly: one JSON object, no unknown field, no
// trailing data, version SchemaVersion, at most MaxTargets targets, each one
// valid (Target.Check), and no two naming the same Secret. Anything else is
// refused whole.
func Parse(data []byte) (Declaration, error) {
	if len(data) > MaxFileBytes {
		return Declaration{}, fmt.Errorf("larger than %d bytes", MaxFileBytes)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var d Declaration
	if err := dec.Decode(&d); err != nil {
		return Declaration{}, fmt.Errorf("decode: %w", err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return Declaration{}, errors.New("trailing data after the declaration")
	}
	if d.Version != SchemaVersion {
		return Declaration{}, fmt.Errorf("version %d, want %d", d.Version, SchemaVersion)
	}
	if len(d.Targets) > MaxTargets {
		return Declaration{}, fmt.Errorf("%d targets, the limit is %d", len(d.Targets), MaxTargets)
	}
	seen := make(map[string]int, len(d.Targets))
	for i, t := range d.Targets {
		if err := t.Check(); err != nil {
			return Declaration{}, fmt.Errorf("target %d: %w", i, err)
		}
		k := t.Namespace + "/" + t.Secret()
		if j, dup := seen[k]; dup {
			return Declaration{}, fmt.Errorf("targets %d and %d name the same Secret", j, i)
		}
		seen[k] = i
	}
	return d, nil
}

// Marshal encodes d as the file holds it, with a trailing newline.
func (d Declaration) Marshal() ([]byte, error) {
	if d.Targets == nil {
		d.Targets = []Target{}
	}
	b, err := json.MarshalIndent(d, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

// Upsert declares t, replacing a target that names the same Secret, and
// reports whether it replaced one.
func (d *Declaration) Upsert(t Target) bool {
	for i, x := range d.Targets {
		if x.Namespace == t.Namespace && x.Secret() == t.Secret() {
			d.Targets[i] = t
			return true
		}
	}
	d.Targets = append(d.Targets, t)
	return false
}

// Remove withdraws every target delivering entry name into namespace, and
// returns how many it removed.
func (d *Declaration) Remove(name, namespace string) int {
	kept := d.Targets[:0]
	for _, x := range d.Targets {
		if x.Name != name || x.Namespace != namespace {
			kept = append(kept, x)
		}
	}
	n := len(d.Targets) - len(kept)
	d.Targets = kept
	return n
}

// FileCheck decides whether the opened declaration may be read. Production
// binds addons.RootOwnedNotShared, the manifest directory's check; a test
// binds one that accepts the test user as the owner.
type FileCheck func(fi fs.FileInfo) error

// Opener opens the declaration for reading. Production binds OpenNoFollow.
type Opener func(path string) (*os.File, error)

// OpenNoFollow opens path read-only with O_NOFOLLOW, so a symlink at the path is
// refused rather than followed, and O_NONBLOCK, so a FIFO there cannot wedge
// the read.
func OpenNoFollow(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
}

// ErrRefused marks a declaration file that exists and was refused: not a
// regular file, failing check, oversized, or not parsing. The reconciler
// delivers nothing from it.
var ErrRefused = errors.New("delivery declaration refused")

// Read reads and parses the declaration at path through open, judging the
// opened descriptor with check. A missing file is an empty declaration and
// exists false. The returned FileInfo is the opened file's, for a caller that
// logs a refusal once per file state; it is nil when the file is absent or
// could not be opened.
func Read(path string, open Opener, check FileCheck) (d Declaration, fi fs.FileInfo, exists bool, err error) {
	data, fi, exists, err := readChecked(path, open, check)
	if err != nil {
		return Declaration{}, fi, exists, err
	}
	if !exists {
		return Declaration{Version: SchemaVersion}, nil, false, nil
	}
	d, err = Parse(data)
	if err != nil {
		return Declaration{}, fi, true, fmt.Errorf("%w: %w", ErrRefused, err)
	}
	return d, fi, true, nil
}

// readChecked reads the file at path through open, judging the opened
// descriptor with check: a regular file, passing check, at most MaxFileBytes.
// A missing file is exists false and no error.
func readChecked(path string, open Opener, check FileCheck) (data []byte, fi fs.FileInfo, exists bool, err error) {
	if err := checkDir(filepath.Dir(path), check); errors.Is(err, fs.ErrNotExist) {
		return nil, nil, false, nil
	} else if err != nil {
		return nil, nil, true, err
	}
	f, err := open(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil, false, nil
	}
	if err != nil {
		if errors.Is(err, syscall.ELOOP) {
			return nil, nil, true, fmt.Errorf("%w: a symlink", ErrRefused)
		}
		return nil, nil, true, fmt.Errorf("open: %w", err)
	}
	defer func() { _ = f.Close() }() // read-only: nothing to flush
	fi, err = f.Stat()
	if err != nil {
		return nil, nil, true, fmt.Errorf("stat the opened file: %w", err)
	}
	if !fi.Mode().IsRegular() {
		return nil, fi, true, fmt.Errorf("%w: not a regular file", ErrRefused)
	}
	if err := check(fi); err != nil {
		return nil, fi, true, fmt.Errorf("%w: %w", ErrRefused, err)
	}
	if fi.Size() > MaxFileBytes {
		return nil, fi, true, fmt.Errorf("%w: larger than %d bytes", ErrRefused, MaxFileBytes)
	}
	data, err = io.ReadAll(io.LimitReader(f, MaxFileBytes+1))
	if err != nil {
		return nil, fi, true, fmt.Errorf("read: %w", err)
	}
	if len(data) > MaxFileBytes {
		return nil, fi, true, fmt.Errorf("%w: larger than %d bytes", ErrRefused, MaxFileBytes)
	}
	return data, fi, true, nil
}

// Write installs d at path, mode FileMode, atomically: a temp file in path's
// directory is handed over by chown (production: root:wheel), chmodded,
// written and fsynced, renamed over path, and the directory fsynced. The
// rename replaces a symlink at path rather than following it. The temp file
// is removed on every error return.
func Write(path string, d Declaration, check FileCheck, chown func(f *os.File) error) error {
	data, err := d.Marshal()
	if err != nil {
		return fmt.Errorf("encode the declaration: %w", err)
	}
	return writeAtomic(path, data, FileMode, check, chown)
}

// writeAtomic installs data at path with mode, as Write describes.
func writeAtomic(path string, data []byte, mode os.FileMode, check FileCheck, chown func(f *os.File) error) (err error) {
	dir := filepath.Dir(path)
	if err := checkDir(dir, check); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-")
	if err != nil {
		return fmt.Errorf("create a temp file: %w", err)
	}
	tmpPath := tmp.Name()
	defer func() {
		if err != nil {
			_ = os.Remove(tmpPath) // best effort: the error already says the write failed
		}
	}()
	if err := writeSynced(tmp, data, mode, chown); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("install: %w", err)
	}
	d2, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("open the directory to sync it: %w", err)
	}
	defer func() { _ = d2.Close() }() // read-only; synced below
	if err := d2.Sync(); err != nil {
		return fmt.Errorf("sync the directory: %w", err)
	}
	return nil
}

// checkDir judges the data root at dir, which holds the declaration, the
// state file and the lock: opened O_NOFOLLOW|O_DIRECTORY, so a symlink is
// refused, and judged with check on that descriptor (production: owned by
// root and not group- or other-writable), so no one but root can swap a file
// in it. It is the keystore floor's data-root check (pkg/keystore), without
// the floor's flock. A missing directory is returned as fs.ErrNotExist.
func checkDir(dir string, check FileCheck) error {
	d, err := os.OpenFile(dir, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_DIRECTORY, 0)
	if errors.Is(err, syscall.ELOOP) || errors.Is(err, syscall.ENOTDIR) {
		return fmt.Errorf("%w: the data root is not a directory (a symlink?)", ErrRefused)
	}
	if err != nil {
		return fmt.Errorf("open the data root: %w", err)
	}
	defer func() { _ = d.Close() }() // read-only
	fi, err := d.Stat()
	if err != nil {
		return fmt.Errorf("stat the data root: %w", err)
	}
	if !fi.IsDir() {
		return fmt.Errorf("%w: the data root is not a directory", ErrRefused)
	}
	if err := check(fi); err != nil {
		return fmt.Errorf("%w: the data root: %w", ErrRefused, err)
	}
	return nil
}

// writeSynced chowns, chmods, writes and fsyncs f, and closes it.
func writeSynced(f *os.File, data []byte, mode os.FileMode, chown func(*os.File) error) error {
	steps := []struct {
		what string
		do   func() error
	}{
		{"chown", func() error { return chown(f) }},
		{"chmod", func() error { return f.Chmod(mode) }},
		{"write", func() error { _, err := f.Write(data); return err }},
		{"sync", f.Sync},
	}
	for _, s := range steps {
		if err := s.do(); err != nil {
			_ = f.Close() // the step's error is the one reported
			return fmt.Errorf("%s the temp file: %w", s.what, err)
		}
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("close the temp file: %w", err)
	}
	return nil
}

// ChownRoot hands f to root:wheel, the declaration's and the state file's
// owner.
func ChownRoot(f *os.File) error { return f.Chown(0, 0) }

// RootCheck is the production FileCheck, the manifest directory's.
var RootCheck FileCheck = addons.RootOwnedNotShared

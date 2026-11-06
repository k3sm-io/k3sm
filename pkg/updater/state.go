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

package updater

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"path/filepath"
	"slices"
	"strings"

	"k3sm.io/k3sm/pkg/updater/layout"
)

// Names inside updater-state.
const (
	markerName    = "swap.json"
	highwaterName = "highwater"
	badName       = "bad"
	stagedName    = "staged"
)

// maxStateFileBytes bounds every file read from updater-state.
const maxStateFileBytes = 64 << 10

const stateFileMode fs.FileMode = 0o600

var (
	// ErrVersionBad reports a version that failed health and is refused until
	// root clears it with repair --clear-bad.
	ErrVersionBad = errors.New("the version is marked bad; sudo k3sm updater repair --clear-bad clears it")
	// ErrDowngrade reports a version below the current version or the
	// high-water mark; only the rollback to previous goes down.
	ErrDowngrade = errors.New("the version is a downgrade; only the rollback to previous goes down")
	// ErrBadState reports a state file that does not parse. The updater stops
	// rather than guess at a rollback target or a floor.
	ErrBadState = errors.New("an updater state file is malformed")
)

// state reads and writes the files in updater-state.
type state struct {
	fs  FS
	dir string
}

func (s state) path(name string) string { return filepath.Join(s.dir, name) }

// read returns a state file's bytes; a missing file is (nil, false, nil). The
// file must be a regular file owned by root, no-follow, within the bound.
func (s state) read(name string) ([]byte, bool, error) {
	f, err := s.fs.OpenRead(s.path(name))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("%w: %s: %w", ErrBadState, name, err)
	}
	defer func() { _ = f.Close() }()
	info, err := f.Info()
	if err != nil {
		return nil, false, fmt.Errorf("%w: %s: %w", ErrBadState, name, err)
	}
	switch {
	case !info.Mode.IsRegular():
		return nil, false, fmt.Errorf("%w: %s is %s", ErrBadState, name, info.Mode)
	case info.UID != 0:
		return nil, false, fmt.Errorf("%w: %s is owned by uid %d", ErrBadState, name, info.UID)
	case info.Mode.Perm()&0o022 != 0:
		return nil, false, fmt.Errorf("%w: %s is writable by group or other", ErrBadState, name)
	}
	data, err := io.ReadAll(io.LimitReader(f, maxStateFileBytes+1))
	if err != nil {
		return nil, false, fmt.Errorf("%w: %s: %w", ErrBadState, name, err)
	}
	if len(data) > maxStateFileBytes {
		return nil, false, fmt.Errorf("%w: %s is over %d bytes", ErrBadState, name, maxStateFileBytes)
	}
	return data, true, nil
}

// remove unlinks a state file; absent is success.
func (s state) remove(name string) error {
	err := s.fs.Unlink(s.path(name))
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	return err
}

// readVersion reads a file holding one version; absent is "".
func (s state) readVersion(name string) (string, error) {
	data, ok, err := s.read(name)
	if err != nil || !ok {
		return "", err
	}
	v := strings.TrimSpace(string(data))
	if err := layout.ValidateVersion(v); err != nil {
		return "", fmt.Errorf("%w: %s: %w", ErrBadState, name, err)
	}
	return v, nil
}

func (s state) highwater() (string, error) { return s.readVersion(highwaterName) }

// raiseHighwater raises the mark to ver and never lowers it.
func (s state) raiseHighwater(ver string) error {
	cur, err := s.highwater()
	if err != nil {
		return err
	}
	if cur != "" {
		c, err := compareVersions(ver, cur)
		if err != nil {
			return err
		}
		if c <= 0 {
			return nil
		}
	}
	return s.fs.WriteFileAtomic(s.path(highwaterName), []byte(NormalizeVersion(ver)+"\n"), stateFileMode)
}

// badList reads the bad list, normalized.
func (s state) badList() ([]string, error) {
	data, ok, err := s.read(badName)
	if err != nil || !ok {
		return nil, err
	}
	var out []string
	for line := range strings.SplitSeq(string(data), "\n") {
		if line == "" {
			continue
		}
		if err := layout.ValidateVersion(line); err != nil {
			return nil, fmt.Errorf("%w: %s: %w", ErrBadState, badName, err)
		}
		out = append(out, NormalizeVersion(line))
	}
	return out, nil
}

// markBad adds ver to the bad list.
func (s state) markBad(ver string) error {
	list, err := s.badList()
	if err != nil {
		return err
	}
	n := NormalizeVersion(ver)
	if slices.Contains(list, n) {
		return nil
	}
	return s.writeBad(append(list, n))
}

// clearBad removes ver from the bad list.
func (s state) clearBad(ver string) error {
	list, err := s.badList()
	if err != nil {
		return err
	}
	n := NormalizeVersion(ver)
	if !slices.Contains(list, n) {
		return nil
	}
	return s.writeBad(slices.DeleteFunc(list, func(v string) bool { return v == n }))
}

func (s state) writeBad(list []string) error {
	data := strings.Join(list, "\n")
	if data != "" {
		data += "\n"
	}
	return s.fs.WriteFileAtomic(s.path(badName), []byte(data), stateFileMode)
}

// checkTarget refuses a version the node may not move up to: a migrated unknown
// name, a bad version, one below the high-water mark, one below current.
func (s state) checkTarget(to, current string) error {
	if layout.IsUnknownVersion(to) {
		return fmt.Errorf("version %s: %w", to, layout.ErrBadVersion)
	}
	bad, err := s.badList()
	if err != nil {
		return err
	}
	if slices.Contains(bad, NormalizeVersion(to)) {
		return fmt.Errorf("version %s: %w", to, ErrVersionBad)
	}
	hw, err := s.highwater()
	if err != nil {
		return err
	}
	for _, floor := range []string{hw, current} {
		if floor == "" || layout.IsUnknownVersion(floor) {
			continue
		}
		c, err := compareVersions(to, floor)
		if err != nil {
			return err
		}
		if c < 0 {
			return fmt.Errorf("version %s below %s: %w", to, floor, ErrDowngrade)
		}
	}
	return nil
}

// stagedRecord is what a finished stage leaves for activate.
type stagedRecord struct {
	Version string `json:"version"`
}

func (s state) staged() (string, error) {
	data, ok, err := s.read(stagedName)
	if err != nil || !ok {
		return "", err
	}
	var r stagedRecord
	if err := strictJSON(data, &r); err != nil {
		return "", fmt.Errorf("%w: %s: %w", ErrBadState, stagedName, err)
	}
	if err := layout.ValidateVersion(r.Version); err != nil {
		return "", fmt.Errorf("%w: %s: %w", ErrBadState, stagedName, err)
	}
	return r.Version, nil
}

func (s state) writeStaged(ver string) error {
	data, err := json.Marshal(stagedRecord{Version: ver})
	if err != nil {
		return err
	}
	return s.fs.WriteFileAtomic(s.path(stagedName), data, stateFileMode)
}

// strictJSON decodes exactly one object with no unknown field.
func strictJSON(data []byte, v any) error {
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return errors.New("bytes after the JSON value")
	}
	return nil
}

// removeStale is OpRemoveStale: lstat, then unlink, refusing a directory. A
// missing name is success.
func removeStale(fsys FS, p string) error {
	info, err := fsys.Lstat(p)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if info.Mode.IsDir() {
		return fmt.Errorf("%s: %w", p, ErrStaleIsDirectory)
	}
	return fsys.Unlink(p)
}

// applySteps carries out a layout plan.
func applySteps(fsys FS, steps []layout.Step) error {
	for _, st := range steps {
		var err error
		switch st.Op {
		case layout.OpRemoveStale:
			err = removeStale(fsys, st.Path)
		case layout.OpSymlink:
			err = fsys.Symlink(st.Target, st.Path)
		case layout.OpRename:
			err = fsys.Rename(st.Path, st.Target)
		default:
			err = fmt.Errorf("unknown step %v", st.Op)
		}
		if err != nil {
			return fmt.Errorf("%s %s: %w", st.Op, st.Path, err)
		}
	}
	return nil
}

// emptyDir removes every entry of dir, up to maxEntries of them per call.
func emptyDir(fsys FS, dir string) error {
	names, err := fsys.ReadDirNames(dir, maxEmptyEntries)
	if err != nil {
		return err
	}
	for _, n := range names {
		if err := fsys.RemoveAll(filepath.Join(dir, n)); err != nil {
			return err
		}
	}
	return nil
}

// maxEmptyEntries bounds one pass over updater-work or a listing of versions.
const maxEmptyEntries = 4096

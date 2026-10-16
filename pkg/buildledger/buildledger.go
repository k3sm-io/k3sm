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

package buildledger

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"

	"k3sm.io/k3sm/internal/atomicfile"
)

// Status is where a build stands.
type Status string

const (
	// StatusRunning is a build that has started and not yet finished. A build
	// that was killed before it could rewrite its record stays here.
	StatusRunning Status = "running"
	// StatusSucceeded is a build whose image reached this node's store and
	// every other sink it was asked for.
	StatusSucceeded Status = "succeeded"
	// StatusFailed is a build that returned an error.
	StatusFailed Status = "failed"
)

const (
	// EngineNative is a build the native packager produced.
	EngineNative = "native"
	// EngineBuildEngine is a build the k3sm build engine produced.
	EngineBuildEngine = "engine"
)

const (
	// MaxRecords is how many records the ledger keeps: a write removes the
	// oldest past this bound.
	MaxRecords = 200
	// MaxErrorBytes bounds a failed record's error text. Build engine errors can
	// carry a whole log tail, and the ledger is a listing, not a log store.
	MaxErrorBytes = 1024
	// maxRecordBytes bounds how much of one record file is read. A record is a
	// few hundred bytes; anything past this is not one.
	maxRecordBytes = 64 << 10
)

// geteuid is a seam so the ownership checks are testable without root.
var geteuid = os.Geteuid

// Record is one build. Its JSON form is what `k3sm build ls -o json` prints.
type Record struct {
	// ID names the record and its file, builds/<id>.json.
	ID string `json:"id"`
	// Dockerfile and Context are absolute paths.
	Dockerfile string `json:"dockerfile"`
	Context    string `json:"context"`
	Tag        string `json:"tag"`
	// Platform is the target, or several separated by commas.
	Platform string `json:"platform"`
	// Engine is EngineNative or EngineBuildEngine.
	Engine    string    `json:"engine"`
	StartedAt time.Time `json:"startedAt"`
	// FinishedAt is unset while the build runs.
	FinishedAt *time.Time `json:"finishedAt,omitempty"`
	Status     Status     `json:"status"`
	// ImageDigest is the digest of the image recorded in this node's store, set
	// on success.
	ImageDigest string `json:"imageDigest,omitempty"`
	// Error is the failure's text, clipped to MaxErrorBytes, set on failure.
	Error string `json:"error,omitempty"`
}

// Duration is how long the build ran, up to now for a running one.
func (r Record) Duration(now time.Time) time.Duration {
	if r.FinishedAt != nil {
		return r.FinishedAt.Sub(r.StartedAt)
	}
	return now.Sub(r.StartedAt)
}

// recordName matches a record file, and nothing else in the directory: not a
// temp file from an interrupted write, not a file someone put there.
var recordName = regexp.MustCompile(`^[0-9a-f]{12}\.json$`)

// Ledger is the record directory. The zero value is not usable; use New.
type Ledger struct {
	dir string
	now func() time.Time
	max int
	// remove deletes a pruned record; a seam so a failing prune is testable.
	remove func(string) error
}

// New returns the ledger rooted at dir. Nothing is created until a write.
func New(dir string) *Ledger {
	return &Ledger{dir: dir, now: time.Now, max: MaxRecords, remove: os.Remove}
}

// DefaultDir is <home>/.k3sm/builds, under the home of the user running the
// build, so the history is that user's own. It refuses a home this process's
// effective user does not own: under sudo the home is usually still the
// operator's, and records written there as root would be files the operator
// cannot remove.
func DefaultDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolve home dir for the build ledger: %w", err)
	}
	return defaultDir(home, geteuid())
}

// defaultDir is DefaultDir for a given home and effective uid.
func defaultDir(home string, euid int) (string, error) {
	if home == "" {
		return "", errors.New("resolve home dir for the build ledger: empty home")
	}
	uid, err := ownerOf(home, os.Stat)
	if err != nil {
		return "", fmt.Errorf("build ledger: %w", err)
	}
	if uid != euid {
		return "", fmt.Errorf("build ledger: home %s is owned by uid %d, not this user (uid %d)", home, uid, euid)
	}
	return filepath.Join(home, ".k3sm", "builds"), nil
}

// ownerOf is the uid that owns path, as stat reports it.
func ownerOf(path string, stat func(string) (os.FileInfo, error)) (int, error) {
	fi, err := stat(path)
	if err != nil {
		return 0, err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, fmt.Errorf("cannot read the owner of %s", path)
	}
	return int(st.Uid), nil
}

// Dir is the directory the ledger reads and writes.
func (l *Ledger) Dir() string { return l.dir }

// Start writes r as a running build: it assigns the id and the start time and
// returns the record as written.
func (l *Ledger) Start(r Record) (Record, error) {
	id, err := newID()
	if err != nil {
		return r, err
	}
	r.ID = id
	r.StartedAt = l.now().UTC()
	r.FinishedAt = nil
	r.Status = StatusRunning
	r.ImageDigest = ""
	r.Error = ""
	return r, l.Write(r)
}

// Finish rewrites r as finished: succeeded with digest when buildErr is nil,
// failed with buildErr's text otherwise.
func (l *Ledger) Finish(r Record, digest string, buildErr error) (Record, error) {
	t := l.now().UTC()
	r.FinishedAt = &t
	if buildErr != nil {
		r.Status = StatusFailed
		r.Error = clip(redact(buildErr.Error()), MaxErrorBytes)
		r.ImageDigest = ""
	} else {
		r.Status = StatusSucceeded
		r.ImageDigest = digest
		r.Error = ""
	}
	return r, l.Write(r)
}

// Write installs r as <dir>/<id>.json (0600, in a 0700 directory), then removes
// the oldest records past the bound. The record is what Write reports on: a
// prune that fails once the record is installed is a warning, not an error.
func (l *Ledger) Write(r Record) error {
	if !recordName.MatchString(r.ID + ".json") {
		return fmt.Errorf("build ledger: invalid record id %q", r.ID)
	}
	if err := l.ensureDir(); err != nil {
		return err
	}
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return fmt.Errorf("build ledger: encode %s: %w", r.ID, err)
	}
	data = append(data, '\n')
	if err := atomicfile.Replace(filepath.Join(l.dir, r.ID+".json"), data, 0o600); err != nil {
		return fmt.Errorf("build ledger: %w", err)
	}
	if err := l.prune(); err != nil {
		slog.Warn("build ledger: remove old records", "dir", l.dir, "err", err)
	}
	return nil
}

// ensureDir makes the ledger directory ready to write. It creates it 0700, or
// accepts an existing one only when it is a real directory (never a symlink,
// which would send the records wherever it points) owned by this user, and
// narrows that one to 0700: the records name the operator's paths.
func (l *Ledger) ensureDir() error {
	fi, err := os.Lstat(l.dir)
	if errors.Is(err, os.ErrNotExist) {
		if err := os.MkdirAll(filepath.Dir(l.dir), 0o700); err != nil {
			return fmt.Errorf("build ledger: create %s: %w", filepath.Dir(l.dir), err)
		}
		if err := os.Mkdir(l.dir, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
			return fmt.Errorf("build ledger: create %s: %w", l.dir, err)
		}
		if fi, err = os.Lstat(l.dir); err != nil {
			return fmt.Errorf("build ledger: %w", err)
		}
	} else if err != nil {
		return fmt.Errorf("build ledger: %w", err)
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("build ledger: %s is a symlink; refusing to write through it", l.dir)
	}
	if !fi.IsDir() {
		return fmt.Errorf("build ledger: %s is not a directory", l.dir)
	}
	uid, err := ownerOf(l.dir, os.Lstat)
	if err != nil {
		return fmt.Errorf("build ledger: %w", err)
	}
	if uid != geteuid() {
		return fmt.Errorf("build ledger: %s is owned by uid %d, not this user", l.dir, uid)
	}
	if fi.Mode().Perm() != 0o700 {
		if err := os.Chmod(l.dir, 0o700); err != nil {
			return fmt.Errorf("build ledger: restrict %s: %w", l.dir, err)
		}
	}
	return nil
}

// List returns the records, newest first. A missing directory is an empty
// ledger. A record that does not decode is skipped: one damaged file must not
// hide the rest of the history.
func (l *Ledger) List() ([]Record, error) {
	entries, err := l.read()
	if err != nil {
		return nil, err
	}
	out := make([]Record, 0, len(entries))
	for _, e := range entries {
		if e.ok {
			out = append(out, e.rec)
		}
	}
	return out, nil
}

// entry is one record file: decoded, or not (ok false), with its name either way
// so prune can remove an undecodable file too.
type entry struct {
	name string
	rec  Record
	ok   bool
}

// read loads every record file, sorted newest first. Undecodable files sort last,
// as the oldest, so they are the first to go when the bound is reached.
func (l *Ledger) read() ([]entry, error) {
	des, err := os.ReadDir(l.dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("build ledger: read %s: %w", l.dir, err)
	}
	var out []entry
	for _, de := range des {
		if !de.Type().IsRegular() || !recordName.MatchString(de.Name()) {
			continue
		}
		e := entry{name: de.Name()}
		if data, err := readRecord(filepath.Join(l.dir, de.Name())); err == nil {
			e.ok = json.Unmarshal(data, &e.rec) == nil && e.rec.ID+".json" == de.Name()
		}
		out = append(out, e)
	}
	now := l.now()
	// A start time in the future is not one this ledger wrote (Start stamps
	// now), so it sorts as the oldest: a hand-edited date must not keep a record
	// at the top, and out of the prune, forever.
	key := func(e entry) time.Time {
		if !e.ok || e.rec.StartedAt.After(now) {
			return time.Time{}
		}
		return e.rec.StartedAt
	}
	slices.SortStableFunc(out, func(a, b entry) int {
		if c := key(b).Compare(key(a)); c != 0 {
			return c
		}
		if a.ok != b.ok {
			if a.ok {
				return -1
			}
			return 1
		}
		return strings.Compare(b.name, a.name)
	})
	return out, nil
}

// prune removes the records past the bound, oldest first.
func (l *Ledger) prune() error {
	entries, err := l.read()
	if err != nil {
		return err
	}
	if len(entries) <= l.max {
		return nil
	}
	var errs []error
	for _, e := range entries[l.max:] {
		if err := l.remove(filepath.Join(l.dir, e.name)); err != nil && !errors.Is(err, os.ErrNotExist) {
			errs = append(errs, err)
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("build ledger: prune: %w", errors.Join(errs...))
	}
	return nil
}

// readRecord reads one record file, refusing one past maxRecordBytes.
func readRecord(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxRecordBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxRecordBytes {
		return nil, fmt.Errorf("%s is larger than %d bytes", path, maxRecordBytes)
	}
	return data, nil
}

// newID is a short random id: 12 hex characters.
func newID() (string, error) {
	var b [6]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("build ledger: generate id: %w", err)
	}
	return hex.EncodeToString(b[:]), nil
}

// clip returns s cut to at most n bytes, on a rune boundary.
func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}

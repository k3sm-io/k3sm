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
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
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
)

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
}

// New returns the ledger rooted at dir. Nothing is created until a write.
func New(dir string) *Ledger {
	return &Ledger{dir: dir, now: time.Now, max: MaxRecords}
}

// DefaultDir is <home>/.k3sm/builds, under the home of the user running the
// build, so the history is that user's own.
func DefaultDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolve home dir for the build ledger: %w", err)
	}
	if home == "" {
		return "", errors.New("resolve home dir for the build ledger: empty home")
	}
	return filepath.Join(home, ".k3sm", "builds"), nil
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
		r.Error = clip(buildErr.Error(), MaxErrorBytes)
		r.ImageDigest = ""
	} else {
		r.Status = StatusSucceeded
		r.ImageDigest = digest
		r.Error = ""
	}
	return r, l.Write(r)
}

// Write installs r as <dir>/<id>.json (0600, in a 0700 directory), then removes
// the oldest records past the bound.
func (l *Ledger) Write(r Record) error {
	if !recordName.MatchString(r.ID + ".json") {
		return fmt.Errorf("build ledger: invalid record id %q", r.ID)
	}
	if err := os.MkdirAll(l.dir, 0o700); err != nil {
		return fmt.Errorf("build ledger: create %s: %w", l.dir, err)
	}
	// MkdirAll leaves an existing directory's mode alone, and the records name
	// the operator's paths, so the directory is narrowed on every write.
	if err := os.Chmod(l.dir, 0o700); err != nil {
		return fmt.Errorf("build ledger: restrict %s: %w", l.dir, err)
	}
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return fmt.Errorf("build ledger: encode %s: %w", r.ID, err)
	}
	data = append(data, '\n')
	if err := atomicfile.Replace(filepath.Join(l.dir, r.ID+".json"), data, 0o600); err != nil {
		return fmt.Errorf("build ledger: %w", err)
	}
	return l.prune()
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
		if data, err := os.ReadFile(filepath.Join(l.dir, de.Name())); err == nil {
			e.ok = json.Unmarshal(data, &e.rec) == nil && e.rec.ID+".json" == de.Name()
		}
		out = append(out, e)
	}
	slices.SortStableFunc(out, func(a, b entry) int {
		if a.ok != b.ok {
			if a.ok {
				return -1
			}
			return 1
		}
		if c := b.rec.StartedAt.Compare(a.rec.StartedAt); c != 0 {
			return c
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
		if err := os.Remove(filepath.Join(l.dir, e.name)); err != nil && !errors.Is(err, os.ErrNotExist) {
			errs = append(errs, err)
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("build ledger: prune: %w", errors.Join(errs...))
	}
	return nil
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

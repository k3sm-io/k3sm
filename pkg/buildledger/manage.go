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
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"syscall"
)

// logSuffix and cancelSuffix name a record's companions: builds/<id>.log holds
// the build's output and builds/<id>.sock is the running build's cancel socket.
const (
	logSuffix    = ".log"
	cancelSuffix = ".sock"
)

// MaxLogBytes bounds one build's stored log. Output past it is dropped and the
// log says so: the bound keeps a looping build from filling the disk, and 16 MiB
// is far more than a build prints.
const MaxLogBytes = 16 << 20

// ErrNotFound is returned when no record carries the id asked for.
var ErrNotFound = errors.New("no build with that id")

// ErrNoLog is returned when a record has no stored log: the build ran before
// logs were kept, or its log could not be written.
var ErrNoLog = errors.New("the build has no stored log")

// validID reports whether id is the shape Start assigns.
func validID(id string) error {
	if !recordName.MatchString(id + ".json") {
		return fmt.Errorf("build ledger: invalid build id %q (want the 12 hex characters `k3sm build ls` shows)", id)
	}
	return nil
}

// Get returns the record id names, or an error wrapping ErrNotFound.
func (l *Ledger) Get(id string) (Record, error) {
	if err := validID(id); err != nil {
		return Record{}, err
	}
	path := filepath.Join(l.dir, id+".json")
	fi, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return Record{}, fmt.Errorf("build %s: %w", id, ErrNotFound)
	}
	if err != nil {
		return Record{}, fmt.Errorf("build ledger: %w", err)
	}
	if !fi.Mode().IsRegular() {
		return Record{}, fmt.Errorf("build ledger: %s is not a regular file", path)
	}
	data, err := readRecord(path)
	if err != nil {
		return Record{}, fmt.Errorf("build ledger: %w", err)
	}
	var r Record
	if err := json.Unmarshal(data, &r); err != nil || r.ID != id {
		return Record{}, fmt.Errorf("build ledger: %s does not hold the record for %s", path, id)
	}
	return r, nil
}

// Cancel rewrites r as cancelled, finished now.
func (l *Ledger) Cancel(r Record) (Record, error) {
	t := l.now().UTC()
	r.FinishedAt = &t
	r.Status = StatusCancelled
	r.ImageDigest = ""
	r.Error = ""
	return r, l.Write(r)
}

// Remove deletes the record id names and its stored log. A record that is not
// there is an error wrapping ErrNotFound; a missing log is not an error.
func (l *Ledger) Remove(id string) error {
	if err := validID(id); err != nil {
		return err
	}
	if err := l.remove(filepath.Join(l.dir, id+".json")); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("build %s: %w", id, ErrNotFound)
		}
		return fmt.Errorf("build ledger: remove %s: %w", id, err)
	}
	if err := l.remove(l.LogPath(id)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("build ledger: remove the log of %s: %w", id, err)
	}
	return nil
}

// LogPath is where the log of build id is stored.
func (l *Ledger) LogPath(id string) string { return filepath.Join(l.dir, id+logSuffix) }

// CancelPath is the cancel socket of running build id.
func (l *Ledger) CancelPath(id string) string { return filepath.Join(l.dir, id+cancelSuffix) }

// CreateLog creates the log of build id (0600, in the 0700 ledger directory)
// and returns a writer over it bounded at MaxLogBytes. It refuses a log that
// already exists or a link in its place.
func (l *Ledger) CreateLog(id string) (*LogWriter, error) {
	if err := validID(id); err != nil {
		return nil, err
	}
	if err := l.ensureDir(); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(l.LogPath(id), os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, fmt.Errorf("build ledger: create the log of %s: %w", id, err)
	}
	return &LogWriter{f: f, max: MaxLogBytes}, nil
}

// OpenLog opens the stored log of build id for reading, or returns an error
// wrapping ErrNoLog when there is none. A link in the log's place is refused.
func (l *Ledger) OpenLog(id string) (*os.File, error) {
	if err := validID(id); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(l.LogPath(id), os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("build %s: %w", id, ErrNoLog)
	}
	if err != nil {
		return nil, fmt.Errorf("build ledger: open the log of %s: %w", id, err)
	}
	return f, nil
}

// LogWriter appends a build's output to its stored log. Write never fails: it
// sits beside the terminal in a tee, and a full disk or the size bound must not
// cut the build's own output short, so a failed or dropped write is reported in
// the log (once) and swallowed. It is safe for concurrent use, since a build's
// stdout and stderr are copied by separate goroutines.
type LogWriter struct {
	mu      sync.Mutex // guards everything below
	f       *os.File
	max     int64
	written int64
	stopped bool
}

// Write appends p, up to the bound, and always reports len(p) written.
func (w *LogWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.stopped || w.f == nil {
		return len(p), nil
	}
	chunk := p
	if room := w.max - w.written; int64(len(chunk)) > room {
		chunk = chunk[:max(room, 0)]
		w.stopped = true
	}
	n, err := w.f.Write(chunk)
	w.written += int64(n)
	if err != nil {
		w.stopped = true
		_, _ = fmt.Fprintf(w.f, "\n[k3sm: the rest of this log could not be written: %v]\n", err)
		return len(p), nil
	}
	if w.stopped {
		_, _ = fmt.Fprintf(w.f, "\n[k3sm: log truncated at %d bytes]\n", w.max)
	}
	return len(p), nil
}

// Close closes the log file.
func (w *LogWriter) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.f == nil {
		return nil
	}
	err := w.f.Close()
	w.f = nil
	return err
}

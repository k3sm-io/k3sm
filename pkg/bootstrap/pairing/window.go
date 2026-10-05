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

package pairing

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// WindowFile is the pairing window's file name under the server work dir.
const WindowFile = "pairing-window.json"

// WindowLockFile is the sibling lock file every read-modify-write of the window
// holds an exclusive flock on.
const WindowLockFile = "pairing-window.lock"

// DefaultMaxJoins is how many completed joins a window admits when the operator
// names no number.
const DefaultMaxJoins = 1

// mintsPerJoin bounds how many tokens a window may mint per join it admits. A
// joiner whose join fails asks again, so a window needs a few mints per join; a
// flooder on the cable that is accepted every 10 s must not mint without bound.
const mintsPerJoin = 4

// Window is the pairing window's persisted state.
type Window struct {
	// Until is when the window closes.
	Until time.Time `json:"until"`
	// MaxJoins is how many completed joins the window admits.
	MaxJoins int `json:"maxJoins"`
	// Completed counts the joins signed with a token this window minted.
	Completed int `json:"completed"`
	// Mints counts the tokens this window minted.
	Mints int `json:"mints,omitempty"`
}

// IsOpen reports whether the window admits a pair request at now: before Until
// and with joins to spare.
func (w Window) IsOpen(now time.Time) bool {
	return now.Before(w.Until) && w.Completed < w.MaxJoins
}

// MintCap is the most tokens this window may mint.
func (w Window) MintCap() int { return w.MaxJoins * mintsPerJoin }

// WindowPath returns the window file's path under a server work dir.
func WindowPath(workDir string) string { return filepath.Join(workDir, WindowFile) }

// WindowStore reads and writes the window file. Every read-modify-write (Open,
// Close, RecordCompleted, ReserveMint) holds an exclusive flock on the sibling
// pairing-window.lock, so `sudo k3sm pair --close` beside the running server can
// never be undone by a mint in flight: the two serialize, in one process or
// across them. flock is per open file description, so two goroutines of one
// process exclude each other as well. The write itself is an atomic rename, so a
// plain Load never sees a torn file.
type WindowStore struct {
	Path string
}

// LockPath is the sibling lock file's path.
func (s WindowStore) LockPath() string {
	return filepath.Join(filepath.Dir(s.Path), WindowLockFile)
}

// locked runs fn holding the exclusive window lock. A lock that cannot be taken
// is an error: the caller fails closed rather than writing unserialized.
func (s WindowStore) locked(fn func() error) error {
	f, err := os.OpenFile(s.LockPath(), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return fmt.Errorf("open pairing window lock: %w", err)
	}
	defer f.Close()
	if geteuid() == 0 {
		if st, err := os.Stat(filepath.Dir(s.Path)); err == nil {
			if sys, ok := st.Sys().(*syscall.Stat_t); ok {
				if err := chown(s.LockPath(), int(sys.Uid), int(sys.Gid)); err != nil {
					return fmt.Errorf("hand the pairing window lock to the work dir's owner: %w", err)
				}
			}
		}
	}
	for {
		err = unix.Flock(int(f.Fd()), unix.LOCK_EX)
		if err != unix.EINTR {
			break
		}
	}
	if err != nil {
		return fmt.Errorf("lock pairing window: %w", err)
	}
	defer func() { _ = unix.Flock(int(f.Fd()), unix.LOCK_UN) }()
	return fn()
}

// Load returns the window, and false when there is none (a closed window).
func (s WindowStore) Load() (Window, bool, error) {
	b, err := os.ReadFile(s.Path)
	if errors.Is(err, os.ErrNotExist) {
		return Window{}, false, nil
	}
	if err != nil {
		return Window{}, false, fmt.Errorf("read pairing window: %w", err)
	}
	var w Window
	if err := json.Unmarshal(b, &w); err != nil {
		return Window{}, false, fmt.Errorf("decode pairing window %s: %w", s.Path, err)
	}
	return w, true, nil
}

// Open writes a fresh window lasting d from now and admitting maxJoins completed
// joins (DefaultMaxJoins when not positive). It replaces any window before it.
func (s WindowStore) Open(now time.Time, d time.Duration, maxJoins int) (Window, error) {
	if d <= 0 {
		return Window{}, fmt.Errorf("pairing window duration must be positive, got %s", d)
	}
	if maxJoins <= 0 {
		maxJoins = DefaultMaxJoins
	}
	w := Window{Until: now.Add(d), MaxJoins: maxJoins}
	return w, s.locked(func() error { return writeAtomic(s.Path, w) })
}

// Close removes the window. An absent window is already closed.
func (s WindowStore) Close() error {
	return s.locked(func() error {
		if err := os.Remove(s.Path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("close pairing window: %w", err)
		}
		return nil
	})
}

// RecordCompleted counts one completed join against the window. With no window
// there is nothing to count.
func (s WindowStore) RecordCompleted() error {
	return s.locked(func() error {
		w, ok, err := s.Load()
		if err != nil || !ok {
			return err
		}
		w.Completed++
		return writeAtomic(s.Path, w)
	})
}

// FailClosed removes the window without taking the lock. It is the last resort
// when the completed-join count cannot be written: an unaccounted window must not
// stay open, and a lock that is itself the failure must not stop the close.
func (s WindowStore) FailClosed() error {
	if err := os.Remove(s.Path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("close pairing window: %w", err)
	}
	return nil
}

// Outstanding counts the one-shot tokens minted for the window generation until
// that are neither consumed nor expired.
type Outstanding func(until time.Time) (int, error)

// Capacity is how many more tokens may be outstanding at once: the joins the
// window still admits. Outstanding tokens above it could outrun maxJoins.
func (w Window) Capacity() int { return w.MaxJoins - w.Completed }

// ReserveMint counts one mint against the window if it is open at now, its mint
// cap is not spent and fewer tokens are outstanding than the window has joins
// left (maxJoins minus completed), returning the window as it was decided on. The
// check and the count are one locked step, so two requests cannot both take the
// last mint.
func (s WindowStore) ReserveMint(now time.Time, outstanding Outstanding) (w Window, open, capped bool, err error) {
	err = s.locked(func() error {
		cur, ok, lerr := s.Load()
		if lerr != nil {
			return lerr
		}
		w = cur
		if !ok || !cur.IsOpen(now) {
			return nil
		}
		open = true
		if cur.Mints >= cur.MintCap() {
			capped = true
			return nil
		}
		out, oerr := outstanding(cur.Until)
		if oerr != nil {
			return fmt.Errorf("count outstanding pairing tokens: %w", oerr)
		}
		if out >= cur.Capacity() {
			capped = true
			return nil
		}
		cur.Mints++
		w = cur
		return writeAtomic(s.Path, cur)
	})
	return w, open, capped, err
}

// writeAtomic writes v as JSON to path at 0600 through a uniquely named temp file
// in the same directory and a rename. When run as root it hands the file to the
// owner of the directory (the service user's work dir), because the running
// server reads and rewrites it as that user.
func writeAtomic(path string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Errorf("encode %s: %w", filepath.Base(path), err)
	}
	f, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".tmp*")
	if err != nil {
		return fmt.Errorf("write %s: %w", filepath.Base(path), err)
	}
	tmp := f.Name()
	committed := false
	defer func() {
		if !committed {
			_ = os.Remove(tmp)
		}
	}()
	if _, err := f.Write(b); err != nil {
		_ = f.Close()
		return fmt.Errorf("write %s: %w", filepath.Base(path), err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("write %s: %w", filepath.Base(path), err)
	}
	if geteuid() == 0 {
		if st, err := os.Stat(filepath.Dir(path)); err == nil {
			if sys, ok := st.Sys().(*syscall.Stat_t); ok {
				if err := chown(tmp, int(sys.Uid), int(sys.Gid)); err != nil {
					return fmt.Errorf("hand %s to the work dir's owner: %w", filepath.Base(path), err)
				}
			}
		}
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("commit %s: %w", filepath.Base(path), err)
	}
	committed = true
	return nil
}

// geteuid and chown are seams so the root branch is testable without privilege.
var (
	geteuid = os.Geteuid
	chown   = os.Chown
)

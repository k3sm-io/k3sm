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

package dataroot

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/unix"
)

// FS is the read-only filesystem seam Read needs, defined here at the consumer
// so unit tests can describe a mount posture no unprivileged test could create.
// OSFS is the production implementation.
type FS interface {
	Stat(path string) (fs.FileInfo, error)
	Statfs(path string, st *unix.Statfs_t) error
	ReadFile(path string) ([]byte, error)
	ReadDir(path string) ([]fs.DirEntry, error)
}

// State is the observed posture of a data root. Only Exists, DeclaredMount,
// Mounted, OwnerUID and OwnerWritable drive decisions; FSType, VolumeName and
// ShadowEntries exist to make a status report or a log line legible.
type State struct {
	// Exists reports whether the directory itself is present.
	Exists bool
	// DeclaredMount reports an /etc/fstab line whose mount-point field is
	// exactly this directory. A subdirectory of a declared root is not declared.
	DeclaredMount bool
	// Mounted reports that a filesystem is mounted ON this directory (as
	// opposed to the directory merely residing on some other filesystem).
	Mounted bool
	// FSType is the mounted filesystem's type (e.g. "apfs"). Status only.
	FSType string
	// VolumeName is the last path element of the mounted device/volume.
	// Status only.
	VolumeName string
	// OwnerUID is the directory's owning uid, 0 when unknown.
	OwnerUID int
	// OwnerWritable reports the owner-write permission bit.
	OwnerWritable bool
	// ShadowEntries names what is already inside a declared-but-unmounted
	// mountpoint — i.e. the shadow content. Status only.
	ShadowEntries []string
}

// Shadowed reports the one posture the daemons must refuse: the data root is
// declared in /etc/fstab as a mount point but nothing is mounted there, so any
// write lands on the boot disk and hides the real volume's contents.
func (s State) Shadowed() bool { return s.DeclaredMount && !s.Mounted }

// ErrNotMounted is the sentinel every shadow refusal wraps. Match it with
// errors.Is, never by string.
var ErrNotMounted = errors.New("data root is declared in /etc/fstab but not mounted")

// Refusal returns the error a daemon exits with when dir is shadowed: the
// sentinel plus the operator action that clears it.
func Refusal(dir string) error {
	return fmt.Errorf("data root %s: %w — mount it (sudo diskutil mount -mountPoint %s <volume>) then restart io.k3sm.netd and io.k3sm.server", dir, ErrNotMounted, dir)
}

// Read reports the posture of dir.
//
// dir is ALWAYS the data root itself (/var/lib/k3sm), never a subdirectory: the
// mount-point comparisons against /etc/fstab and against statfs(2) are exact, so
// passing <root>/run reports DeclaredMount=false and Mounted=false and the
// shadow verdict silently disappears.
//
// A missing dir is not an error (Exists=false) — that is the ordinary
// first-install posture. Nor is a missing or unreadable /etc/fstab
// (DeclaredMount=false): no declaration means no volume was promised.
func Read(fsys FS, dir string) (State, error) {
	dir = filepath.Clean(dir)
	var s State

	if data, err := fsys.ReadFile(FstabPath); err == nil {
		for _, e := range parseFstab(data) {
			if filepath.Clean(e.Dir) == dir {
				s.DeclaredMount = true
				break
			}
		}
	}

	fi, err := fsys.Stat(dir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return s, nil
		}
		return s, fmt.Errorf("stat data root %s: %w", dir, err)
	}
	s.Exists = true
	s.OwnerWritable = fi.Mode().Perm()&0o200 != 0
	// os.Stat's platform payload; a fake that omits it just leaves OwnerUID 0.
	if st, ok := fi.Sys().(*syscall.Stat_t); ok && st != nil {
		s.OwnerUID = int(st.Uid)
	}

	// A mount point is a directory whose device differs from its parent's.
	// That is the test that survives macOS's /var -> /private/var symlink:
	// statfs(2) and mount(8) report the RESOLVED mount point, so a string
	// compare against the declared path calls a healthy, mounted data root
	// "not mounted" -- the shadow verdict about a working Mac (found live
	// 2026-09-05, one commit after the guard landed). The name compare stays
	// as a second witness for callers whose Stat payload carries no device.
	s.Mounted = mountedByDevice(fsys, fi, dir)
	var st unix.Statfs_t
	if err := fsys.Statfs(dir, &st); err == nil {
		if cstring(st.Mntonname[:]) == dir {
			s.Mounted = true
		}
		if s.Mounted {
			s.FSType = cstring(st.Fstypename[:])
			s.VolumeName = filepath.Base(cstring(st.Mntfromname[:]))
		}
	}

	if s.Shadowed() {
		if entries, err := fsys.ReadDir(dir); err == nil {
			for _, e := range entries {
				s.ShadowEntries = append(s.ShadowEntries, e.Name())
			}
		}
	}
	return s, nil
}

// cstring decodes a NUL-terminated fixed-width kernel string field.
func cstring(b []byte) string {
	if i := bytes.IndexByte(b, 0); i >= 0 {
		b = b[:i]
	}
	return string(b)
}

// mountedByDevice reports whether dir sits on a different device than its
// parent directory -- the definition of a mount point that no symlink in the
// path can disturb. It answers false when either Stat payload carries no
// device (a fake), leaving the mount-name compare in Read as the witness.
func mountedByDevice(fsys FS, fi fs.FileInfo, dir string) bool {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || st == nil || st.Dev == 0 {
		return false
	}
	parent := filepath.Dir(dir)
	if parent == dir {
		return false
	}
	pfi, err := fsys.Stat(parent)
	if err != nil {
		return false
	}
	pst, ok := pfi.Sys().(*syscall.Stat_t)
	if !ok || pst == nil || pst.Dev == 0 {
		return false
	}
	return pst.Dev != st.Dev
}

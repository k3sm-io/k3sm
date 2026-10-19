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

package updatectl

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math/rand/v2"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	"k3sm.io/k3sm/pkg/install"
)

// Every operation on the release pin runs relative to directory descriptors,
// never through a path a less privileged user could redirect. The server work
// dir belongs to the service user, which can rename or replace the pin
// directory inside it at any moment; so the work dir is opened once, the pin
// directory is opened relative to it without following a symlink and checked
// on the opened descriptor, and every later step (the chmod, the temp file,
// the rename, the unlink) acts on that descriptor. A swap after the check can
// then only move the directory root is writing into, never redirect root's
// write elsewhere. The reader holds the pin to the same owner and mode checks
// on the descriptors it reads through. Those two are the defence; the
// writer's after-the-fact check that the directory is still in place
// (samePinDir) only turns a swap into a clear error instead of a pin written
// where nothing will read it.

// pinDirChecked is called after the writer has checked the pin directory and
// before it writes the pin: a test seam for swapping the directory there.
var pinDirChecked = func() {}

// openWorkDir opens workDir as a directory, without following it if it is a
// symlink. A missing work dir is an error wrapping fs.ErrNotExist.
func openWorkDir(workDir string) (int, error) {
	fd, err := unix.Open(workDir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if errors.Is(err, unix.ENOENT) {
		return -1, fmt.Errorf("open the work dir %s: %w", workDir, fs.ErrNotExist)
	}
	if err != nil {
		return -1, fmt.Errorf("open the work dir %s: %w", workDir, err)
	}
	return fd, nil
}

// statProblem says why st cannot be trusted as the pin directory (wantDir) or
// the pin file: the wrong type (a symlink included), an owner other than
// owner, or a mode its group or others may write. Empty means trusted.
func statProblem(st *unix.Stat_t, owner uint32, wantDir bool) string {
	switch typ := st.Mode & unix.S_IFMT; {
	case typ == unix.S_IFLNK:
		return "a symlink"
	case wantDir && typ != unix.S_IFDIR:
		return "not a directory"
	case !wantDir && typ != unix.S_IFREG:
		return "not a regular file"
	}
	if st.Uid != owner {
		return fmt.Sprintf("owned by uid %d, not uid %d", st.Uid, owner)
	}
	if st.Mode&0o022 != 0 {
		return fmt.Sprintf("writable by its group or others (mode %#o)", st.Mode&0o7777)
	}
	return ""
}

// openPinDirAt opens the pin directory relative to the work dir descriptor
// parent, without following a symlink, and checks it on the opened
// descriptor. A missing directory is an error wrapping fs.ErrNotExist.
func openPinDirAt(parent int, workDir string, owner uint32) (int, error) {
	dir := ReleasePinDir(workDir)
	fd, err := unix.Openat(parent, releasePinDirName, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if errors.Is(err, unix.ENOENT) {
		return -1, fmt.Errorf("open %s: %w", dir, fs.ErrNotExist)
	}
	if err != nil {
		// A symlink fails O_NOFOLLOW with ELOOP, a file O_DIRECTORY with ENOTDIR.
		return -1, fmt.Errorf("%s is not a real directory: %w", dir, err)
	}
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		_ = unix.Close(fd)
		return -1, fmt.Errorf("stat %s: %w", dir, err)
	}
	if p := statProblem(&st, owner, true); p != "" {
		_ = unix.Close(fd)
		return -1, fmt.Errorf("%s is %s", dir, p)
	}
	return fd, nil
}

// WriteReleasePin records pin under workDir. The caller must be root: the pin
// directory is created when missing, must be a real directory owned by root
// that no one else may write, and is set to 0755; the pin is written to a new
// temp file in it (0644, fsync'ed) and renamed over the pin, and the
// directory is fsync'ed. Every step after the check acts on the checked
// directory's descriptor; if the directory was moved away meanwhile, the
// write fails and leaves nothing at the pin path.
func WriteReleasePin(workDir string, pin ReleasePin) error {
	return writeReleasePin(workDir, pin, 0)
}

func writeReleasePin(workDir string, pin ReleasePin, owner uint32) error {
	if err := pin.Validate(); err != nil {
		return fmt.Errorf("write the release pin: %w", err)
	}
	b, err := json.Marshal(pin)
	if err != nil {
		return fmt.Errorf("write the release pin: %w", err)
	}
	parent, err := openWorkDir(workDir)
	if err != nil {
		return fmt.Errorf("write the release pin: %w", err)
	}
	defer func() { _ = unix.Close(parent) }()
	if err := unix.Mkdirat(parent, releasePinDirName, 0o755); err != nil && !errors.Is(err, unix.EEXIST) {
		return fmt.Errorf("write the release pin: create %s: %w", ReleasePinDir(workDir), err)
	}
	dfd, err := openPinDirAt(parent, workDir, owner)
	if err != nil {
		return fmt.Errorf("write the release pin: %w", err)
	}
	defer func() { _ = unix.Close(dfd) }()
	if err := unix.Fchmod(dfd, 0o755); err != nil {
		return fmt.Errorf("write the release pin: chmod %s: %w", ReleasePinDir(workDir), err)
	}
	pinDirChecked()
	if err := writePinAt(dfd, append(b, '\n')); err != nil {
		return fmt.Errorf("write the release pin %s: %w", ReleasePinPath(workDir), err)
	}
	if err := samePinDir(parent, dfd); err != nil {
		// The pin went into a directory no longer at the pin path, so no
		// reader will find it: take it back out and say so.
		_ = unix.Unlinkat(dfd, releasePinFileName, 0)
		return fmt.Errorf("write the release pin: %s was replaced during the write: %w", ReleasePinDir(workDir), err)
	}
	return nil
}

// writePinAt writes data to a new temp file in the directory dfd, created
// exclusively and without following a symlink, chmods it 0644 and fsyncs it,
// renames it over the pin and fsyncs the directory. The temp file is removed
// on every error.
func writePinAt(dfd int, data []byte) error {
	tmp := "." + releasePinFileName + ".tmp-" + strconv.FormatUint(rand.Uint64(), 36)
	fd, err := unix.Openat(dfd, tmp, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return fmt.Errorf("create the temp file: %w", err)
	}
	f := os.NewFile(uintptr(fd), tmp)
	err = func() error {
		if _, err := f.Write(data); err != nil {
			return err
		}
		if err := f.Chmod(0o644); err != nil {
			return err
		}
		return f.Sync()
	}()
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = unix.Renameat(dfd, tmp, dfd, releasePinFileName)
	}
	if err != nil {
		_ = unix.Unlinkat(dfd, tmp, 0)
		return err
	}
	return unix.Fsync(dfd)
}

// samePinDir reports an error unless the pin directory entry in parent is
// still the directory dfd holds. It is diagnostic, not a defence: a swap
// after it is not seen, and none needs to be, because the write already went
// through the checked descriptor and a reader holds whatever it finds at the
// pin path to the owner and mode checks. It only makes a swap during the
// write fail loudly instead of leaving a pin no reader will find.
func samePinDir(parent, dfd int) error {
	var held, now unix.Stat_t
	if err := unix.Fstat(dfd, &held); err != nil {
		return err
	}
	if err := unix.Fstatat(parent, releasePinDirName, &now, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return err
	}
	if held.Dev != now.Dev || held.Ino != now.Ino {
		return errors.New("the directory entry now names another file")
	}
	return nil
}

// Cleared is what ClearReleasePin did.
type Cleared struct {
	// Path is the pin file removed, or, when the pin directory entry could
	// not be trusted, the pin directory recreated in its place. Empty means
	// there was nothing to clear.
	Path string
	// Untrusted says why the pin directory entry could not be trusted, when
	// it was moved aside.
	Untrusted string
	// Aside is where the untrusted entry was moved, in the work dir. root
	// never reads, walks or deletes it.
	Aside string
	// Asides are every entry moved aside, Aside first, when a writer planted
	// a new entry between the rename and the mkdir. They accumulate in the
	// work dir and are the service user's to remove.
	Asides []string
}

// pinClearChecked is called after ClearReleasePin has judged the pin
// directory entry and before it acts on it: a test seam for changing the
// entry there.
var pinClearChecked = func() {}

// renameAsideHook is called after ClearReleasePin has moved an entry aside and
// before it creates the fresh pin directory: a test seam for a writer racing
// to plant a new entry there.
var renameAsideHook = func() {}

// maxAsideAttempts bounds how often ClearReleasePin moves an untrusted entry
// aside and tries to create a fresh pin directory in its place, against a
// writer that plants a new entry each time. Each attempt is constant work, so
// no tree shape can make a clear fail; only a writer racing every attempt can.
const maxAsideAttempts = 8

// ClearReleasePin removes the release pin under workDir, as root. A trusted
// pin directory keeps its place and loses only the pin file. A pin directory
// entry that cannot be trusted (a symlink, not a directory, another owner,
// writable by its group or others) is renamed aside within the work dir,
// as an entry, so a symlink moves as a link and is never followed, to a new
// name update.untrusted-<unix nanoseconds> that no existing entry holds; a
// fresh root-owned 0755 pin directory is then created in its place. The
// aside entry is never read, walked or deleted, so no tree a less privileged
// user plants, however deep or however often refilled, can stop the clear.
// Aside entries accumulate in the work dir and are the service user's to
// remove. A writer that replants the entry after every attempt makes the
// clear give up with a *PinDirContestedError naming the asides and the
// recovery (PinClearRecovery). A missing work dir, directory or pin is not an
// error.
func ClearReleasePin(workDir string) (Cleared, error) {
	return clearReleasePin(workDir, 0)
}

func clearReleasePin(workDir string, owner uint32) (Cleared, error) {
	parent, err := openWorkDir(workDir)
	if errors.Is(err, fs.ErrNotExist) {
		return Cleared{}, nil
	}
	if err != nil {
		return Cleared{}, fmt.Errorf("clear the release pin: %w", err)
	}
	defer func() { _ = unix.Close(parent) }()
	var st unix.Stat_t
	err = unix.Fstatat(parent, releasePinDirName, &st, unix.AT_SYMLINK_NOFOLLOW)
	if errors.Is(err, unix.ENOENT) {
		return Cleared{}, nil
	}
	if err != nil {
		return Cleared{}, fmt.Errorf("clear the release pin: stat %s: %w", ReleasePinDir(workDir), err)
	}
	if p := statProblem(&st, owner, true); p != "" {
		pinClearChecked()
		return replaceUntrustedPinDir(parent, workDir, owner, p)
	}
	dfd, err := openPinDirAt(parent, workDir, owner)
	if err != nil {
		// It changed since the stat; a second run sees what it is now.
		return Cleared{}, fmt.Errorf("clear the release pin: %w", err)
	}
	defer func() { _ = unix.Close(dfd) }()
	err = unix.Unlinkat(dfd, releasePinFileName, 0)
	if errors.Is(err, unix.ENOENT) {
		return Cleared{}, nil
	}
	if err != nil {
		return Cleared{}, fmt.Errorf("clear the release pin: unlink %s: %w", ReleasePinPath(workDir), err)
	}
	if err := unix.Fsync(dfd); err != nil {
		return Cleared{}, fmt.Errorf("clear the release pin: sync %s: %w", ReleasePinDir(workDir), err)
	}
	return Cleared{Path: ReleasePinPath(workDir)}, nil
}

// replaceUntrustedPinDir moves the untrusted pin directory entry in parent
// aside and creates a fresh pin directory in its place, retrying when another
// entry appears at the pin directory's name in between. why is what made the
// first entry untrusted. Aside entries accumulate in the work dir; they are
// the service user's to remove, and root never touches them again.
func replaceUntrustedPinDir(parent int, workDir string, owner uint32, why string) (Cleared, error) {
	var asides []string
	for range maxAsideAttempts {
		aside, err := renameAside(parent)
		if err != nil && !errors.Is(err, unix.ENOENT) {
			return Cleared{}, fmt.Errorf("clear the release pin: move %s aside: %w", ReleasePinDir(workDir), err)
		}
		if aside != "" {
			asides = append(asides, filepath.Join(workDir, aside))
		}
		renameAsideHook()
		err = unix.Mkdirat(parent, releasePinDirName, 0o755)
		if errors.Is(err, unix.EEXIST) {
			continue // planted again since the rename: move that aside too
		}
		if err != nil {
			return Cleared{}, fmt.Errorf("clear the release pin: create %s: %w", ReleasePinDir(workDir), err)
		}
		dfd, err := openPinDirAt(parent, workDir, owner)
		if err != nil {
			// Swapped between the mkdir and the open: try again.
			continue
		}
		err = unix.Fchmod(dfd, 0o755)
		if err == nil {
			err = unix.Fsync(parent)
		}
		_ = unix.Close(dfd)
		if err != nil {
			return Cleared{}, fmt.Errorf("clear the release pin: set up %s: %w", ReleasePinDir(workDir), err)
		}
		out := Cleared{Path: ReleasePinDir(workDir), Untrusted: why, Asides: asides}
		if len(asides) > 0 {
			out.Aside = asides[0]
		}
		return out, nil
	}
	return Cleared{}, &PinDirContestedError{Dir: ReleasePinDir(workDir), Attempts: maxAsideAttempts, Asides: asides}
}

// PinDirContestedError is ClearReleasePin giving up because a new entry
// appeared at the pin directory's name after each of its attempts to move one
// aside: something running as the service user is replanting it. Asides are
// the entries it moved aside, each left in the work dir.
type PinDirContestedError struct {
	// Dir is the pin directory path.
	Dir string
	// Attempts is how many times an entry was moved aside.
	Attempts int
	// Asides are the full paths of the entries moved aside, in order.
	Asides []string
}

// PinClearRecovery is the documented recovery when a clear is contested: stop
// the control plane, which runs as the service user, clear the pin again, and
// start the control plane.
var PinClearRecovery = "sudo launchctl bootout system/" + install.ServerLabel +
	"; sudo k3sm update apply --clear-pin" +
	"; sudo launchctl bootstrap system " + filepath.Join(install.DefaultLaunchDaemonDir, install.ServerLabel+".plist")

func (e *PinDirContestedError) Error() string {
	moved := "none"
	if len(e.Asides) > 0 {
		moved = strings.Join(e.Asides, ", ")
	}
	return fmt.Sprintf("clear the release pin: %s was replaced again after each of %d attempts to move it aside (moved aside: %s); stop the server and clear again: %s",
		e.Dir, e.Attempts, moved, PinClearRecovery)
}

// renameAside renames the pin directory entry in parent, as an entry and
// without following it, to update.untrusted-<unix nanoseconds>, refusing to
// replace any existing entry (RENAME_EXCL) and picking a new name when one
// exists. It returns the new name.
func renameAside(parent int) (string, error) {
	for i := range 16 {
		name := releasePinDirName + ".untrusted-" + strconv.FormatInt(time.Now().UnixNano()+int64(i), 10)
		err := unix.RenameatxNp(parent, releasePinDirName, parent, name, unix.RENAME_EXCL)
		if errors.Is(err, unix.EEXIST) {
			continue
		}
		if err != nil {
			return "", err
		}
		return name, nil
	}
	return "", errors.New("no free aside name")
}

// readReleasePin reads the pin under workDir, held to the checks the pin
// needs: a real directory and a regular file, both owned by owner and writable
// by no one else. A missing work dir, directory or file is (nil, nil). The
// directory is opened relative to the work dir and the file relative to the
// directory, neither following a symlink, and both are checked on the opened
// descriptors, so neither can be swapped between the check and the read.
func readReleasePin(workDir string, owner uint32) (*ReleasePin, error) {
	parent, err := openWorkDir(workDir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer func() { _ = unix.Close(parent) }()
	dfd, err := openPinDirAt(parent, workDir, owner)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer func() { _ = unix.Close(dfd) }()
	path := ReleasePinPath(workDir)
	fd, err := unix.Openat(dfd, releasePinFileName, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if errors.Is(err, unix.ENOENT) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	f := os.NewFile(uintptr(fd), path)
	defer func() { _ = f.Close() }()
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return nil, fmt.Errorf("stat %s: %w", path, err)
	}
	if p := statProblem(&st, owner, false); p != "" {
		return nil, fmt.Errorf("%s is %s", path, p)
	}
	raw, err := io.ReadAll(io.LimitReader(f, maxReleasePinBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	if len(raw) > maxReleasePinBytes {
		return nil, fmt.Errorf("%s is larger than %d bytes", path, maxReleasePinBytes)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var pin ReleasePin
	if err := dec.Decode(&pin); err != nil {
		return nil, fmt.Errorf("decode %s: %w", path, err)
	}
	if err := pin.Validate(); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &pin, nil
}

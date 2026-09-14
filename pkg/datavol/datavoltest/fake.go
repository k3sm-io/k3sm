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

// Package datavoltest provides the one exported test double for pkg/datavol's
// seams: Fake implements Volumes, Keychain, Indexing, Launchd and
// MigrateSystem over in-memory state, so a unit test can describe a disk
// posture no unprivileged process could create and assert the exact sequence
// of privileged operations k3sm would have run.
//
// It lives in its own package rather than in a _test.go file because
// pkg/install needs it too: its sequencing test points Fake.Log at its own
// call slice, so one interleaved log proves the order across both packages'
// seams.
package datavoltest

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"k3sm.io/k3sm/pkg/dataroot"
	"k3sm.io/k3sm/pkg/datavol"
)

// Volume is one APFS volume the Fake pretends to have.
type Volume struct {
	// UUID is the volume UUID, the key of Fake.Vols.
	UUID string
	// Name is the APFS volume label.
	Name string
	// Container is the APFS container it lives in, e.g. "disk3".
	Container string
	// Device is the device identifier, e.g. "disk3s7".
	Device string
	// Mountpoint is where it is mounted; empty when it is not.
	Mountpoint string
	// Quota, Reserve and InUse are what Capacity reports.
	Quota   uint64
	Reserve uint64
	InUse   uint64
	// Encrypted means the volume is passphrase-gated: Info reports it as
	// FileVault, and Info's own Encrypted (encryption at rest) is always true,
	// as it is for every volume on Apple silicon internal storage.
	Encrypted bool
	// Locked and CaseSensitive are what Info reports under those names.
	Locked        bool
	CaseSensitive bool
	// FilesystemType is what Info reports, "apfs" unless a test wants a
	// foreign volume.
	FilesystemType string
	// Passphrase is what Unlock demands, when AddVolume created it with one.
	Passphrase string
	// HasMarker makes the volume carry k3sm's provenance marker at its root:
	// FS().Stat reports the marker present wherever the volume is mounted,
	// including a temporary probe mount. It is how a test describes a volume
	// k3sm made on an earlier run.
	HasMarker bool
}

// Fake implements every seam pkg/datavol takes.
//
// It is safe for concurrent use, and every method appends a line describing
// the call to Calls (and to Log, when set) BEFORE it acts, so an assertion on
// the sequence sees an attempt even if the test injected an error for it.
type Fake struct {
	mu sync.Mutex

	// Vols are the volumes that exist, keyed by UUID.
	Vols map[string]*Volume
	// Keys are the System-keychain items, keyed by volume UUID.
	Keys map[string]string
	// Errs injects an error for one verb: "info", "capacity", "addvolume",
	// "mount", "unmount", "deletevolume", "unlock", "store", "lookup",
	// "delete", "spotlight", "timemachine", "copytree", "rename",
	// "removeall".
	Errs map[string]error
	// Fstab is what the FS serves for dataroot.FstabPath; empty means the
	// file is absent.
	Fstab string
	// Files are extra files the FS serves by exact path, e.g. a data-volume
	// record. An absent path reads as os.ErrNotExist.
	Files map[string]string
	// LoadedLabels are the LaunchDaemons Loaded reports as running.
	LoadedLabels map[string]bool
	// DropQuota makes AddVolume create the volume with no quota, the failure
	// Ensure must catch and undo.
	DropQuota bool
	// Container is the APFS container Info reports for "/", i.e. where a new
	// volume is created.
	Container string
	// NextUUID is the UUID AddVolume assigns; a generated one when empty.
	NextUUID string
	// Calls is every seam call, in order.
	Calls []string
	// Log, when set, receives every call line too, so another package's test
	// can interleave these into its own ordering assertion.
	Log func(string)

	// seq numbers generated UUIDs.
	seq int
}

// New returns a Fake with its maps ready and a boot container.
func New() *Fake {
	return &Fake{
		Vols:         map[string]*Volume{},
		Keys:         map[string]string{},
		Errs:         map[string]error{},
		Files:        map[string]string{},
		LoadedLabels: map[string]bool{},
		Container:    "disk3",
	}
}

// Deps returns the Fake wired into all three pkg/datavol seams.
func (f *Fake) Deps() datavol.Deps {
	return datavol.Deps{Volumes: f, Keychain: f, Indexing: f}
}

// Add registers an existing volume and returns it, so a test can describe the
// disk before the operation under test runs.
func (f *Fake) Add(v Volume) *Volume {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.Vols == nil {
		f.Vols = map[string]*Volume{}
	}
	if v.FilesystemType == "" {
		v.FilesystemType = "apfs"
	}
	copied := v
	f.Vols[v.UUID] = &copied
	return &copied
}

// Mounted reports whether the volume with the given UUID is mounted.
func (f *Fake) Mounted(uuid string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	v, ok := f.Vols[uuid]
	return ok && v.Mountpoint != ""
}

// record appends one call line. The caller must NOT hold f.mu.
func (f *Fake) record(format string, args ...any) {
	line := fmt.Sprintf(format, args...)
	f.mu.Lock()
	f.Calls = append(f.Calls, line)
	log := f.Log
	f.mu.Unlock()
	if log != nil {
		log(line)
	}
}

// SetErr injects (or clears, with nil) the error for one verb under the
// Fake's lock, so a test may change its mind while an operation is retrying.
func (f *Fake) SetErr(verb string, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.Errs == nil {
		f.Errs = map[string]error{}
	}
	if err == nil {
		delete(f.Errs, verb)
		return
	}
	f.Errs[verb] = err
}

// fail returns the error injected for verb, if any.
func (f *Fake) fail(verb string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.Errs[verb]
}

// Info implements datavol.Volumes. target may be a UUID, a volume name, a
// mount point, a device identifier, or "/" for the boot volume.
func (f *Fake) Info(_ context.Context, target string) (datavol.Info, error) {
	f.record("info %s", target)
	if err := f.fail("info"); err != nil {
		return datavol.Info{}, err
	}
	if target == "/" {
		return datavol.Info{
			DeviceIdentifier:   "disk3s5",
			VolumeName:         "Macintosh HD",
			MountPoint:         "/",
			ContainerReference: f.Container,
			FilesystemType:     "apfs",
			FilesystemName:     "APFS",
		}, nil
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	v := f.find(target)
	if v == nil {
		return datavol.Info{}, fmt.Errorf("could not find disk: %s", target)
	}
	name := "APFS"
	if v.CaseSensitive {
		name = "Case-sensitive APFS"
	}
	return datavol.Info{
		DeviceIdentifier:   v.Device,
		VolumeUUID:         v.UUID,
		VolumeName:         v.Name,
		MountPoint:         v.Mountpoint,
		ContainerReference: v.Container,
		FilesystemType:     v.FilesystemType,
		FilesystemName:     name,
		CaseSensitive:      v.CaseSensitive,
		// Mirrors the platform: encryption at rest is reported for every
		// volume on Apple silicon internal storage, while FileVault is
		// reported only for one that is actually passphrase-gated.
		Encrypted: true,
		FileVault: v.Encrypted,
		Locked:    v.Locked,
	}, nil
}

// find locates a volume by any handle diskutil would accept. f.mu must be held.
func (f *Fake) find(target string) *Volume {
	for _, v := range f.Vols {
		switch {
		case strings.EqualFold(v.UUID, target),
			v.Name == target,
			v.Device == target,
			v.Mountpoint != "" && v.Mountpoint == target:
			return v
		}
	}
	return nil
}

// Capacity implements datavol.Volumes.
func (f *Fake) Capacity(_ context.Context, container, uuid string) (datavol.Capacity, error) {
	f.record("capacity %s %s", container, uuid)
	if err := f.fail("capacity"); err != nil {
		return datavol.Capacity{}, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	v := f.find(uuid)
	if v == nil {
		return datavol.Capacity{}, fmt.Errorf("no volume %s in apfs container %q", uuid, container)
	}
	return datavol.Capacity{Quota: v.Quota, Reserve: v.Reserve, InUse: v.InUse}, nil
}

// AddVolume implements datavol.Volumes. The new volume gets the requested
// quota unless DropQuota is set, which is how a test reproduces a macOS that
// silently ignored -quota.
func (f *Fake) AddVolume(_ context.Context, container, name string, quotaBytes uint64, passphrase string) error {
	f.record("addvolume %s %s quota=%d encrypted=%t", container, name, quotaBytes, passphrase != "")
	if err := f.fail("addvolume"); err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.seq++
	uuid := f.NextUUID
	if uuid == "" {
		uuid = fmt.Sprintf("00000000-0000-0000-0000-%012d", f.seq)
	}
	quota := quotaBytes
	if f.DropQuota {
		quota = 0
	}
	if f.Vols == nil {
		f.Vols = map[string]*Volume{}
	}
	f.Vols[uuid] = &Volume{
		UUID:           uuid,
		Name:           name,
		Container:      container,
		Device:         fmt.Sprintf("disk3s%d", 10+f.seq),
		Quota:          quota,
		InUse:          24576,
		Encrypted:      passphrase != "",
		CaseSensitive:  true,
		FilesystemType: "apfs",
		Passphrase:     passphrase,
	}
	return nil
}

// Mount implements datavol.Volumes.
func (f *Fake) Mount(_ context.Context, uuid, mountpoint string) error {
	f.record("mount %s %s", uuid, mountpoint)
	if err := f.fail("mount"); err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	v := f.find(uuid)
	if v == nil {
		return fmt.Errorf("could not find disk: %s", uuid)
	}
	if v.Locked {
		return fmt.Errorf("volume %s is locked", uuid)
	}
	v.Mountpoint = mountpoint
	return nil
}

// Unmount implements datavol.Volumes.
func (f *Fake) Unmount(_ context.Context, target string) error {
	f.record("unmount %s", target)
	if err := f.fail("unmount"); err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	v := f.find(target)
	if v == nil {
		return fmt.Errorf("could not find disk: %s", target)
	}
	v.Mountpoint = ""
	return nil
}

// DeleteVolume implements datavol.Volumes.
func (f *Fake) DeleteVolume(_ context.Context, uuid string) error {
	f.record("deletevolume %s", uuid)
	if err := f.fail("deletevolume"); err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	v := f.find(uuid)
	if v == nil {
		return fmt.Errorf("could not find disk: %s", uuid)
	}
	delete(f.Vols, v.UUID)
	return nil
}

// Unlock implements datavol.Volumes.
func (f *Fake) Unlock(_ context.Context, uuid, passphrase string) error {
	f.record("unlock %s", uuid)
	if err := f.fail("unlock"); err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	v := f.find(uuid)
	if v == nil {
		return fmt.Errorf("could not find disk: %s", uuid)
	}
	if v.Passphrase != "" && v.Passphrase != passphrase {
		return fmt.Errorf("volume %s: wrong passphrase", uuid)
	}
	v.Locked = false
	return nil
}

// Store implements datavol.Keychain.
func (f *Fake) Store(_ context.Context, uuid, passphrase string) error {
	f.record("store %s", uuid)
	if err := f.fail("store"); err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.Keys == nil {
		f.Keys = map[string]string{}
	}
	f.Keys[uuid] = passphrase
	return nil
}

// Lookup implements datavol.Keychain.
func (f *Fake) Lookup(_ context.Context, uuid string) (string, error) {
	f.record("lookup %s", uuid)
	if err := f.fail("lookup"); err != nil {
		return "", err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	pw, ok := f.Keys[uuid]
	if !ok {
		return "", fmt.Errorf("the specified item could not be found in the keychain")
	}
	return pw, nil
}

// Delete implements datavol.Keychain. A missing item is not an error, as the
// real security(1) path is written to treat it.
func (f *Fake) Delete(_ context.Context, uuid string) error {
	f.record("delete %s", uuid)
	if err := f.fail("delete"); err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.Keys, uuid)
	return nil
}

// SpotlightOff implements datavol.Indexing.
func (f *Fake) SpotlightOff(_ context.Context, mountpoint string) error {
	f.record("spotlight %s", mountpoint)
	return f.fail("spotlight")
}

// TimeMachineExclude implements datavol.Indexing.
func (f *Fake) TimeMachineExclude(_ context.Context, mountpoint string) error {
	f.record("timemachine %s", mountpoint)
	return f.fail("timemachine")
}

// Loaded implements datavol.Launchd.
func (f *Fake) Loaded(label string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.LoadedLabels[label]
}

// CopyTree implements datavol.MigrateSystem with a real recursive copy, so the
// verification walk in Migrate has something true to compare.
func (f *Fake) CopyTree(src, dst string) error {
	f.record("copytree %s %s", src, dst)
	if err := f.fail("copytree"); err != nil {
		return err
	}
	return copyTree(src, dst)
}

// Rename implements datavol.MigrateSystem.
func (f *Fake) Rename(old, new string) error {
	f.record("rename %s %s", old, new)
	if err := f.fail("rename"); err != nil {
		return err
	}
	return os.Rename(old, new)
}

// RemoveAll implements datavol.MigrateSystem.
func (f *Fake) RemoveAll(path string) error {
	f.record("removeall %s", path)
	if err := f.fail("removeall"); err != nil {
		return err
	}
	return os.RemoveAll(path)
}

// copyTree copies a directory tree, preserving permission bits and modes. It
// stands in for ditto(1); tests run unprivileged, so ownership is whatever the
// test process is on both sides.
func copyTree(src, dst string) error {
	return filepath.WalkDir(src, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)
		fi, err := d.Info()
		if err != nil {
			return err
		}
		if d.IsDir() {
			return os.MkdirAll(target, fi.Mode().Perm())
		}
		if !d.Type().IsRegular() {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return err
		}
		return os.WriteFile(target, data, fi.Mode().Perm())
	})
}

// FS returns a dataroot.FS backed by the Fake's mount state.
//
// Stat reports a DIFFERENT device for a mounted mount point than for its
// parent, because that device compare is how dataroot.Read decides a directory
// is a mount point; paths the Fake knows nothing about fall through to the
// real filesystem, so a test can use a temp directory as its mount point and
// let MountRecorded really create the directory and the marker in it. ReadFile,
// by contrast, never falls through: it serves Fstab and Files and nothing else,
// so no test can accidentally read the running Mac's own /etc/fstab or
// data-volume record.
func (f *Fake) FS() dataroot.FS { return fakeFS{f: f} }

// mountedDevice is the device id Stat reports for a mounted mount point;
// everything else reports parentDevice.
const (
	mountedDevice int32 = 42
	parentDevice  int32 = 1
)

type fakeFS struct{ f *Fake }

// mountpointOf reports whether path is the mount point of a mounted volume.
func (s fakeFS) isMountpoint(path string) bool {
	s.f.mu.Lock()
	defer s.f.mu.Unlock()
	clean := filepath.Clean(path)
	for _, v := range s.f.Vols {
		if v.Mountpoint != "" && filepath.Clean(v.Mountpoint) == clean {
			return true
		}
	}
	return false
}

func (s fakeFS) Stat(path string) (fs.FileInfo, error) {
	if s.isMountpoint(path) {
		return fakeInfo{name: filepath.Base(path), mode: fs.ModeDir | 0o755, dev: mountedDevice}, nil
	}
	if s.hasMarkerAt(path) {
		return fakeInfo{name: filepath.Base(path), mode: 0o644, dev: mountedDevice}, nil
	}
	fi, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	return fakeInfo{name: fi.Name(), mode: fi.Mode(), size: fi.Size(), dev: parentDevice}, nil
}

// hasMarkerAt reports whether path is the provenance marker of a mounted
// volume the test declared as carrying one.
func (s fakeFS) hasMarkerAt(path string) bool {
	s.f.mu.Lock()
	defer s.f.mu.Unlock()
	clean := filepath.Clean(path)
	for _, v := range s.f.Vols {
		if v.HasMarker && v.Mountpoint != "" && filepath.Join(v.Mountpoint, datavol.MarkerName) == clean {
			return true
		}
	}
	return false
}

func (s fakeFS) Statfs(path string, st *unix.Statfs_t) error {
	on := "/"
	if s.isMountpoint(path) {
		on = filepath.Clean(path)
	}
	copyC(st.Mntonname[:], on)
	copyC(st.Fstypename[:], "apfs")
	copyC(st.Mntfromname[:], "/dev/disk3s7")
	return nil
}

func (s fakeFS) ReadFile(path string) ([]byte, error) {
	s.f.mu.Lock()
	defer s.f.mu.Unlock()
	if data, ok := s.f.Files[path]; ok {
		return []byte(data), nil
	}
	if path == dataroot.FstabPath && s.f.Fstab != "" {
		return []byte(s.f.Fstab), nil
	}
	return nil, &fs.PathError{Op: "open", Path: path, Err: fs.ErrNotExist}
}

func (s fakeFS) ReadDir(path string) ([]fs.DirEntry, error) { return os.ReadDir(path) }

// copyC writes a NUL-terminated string into a fixed-width kernel field.
func copyC(dst []byte, s string) {
	n := copy(dst, s)
	if n < len(dst) {
		dst[n] = 0
	}
}

// fakeInfo is an fs.FileInfo whose Sys() carries a device id, like os.Stat's.
type fakeInfo struct {
	name string
	mode fs.FileMode
	size int64
	dev  int32
}

func (f fakeInfo) Name() string       { return f.name }
func (f fakeInfo) Size() int64        { return f.size }
func (f fakeInfo) Mode() fs.FileMode  { return f.mode }
func (f fakeInfo) ModTime() time.Time { return time.Time{} }
func (f fakeInfo) IsDir() bool        { return f.mode.IsDir() }
func (f fakeInfo) Sys() any           { return &syscall.Stat_t{Dev: f.dev} }

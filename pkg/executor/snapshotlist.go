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

package executor

import (
	"errors"
	"io/fs"
	"os"
	"slices"
	"strings"
	"time"
)

// SnapshotKind classifies a file in the snapshots directory.
type SnapshotKind string

const (
	// SnapshotScheduled is a snapshot the schedule wrote for the node being asked about.
	SnapshotScheduled SnapshotKind = "scheduled"
	// SnapshotManual is a `k3sm snapshot save` file: k3sm-snapshot-<stamp> or
	// k3sm-etcd-snapshot-<stamp>, .db or .zip.
	SnapshotManual SnapshotKind = "manual"
	// SnapshotOther is a scheduled-shaped name of another node, or a name k3sm does
	// not write.
	SnapshotOther SnapshotKind = "other"
)

// partialSnapshotSuffix ends every partial or staging name a save writes (<name>.tmp,
// <name>.plain.tmp, <name>.restoring.tmp). Such a file is never a snapshot.
const partialSnapshotSuffix = ".tmp"

// manualSnapshotPrefixes start the names `k3sm snapshot save` generates.
var manualSnapshotPrefixes = []string{"k3sm-etcd-snapshot-", "k3sm-snapshot-"}

// SnapshotInfo is one snapshot file's metadata, read without opening it.
type SnapshotInfo struct {
	Name string `json:"name"`
	Size int64  `json:"size"`
	// Created is the key retention orders by: the earlier of the name's stamp and the
	// file's mtime. It is zero when that is after the current time (written under a
	// clock that was ahead), so such a file sorts as the oldest.
	Created    time.Time    `json:"created"`
	Kind       SnapshotKind `json:"kind"`
	Compressed bool         `json:"compressed"`

	// stamp is the time the name records (zero: the name records none).
	stamp time.Time
}

// IsPartialSnapshotName reports whether name is a partial write or staging name,
// never a snapshot.
func IsPartialSnapshotName(name string) bool {
	return strings.HasSuffix(name, partialSnapshotSuffix)
}

// ListSnapshots returns the snapshots in dir, through ListSnapshotsFS over
// os.DirFS(dir). A missing dir is an empty list.
func ListSnapshots(dir, node string, now time.Time) ([]SnapshotInfo, error) {
	return ListSnapshotsFS(os.DirFS(dir), node, now)
}

// ListSnapshotsFS returns the snapshots at the top of fsys, newest first by Created
// (ties by name, descending), classified for node. Only regular files with a final
// name are listed: directories, symlinks, devices and partial (.tmp) names are
// skipped. It reads the directory and each entry's Lstat; it never opens a file. A
// missing directory is an empty list. Listing through an os.Root's FS resolves the
// directory the same way the root's removals do.
func ListSnapshotsFS(fsys fs.FS, node string, now time.Time) ([]SnapshotInfo, error) {
	entries, err := fs.ReadDir(fsys, ".")
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	var out []SnapshotInfo
	for _, e := range entries {
		name := e.Name()
		if !e.Type().IsRegular() || IsPartialSnapshotName(name) {
			continue
		}
		fi, err := fs.Lstat(fsys, name)
		if err != nil || !fi.Mode().IsRegular() {
			continue
		}
		info := classifySnapshot(node, name)
		info.Size = fi.Size()
		info.Created = fi.ModTime()
		if !info.stamp.IsZero() && info.stamp.Before(info.Created) {
			info.Created = info.stamp
		}
		if info.Created.After(now.Add(etcdSnapshotWakeEvery)) {
			info.Created = time.Time{}
		}
		out = append(out, info)
	}
	slices.SortFunc(out, compareSnapshots)
	return out, nil
}

// IsSnapshotName reports whether name has a shape k3sm writes for a final snapshot:
// a scheduled snapshot of any node, or a `k3sm snapshot save` name. A partial
// (.tmp) name is not one.
func IsSnapshotName(name string) bool {
	if IsPartialSnapshotName(name) {
		return false
	}
	if _, ok := parseAnyScheduledEtcdSnapshot(name); ok {
		return true
	}
	return classifySnapshot("", name).Kind == SnapshotManual
}

// compareSnapshots orders newest first by Created, ties by name descending: the
// retention order.
func compareSnapshots(a, b SnapshotInfo) int {
	if c := b.Created.Compare(a.Created); c != 0 {
		return c
	}
	return strings.Compare(b.Name, a.Name)
}

// classifySnapshot reads name's kind, compression and stamp.
func classifySnapshot(node, name string) SnapshotInfo {
	info := SnapshotInfo{Name: name, Kind: SnapshotOther, Compressed: strings.HasSuffix(name, compressedSnapshotExt)}
	if taken, ok := parseScheduledEtcdSnapshot(node, name); ok {
		info.Kind, info.stamp = SnapshotScheduled, taken
		return info
	}
	if taken, ok := parseAnyScheduledEtcdSnapshot(name); ok {
		info.stamp = taken
		return info
	}
	for _, p := range manualSnapshotPrefixes {
		rest, ok := strings.CutPrefix(name, p)
		if !ok {
			continue
		}
		stamp, ok := strings.CutSuffix(rest, ".db")
		if !ok {
			stamp, ok = strings.CutSuffix(rest, compressedSnapshotExt)
		}
		if !ok {
			break
		}
		if t, err := time.Parse(snapshotNameLayout, stamp); err == nil {
			info.Kind, info.stamp = SnapshotManual, t
		}
		break
	}
	return info
}

// parseAnyScheduledEtcdSnapshot reports whether name has the scheduled shape for any
// node, etcd-snapshot-<node>-<unix seconds>[.zip], and its stamp.
func parseAnyScheduledEtcdSnapshot(name string) (time.Time, bool) {
	rest, ok := strings.CutPrefix(strings.TrimSuffix(name, compressedSnapshotExt), scheduledSnapshotPrefix)
	if !ok {
		return time.Time{}, false
	}
	i := strings.LastIndexByte(rest, '-')
	if i <= 0 {
		return time.Time{}, false
	}
	return parseScheduledEtcdSnapshot(rest[:i], name)
}

// SelectScheduledPrune returns the scheduled snapshots of infos past the newest keep,
// oldest last, in retention order. Only SnapshotScheduled entries are candidates, so a
// manual save or another node's snapshot never is. justTaken (a name, or "") is never
// selected and holds one of the keep slots, as the schedule's own retention needs:
// the snapshot it just wrote counts toward keep whether or not the listing saw it.
// It re-sorts its own copy, so an unsorted infos is handled, and a justTaken name not
// present in infos still holds a slot.
func SelectScheduledPrune(infos []SnapshotInfo, keep int, justTaken string) []SnapshotInfo {
	var sched []SnapshotInfo
	for _, in := range infos {
		if in.Kind == SnapshotScheduled && !IsPartialSnapshotName(in.Name) {
			sched = append(sched, in)
		}
	}
	slices.SortFunc(sched, compareSnapshots)
	slots := keep
	if justTaken != "" {
		slots--
	}
	var out []SnapshotInfo
	for _, in := range sched {
		if in.Name == justTaken {
			continue
		}
		if slots > 0 {
			slots--
			continue
		}
		out = append(out, in)
	}
	return out
}

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

package keystore

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
)

// This file is the user scope's entry quotas and its rm:
// docs/design/keystore.md § "User scope", "Quotas". A scope holds at most
// 256 entries and 16 MiB of sealed records; past either, put answers
// ErrQuota, and rm, which frees every version of an entry, still works.
// (The delivery bound is the delivery record's: deliveries.go.)

const (
	// maxScopeEntries is the most entries one user scope holds.
	maxScopeEntries = 256
	// maxScopeBytes is the most sealed record bytes one user scope holds:
	// every file in every entry directory, version records and pointers.
	maxScopeBytes = 16 << 20
)

// checkScopeQuota refuses, as ErrQuota, a put of value as name into
// entries when the scope already holds maxScopeEntries entries, or when its
// sealed records and the new entry's two records (version 1 and its
// pointer) would pass maxScopeBytes.
func checkScopeQuota(entries *os.Root, name string, value []byte) error {
	names, err := readDirNames(entries, maxDirNames)
	if err != nil {
		return err
	}
	count := 0
	var total int64
	for _, n := range names {
		if checkName(n) != nil {
			continue
		}
		count++
		size, err := entryBytes(entries, n)
		if err != nil {
			return err
		}
		total += size
	}
	if count >= maxScopeEntries {
		return fmt.Errorf("%w: the scope holds %d entries, at most %d", ErrQuota, count, maxScopeEntries)
	}
	add := int64(headerSize+len(name)+len(value)+tagSize) + int64(headerSize+len(currentName)+pointerSize+tagSize)
	if total+add > maxScopeBytes {
		return fmt.Errorf("%w: the scope's sealed records would be %d bytes, over %d; rm an entry rotated often, then put it again", ErrQuota, total+add, maxScopeBytes)
	}
	return nil
}

// entryBytes sums the sizes of the regular files in entries/name, without
// following a symlink. A name that is not a directory counts nothing.
func entryBytes(entries *os.Root, name string) (int64, error) {
	e, err := openEntryDirRaw(entries, name)
	if errors.Is(err, ErrNotFound) || errors.Is(err, ErrCorrupt) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	defer e.close()
	files, err := readDirNames(e.root, maxDirNames)
	if err != nil {
		return 0, err
	}
	var total int64
	for _, f := range files {
		fi, err := e.root.Lstat(f)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return 0, err
		}
		if fi.Mode().IsRegular() {
			total += fi.Size()
		}
	}
	return total, nil
}

// Delete removes input and every version of it from the caller's scope:
// rm. It is never refused for a quota, since it is how room is made. Like
// Put it opens the scope first, so the GeneratedUID check runs, never mints,
// and refuses while a Rewrap is half done. An entry directory without a
// current pointer, which the user scope reads as damage, is removed too.
func (u *UserScope) Delete(ctx context.Context, input string) error {
	if err := u.delete(ctx, input); err != nil {
		return fail("rm", err)
	}
	return nil
}

func (u *UserScope) delete(ctx context.Context, input string) error {
	if err := u.s.checkConfig(); err != nil {
		return err
	}
	name, err := u.own("rm", input)
	if err != nil {
		return err
	}
	root, done, err := u.s.openLocked(ctx, false, true)
	if errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("%w: the keystore directory is missing", ErrScopeAbsent)
	}
	if err != nil {
		return err
	}
	defer done()
	k, err := u.masterForWrite()
	if err != nil {
		return err
	}
	_, entries, err := u.openScope(root, func() (keys, error) { return k, nil })
	if err != nil {
		return err
	}
	defer func() { _ = entries.Close() }() // every removal is fsynced
	fi, err := entries.Lstat(name)
	if errors.Is(err, fs.ErrNotExist) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	if fi.IsDir() {
		// The pointer first, so a crash leaves a directory the user scope
		// reads as damage, never an older entry; RemoveAll removes a symlink
		// itself, never what it names.
		e, err := openEntryDirRaw(entries, name)
		if err != nil {
			return err
		}
		err = e.root.RemoveAll(currentName)
		if err == nil {
			err = syncDir(e.root)
		}
		e.close()
		if err != nil {
			return err
		}
		if err := u.s.step("delete " + name); err != nil {
			return err
		}
	}
	if err := entries.RemoveAll(name); err != nil {
		return err
	}
	return syncDir(entries)
}

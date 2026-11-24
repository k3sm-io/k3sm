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
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
)

// DenialCause is which of the places on the way to the store directory denied
// the server's open (StoreDirDenial).
type DenialCause int

const (
	// DeniedParent is a parent the service user cannot search or read:
	// server/, or the data root above it. It is never the race with a root
	// put, which never touches either.
	DeniedParent DenialCause = iota + 1
	// DeniedForeign is a store directory owned by a uid that is neither
	// root nor the service user. A root put's mkdir makes it root's until
	// its handover, so it is never that race, and nothing the store wrote
	// is known to be in it.
	DeniedForeign
	// DeniedOwn is a store directory owned by root or the service user. One
	// pass may be the race with a root put; a denial that persists is one
	// of the causes DirDenial reads.
	DeniedOwn
)

// DirDenial is what can be read, without opening it, about a directory the
// server could not open: its owner, its mode, its flags (all by Lstat, which
// needs only its parent's search permission) and whether it carries an
// extended ACL (read by path, linkHasExtendedACL). It names a repair; it is
// never a judgement, since a name can change between it and any later open.
type DirDenial struct {
	// Cause is where the denial is.
	Cause DenialCause
	// Path is the directory the repair is for: the store directory, or for
	// DeniedParent the parent that denied the walk.
	Path string
	// Unreachable is set for DeniedParent when Path itself could not be
	// Lstat'd: the directory above Path denies the search.
	Unreachable bool
	// Owner, Mode and Immutable are the Lstat's; Known reports one was read.
	Owner     uint32
	Mode      fs.FileMode
	Immutable bool
	Known     bool
	// ACL reports an extended ACL entry; ACLUnknown that it could not be
	// read, so one may be there.
	ACL        bool
	ACLUnknown bool
}

// StoreDirDenial is the denial EnsureDir found, for an err that is
// StoreDirDenied, and false for any other err.
func StoreDirDenial(err error) (DirDenial, bool) {
	var e *storeDirError
	if !errors.As(err, &e) || !e.denied {
		return DirDenial{}, false
	}
	return e.denial, true
}

// diagnoseDenied reads why the store directory could not be opened. inParent
// is set when the denial came from the parent's open or the mkdir in it
// (mkdirOwned): the parent is the cause whatever the store directory's own
// Lstat says. An Lstat of the store directory that fails with EACCES is the
// parent too: it needs only the parent's search permission.
func (s *FileStore) diagnoseDenied(inParent bool) DirDenial {
	parent := filepath.Dir(s.dir)
	fi, err := os.Lstat(s.dir)
	if inParent || errors.Is(err, syscall.EACCES) {
		d := DirDenial{Cause: DeniedParent, Path: parent}
		if pfi, perr := os.Lstat(parent); perr != nil {
			d.Unreachable = true
		} else {
			d.read(pfi)
		}
		return d
	}
	d := DirDenial{Cause: DeniedOwn, Path: s.dir}
	if err != nil {
		return d
	}
	d.read(fi)
	if d.Known && d.Owner != 0 && d.Owner != s.uid {
		d.Cause = DeniedForeign
	}
	return d
}

// read fills d from fi, an Lstat of d.Path, and the ACL read by that path.
func (d *DirDenial) read(fi fs.FileInfo) {
	if st, ok := fi.Sys().(*syscall.Stat_t); ok && st != nil {
		d.Owner, d.Immutable, d.Known = st.Uid, statImmutable(st), true
	}
	d.Mode = fi.Mode().Perm()
	acl, err := linkHasExtendedACL(d.Path)
	d.ACL, d.ACLUnknown = acl, err != nil
}

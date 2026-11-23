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
	"log/slog"
	"sync"

	"golang.org/x/sys/unix"
)

// Root-written files in the data root (the removed-scopes record, the
// maintenance marker, the floor acknowledgement) are root's, unflagged,
// and replaced only by rename. Any local user can link(2) such a file into
// a directory of its own, and the alias gives it no write power: root never
// writes the inode in place, and the file is closed to group and other
// writes. So a second link is a Warn, never a refusal; refusing it would let
// any user block every scope open, the maintenance verbs and the floor
// acknowledgement. The service-owned flagged logs keep their one-link rule:
// a flagged file cannot be linked.

// errRootFileShape is a root-written data-root file that is not a regular
// file of the data root's owner, closed to group and other writes, with no
// file flag and no extended ACL.
var errRootFileShape = errors.New("it is not a regular file of the data root's owner (root), closed to group and other writes, with no file flag and no extended ACL")

// warnedLinks holds the names already warned of a second link, so each is
// warned once a process.
var warnedLinks sync.Map

// judgeRootFile judges the root-written file name open at fd, which st
// describes: type, owner, mode, flags and ACL. A link count above one is
// warned of once and accepted.
func (s *FileStore) judgeRootFile(fd int, st *unix.Stat_t, name string) error {
	if st.Mode&unix.S_IFMT != unix.S_IFREG || int64(st.Uid) != int64(s.floorUID) || st.Mode&0o022 != 0 {
		return errRootFileShape
	}
	fl, err := fdFlags(fd)
	if err != nil || fl != 0 {
		return errRootFileShape
	}
	if acl, err := fdHasACL(fd); err != nil || acl {
		return errRootFileShape
	}
	if st.Nlink > 1 {
		if _, seen := warnedLinks.LoadOrStore(name, true); !seen {
			slog.Warn("a root-written keystore file in the data root has more than one link; root replaces it only by rename, so the other name keeps an old copy and gives no write power", "file", name, "links", st.Nlink)
		}
	}
	return nil
}

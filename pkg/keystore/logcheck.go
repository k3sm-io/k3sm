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

	"golang.org/x/sys/unix"
)

// UserFloorLogName, AuditLogName and RunDirName are the names install
// creates: the two append-only logs, each in its own directory in
// LogsDirName (FloorDirName, AuditDirName), and the keystore's
// run directory in the data root (docs/design/keystore.md § "The user-scope floor").
// UserScopesDirName is the user scopes' directory in the entries'
// directory, whose presence makes a missing floor a restore, not an
// install.
const (
	UserFloorLogName  = userFloorLogName
	AuditLogName      = auditLogName
	RunDirName        = "keystore-run"
	UserScopesDirName = userScopesName
	// LogsDirName is the logs' directory in the data root, root's 0755;
	// FloorDirName and AuditDirName the logs' own directories in it, root's
	// 0755; StagingDirName the root-only staging directory a replacement
	// log directory is built in.
	LogsDirName    = logsDirName
	FloorDirName   = floorDirName
	AuditDirName   = auditDirName
	StagingDirName = stagingDirName
	// ArchivesDirName is the audit archives' directory in AuditDirName,
	// root's ArchivesDirMode, which only root can reach.
	ArchivesDirName = archivesDirName
	ArchivesDirMode = archivesDirMode
	// FloorLockName is keystore-lock in the data root, which every
	// maintenance verb holds while it runs.
	FloorLockName = floorLockName
)

// LogDirOf is the directory in LogsDirName that holds the log name.
func LogDirOf(name string) string { return logDirOf(name) }

// MaintenanceMarkerName is the maintenance marker in the data root:
// present only while floor --rebuild or audit --rotate runs, or after one
// stopped part-way, until the next maintenance verb or install, run with
// no maintenance lock held, removes it.
const MaintenanceMarkerName = maintenanceMarkerName

// LinkedLogRepair reports, when err is a log refused for more than one link
// (a hard link to it), the root verb that repairs it: floor --rebuild for
// the floor and audit --rotate for the audit log, each of which replaces
// the log with a fresh file.
func LinkedLogRepair(err error) (string, bool) {
	var le logLinkedError
	if errors.As(err, &le) {
		return repairVerb(le.log), true
	}
	return "", false
}

// JudgeDirFlagsACL refuses the directory open at fd, as the keystore judges
// its data root, when it carries a file flag beside SF_APPEND or a
// non-empty extended ACL, or when either cannot be read.
func JudgeDirFlagsACL(fd int) error { return judgeFlagsACL(fd, fdFlags) }

// CheckLogFlags opens each append-only log through the data root and judges
// it on its descriptor, as every read and append does (judgeLog): a log
// whose SF_APPEND flag is clear, one that is not the service user's, or one
// that is missing is an error, and the first refusal is returned. It reads
// and writes nothing. It is the flag and owner check of the doctor row; the
// start step makes the same check (CheckLogBounds) before the user scope
// starts. Its error names no figure a socket caller could use, but it is
// root's: the doctor prints it.
func (s *FileStore) CheckLogFlags(ctx context.Context) error {
	for _, name := range []string{userFloorLogName, auditLogName} {
		if err := ctx.Err(); err != nil {
			return err
		}
		l := &appendLog{s: s, name: name}
		f, _, err := l.open(unix.O_RDONLY)
		if err != nil {
			return err
		}
		if err := f.Close(); err != nil {
			return fmt.Errorf("close %s: %w", name, err)
		}
	}
	return nil
}

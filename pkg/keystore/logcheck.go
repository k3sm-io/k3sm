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
	"fmt"

	"golang.org/x/sys/unix"
)

// UserFloorLogName, AuditLogName and RunDirName are the names install
// creates in the data root: the two append-only logs and the keystore's
// run directory (docs/design/keystore.md § "The user-scope floor").
// UserScopesDirName is the user scopes' directory in the entries'
// directory, whose presence makes a missing floor a restore, not an
// install.
const (
	UserFloorLogName  = userFloorLogName
	AuditLogName      = auditLogName
	RunDirName        = "keystore-run"
	UserScopesDirName = userScopesName
)

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

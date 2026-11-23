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
)

// auditViaRoot is a root verb's via (docs/design/keystore.md § "The audit
// log": coverage).
const auditViaRoot = "root"

// AuditRoot appends the one audit line of a root verb: op (put, rotate, rm,
// rewrap, deliver, undeliver, list, show) on the system-scope entry name,
// via root, with result: "ok", or the verb's own word for how it ended
// ("refused", "resumed"); a result outside lowercase letters and '-' is
// written as the placeholder, and so is a name outside the entry grammar,
// or none. It appends under the
// exclusive store lock, as every append does.
//
// The line is written only once install has created the audit log: before
// that the system scope works as in Phase A and AuditRoot writes nothing
// and returns nil. A log that is missing while user scopes exist, or one
// the check refuses (flag clear, not the service user's), is an error: the
// verb has run, and the caller reports that its line was not written.
func (s *FileStore) AuditRoot(ctx context.Context, op, name, result string) error {
	if err := s.checkConfig(); err != nil {
		return err
	}
	if checkName(name) != nil {
		name = auditPlaceholder
	}
	if !auditWord(op) {
		op = auditPlaceholder
	}
	if !auditWord(result) {
		result = auditPlaceholder
	}
	_, done, err := s.openLocked(ctx, false, true)
	if err != nil {
		return err
	}
	defer done()
	err = s.auditSink.append(auditLine{op: op, via: auditViaRoot, scope: scopeSystem, name: name, result: result})
	if errors.Is(err, errLogMissing) && !errors.Is(err, errLogMissingScopes) {
		return nil
	}
	return err
}

// auditWord reports whether w is a non-empty word of lowercase letters and
// '-', at most 32 bytes: an op or a result a root verb may write.
func auditWord(w string) bool {
	if w == "" || len(w) > 32 {
		return false
	}
	for _, c := range []byte(w) {
		if (c < 'a' || c > 'z') && c != '-' {
			return false
		}
	}
	return true
}

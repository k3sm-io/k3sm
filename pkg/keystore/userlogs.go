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

import "errors"

// The user-scope floor and the audit log are append-only files
// (docs/design/keystore.md § "The user-scope floor", "The audit log"),
// which the next change builds. Until then the store reaches each through
// an interface on FileStore, and New installs one that refuses every call:
// a user-scope write that needs a floor line or an audit line fails closed
// rather than run without one. Tests install in-memory fakes.

// userFloorLog is the user-scope floor: (scope, name, generation, seq)
// lines, of which a reader takes, per (scope, name), the highest seq among
// the lines of a generation, so the floor only rises.
type userFloorLog interface {
	// floor returns the highest seq recorded for scope, name and gen, or 0
	// when none is.
	floor(scope, name string, gen [generationSize]byte) (uint64, error)
	// append records one line.
	append(scope, name string, gen [generationSize]byte, seq uint64) error
}

// auditLine is one audit line's fields that this package fills: never a
// value and never a value's length.
type auditLine struct {
	op, scope, name, namespace, result string
	// delivery is the KeyDelivery UID a withdraw names, or
	// auditPlaceholder for one outside the grammar; empty for other ops.
	delivery string
}

// auditSink appends audit lines.
//
// The contract (docs/design/keystore.md § "The audit log": every append
// takes the store .lock): every append runs while the caller holds the
// exclusive store lock. A grant appends its line before its first write and
// a revocation after its commit, each under the lock it does its work in; a
// refusal after the lock was taken is appended before the lock is released;
// a refusal before it takes the lock briefly to append (auditBriefly), and
// one for which the lock cannot be had is not audited.
type auditSink interface {
	append(auditLine) error
}

// errUserLogsUnbuilt is every call to the user-scope floor or the audit log
// in a build that has not got the append-only files yet.
var errUserLogsUnbuilt = errors.New("the user-scope floor and audit log are not built in this release, so no user-scope write can be recorded; nothing was changed")

// unbuiltUserFloor refuses every call.
type unbuiltUserFloor struct{}

func (unbuiltUserFloor) floor(string, string, [generationSize]byte) (uint64, error) {
	return 0, errUserLogsUnbuilt
}

func (unbuiltUserFloor) append(string, string, [generationSize]byte, uint64) error {
	return errUserLogsUnbuilt
}

// unbuiltAudit refuses every call.
type unbuiltAudit struct{}

func (unbuiltAudit) append(auditLine) error { return errUserLogsUnbuilt }

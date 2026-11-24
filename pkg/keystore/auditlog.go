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
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"k3sm.io/k3sm/pkg/keystore/internal/strictjson"
)

// auditFormat is the audit line format's version, "v". It bumps only on a
// breaking change; a reader ignores fields it does not know.
const auditFormat = 1

// auditRecord is one audit line as it is written and read
// (docs/design/keystore.md § "The audit log"). It has no field for a value
// and none for a value's length, so no line can carry either. Via names the
// path the operation came by ("root" for a root verb, "socket" for an
// operation that arrived on the user socket); a line without it, as every
// line written before it existed is, still reads. Caller is the socket
// peer: its uid, and its pid, which is advisory. Version and Fingerprint
// are the version an operation wrote and its per-scope fingerprint, on the
// lines of the operations that write one (put, rotate); every other line
// carries neither. Request and Dropped are a post-frame refused line's
// (userrefused.go): the operation refused, and a summary's dropped count.
// The delivery field is
// DeliveryUID in Go, not Delivery: the export gate (unexported_test.go)
// reads a bare Delivery identifier as the delivery type, and would count
// every exported caller of the audit writer as reaching the user scope.
type auditRecord struct {
	V           int          `json:"v"`
	TS          string       `json:"ts"`
	Op          string       `json:"op"`
	Via         string       `json:"via,omitempty"`
	Caller      *auditCaller `json:"caller,omitempty"`
	Scope       string       `json:"scope"`
	Name        string       `json:"name"`
	Version     uint64       `json:"version,omitempty"`
	Fingerprint string       `json:"fingerprint,omitempty"`
	Namespace   string       `json:"namespace"`
	DeliveryUID string       `json:"delivery,omitempty"`
	Request     string       `json:"request,omitempty"`
	Result      string       `json:"result"`
	Dropped     uint64       `json:"dropped,omitempty"`
}

// auditCaller is an audit line's caller: the socket peer's uid, and its
// pid, advisory only (a pid is reused, and is read at the connection's
// accept), omitted when the peer credentials gave none.
type auditCaller struct {
	UID uint32 `json:"uid"`
	PID int32  `json:"pid,omitempty"`
}

// auditCallerKeys are auditCaller's JSON keys, exact.
var auditCallerKeys = []string{"uid", "pid"}

// UnmarshalJSON decodes a caller object as strictly as the line around it
// (auditKeysStrictOf): a key given twice, or a known key in another case,
// makes the whole line damage, so no reader picks between two uids.
func (c *auditCaller) UnmarshalJSON(b []byte) error {
	if err := auditKeysStrictOf(b, auditCallerKeys); err != nil {
		return fmt.Errorf("the caller: %w", err)
	}
	type plain auditCaller
	var p plain
	if err := json.Unmarshal(b, &p); err != nil {
		return err
	}
	*c = auditCaller(p)
	return nil
}

// fileAuditLog is the file-backed audit log.
type fileAuditLog struct{ log *appendLog }

func newFileAuditLog(s *FileStore) *fileAuditLog {
	l := &appendLog{s: s, name: auditLogName}
	l.lineUID = func(_ *logState, line []byte) (uint32, bool, error) {
		return auditLineCharge(line)
	}
	return &fileAuditLog{log: l}
}

// auditLineCharge reads line, an audit line without its newline, for
// charging: the uid of its scope (0 for none) and whether its via is the
// reconciler's, which in the revocation class draws on that uid's
// reconciler allowance (lineCharge). A line this build cannot read,
// strictly, is damage charged to no uid: the audit log is evidence, and one
// unreadable line is skipped and counted, never stopping the store.
func auditLineCharge(line []byte) (uint32, bool, error) {
	r, err := parseAuditLine(line)
	if err != nil {
		return 0, false, err
	}
	return scopeUID(r.Scope), r.Via == auditViaReconciler, nil
}

func (a *fileAuditLog) append(l auditLine) error {
	line, err := marshalAuditLine(l, a.log.s.now())
	if err != nil {
		return err
	}
	return a.log.appendLine(scopeUID(l.scope), line, l.revoke, l.revoke)
}

// marshalAuditLine encodes l as one JSON line at now, its newline
// included, refusing one longer than maxLogLine.
func marshalAuditLine(l auditLine, now time.Time) ([]byte, error) {
	b, err := json.Marshal(auditRecord{
		V:           auditFormat,
		TS:          now.UTC().Format(time.RFC3339Nano),
		Op:          l.op,
		Via:         l.via,
		Caller:      l.caller,
		Scope:       l.scope,
		Name:        l.name,
		Version:     l.version,
		Fingerprint: l.fingerprint,
		Namespace:   l.namespace,
		DeliveryUID: l.delivery,
		Request:     l.request,
		Result:      l.result,
		Dropped:     l.dropped,
	})
	if err != nil {
		return nil, fmt.Errorf("encode an audit line: %w", err)
	}
	if len(b)+1 > maxLogLine {
		return nil, fmt.Errorf("%w: refused a %d-byte audit line for %s", errLogLineTooLong, len(b)+1, l.op)
	}
	return append(b, '\n'), nil
}

// parseAuditLine is the audit reader for one line without its newline: a
// JSON object of at most maxLogLine bytes with "v" 1. Fields it does not
// know are ignored, so a later writer may add some; but it decodes strictly
// for charging (auditKeysStrict): a known key spelled in another case, or
// any key given twice, is an error, so a line is never charged to whichever
// scope a lenient decoder would pick. A line of another format version, one
// that is not a JSON object, or a longer one, is an error too.
func parseAuditLine(line []byte) (auditRecord, error) {
	var r auditRecord
	if len(line)+1 > maxLogLine {
		return r, errLogLineTooLong
	}
	if err := auditKeysStrict(line); err != nil {
		return auditRecord{}, err
	}
	if err := json.Unmarshal(line, &r); err != nil {
		return auditRecord{}, fmt.Errorf("an audit line does not parse: %w", err)
	}
	if r.V != auditFormat {
		return auditRecord{}, errors.New("an audit line is not format version 1")
	}
	return r, nil
}

// auditKeys are auditRecord's JSON keys, exact.
var auditKeys = []string{"v", "ts", "op", "via", "caller", "scope", "name", "version", "fingerprint", "namespace", "delivery", "request", "result", "dropped"}

// auditKeysStrict refuses line unless it is one JSON object whose keys are
// each given once and, where one matches a known key under encoding/json's
// case folding, spelled exactly as that key. With it json.Unmarshal reads
// each known field from the one key a strict decoder would.
func auditKeysStrict(line []byte) error { return auditKeysStrictOf(line, auditKeys) }

// auditKeysStrictOf is auditKeysStrict over the known keys known: the
// keystore's one strict-object rule (strictjson.Object), so the audit
// reader and the socket's request headers judge keys alike.
func auditKeysStrictOf(line []byte, known []string) error {
	if _, err := strictjson.Object(line, known...); err != nil {
		return fmt.Errorf("an audit line does not parse strictly: %w", err)
	}
	return nil
}

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
)

// auditFormat is the audit line format's version, "v". It bumps only on a
// breaking change; a reader ignores fields it does not know.
const auditFormat = 1

// auditRecord is one audit line as it is written and read
// (docs/design/keystore.md § "The audit log"). It has no field for a value
// and none for a value's length, so no line can carry either. The caller,
// via and fingerprint fields are the socket's and root verbs' to add.
type auditRecord struct {
	V         int    `json:"v"`
	TS        string `json:"ts"`
	Op        string `json:"op"`
	Scope     string `json:"scope"`
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
	Delivery  string `json:"delivery,omitempty"`
	Result    string `json:"result"`
}

// fileAuditLog is the file-backed audit log.
type fileAuditLog struct{ log *appendLog }

func newFileAuditLog(s *FileStore) *fileAuditLog {
	l := &appendLog{s: s, name: auditLogName}
	l.lineUID = func(_ *logState, line []byte) (uint32, error) {
		r, err := parseAuditLine(line)
		if err != nil {
			// A line this build cannot read is charged to no uid: the audit
			// log is evidence, and one unreadable line does not stop the
			// store.
			return 0, nil
		}
		return scopeUID(r.Scope), nil
	}
	return &fileAuditLog{log: l}
}

func (a *fileAuditLog) append(l auditLine) error {
	line, err := marshalAuditLine(l, a.log.s.now())
	if err != nil {
		return err
	}
	return a.log.appendLine(scopeUID(l.scope), line, l.revoke)
}

// marshalAuditLine encodes l as one JSON line at now, its newline
// included, refusing one longer than maxLogLine.
func marshalAuditLine(l auditLine, now time.Time) ([]byte, error) {
	b, err := json.Marshal(auditRecord{
		V:         auditFormat,
		TS:        now.UTC().Format(time.RFC3339Nano),
		Op:        l.op,
		Scope:     l.scope,
		Name:      l.name,
		Namespace: l.namespace,
		Delivery:  l.delivery,
		Result:    l.result,
	})
	if err != nil {
		return nil, fmt.Errorf("encode an audit line: %w", err)
	}
	if len(b)+1 > maxLogLine {
		return nil, fmt.Errorf("%w: refused a %d-byte audit line for %s", errLogLineTooLong, len(b)+1, l.op)
	}
	return append(b, '\n'), nil
}

// parseAuditLine is the tolerant audit reader for one line without its
// newline: a JSON object of at most maxLogLine bytes with "v" 1. Fields it
// does not know are ignored, so a later writer may add some; a line of
// another format version, one that is not a JSON object, or a longer one,
// is an error.
func parseAuditLine(line []byte) (auditRecord, error) {
	var r auditRecord
	if len(line)+1 > maxLogLine {
		return r, errLogLineTooLong
	}
	if err := json.Unmarshal(line, &r); err != nil {
		return auditRecord{}, fmt.Errorf("an audit line does not parse: %w", err)
	}
	if r.V != auditFormat {
		return auditRecord{}, errors.New("an audit line is not format version 1")
	}
	return r, nil
}

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
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// auditFormat is the audit line format's version, "v". It bumps only on a
// breaking change; a reader ignores fields it does not know.
const auditFormat = 1

// auditRecord is one audit line as it is written and read
// (docs/design/keystore.md § "The audit log"). It has no field for a value
// and none for a value's length, so no line can carry either. Via names the
// path the operation came by ("root" for a root verb); a line without it,
// as every line written before it existed is, still reads. The caller and
// fingerprint fields are the socket's to add.
type auditRecord struct {
	V         int    `json:"v"`
	TS        string `json:"ts"`
	Op        string `json:"op"`
	Via       string `json:"via,omitempty"`
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
			// A line this build cannot read, strictly, is damage charged to
			// no uid: the audit log is evidence, and one unreadable line is
			// skipped and counted, never stopping the store.
			return 0, err
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
	return a.log.appendLine(scopeUID(l.scope), line, l.revoke, l.revoke)
}

// marshalAuditLine encodes l as one JSON line at now, its newline
// included, refusing one longer than maxLogLine.
func marshalAuditLine(l auditLine, now time.Time) ([]byte, error) {
	b, err := json.Marshal(auditRecord{
		V:         auditFormat,
		TS:        now.UTC().Format(time.RFC3339Nano),
		Op:        l.op,
		Via:       l.via,
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
var auditKeys = []string{"v", "ts", "op", "via", "scope", "name", "namespace", "delivery", "result"}

// auditKeysStrict refuses line unless it is one JSON object whose keys are
// each given once and, where one matches a known key under encoding/json's
// case folding, spelled exactly as that key. With it json.Unmarshal reads
// each known field from the one key a strict decoder would.
func auditKeysStrict(line []byte) error {
	dec := json.NewDecoder(bytes.NewReader(line))
	if tok, err := dec.Token(); err != nil || tok != json.Delim('{') {
		return errors.New("an audit line is not a JSON object")
	}
	var seen []string
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return fmt.Errorf("an audit line does not parse: %w", err)
		}
		key, ok := tok.(string)
		if !ok {
			return errors.New("an audit line does not parse: a key is not a string")
		}
		for _, k := range seen {
			if strings.EqualFold(k, key) {
				return errors.New("an audit line gives a key twice")
			}
		}
		seen = append(seen, key)
		for _, k := range auditKeys {
			if strings.EqualFold(k, key) && k != key {
				return errors.New("an audit line spells a known key in another case")
			}
		}
		var v json.RawMessage
		if err := dec.Decode(&v); err != nil {
			return fmt.Errorf("an audit line does not parse: %w", err)
		}
	}
	if _, err := dec.Token(); err != nil {
		return fmt.Errorf("an audit line does not parse: %w", err)
	}
	return nil
}

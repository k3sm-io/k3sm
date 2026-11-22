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
	"testing"
)

// The audit reader decodes strictly for charging: a known key in another
// case, or a key given twice, is uncharged damage, never a line charged to
// whichever scope a lenient decoder would pick.
func TestAuditLineChargedStrictly(t *testing.T) {
	s, _, _ := fileLogScope(t)
	l := s.auditSink.(*fileAuditLog).log
	for _, tc := range []struct {
		line string
		uid  uint32
		ok   bool
	}{
		{`{"v":1,"op":"rm","scope":"user/1001","result":"ok"}`, 1001, true},
		{`{"v":1,"op":"rm","scope":"user/1001","extra":"x","result":"ok"}`, 1001, true},
		{`{"v":1,"op":"rm","SCOPE":"user/1001","result":"ok"}`, 0, false},
		{`{"v":1,"op":"rm","Scope":"user/1001","result":"ok"}`, 0, false},
		{`{"v":1,"op":"rm","scope":"user/1001","scope":"user/1002","result":"ok"}`, 0, false},
		{`{"v":1,"op":"rm","scope":"user/1001","Scope":"user/1002","result":"ok"}`, 0, false},
		{`{"V":1,"op":"rm","scope":"user/1001","result":"ok"}`, 0, false},
		{`{"v":1,"v":1,"op":"rm","scope":"user/1001","result":"ok"}`, 0, false},
	} {
		uid, err := l.lineUID(nil, []byte(tc.line))
		if (err == nil) != tc.ok || uid != tc.uid {
			t.Errorf("lineUID(%s) = %d, %v; want %d, accepted %v", tc.line, uid, err, tc.uid, tc.ok)
		}
	}
	// Such a line past the hard cap, where the audit log is read, is
	// skipped and counted as damage.
	size := int64(len(readLog(t, s, auditLogName)))
	s.logSoftCap, s.logHardCap = size, size
	appendLogBytes(t, s, auditLogName, []byte(`{"v":1,"op":"rm","scope":"user/1001","result":"ok"}`+"\n"))
	appendLogBytes(t, s, auditLogName, []byte(`{"v":1,"op":"rm","scope":"user/1001","scope":"user/1002","result":"ok"}`+"\n"))
	if n, _, err := s.CheckLogBounds(context.Background()); err != nil || n != 1 {
		t.Fatalf("CheckLogBounds over a duplicate-key audit line: %d, %v, want 1, nil", n, err)
	}
}

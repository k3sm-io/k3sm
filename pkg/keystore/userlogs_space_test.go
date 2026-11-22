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
	"context"
	"errors"
	"testing"
)

// U24: every append preflights free space on the log's descriptor and
// refuses, retryably and writing nothing, below 1 MiB plus the line.
func TestLogAppendPreflightsFreeSpace(t *testing.T) {
	ctx := context.Background()
	s, server, u := fileLogScope(t)
	var asked int
	free := func(int) (uint64, error) { asked++; return logFreeMargin, nil }
	s.userFloor.(*fileFloorLog).log.freeSpace = free
	s.auditSink.(*fileAuditLog).log.freeSpace = free
	snap := treeSnapshot(t, server)
	floor, audit := readLog(t, s, userFloorLogName), readLog(t, s, auditLogName)
	if _, err := u.Put(ctx, "user/1001/other", KindOpaque, []byte("v")); !errors.Is(err, errLogNoSpace) {
		t.Fatalf("put with too little free space: %v, want errLogNoSpace", err)
	}
	if asked == 0 {
		t.Fatal("free space was not asked")
	}
	if errors.Is(errLogNoSpace, ErrCorrupt) {
		t.Fatal("a refusal for space is damage")
	}
	checkTreeUnchanged(t, snap, treeSnapshot(t, server))
	if !bytes.Equal(floor, readLog(t, s, userFloorLogName)) || !bytes.Equal(audit, readLog(t, s, auditLogName)) {
		t.Fatal("a line was appended with too little free space")
	}
}

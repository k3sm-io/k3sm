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
	"strings"
	"testing"
)

// TestUserWriteGuardFailsClosed: the user scope's pending-merge guard
// refuses a store with no data root, where whether a restore is staged
// cannot be read, rather than letting the write through as MergePending's
// nil (no floor, so nothing pending) would.
func TestUserWriteGuardFailsClosed(t *testing.T) {
	s, _ := newTestStore(t)
	fakeGUIDs(t, map[uint32][generationSize]byte{1001: guid(0xA1)})
	u := userScope(t, s, 1001)
	if err := u.userWriteAllowed(); err != nil {
		t.Fatalf("the guard with a data root and no restore staged: %v", err)
	}
	s.dataRoot = ""
	if err := u.userWriteAllowed(); !errors.Is(err, errInvalidConfig) {
		t.Fatalf("the guard with no data root: %v, want a refusal", err)
	}
}

// TestMergePendingRefusalSaysWhatItWrote: a user write refused while a
// restore is staged appends its one refused line to the audit log, as
// every user refusal does, changes no entry, and its text says exactly
// that.
func TestMergePendingRefusalSaysWhatItWrote(t *testing.T) {
	ctx := context.Background()
	s, server := newTestStore(t)
	mustPut(t, s, "k", KindOpaque, []byte("v"))
	fakeGUIDs(t, map[uint32][generationSize]byte{1001: guid(0xA1)})
	_, audit := userLogs(s)
	u := userScope(t, s, 1001)
	writeAsideFloor(t, server, floorOf(t, server))
	before := len(audit.all())
	_, err := u.Put(ctx, "user/1001/a", KindOpaque, []byte("v"))
	if !errors.Is(err, errMergePending) {
		t.Fatalf("a user put with a restore staged: %v, want errMergePending", err)
	}
	lines := audit.all()[before:]
	if len(lines) != 1 || lines[0].result == auditResultOK {
		t.Fatalf("the refused put's audit lines %+v, want its one refused line", lines)
	}
	if want := "writes nothing but, for a user verb, at most its one refused line in the audit log"; !strings.Contains(err.Error(), want) {
		t.Fatalf("the refusal %q does not say %q", err, want)
	}
}

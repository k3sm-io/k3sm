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
	"strings"
	"testing"
	"time"
)

// A configuration under which a uid's revocation budget is already spent
// past the hard cap would silently disable that uid's revocations: it is
// refused at store open, naming the remedy.
func TestCheckLogBoundsRefusesSpentRevocationBudget(t *testing.T) {
	ctx := context.Background()
	s, _, _ := fileLogScope(t)
	size := int64(len(readLog(t, s, auditLogName)))
	s.logSoftCap, s.logHardCap, s.logRevokeBudget = size, size, 4*maxLogLine
	line, err := marshalAuditLine(auditLine{op: "rm", scope: "user/1001", name: "token", result: "ok"}, time.Unix(1_800_000_000, 0))
	if err != nil {
		t.Fatal(err)
	}
	appendLogBytes(t, s, auditLogName, bytes.Repeat(line, 4*maxLogLine/len(line)))
	if err := s.CheckLogBounds(ctx); err != nil {
		t.Fatalf("store open with the budget not yet spent: %v", err)
	}
	appendLogBytes(t, s, auditLogName, bytes.Repeat(line, 2))
	err = s.CheckLogBounds(ctx)
	if !errors.Is(err, errInvalidConfig) || !errors.Is(err, errLogRevokeBudgetSpent) {
		t.Fatalf("store open with a uid past its revocation budget: %v, want errLogRevokeBudgetSpent", err)
	}
	if !strings.Contains(err.Error(), "sudo k3sm doctor") || !strings.Contains(err.Error(), "caps") {
		t.Fatalf("the refusal %q does not name the remedy", err)
	}
}

// The revocation budget holds at least two whole lines.
func TestCheckConfigRevocationBudgetFloor(t *testing.T) {
	s, _ := newTestStore(t)
	s.logRevokeBudget = 2*maxLogLine - 1
	if err := s.checkConfig(); !errors.Is(err, errInvalidConfig) {
		t.Fatalf("checkConfig with a budget under two lines: %v, want errInvalidConfig", err)
	}
	s.logRevokeBudget = 2 * maxLogLine
	if err := s.checkConfig(); err != nil {
		t.Fatalf("checkConfig with a budget of two lines: %v", err)
	}
}

// The default budget holds one scope's full revocation: every entry rm'd
// under the longest scope and name, each a floor tombstone and an audit
// line; and logReadBound stays overflow-free at the caps' bounds with it.
func TestDefaultRevocationBudgetHoldsFullRevocation(t *testing.T) {
	scope := userScopeOf(maxScopeUID)
	name := strings.Repeat("a", maxNameLen)
	tomb, err := tombLine(scope, name, [generationSize]byte{})
	if err != nil {
		t.Fatal(err)
	}
	worst := 0
	for _, result := range []string{"ok", "committed", "scope-absent", "not-found", "log-full", "corrupt", "error"} {
		al, err := marshalAuditLine(auditLine{op: "rm", scope: scope, name: name, result: result}, time.Date(2026, 12, 31, 23, 59, 59, 999999999, time.UTC))
		if err != nil {
			t.Fatal(err)
		}
		worst = max(worst, len(al))
	}
	need := int64(maxScopeEntries * (len(tomb) + worst))
	if defaultLogRevocationBytes < need {
		t.Fatalf("defaultLogRevocationBytes %d is under one scope's full revocation, %d", int64(defaultLogRevocationBytes), need)
	}
	if defaultLogRevocationBytes > maxLogRevokeBudget || defaultLogRevocationBytes < 2*maxLogLine {
		t.Fatalf("defaultLogRevocationBytes %d is outside its bounds", int64(defaultLogRevocationBytes))
	}
	s, _ := newTestStore(t)
	s.logHardCap, s.logRevokeBudget = maxLogHardCap, defaultLogRevocationBytes
	if b := s.logReadBound(); b <= s.logHardCap || b < 0 {
		t.Fatalf("logReadBound() = %d, overflowed", b)
	}
}

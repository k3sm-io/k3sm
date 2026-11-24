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
	"fmt"
	"slices"
	"strings"
	"testing"
)

// A change already committed part way whose audit line then fails keeps
// both failures: the result is still Committed, carries the audit
// failure, and is logged at Warn with the scope and verb, never a figure.
func TestCommittedChangeKeepsAuditFailure(t *testing.T) {
	ctx := context.Background()
	t.Run("rm", func(t *testing.T) {
		s, _, u := newDeliveryScope(t)
		fl, audit := userLogs(s)
		fl.mu.Lock()
		for _, g := range []byte{0x31, 0x32} {
			fl.lines = append(fl.lines, memFloorLine{scope: "user/1001", name: "gone", gen: guid(g), seq: 1})
		}
		fl.buryLimit = fl.buried + 1
		fl.mu.Unlock()
		audit.mu.Lock()
		audit.fail = true
		audit.mu.Unlock()
		logs := captureWarn(t)
		err := u.Delete(ctx, "user/1001/gone")
		checkCommittedAuditFailure(t, err, logs.String(), "rm")
	})
	t.Run("withdraw", func(t *testing.T) {
		s, _, u := newDeliveryScope(t)
		if err := u.addDelivery(ctx, testDelivery(1)); err != nil {
			t.Fatal(err)
		}
		fl, audit := userLogs(s)
		fl.mu.Lock()
		fl.failAppend = true
		fl.mu.Unlock()
		audit.mu.Lock()
		audit.fail = true
		audit.mu.Unlock()
		logs := captureWarn(t)
		err := u.withdrawDelivery(ctx, testDelivery(1).uid)
		checkCommittedAuditFailure(t, err, logs.String(), "withdraw")
	})
}

func checkCommittedAuditFailure(t *testing.T, err error, logs, verb string) {
	t.Helper()
	if !Committed(err) {
		t.Fatalf("%s committed part way with its audit failing: %v, want Committed", verb, err)
	}
	if !strings.Contains(err.Error(), "injected audit append failure") {
		t.Errorf("%s: %v, want the audit failure kept beside the commit", verb, err)
	}
	if !strings.Contains(logs, "level=WARN") || !strings.Contains(logs, "scope=user/1001") || !strings.Contains(logs, "op="+verb) {
		t.Errorf("%s: Warn log %q, want the scope and verb", verb, logs)
	}
	if strings.Contains(logs, "injected") {
		t.Errorf("%s: Warn log %q carries the error text", verb, logs)
	}
}

// auditResults is the closed set auditResult names an operation's outcome
// from; "error" is every refusal it has no other name for.
var auditResults = []string{
	auditResultOK, auditResultCommitted, "quota", "not-found", "exists", "scope-absent", "corrupt",
	"log-full", "invalid-name", "kind-mismatch", "quarantined", "floor-degraded", "error",
}

// A refusal's audit result names its sentinel from the closed set
// auditResults: a bad name, a kind mismatch, a quarantine and the floor's
// damage are told apart, never collapsed to "error"; a refusal with no
// name of its own is "error", and every result is in the set.
func TestAuditResultNamesRefusals(t *testing.T) {
	wrap := func(err error) error { return fmt.Errorf("user scope put: %w", err) }
	for _, tc := range []struct {
		err  error
		want string
	}{
		{wrap(ErrInvalidName), "invalid-name"},
		{wrap(ErrKindMismatch), "kind-mismatch"},
		{wrap(fmt.Errorf("%w: %w", errScopeQuarantined, errFloorDegraded)), "quarantined"},
		{wrap(errFloorDegraded), "floor-degraded"},
		{wrap(ErrQuota), "quota"},
		{wrap(ErrCorrupt), "corrupt"},
		{wrap(errors.New("no sentinel")), "error"},
		{wrap(ErrTypedCredential), "error"},
	} {
		got := auditResult(tc.err)
		if got != tc.want {
			t.Errorf("auditResult(%v) = %q, want %q", tc.err, got, tc.want)
		}
		if !slices.Contains(auditResults, got) {
			t.Errorf("auditResult(%v) = %q, outside auditResults", tc.err, got)
		}
	}
}

// A partial commit is audited as "committed", apart from a whole one's "ok".
func TestAuditResultCommitted(t *testing.T) {
	if got := auditResult(nil); got != "ok" {
		t.Errorf("auditResult(nil) = %q, want ok", got)
	}
	if got := auditResult(errCommitted); got != "committed" {
		t.Errorf("auditResult(errCommitted) = %q, want committed", got)
	}
	if got := auditResult(committedf(errors.New("x"), "y")); got != "committed" {
		t.Errorf("auditResult(ErrCommitted) = %q, want committed", got)
	}
	ctx := context.Background()
	s, _, u := newDeliveryScope(t)
	fl, _ := userLogs(s)
	fl.mu.Lock()
	for _, g := range []byte{0x31, 0x32} {
		fl.lines = append(fl.lines, memFloorLine{scope: "user/1001", name: "gone", gen: guid(g), seq: 1})
	}
	fl.buryLimit = fl.buried + 1
	fl.mu.Unlock()
	if err := u.Delete(ctx, "user/1001/gone"); !Committed(err) {
		t.Fatalf("rm whose second tombstone failed: %v", err)
	}
	if l := lastAudit(t, s); l.result != "committed" {
		t.Fatalf("partial rm audited %q, want committed", l.result)
	}
	fl.mu.Lock()
	fl.buryLimit = 0
	fl.mu.Unlock()
	if err := u.Delete(ctx, "user/1001/gone"); err != nil {
		t.Fatal(err)
	}
	if l := lastAudit(t, s); l.result != "ok" {
		t.Fatalf("whole rm audited %q, want ok", l.result)
	}
	// The reader takes the result as written.
	line, err := marshalAuditLine(auditLine{op: "rm", scope: "user/1001", name: "gone", result: "committed"}, s.now())
	if err != nil {
		t.Fatal(err)
	}
	if r, err := parseAuditLine(bytes.TrimSuffix(line, []byte("\n"))); err != nil || r.Result != auditResultCommitted {
		t.Fatalf("parse of a committed line: %+v, %v", r, err)
	}
}

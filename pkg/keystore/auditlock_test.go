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
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"testing"
)

// heldAudit is an audit sink that, on each append, asserts the store lock
// is held: a second descriptor on the lock file cannot take it.
type heldAudit struct {
	lockPath string
	mu       sync.Mutex
	lines    []auditLine
	unheld   []auditLine
}

func (a *heldAudit) append(l auditLine) error {
	held := false
	if f, err := os.Open(a.lockPath); err == nil {
		err = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		held = errors.Is(err, syscall.EWOULDBLOCK)
		_ = f.Close() // releases the lock it may have taken
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.lines = append(a.lines, l)
	if !held {
		a.unheld = append(a.unheld, l)
	}
	return nil
}

// TestAuditAppendsHoldTheLock pins the auditSink contract: every append,
// grant, revocation or refusal, runs while the caller holds the store lock.
func TestAuditAppendsHoldTheLock(t *testing.T) {
	ctx := context.Background()
	s, server, u := newDeliveryScope(t)
	a := &heldAudit{lockPath: filepath.Join(server, "keystore", lockName)}
	s.auditSink = a
	steps := []struct {
		name string
		run  func() error
	}{
		{"put", func() error { _, err := u.Put(ctx, "user/1001/other", KindOpaque, []byte("v")); return err }},
		{"put refused for its name", func() error { _, err := u.Put(ctx, "user/1001/Bad Name", KindOpaque, []byte("v")); return err }},
		{"put refused for its value", func() error { _, err := u.Put(ctx, "user/1001/empty", KindOpaque, nil); return err }},
		{"put refused under the lock", func() error { _, err := u.Put(ctx, "user/1001/other", KindOpaque, []byte("v")); return err }},
		{"deliver", func() error { return u.addDelivery(ctx, testDelivery(1)) }},
		{"deliver refused for its fields", func() error { d := testDelivery(2); d.uid = "x"; return u.addDelivery(ctx, d) }},
		{"deliver refused under the lock", func() error { return u.addDelivery(ctx, testDelivery(1)) }},
		{"withdraw", func() error { return u.withdrawDelivery(ctx, testDelivery(1).uid) }},
		{"withdraw refused under the lock", func() error { return u.withdrawDelivery(ctx, testDelivery(9).uid) }},
		{"rm", func() error { return u.Delete(ctx, "user/1001/other") }},
		{"rm refused for its name", func() error { return u.Delete(ctx, "user/1001/Bad Name") }},
		{"rm refused under the lock", func() error { return u.Delete(ctx, "user/1001/other") }},
	}
	for _, st := range steps {
		n := len(a.lines)
		_ = st.run() // refusals are expected; the lines are what is checked
		if len(a.lines) == n {
			t.Errorf("%s appended no audit line", st.name)
		}
	}
	for _, l := range a.unheld {
		t.Errorf("audit line %+v appended without the store lock", l)
	}
}

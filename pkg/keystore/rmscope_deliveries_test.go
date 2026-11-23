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
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// A rolled-back authentic delivery record, put back from before a delivery
// was added, names no delivery; read against the floor it is a rollback,
// so rm-scope never reports exit 0 over it: it removes the scope committed,
// saying its deliveries were not checked, and prints no restore advice.
func TestRmScopeRolledBackDeliveriesIsNotExitZero(t *testing.T) {
	s, server, u := fileLogScope(t)
	older := readDeliveriesBytes(t, server)
	if err := u.addDelivery(t.Context(), testDelivery(1)); err != nil {
		t.Fatal(err)
	}
	putBackDeliveries(t, server, older)
	res, err := s.RemoveScope(t.Context(), 1001)
	if err == nil || !Committed(err) {
		t.Fatalf("rm-scope over a rolled-back delivery record: %v (recorded %v), want committed, not exit 0", err, res.Recorded)
	}
	msg := err.Error()
	if !strings.Contains(msg, "deliveries from this scope were not checked") || !strings.Contains(msg, "older") {
		t.Errorf("the error %q does not say the record is older and deliveries were not checked", msg)
	}
	if strings.Contains(msg, "sudo") || strings.Contains(msg, "restore the matched set") {
		t.Errorf("the error %q carries the shared restore advice", msg)
	}
}

// A delivery record that names no delivery but cannot be checked against
// the floor (the floor did not read) is never exit 0: committed, with the
// "not confirmed" note.
func TestRmScopeUnverifiedDeliveriesIsNotExitZero(t *testing.T) {
	s, _, _ := fileLogScope(t)
	setSeam(t, &rmReadDeliveries, func(*UserScope, *openedScope) (deliveriesRead, error) {
		return deliveriesRead{unverified: unix.EIO}, nil
	})
	_, err := s.RemoveScope(t.Context(), 1001)
	if err == nil || !Committed(err) || !strings.Contains(err.Error(), "deliveries are not confirmed") {
		t.Fatalf("rm-scope with the floor unread for the delivery check: %v, want committed, deliveries not confirmed", err)
	}
}

// The no-key and untrusted paths never read the delivery record, and say
// so.
func TestRmScopeKeylessPathsSayDeliveriesUnchecked(t *testing.T) {
	for name, damage := range map[string]func(p string) error{
		"no key":    os.Remove,
		"untrusted": func(p string) error { return os.WriteFile(p, []byte("not a key record"), fileMode) },
	} {
		t.Run(name, func(t *testing.T) {
			s, server, _ := fileLogScope(t)
			if err := damage(filepath.Join(scopeDir(server, "1001"), scopeKeyName)); err != nil {
				t.Fatal(err)
			}
			_, err := s.RemoveScope(t.Context(), 1001)
			if err == nil || !Committed(err) || !strings.Contains(err.Error(), "the scope's deliveries were not checked") {
				t.Fatalf("rm-scope on the %s path: %v, want committed, saying deliveries were not checked", name, err)
			}
		})
	}
}

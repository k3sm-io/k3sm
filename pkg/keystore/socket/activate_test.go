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

package socket

import (
	"context"
	"errors"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

// The activation tests that need no descriptor. The ones that hand a real
// socket over, as launchd does, are in activate_integration_test.go, behind
// the integration tag.

// fakeActivator hands out fds, or err, and counts its calls.
type fakeActivator struct {
	fds   func(t *testing.T) []int
	err   error
	calls int
	t     *testing.T
	// handed is set once a call returned descriptors; locked once a call
	// ran with syscall.ForkLock held.
	handed, locked bool
}

// Activate answers EALREADY after a call that handed descriptors over, as
// <launch.h> documents launch_activate_socket does (not measured), and records whether syscall.ForkLock was
// read-held during the call.
func (a *fakeActivator) Activate(string) ([]int, error) {
	a.calls++
	if syscall.ForkLock.TryLock() {
		syscall.ForkLock.Unlock()
	} else {
		a.locked = true
	}
	if a.handed {
		return nil, unix.EALREADY
	}
	var fds []int
	if a.fds != nil {
		fds = a.fds(a.t)
	}
	a.handed = a.handed || len(fds) > 0
	return fds, a.err
}

// passPath is a path check that passes.
func passPath(string) error { return nil }

// launchd binds an activated socket under /var/run/com.apple.launchd.<random>/
// and renames it into place, so the descriptor's address reads that name
// (measured); it is accepted for the entry's own name only.
func TestLaunchdBindName(t *testing.T) {
	for p, want := range map[string]bool{
		"/var/run/com.apple.launchd.IIQ24YBjg6/keys":      true,
		"/var/run/com.apple.launchd.IIQ24YBjg6/other":     false,
		"/var/run/com.apple.launchd./keys":                false,
		"/var/run/com.apple.launchd.a/b/keys":             false,
		"/var/run/com.apple.launchd.../keys":              false,
		"/tmp/com.apple.launchd.IIQ24YBjg6/keys":          false,
		"/var/run/com.apple.launchd.IIQ24YBjg6/keys.sock": false,
	} {
		if got := launchdBindName(p, "keys"); got != want {
			t.Errorf("%s: %v, want %v", p, got, want)
		}
	}
}

// The refusals launchd answers with no descriptor are ActivationErrors with
// their terminal reasons: ESRCH is OffNotActivated, ENOENT
// OffSocketParentMissing, EALREADY OffAlreadyActivated, and no descriptor at
// all ErrActivatedWrong (OffActivatedWrong); a nil activator is not
// activated. The refusals of a descriptor handed over are
// TestActivatedListenerRefusals (integration).
func TestActivationRefusalsWithoutDescriptor(t *testing.T) {
	for _, tt := range []struct {
		name string
		a    *fakeActivator
		is   error
		want string
		r    OffReason
	}{
		{"not the launchd job", &fakeActivator{err: unix.ESRCH}, ErrNotActivated, "not the server's launchd job", OffNotActivated},
		{"no socket of that name for this job", &fakeActivator{err: unix.ENOENT}, ErrNotActivated, "no socket of that name for this job", OffSocketParentMissing},
		{"already activated", &fakeActivator{err: unix.EALREADY}, unix.EALREADY, "already handed", OffAlreadyActivated},
		{"no descriptor", &fakeActivator{}, ErrActivatedWrong, "no descriptor", OffActivatedWrong},
	} {
		t.Run(tt.name, func(t *testing.T) {
			tt.a.t = t
			ln, err := NewActivation("keys", "/nonexistent/keys.sock", tt.a, passPath).Source()(context.Background())
			var ae *ActivationError
			if ln != nil || !errors.Is(err, tt.is) || !errors.As(err, &ae) || ae.Reason != tt.r {
				t.Fatalf("got %v, %v; want %v as %q", ln, err, tt.is, tt.r)
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error %q does not say %q", err, tt.want)
			}
			if tt.a.locked {
				t.Fatal("launch_activate_socket ran with syscall.ForkLock held")
			}
		})
	}
	if _, err := NewActivation("keys", "/nonexistent/keys.sock", nil, passPath).Source()(context.Background()); !errors.Is(err, ErrNotActivated) {
		t.Fatalf("nil activator: %v", err)
	}
}

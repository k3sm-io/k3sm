//go:build integration

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

package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"

	"k3sm.io/k3sm/pkg/install"
	"k3sm.io/k3sm/pkg/keystore/socket"
)

// The activation's path check over a real socket handed over as launchd
// does: in the integration tier, since it binds a kernel socket
// (internal/testgate).

// fixedActivator hands out one listening socket at path, then EALREADY.
type fixedActivator struct {
	t    *testing.T
	path string
	done bool
}

func (a *fixedActivator) Activate(string) ([]int, error) {
	if a.done {
		return nil, unix.EALREADY
	}
	a.done = true
	fd, err := unix.Socket(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	if err != nil {
		a.t.Fatal(err)
	}
	if err := unix.Bind(fd, &unix.SockaddrUnix{Name: a.path}); err != nil {
		a.t.Fatal(err)
	}
	if err := unix.Listen(fd, 4); err != nil {
		a.t.Fatal(err)
	}
	unix.CloseOnExec(fd)
	return []int{fd}, nil
}

// The activation's path check is doctor's rule: a socket at the clients'
// path that this (non-root) user owns, in its group, is refused as OffActivatedWrong, the
// descriptor launchd handed over notwithstanding; a missing path and a
// regular file are refused by the same rule (TestDoctorKeystoreSocketLstat).
func TestActivationRefusesClientPathNotRoots(t *testing.T) {
	dir, err := os.MkdirTemp("", "kswd")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	path := filepath.Join(dir, "keys.sock")
	act := socket.NewActivation(install.KeystoreSocketsEntry, path, &fixedActivator{t: t, path: path}, checkKeystoreSocketPath)
	_, err = act.Source()(context.Background())
	var ae *socket.ActivationError
	if !errors.As(err, &ae) || ae.Reason != socket.OffActivatedWrong || !errors.Is(err, errNoListeningSocket) {
		t.Fatalf("got %v, want OffActivatedWrong over doctor's no-listening-socket rule", err)
	}
	for _, p := range []string{filepath.Join(dir, "absent"), dir} {
		if err := checkKeystoreSocketPath(p); !errors.Is(err, errNoListeningSocket) {
			t.Errorf("%s: %v, want no listening socket", p, err)
		}
	}
}

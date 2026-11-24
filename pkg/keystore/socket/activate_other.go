//go:build !darwin || !cgo

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
	"errors"

	"golang.org/x/sys/unix"
)

// LaunchdActivator is the Activator over launch_activate_socket. Without
// cgo on darwin, or off darwin, there is no launchd to ask: every call
// fails with ESRCH, so the user scope stays off.
type LaunchdActivator struct{}

// Activate reports that no socket was activated.
func (LaunchdActivator) Activate(string) ([]int, error) { return nil, unix.ESRCH }

// socketAccepting cannot read a socket's state without darwin's libproc.
func socketAccepting(int) (bool, error) {
	return false, errors.New("the listening state cannot be read on this build")
}

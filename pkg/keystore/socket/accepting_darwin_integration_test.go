//go:build integration && darwin

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
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

// socketAccepting reads proc_pidfdinfo's socket options: a listening
// socket is true, a bound socket that is not listening is false, and a
// descriptor that is not a socket is an error, never a false with no
// error. It binds real sockets, so it is in the integration tier.
func TestSocketAcceptingReadsTheListeningState(t *testing.T) {
	dir := sockDir(t)
	for _, tt := range []struct {
		name   string
		listen bool
	}{{"listening", true}, {"bound, not listening", false}} {
		fd, err := unix.Socket(unix.AF_UNIX, unix.SOCK_STREAM, 0)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = unix.Close(fd) }() // a probe
		if err := unix.Bind(fd, &unix.SockaddrUnix{Name: filepath.Join(dir, tt.name[:1]+".sock")}); err != nil {
			t.Fatal(err)
		}
		if tt.listen {
			if err := unix.Listen(fd, 1); err != nil {
				t.Fatal(err)
			}
		}
		if got, err := socketAccepting(fd); err != nil || got != tt.listen {
			t.Errorf("%s: socketAccepting = %v, %v; want %v, nil", tt.name, got, err, tt.listen)
		}
	}
	var p [2]int
	if err := unix.Pipe(p[:]); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = unix.Close(p[0]); _ = unix.Close(p[1]) }() // a probe
	if got, err := socketAccepting(p[0]); err == nil || got {
		t.Errorf("a pipe: socketAccepting = %v, %v; want an error", got, err)
	}
}

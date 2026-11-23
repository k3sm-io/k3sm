//go:build integration && darwin && cgo

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
	"net"
	"os"
	"testing"

	"golang.org/x/sys/unix"
)

// TestKernelPeerSourcesOnASocketpair calls the real primitives directly,
// never through the seams TestMain stubs: on a connected unix socketpair the
// peer is this process.
func TestKernelPeerSourcesOnASocketpair(t *testing.T) {
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	conns := make([]net.Conn, 2)
	for i, fd := range fds {
		f := os.NewFile(uintptr(fd), "socketpair")
		c, err := net.FileConn(f)
		_ = f.Close() // FileConn holds its own descriptor
		if err != nil {
			t.Fatal(err)
		}
		conns[i] = c
		defer func() { _ = c.Close() }()
	}
	pc, err := readPeerCred(conns[0])
	if err != nil {
		t.Fatalf("readPeerCred = %v", err)
	}
	if pc.UID != uint32(os.Geteuid()) || pc.PID != int32(os.Getpid()) {
		t.Fatalf("peer uid %d pid %d, want %d and %d", pc.UID, pc.PID, os.Geteuid(), os.Getpid())
	}
	// audit_token_t: val[1] is the euid, val[5] the pid.
	if pc.Token[1] != pc.UID || int32(pc.Token[5]) != pc.PID {
		t.Fatalf("token %v does not name uid %d pid %d", pc.Token, pc.UID, pc.PID)
	}
	// The answer depends on whether the test itself runs sandboxed; it
	// must be an answer.
	if _, err := sandboxedByToken(pc.Token); err != nil {
		t.Fatalf("sandboxedByToken = %v", err)
	}
	if _, err := readPeerCred(&countingConn{}); err == nil {
		t.Fatal("readPeerCred took a conn with no descriptor")
	}
}

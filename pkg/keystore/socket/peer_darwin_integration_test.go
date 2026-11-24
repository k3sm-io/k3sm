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
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"unsafe"

	"golang.org/x/sys/unix"
)

// integrationNoCgo is set by peer_nocgo_integration_test.go in a build
// without cgo, where the real peer primitives do not exist (peer_other.go):
// the tests here then skip. The file is not tagged cgo itself so that the
// real-socket gate, which evaluates cgo as false, sees it as integration-tier.
var integrationNoCgo bool

// requireCgo skips t in a build without cgo.
func requireCgo(t *testing.T) {
	t.Helper()
	if integrationNoCgo {
		t.Skip("the real peer primitives need CGO_ENABLED=1")
	}
}

// TestIntegrationKernelPeerSourcesOnASocketpair calls the real primitives
// directly, never through the seams TestMain stubs: on a connected unix
// socketpair the peer is this process.
func TestIntegrationKernelPeerSourcesOnASocketpair(t *testing.T) {
	requireCgo(t)
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
	// libbsm reads the same euid and pid off the token: the listener's
	// cross-check passes on a live self-peer.
	if !pc.UIDRead || pc.TokenEUID != pc.UID || pc.TokenPID != pc.PID {
		t.Fatalf("token euid %d pid %d (uid read %v), want %d and %d", pc.TokenEUID, pc.TokenPID, pc.UIDRead, pc.UID, pc.PID)
	}
	// The answer depends on whether the test itself runs sandboxed; it
	// must be an answer.
	sandboxed, err := sandboxedByToken(pc.Token)
	if err != nil {
		t.Fatalf("sandboxedByToken = %v", err)
	}
	// The start-time self-control asks about the same process through
	// task_info's token and must agree: usable (nil) exactly when the
	// process reads as not sandboxed.
	if err := selfSandboxCheck(); (err == nil) == sandboxed {
		t.Fatalf("selfSandboxCheck = %v, but the peer read as sandboxed=%v", err, sandboxed)
	}
	if _, err := readPeerCred(&countingConn{}); err == nil {
		t.Fatal("readPeerCred took a conn with no descriptor")
	}
}

// peerHelperEnv carries the helper child's orders: "<mode>:<socket path>".
// Mode "exit" connects, writes a HELLO and exits; mode "stay" connects and
// stays connected until its stdin closes.
const peerHelperEnv = "K3SM_KEYSTORE_PEER_HELPER"

// TestIntegrationPeerHelper is the helper child the peer tests re-exec this
// test binary as; without peerHelperEnv it skips.
func TestIntegrationPeerHelper(t *testing.T) {
	orders := os.Getenv(peerHelperEnv)
	if orders == "" {
		t.Skip("runs only as the helper child of the peer tests")
	}
	mode, path, _ := strings.Cut(orders, ":")
	c, err := net.Dial("unix", path)
	if err != nil {
		t.Fatalf("helper dial: %v", err)
	}
	switch mode {
	case "exit":
		if err := WriteFrame(c, Frame{Type: TypeHello, Header: []byte(`{"proto":"k3sm-keys","min":1,"max":1}`)}); err != nil {
			t.Fatalf("helper HELLO: %v", err)
		}
		os.Exit(0) // the connection is never closed by hand: the process ends with it queued
	case "stay":
		_, _ = io.Copy(io.Discard, os.Stdin) // until the parent closes stdin
		_ = c.Close()
	default:
		t.Fatalf("helper mode %q", mode)
	}
}

// realPeerCreds and realPeerSandbox reach the kernel primitives directly,
// past the seams TestMain stubs.
type realPeerCreds struct{}

func (realPeerCreds) PeerCred(c net.Conn) (PeerCred, error) { return readPeerCred(c) }

type realPeerSandbox struct{}

func (realPeerSandbox) Sandboxed(token AuditToken) (bool, error) { return sandboxedByToken(token) }

// localPeerToken is LOCAL_PEERTOKEN from <sys/un.h>.
const localPeerToken = 0x006

// integrationServiceUID is a uid no test runs as, so the test user is not
// refused as the service uid.
const integrationServiceUID = 300

// peerSocket listens on a unix socket under a short temporary directory
// (sun_path holds 104 bytes; t.TempDir's names can pass that).
func peerSocket(t *testing.T) (net.Listener, string) {
	t.Helper()
	dir, err := os.MkdirTemp("", "kspeer")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	path := filepath.Join(dir, "s")
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	return ln, path
}

// integrationListener is a Listener over ln with the real peer sources.
func integrationListener(t *testing.T, ln net.Listener) *Listener {
	t.Helper()
	h, err := NewHandler(bubbleClock{}.Now)
	if err != nil {
		t.Fatal(err)
	}
	l, err := NewListener(ln, realPeerCreds{}, realPeerSandbox{}, integrationServiceUID, bubbleClock{}, &fakeAuditor{}, h)
	if err != nil {
		t.Fatal(err)
	}
	return l
}

// helperCmd re-execs this test binary as the helper child.
func helperCmd(t *testing.T, mode, path string, wrap ...string) *exec.Cmd {
	t.Helper()
	args := append(wrap, os.Args[0], "-test.run", "^TestIntegrationPeerHelper$")
	cmd := exec.Command(args[0], args[1:]...)
	cmd.Env = append(os.Environ(), peerHelperEnv+"="+mode+":"+path)
	cmd.Stderr = os.Stderr
	return cmd
}

// TestIntegrationDeadPeerRefused: a peer that connects, writes a HELLO and
// exits before the accept is never admitted. It records exactly what each
// kernel read returns for the dead peer.
func TestIntegrationDeadPeerRefused(t *testing.T) {
	requireCgo(t)
	ln, path := peerSocket(t)
	l := integrationListener(t, ln)
	cmd := helperCmd(t, "exit", path)
	if err := cmd.Run(); err != nil {
		t.Fatalf("helper child: %v", err)
	}
	childPID := int32(cmd.ProcessState.Pid())
	c, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()

	raw, err := c.(*net.UnixConn).SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	_ = raw.Control(func(fd uintptr) {
		x, err := unix.GetsockoptXucred(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
		if err != nil {
			t.Logf("measured: LOCAL_PEERCRED err=%v", err)
		} else {
			t.Logf("measured: LOCAL_PEERCRED ok version=%d uid=%d", x.Version, x.Uid)
		}
		pid, err := unix.GetsockoptInt(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERPID)
		t.Logf("measured: LOCAL_PEERPID pid=%d err=%v (child pid %d)", pid, err, childPID)
		// LOCAL_PEERTOKEN (0x006) has no x/sys getter: a raw getsockopt
		// of the 32-byte audit_token_t.
		var tok AuditToken
		n := uint32(unsafe.Sizeof(tok))
		_, _, errno := unix.Syscall6(unix.SYS_GETSOCKOPT, fd, unix.SOL_LOCAL, localPeerToken,
			uintptr(unsafe.Pointer(&tok)), uintptr(unsafe.Pointer(&n)), 0)
		if errno != 0 {
			t.Logf("measured: LOCAL_PEERTOKEN err=%v", errno)
			return
		}
		t.Logf("measured: LOCAL_PEERTOKEN ok len=%d token=%v", n, tok)
		sandboxed, err := sandboxedByToken(tok)
		t.Logf("measured: sandbox check on the dead peer's token sandboxed=%v err=%v", sandboxed, err)
	})
	pc, credErr := readPeerCred(c)
	t.Logf("measured: readPeerCred uidRead=%v uid=%d pid=%d tokenEUID=%d tokenPID=%d token=%v err=%v",
		pc.UIDRead, pc.UID, pc.PID, pc.TokenEUID, pc.TokenPID, pc.Token, credErr)
	peer, reason := l.check(c)
	uid := peer.UID
	t.Logf("measured: listener check uid=%d reason=%q", uid, reason)
	if reason == "" {
		t.Fatalf("the listener admitted a peer that had exited before the accept (uid %d)", uid)
	}
	if pc.UIDRead && uid != pc.UID {
		t.Fatalf("the refusal names uid %d, but uid %d was read", uid, pc.UID)
	}
	// A dead login peer is charged to its own uid's share, not to the
	// no-uid class: the refusal is cred-unreadable under the uid the child
	// ran as, which is this process's.
	if reason != ReasonCredUnreadable {
		t.Fatalf("listener check refused with %q, want %q", reason, ReasonCredUnreadable)
	}
	if want := uint32(os.Getuid()); uid != want {
		t.Fatalf("the refusal names uid %d, want the test process's uid %d", uid, want)
	}
}

// TestIntegrationSandboxedPeerRefused: a child that sandboxes itself with
// sandbox-exec and stays connected reads as sandboxed through the real
// sandbox source, and the listener refuses it with reason sandboxed.
func TestIntegrationSandboxedPeerRefused(t *testing.T) {
	requireCgo(t)
	const sandboxExec = "/usr/bin/sandbox-exec"
	if _, err := os.Stat(sandboxExec); err != nil {
		t.Skipf("%s is missing on this macOS (%v): the self-sandboxed peer cannot be measured here", sandboxExec, err)
	}
	ln, path := peerSocket(t)
	l := integrationListener(t, ln)
	cmd := helperCmd(t, "stay", path, sandboxExec, "-p", "(version 1)(allow default)")
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = stdin.Close() // the helper leaves on EOF
		if err := cmd.Wait(); err != nil {
			t.Errorf("helper child: %v", err)
		}
	}()
	c, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	pc, err := readPeerCred(c)
	if err != nil {
		t.Fatalf("readPeerCred on a live sandboxed peer = %v", err)
	}
	sandboxed, err := sandboxedByToken(pc.Token)
	t.Logf("measured: sandboxed peer pid=%d uid=%d sandboxed=%v err=%v", pc.PID, pc.UID, sandboxed, err)
	if err != nil || !sandboxed {
		t.Fatalf("the real sandbox source answered sandboxed=%v err=%v for a sandbox-exec child", sandboxed, err)
	}
	peer, reason := l.check(c)
	uid := peer.UID
	t.Logf("measured: listener check uid=%d reason=%q", uid, reason)
	if reason != ReasonSandboxed {
		t.Fatalf("listener check = %q under uid %d, want %q", reason, uid, ReasonSandboxed)
	}
}

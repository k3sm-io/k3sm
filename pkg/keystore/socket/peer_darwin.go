//go:build darwin && cgo

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

// The kernel reads behind KernelPeerCreds and KernelPeerSandbox, the only cgo
// in this package.
//
// The peer-credential read is a deliberate leaf copy of the two existing
// ones, which are unexported in their repos: uidVerifier.Verify in
// darwin-net's pkg/netd/peercred.go (LOCAL_PEERCRED) and controlPeerUID with
// the LOCAL_PEERPID read beside it in runtimed's pkg/sandbox/vmadopt_darwin.go.
// LOCAL_PEERTOKEN is public (<sys/un.h>, 0x006) but x/sys has no getter for a
// 32-byte option, so it is read here in C.
//
// sandbox_check_by_audit_token is PRIVATE SPI: no public SDK header declares
// it. It is exported by /usr/lib/system/libsystem_sandbox.dylib (listed in
// the SDK's libsystem_sandbox.tbd), part of libSystem, which every process
// has loaded. It is NOT linked: it is resolved with dlsym(RTLD_DEFAULT) at
// first use and called through a pointer typed in the form Apple's own SPI
// headers use, so a macOS that drops it does not stop the binary from
// launching; the sandbox check then fails for every peer (sandbox-unknown)
// and the listener refuses everyone. With operation NULL and filter type 0
// (SANDBOX_FILTER_NONE) it asks only whether the process is sandboxed: 1
// yes, 0 no, -1 error with errno set. It is reached only through
// PeerSandboxSource and SandboxSelfCheck, so a change in the symbol is
// confined to this file.

/*
#include <errno.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/ucred.h>
#include <bsm/libbsm.h>
#include <dlfcn.h>
#include <pthread.h>
#include <mach/mach.h>

#cgo LDFLAGS: -lbsm

typedef int (*k3sm_sandbox_check_fn)(audit_token_t token, const char *operation, int type, ...);

static k3sm_sandbox_check_fn k3sm_sandbox_check;
static pthread_once_t k3sm_sandbox_once = PTHREAD_ONCE_INIT;

static void k3sm_sandbox_resolve(void) {
	k3sm_sandbox_check = (k3sm_sandbox_check_fn)dlsym(RTLD_DEFAULT, "sandbox_check_by_audit_token");
}

// k3sm_sandbox_available reports whether the symbol resolved, resolving it
// on the first call.
static int k3sm_sandbox_available(void) {
	pthread_once(&k3sm_sandbox_once, k3sm_sandbox_resolve);
	return k3sm_sandbox_check != NULL;
}

static int k3sm_self_token(audit_token_t *tok) {
	mach_msg_type_number_t n = TASK_AUDIT_TOKEN_COUNT;
	return task_info(mach_task_self(), TASK_AUDIT_TOKEN, (task_info_t)tok, &n);
}

static int k3sm_peer_token(int fd, audit_token_t *tok) {
	socklen_t len = sizeof(*tok);
	if (getsockopt(fd, SOL_LOCAL, LOCAL_PEERTOKEN, tok, &len) != 0) {
		return errno;
	}
	if (len != sizeof(*tok)) {
		return EINVAL;
	}
	return 0;
}

static int k3sm_token_sandboxed(audit_token_t *tok, int *err) {
	if (!k3sm_sandbox_available()) {
		*err = ENOSYS;
		return -2;
	}
	errno = 0;
	int rc = k3sm_sandbox_check(*tok, NULL, 0);
	*err = errno;
	return rc;
}
*/
import "C"

import (
	"errors"
	"fmt"
	"net"
	"syscall"

	"golang.org/x/sys/unix"
)

// readPeerCred reads the peer of c, an accepted unix connection, off its
// descriptor: euid from LOCAL_PEERCRED, pid from LOCAL_PEERPID, audit token
// from LOCAL_PEERTOKEN, and the euid and pid the token carries through
// libbsm. The uid is read first; a read that fails after it returns its
// error with the uid read (UIDRead), so the listener refuses an ineligible
// uid under that uid and an eligible one as cred-unreadable under it.
func readPeerCred(c net.Conn) (PeerCred, error) {
	sc, ok := c.(syscall.Conn)
	if !ok {
		return PeerCred{}, fmt.Errorf("keystore socket: peer credentials: %T has no descriptor", c)
	}
	raw, err := sc.SyscallConn()
	if err != nil {
		return PeerCred{}, fmt.Errorf("keystore socket: peer credentials: %w", err)
	}
	var pc PeerCred
	var opErr error
	if err := raw.Control(func(fd uintptr) {
		x, err := unix.GetsockoptXucred(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
		if err != nil {
			opErr = fmt.Errorf("LOCAL_PEERCRED: %w", err)
			return
		}
		if x.Version != C.XUCRED_VERSION {
			opErr = fmt.Errorf("LOCAL_PEERCRED: xucred version %d", x.Version)
			return
		}
		pc.UID, pc.UIDRead = x.Uid, true
		pid, err := unix.GetsockoptInt(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERPID)
		if err != nil {
			opErr = fmt.Errorf("LOCAL_PEERPID: %w", err)
			return
		}
		pc.PID = int32(pid)
		var tok C.audit_token_t
		if rc := C.k3sm_peer_token(C.int(fd), &tok); rc != 0 {
			opErr = fmt.Errorf("LOCAL_PEERTOKEN: %w", syscall.Errno(rc))
			return
		}
		for i := range pc.Token {
			pc.Token[i] = uint32(tok.val[i])
		}
		pc.TokenEUID = uint32(C.audit_token_to_euid(tok))
		pc.TokenPID = int32(C.audit_token_to_pid(tok))
	}); err != nil {
		return PeerCred{}, fmt.Errorf("keystore socket: peer credentials: %w", err)
	}
	if opErr != nil {
		return pc, fmt.Errorf("keystore socket: peer credentials: %w", opErr)
	}
	return pc, nil
}

// errSandboxAnswer is a sandbox check that answered neither yes nor no.
var errSandboxAnswer = errors.New("keystore socket: sandbox_check_by_audit_token answered neither 0 nor 1")

// errSandboxSymbol is a process in which sandbox_check_by_audit_token does
// not resolve.
var errSandboxSymbol = errors.New("keystore socket: sandbox_check_by_audit_token does not resolve on this macOS")

// sandboxedByToken asks whether the process token names is sandboxed. An
// answer other than 0 or 1 is an error, and so is a symbol that does not
// resolve.
func sandboxedByToken(token AuditToken) (bool, error) {
	var tok C.audit_token_t
	for i := range token {
		tok.val[i] = C.uint(token[i])
	}
	return sandboxedByCToken(&tok)
}

func sandboxedByCToken(tok *C.audit_token_t) (bool, error) {
	var e C.int
	switch rc := C.k3sm_token_sandboxed(tok, &e); rc {
	case 0:
		return false, nil
	case 1:
		return true, nil
	case -2:
		return false, errSandboxSymbol
	default:
		return false, fmt.Errorf("%w: %d (%v)", errSandboxAnswer, int(rc), syscall.Errno(e))
	}
}

// selfSandboxCheck asks the sandbox check about this process's own audit
// token (task_info TASK_AUDIT_TOKEN) and requires the answer 0, not
// sandboxed: the server runs unsandboxed under launchd.
func selfSandboxCheck() error {
	var tok C.audit_token_t
	if kr := C.k3sm_self_token(&tok); kr != C.KERN_SUCCESS {
		return fmt.Errorf("keystore socket: task_info(TASK_AUDIT_TOKEN): kern_return %d", int(kr))
	}
	sandboxed, err := sandboxedByCToken(&tok)
	if err != nil {
		return err
	}
	if sandboxed {
		return errors.New("keystore socket: the sandbox check says the server itself is sandboxed")
	}
	return nil
}

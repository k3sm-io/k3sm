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

package netserve

import (
	"errors"
	"strconv"
	"syscall"

	"golang.org/x/sys/unix"
)

// errSocketCannotReceive reports a socket whose receive buffer has been flushed:
// SO_RCVBUF reads 0 and the kernel has marked it unable to receive.
//
// On macOS this is how a socket comes out of an SCM_RIGHTS handover that the
// kernel's unix-socket garbage collector (unp_gc) caught in flight. The collector
// runs asynchronously, triggered by any process closing a unix socket while rights
// are in flight anywhere on the host, and it can judge a descriptor unreachable in
// the moment between the sender closing its copy and the receiver installing it.
// It then calls sorflush on that socket, which sets SS_CANTRCVMORE and zeroes the
// receive buffer's fields, its high-water mark among them, and the descriptor is
// delivered anyway. The socket stays bound: datagrams addressed to it are counted
// and discarded, and recvfrom returns 0 bytes with no error at once, forever. The
// netd helper hands every privileged socket over this way, so the resolver checks
// each one it adopts; a direct bind never transits and never needs the check.
var errSocketCannotReceive = errors.New("socket cannot receive: its receive buffer was flushed (SO_RCVBUF 0) in the fd handover")

// checkReceiving returns errSocketCannotReceive when c is a socket whose SO_RCVBUF
// reads 0. A c that is not a socket, or whose buffer size cannot be read, passes:
// the check proves a known-bad state and never guesses at an unknown one.
func checkReceiving(c any) error {
	if n, ok := socketRcvBuf(c); ok && n == 0 {
		return errSocketCannotReceive
	}
	return nil
}

// socketRcvBuf reads c's SO_RCVBUF (the kernel's receive high-water mark) and
// reports whether it could.
func socketRcvBuf(c any) (int, bool) {
	sc, ok := c.(syscall.Conn)
	if !ok {
		return 0, false
	}
	rc, err := sc.SyscallConn()
	if err != nil {
		return 0, false
	}
	var n int
	var gerr error
	if err := rc.Control(func(fd uintptr) { n, gerr = rcvBufOf(fd) }); err != nil || gerr != nil {
		return 0, false
	}
	return n, true
}

// rcvBufOf reads SO_RCVBUF on fd. It is a var so a unit test can stand in a value
// without a real socket; nothing in the product replaces it.
var rcvBufOf = func(fd uintptr) (int, error) {
	return unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_RCVBUF)
}

// rcvbufAttr renders a socketRcvBuf result for a log line.
func rcvbufAttr(n int, known bool) string {
	if !known {
		return "unknown"
	}
	return strconv.Itoa(n)
}

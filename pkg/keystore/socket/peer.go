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

import "net"

// AuditToken is a process's audit token (audit_token_t, eight 32-bit words)
// as the kernel reports it for a socket's peer.
type AuditToken [8]uint32

// PeerCred is what the kernel says about an accepted connection's peer, read
// at accept. UID is the peer's effective uid at connect time and is the
// authority; PID is advisory, for an audit line; Token names the process for
// the sandbox check.
type PeerCred struct {
	UID   uint32
	PID   int32
	Token AuditToken
}

// PeerCredSource reads an accepted connection's peer credentials. An error
// refuses the connection.
type PeerCredSource interface {
	PeerCred(c net.Conn) (PeerCred, error)
}

// PeerSandboxSource reports whether the process an audit token names runs
// under a sandbox. An error refuses the connection.
type PeerSandboxSource interface {
	Sandboxed(token AuditToken) (bool, error)
}

// The real primitives behind KernelPeerCreds and KernelPeerSandbox. They are
// variables so that the package's TestMain can replace each with a stub that
// panics, which keeps every unit test off the host's sockets and sandbox.
// The listener never reads them: it takes its sources as constructor
// parameters.
var (
	peerCredSeam    = readPeerCred
	peerSandboxSeam = sandboxedByToken
)

// KernelPeerCreds is the production PeerCredSource: LOCAL_PEERCRED,
// LOCAL_PEERPID and LOCAL_PEERTOKEN read off the accepted descriptor. Off
// darwin it refuses every connection.
type KernelPeerCreds struct{}

// PeerCred implements PeerCredSource.
func (KernelPeerCreds) PeerCred(c net.Conn) (PeerCred, error) { return peerCredSeam(c) }

// KernelPeerSandbox is the production PeerSandboxSource: the sandbox check
// on the peer's audit token. Off darwin it refuses every connection.
type KernelPeerSandbox struct{}

// Sandboxed implements PeerSandboxSource.
func (KernelPeerSandbox) Sandboxed(token AuditToken) (bool, error) { return peerSandboxSeam(token) }

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
	"strings"
	"testing"
)

// TestMain bans the real primitives behind the package's seams at unit tier:
// before any test runs, each seam is a stub that panics, naming the primitive
// (docs/design/keystore.md § "Package layout and seams"). The listener's
// sources are constructor parameters, so a test passes fakes; the stubs make
// the production sources, KernelPeerCreds and KernelPeerSandbox, panic if a
// unit test reaches them.
func TestMain(m *testing.M) {
	peerCredSeam = func(net.Conn) (PeerCred, error) {
		panic("a unit test reached LOCAL_PEERCRED: pass a fake peer-credential source")
	}
	peerSandboxSeam = func(AuditToken) (bool, error) {
		panic("a unit test reached sandbox_check_by_audit_token: pass a fake peer-sandbox source")
	}
	os.Exit(m.Run())
}

// TestRealPrimitivesUnreachable proves TestMain's stubs are in place: each
// production source, called in a test build, panics naming its primitive.
func TestRealPrimitivesUnreachable(t *testing.T) {
	client, server := net.Pipe()
	defer func() { _ = client.Close(); _ = server.Close() }()
	for _, tt := range []struct {
		name, primitive string
		call            func()
	}{
		{"KernelPeerCreds", "LOCAL_PEERCRED", func() { _, _ = KernelPeerCreds{}.PeerCred(server) }},
		{"KernelPeerSandbox", "sandbox_check_by_audit_token", func() { _, _ = KernelPeerSandbox{}.Sandboxed(AuditToken{}) }},
		{"peerCredSeam", "LOCAL_PEERCRED", func() { _, _ = peerCredSeam(server) }},
		{"peerSandboxSeam", "sandbox_check_by_audit_token", func() { _, _ = peerSandboxSeam(AuditToken{}) }},
	} {
		t.Run(tt.name, func(t *testing.T) {
			defer func() {
				r := recover()
				if s, _ := r.(string); !strings.Contains(s, tt.primitive) {
					t.Fatalf("the source for %s did not panic naming it: %v", tt.primitive, r)
				}
			}()
			tt.call()
		})
	}
}

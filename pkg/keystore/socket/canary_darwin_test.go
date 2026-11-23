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

import "testing"

// TestSandboxCheckByAuditTokenSymbolCanary is the symbol canary for
// sandbox_check_by_audit_token, the private SPI behind KernelPeerSandbox
// (peer_darwin.go), which no public SDK header declares. The package
// resolves it with dlsym at first use, so a macOS without it still launches
// the binary and the listener refuses every peer as sandbox-unknown; this
// names it at run time, so a renamed or dropped export is a red test naming
// the symbol rather than a listener that silently admits no one. The
// negative case proves the lookup can say no.
func TestSandboxCheckByAuditTokenSymbolCanary(t *testing.T) {
	if !symbolResolves("sandbox_check_by_audit_token") {
		t.Fatal("sandbox_check_by_audit_token does not resolve: the listener's peer-sandbox check needs it")
	}
	if symbolResolves("k3sm_socket_no_such_symbol_canary") {
		t.Fatal("the canary resolves a symbol that does not exist, so it proves nothing")
	}
}

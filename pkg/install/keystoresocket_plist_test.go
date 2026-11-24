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

package install

import (
	"strings"
	"testing"
)

// U104 (the plist's half): the server plist carries one Sockets entry,
// KeystoreSocketsEntry, at <dataRoot>/keystore-sock/keys.sock and mode
// 0666 (438), for the default and a custom data root; the agent, netd and
// data-volume plists carry none.
func TestServerPlistActivatesKeystoreSocket(t *testing.T) {
	entry := func(path string) string {
		return "  <key>Sockets</key>\n  <dict>\n    <key>keys</key>\n    <dict>\n" +
			"      <key>SockPathName</key>\n      <string>" + path + "</string>\n" +
			"      <key>SockPathMode</key>\n      <integer>438</integer>\n    </dict>\n  </dict>\n"
	}
	for _, tc := range []struct {
		name string
		cfg  Config
		path string
	}{
		{"default data root", Config{}, "/var/lib/k3sm/keystore-sock/keys.sock"},
		{"custom data root", Config{DataRoot: "/Volumes/k3sm/data"}, "/Volumes/k3sm/data/keystore-sock/keys.sock"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := string(ServerPlist(tc.cfg))
			if !strings.Contains(got, entry(tc.path)) {
				t.Fatalf("the server plist has no keystore Sockets entry for %s:\n%s", tc.path, got)
			}
			if n := strings.Count(got, "<key>Sockets</key>"); n != 1 {
				t.Fatalf("%d Sockets keys, want 1", n)
			}
		})
	}
	if KeystoreSocketMode != 0o666 {
		t.Fatalf("KeystoreSocketMode %#o, want 0666", KeystoreSocketMode)
	}
	for name, p := range map[string][]byte{"agent": AgentPlist(Config{}), "netd": NetdPlist(Config{}), "datavol": DatavolPlist(Config{})} {
		if strings.Contains(string(p), "Sockets") {
			t.Errorf("the %s plist carries a Sockets entry", name)
		}
	}
}

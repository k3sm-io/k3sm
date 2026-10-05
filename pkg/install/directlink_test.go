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
	"log/slog"
	"strings"
	"testing"
)

// TestAutoJoinAgentPlist pins the --auto-join daemon's argv: it names no server
// and no token file, only --auto-join, and a carried-over argv drops the flag the
// renderer owns.
func TestAutoJoinAgentPlist(t *testing.T) {
	plist := string(AgentPlist(Config{Role: RoleAgent, AutoJoin: true}))
	mustContain(t, plist, "<string>--auto-join</string>")
	for _, absent := range []string{"--server", "--token-file"} {
		if strings.Contains(plist, absent) {
			t.Errorf("an auto-join plist renders %s:\n%s", absent, plist)
		}
	}
	if got := filterManagedAgentArgs([]string{"--auto-join", "--dns-vip", "10.43.0.10"}); len(got) != 2 || got[0] != "--dns-vip" {
		t.Errorf("carry-over kept the renderer's --auto-join: %v", got)
	}
}

// TestJoinPreflightAcceptsAZonedLiteralForTheAgentJoin pins that a --server that
// is a zoned link-local literal is dialled as it stands (no resolver answers for
// a zone), and that an --auto-join install has no endpoint to check at all.
func TestJoinPreflightAcceptsAZonedLiteralForTheAgentJoin(t *testing.T) {
	f := &fakeSystem{}
	cfg := Config{Role: RoleAgent, JoinServer: "fe80::1%en2", Logger: slog.New(slog.DiscardHandler)}
	if _, err := preflightJoinEndpoint(f, cfg); err != nil {
		t.Fatalf("preflight of a zoned server: %v", err)
	}
	if idx(f.calls, "DialJoinServer:[fe80::1%en2]:9345") < 0 {
		t.Errorf("the zoned literal was not dialled as it stands; calls = %v", f.calls)
	}
	for _, c := range f.calls {
		if strings.HasPrefix(c, "ResolveJoinHost:") {
			t.Errorf("a zoned literal went to the resolver: %v", f.calls)
		}
	}

	auto := &fakeSystem{}
	if _, err := preflightJoinEndpoint(auto, Config{Role: RoleAgent, AutoJoin: true, Logger: slog.New(slog.DiscardHandler)}); err != nil {
		t.Fatalf("preflight of an auto-join install: %v", err)
	}
	if len(auto.calls) != 0 {
		t.Errorf("an auto-join install probed an endpoint: %v", auto.calls)
	}
	if _, err := preflightJoinEndpoint(auto, Config{Role: RoleAgent, AutoJoin: true, JoinServer: "192.0.2.1", Logger: slog.New(slog.DiscardHandler)}); err == nil {
		t.Error("--auto-join with --server was accepted")
	}
}

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

package main

import (
	"errors"
	"flag"
	"net/netip"
	"slices"
	"testing"

	"k3sm.io/darwin-net/pkg/proxy"

	"k3sm.io/k3sm/pkg/install"
)

// TestNodePortAddressesFlag pins the --nodeport-addresses surface: both node
// daemons take it, install validates it, records it in the node daemon's
// arguments for its role, keeps a carried value when it is not passed and
// clears it when passed empty, and the daemon resolves it once against this
// Mac's addresses and its own node address.
func TestNodePortAddressesFlag(t *testing.T) {
	t.Run("server and agent register the flag", func(t *testing.T) {
		var so serverOptions
		sfs := flag.NewFlagSet("server", flag.ContinueOnError)
		if err := registerServerFlags(sfs, &so); err != nil {
			t.Fatal(err)
		}
		if err := sfs.Parse([]string{"--nodeport-addresses", "local"}); err != nil || so.nodePortAddresses != "local" {
			t.Fatalf("server --nodeport-addresses = %q, %v", so.nodePortAddresses, err)
		}
		var ao agentOptions
		afs := flag.NewFlagSet("agent", flag.ContinueOnError)
		registerAgentFlags(afs, &ao)
		if err := afs.Parse([]string{"--nodeport-addresses", "127.0.0.0/8,100.64.0.0/10"}); err != nil || ao.nodePortAddresses != "127.0.0.0/8,100.64.0.0/10" {
			t.Fatalf("agent --nodeport-addresses = %q, %v", ao.nodePortAddresses, err)
		}
	})

	t.Run("install records it for the server", func(t *testing.T) {
		o, err := parseInstallFlags([]string{"--user", "alice", "--nodeport-addresses", "local"})
		if err != nil {
			t.Fatal(err)
		}
		args := install.RecordedServerArgs(o.installConfig("", nil, nil))
		if i := slices.Index(args, "--nodeport-addresses"); i < 0 || i+1 >= len(args) || args[i+1] != "local" {
			t.Fatalf("recorded server args %q do not carry --nodeport-addresses local", args)
		}
	})

	t.Run("install records it for the agent", func(t *testing.T) {
		o, err := parseInstallFlags([]string{"--agent", "--server", "192.0.2.10", "--token-file", "/var/root/tok", "--nodeport-addresses", "local"})
		if err != nil {
			t.Fatal(err)
		}
		args := install.RecordedAgentArgs(o.installConfig("", nil, nil))
		if i := slices.Index(args, "--nodeport-addresses"); i < 0 || i+1 >= len(args) || args[i+1] != "local" {
			t.Fatalf("recorded agent args %q do not carry --nodeport-addresses local", args)
		}
	})

	t.Run("unpassed keeps a carried value; empty clears it", func(t *testing.T) {
		carried := []string{"--nodeport-addresses", "local", "--mesh-ip", "100.64.0.1"}
		o, err := parseInstallFlags([]string{"--user", "alice"})
		if err != nil {
			t.Fatal(err)
		}
		cfg := o.installConfig("", nil, nil)
		cfg.ExtraServerArgs = carried
		if got := install.RecordedServerArgs(cfg); !slices.Contains(got, "--nodeport-addresses") {
			t.Errorf("an unpassed flag dropped the carried value: %q", got)
		}
		o, err = parseInstallFlags([]string{"--user", "alice", "--nodeport-addresses", ""})
		if err != nil {
			t.Fatal(err)
		}
		cfg = o.installConfig("", nil, nil)
		cfg.ExtraServerArgs = carried
		if got := install.RecordedServerArgs(cfg); slices.Contains(got, "--nodeport-addresses") || !slices.Contains(got, "--mesh-ip") {
			t.Errorf("an empty --nodeport-addresses did not clear only the carried value: %q", got)
		}
	})

	t.Run("a setting beside --network none is refused at entry", func(t *testing.T) {
		spec := "local"
		if err := checkNodePortAddresses(&spec, "none"); !errors.Is(err, install.ErrNodePortAddressesWithoutDatapath) {
			t.Errorf("server/agent entry check = %v, want ErrNodePortAddressesWithoutDatapath", err)
		}
		err := runAgent([]string{"--server", "192.0.2.10", "--network", "none", "--nodeport-addresses", "local"})
		if !errors.Is(err, install.ErrNodePortAddressesWithoutDatapath) {
			t.Errorf("k3sm agent = %v, want ErrNodePortAddressesWithoutDatapath", err)
		}
		blank := "   "
		if err := checkNodePortAddresses(&blank, "none"); err != nil || blank != "" {
			t.Errorf("a whitespace-only setting = %q, %v; want it normalised to unset and accepted", blank, err)
		}
		padded := " local "
		if err := checkNodePortAddresses(&padded, "auto"); err != nil || padded != "local" {
			t.Errorf("a padded setting = %q, %v; want %q", padded, err, "local")
		}
	})

	t.Run("install trims; whitespace-only clears the recorded value", func(t *testing.T) {
		o, err := parseInstallFlags([]string{"--user", "alice", "--nodeport-addresses", "  "})
		if err != nil {
			t.Fatal(err)
		}
		cfg := o.installConfig("", nil, nil)
		cfg.ExtraServerArgs = []string{"--nodeport-addresses", "local"}
		if got := install.RecordedServerArgs(cfg); slices.Contains(got, "--nodeport-addresses") {
			t.Errorf("a whitespace-only --nodeport-addresses kept the carried value: %q", got)
		}
		o, err = parseInstallFlags([]string{"--user", "alice", "--nodeport-addresses", " local "})
		if err != nil {
			t.Fatal(err)
		}
		args := install.RecordedServerArgs(o.installConfig("", nil, nil))
		if i := slices.Index(args, "--nodeport-addresses"); i < 0 || args[i+1] != "local" {
			t.Errorf("recorded args %q, want the trimmed value", args)
		}
	})

	t.Run("an unusable spec is refused at parse", func(t *testing.T) {
		if _, err := parseInstallFlags([]string{"--user", "alice", "--nodeport-addresses", "lan"}); !errors.Is(err, proxy.ErrNodePortAddresses) {
			t.Errorf("install accepted --nodeport-addresses lan: %v", err)
		}
	})

	t.Run("the daemon resolves the preset to loopback and its node address", func(t *testing.T) {
		saved := nodePortHostAddrs
		nodePortHostAddrs = func() ([]netip.Addr, error) {
			return []netip.Addr{netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("192.0.2.10")}, nil
		}
		t.Cleanup(func() { nodePortHostAddrs = saved })
		got, err := resolveNodePortAddresses("local", "100.64.0.1")
		if err != nil {
			t.Fatal(err)
		}
		want := []netip.Addr{netip.MustParseAddr("100.64.0.1"), netip.MustParseAddr("127.0.0.1")}
		if !slices.Equal(got, want) {
			t.Errorf("resolved %v, want %v (never the LAN address)", got, want)
		}
		if got, err := resolveNodePortAddresses("", "100.64.0.1"); got != nil || err != nil {
			t.Errorf("an empty spec resolved to %v, %v; want the wildcard (nil)", got, err)
		}
	})
}

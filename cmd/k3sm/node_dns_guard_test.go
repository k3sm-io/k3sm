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
	"log/slog"
	"strings"
	"testing"

	"k3sm.io/darwin-net/pkg/dns"

	"k3sm.io/k3sm/pkg/bootstrap"
	"k3sm.io/k3sm/pkg/hostnet"
)

// TestStandaloneNodeGuardsDNSEnvInjection is the B43 gate: the standalone `k3sm
// node --runtime runtimed` command binds NO cluster-DNS resolver (only
// server.go/agent.go call netserve.New before reaching the shared
// startNode/buildProvider/runtimedConfig path — see the standaloneDNSGuard doc
// comment), so it must never inject K3SM_DNS_* env pointing at a dead VIP.
//
// (a) standalone node -> no K3SM_DNS_* in the pod env wiring: asserted at the
//
//	shared seam runtimedConfig feeds — dns.PodDNSConfig + dns.ConfigToEnv, the
//	SAME two calls pkg/provider's buildBox/injectClusterDNSEnv make with
//	ResolverVIP/ClusterDomain — rather than duplicating that translation.
//
// (b) an explicit --dns-vip in standalone mode -> a loud error, not injection.
//
// (c) the server/agent paths still inject: a non-standalone nodeOptions (what
//
//	server.go's inline nodeOpts literal and agent.go's agentNodeOptions both
//	produce — neither ever sets opts.standalone) keeps defaulting and injecting
//	exactly as before B43.
func TestStandaloneNodeGuardsDNSEnvInjection(t *testing.T) {
	t.Parallel()

	t.Run("a_standalone_no_injection", func(t *testing.T) {
		t.Parallel()
		// Mirrors runNode: standalone=true, --dns-vip left at its new "" default.
		cfg := runtimedConfig(nodeOptions{standalone: true, domain: "cluster.local"}, nil)
		if cfg.ResolverVIP != "" {
			t.Fatalf("ResolverVIP = %q, want \"\" (standalone binds no resolver — B43)", cfg.ResolverVIP)
		}
		dnsCfg := dns.PodDNSConfig(cfg.ResolverVIP, cfg.ClusterDomain, "default")
		env := dns.ConfigToEnv(dnsCfg)
		if env != nil {
			t.Fatalf("ConfigToEnv(standalone) = %v, want nil (no K3SM_DNS_* env — a standalone pod must fall back to the host resolver, not dial a dead VIP)", env)
		}
	})

	t.Run("b_explicit_dns_vip_fails_fast", func(t *testing.T) {
		t.Parallel()
		log := slog.New(slog.DiscardHandler)
		err := standaloneDNSGuard(nodeOptions{runtime: runtimeRuntimed, dnsVIP: "10.43.0.10"}, log)
		if err == nil {
			t.Fatal("standaloneDNSGuard(explicit --dns-vip) = nil, want a loud error (standalone binds no resolver on that VIP)")
		}
		if !strings.Contains(err.Error(), "10.43.0.10") {
			t.Errorf("error %q does not name the rejected --dns-vip value", err.Error())
		}
		// No error, and no request, for the explicit rootless-dev opt-out: --dns-vip
		// is already inert there (runtimedConfig is never called for hostprocess).
		if err := standaloneDNSGuard(nodeOptions{runtime: runtimeHostProcess, dnsVIP: "10.43.0.10"}, log); err != nil {
			t.Errorf("standaloneDNSGuard(hostprocess, --dns-vip set) = %v, want nil (the flag is a no-op under hostprocess)", err)
		}
		// The default (unset) case: no error.
		if err := standaloneDNSGuard(nodeOptions{runtime: runtimeRuntimed}, log); err != nil {
			t.Errorf("standaloneDNSGuard(no --dns-vip) = %v, want nil", err)
		}
	})

	t.Run("c_server_and_agent_paths_still_inject", func(t *testing.T) {
		t.Parallel()
		// server.go's inline `nodeOpts := nodeOptions{...}` literal never sets
		// standalone — reproduced directly here (the zero value, false).
		serverLike := nodeOptions{dnsVIP: "10.43.0.10", domain: "cluster.local"}
		if serverLike.standalone {
			t.Fatal("a server-shaped nodeOptions literal must not be standalone")
		}
		cfg := runtimedConfig(serverLike, nil)
		if cfg.ResolverVIP != "10.43.0.10" {
			t.Fatalf("ResolverVIP = %q, want the threaded --dns-vip (server path unaffected by the B43 guard)", cfg.ResolverVIP)
		}
		env := dns.ConfigToEnv(dns.PodDNSConfig(cfg.ResolverVIP, cfg.ClusterDomain, "default"))
		if env == nil {
			t.Fatal("ConfigToEnv(server-shaped) = nil, want the K3SM_DNS_* env map (the server path must keep injecting)")
		}
		if env[dns.EnvDNSServer] != "10.43.0.10" {
			t.Errorf("%s = %q, want 10.43.0.10", dns.EnvDNSServer, env[dns.EnvDNSServer])
		}

		// agent.go's real constructor: proves the ACTUAL production function never
		// sets standalone (not just a hand-copied literal above).
		agentOpts := agentNodeOptions(
			agentOptions{clusterIP: "10.43.0.10", domain: "cluster.local"},
			&bootstrap.JoinResult{PodCIDR: "100.64.1.0/24"},
			"/tmp/node.kubeconfig",
			hostnet.Mode{},
		)
		if agentOpts.standalone {
			t.Fatal("agentNodeOptions produced a standalone nodeOptions — the B43 guard must not leak into the agent path")
		}
		agentCfg := runtimedConfig(agentOpts, nil)
		agentEnv := dns.ConfigToEnv(dns.PodDNSConfig(agentCfg.ResolverVIP, agentCfg.ClusterDomain, "default"))
		if agentEnv == nil {
			t.Fatal("ConfigToEnv(agent-shaped) = nil, want the K3SM_DNS_* env map (the agent path must keep injecting)")
		}
	})

	// Bare zero-value nodeOptions{} (standalone=false, matching every existing
	// TestRuntimedConfiguresPostureVIPs assertion) must be UNCHANGED by B43: the
	// empty-dnsVIP default-fill still applies.
	t.Run("bare_zero_value_unaffected", func(t *testing.T) {
		t.Parallel()
		if got := runtimedConfig(nodeOptions{}, nil).ResolverVIP; got != dns.DefaultDNSVIP {
			t.Errorf("ResolverVIP with a bare nodeOptions{} = %q, want the unchanged default %q", got, dns.DefaultDNSVIP)
		}
	})
}

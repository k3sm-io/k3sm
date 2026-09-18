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
	"strings"
	"testing"

	"k3sm.io/k3sm/pkg/install"
)

// TestInstallAgentFlags pins the role CONTRACT of `k3sm install`, which is the
// part of the agent role a unit test can reach: the install itself needs root
// and a cluster, but every refusal an operator is likely to meet is decided
// here, before any privilege is taken.
func TestInstallAgentFlags(t *testing.T) {
	t.Run("no --agent installs the control plane", func(t *testing.T) {
		opts, err := parseInstallFlags([]string{"--user", "alice"})
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		if opts.role() != install.RoleServer {
			t.Errorf("role = %q, want the control plane", opts.role())
		}
	})

	t.Run("--agent carries the join through", func(t *testing.T) {
		opts, err := parseInstallFlags([]string{"--agent", "--server", "192.0.2.10", "--node-ip", "100.64.0.7", "--token-file", "/var/root/tok"})
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		if opts.role() != install.RoleAgent {
			t.Errorf("role = %q, want the agent", opts.role())
		}
		if opts.server != "192.0.2.10" || opts.nodeIP != "100.64.0.7" || opts.tokenFile != "/var/root/tok" {
			t.Errorf("parsed %+v, want the join target, this node's address and the token file", opts)
		}
	})

	t.Run("--token-file is optional on an agent", func(t *testing.T) {
		// A node that has already joined starts from its stored credential, so
		// requiring a token file would make a reinstall need a token it does not.
		if _, err := parseInstallFlags([]string{"--agent", "--server", "192.0.2.10", "--node-ip", "100.64.0.7"}); err != nil {
			t.Fatalf("an agent install without a token file was refused: %v", err)
		}
	})

	t.Run("--agent without a join target is refused", func(t *testing.T) {
		for _, args := range [][]string{
			{"--agent"},
			{"--agent", "--node-ip", "100.64.0.7"},
		} {
			_, err := parseInstallFlags(args)
			if err == nil {
				t.Errorf("%v was accepted; --agent needs --server", args)
				continue
			}
			if !strings.Contains(err.Error(), "--server") {
				t.Errorf("error %q must name the missing flag", err)
			}
		}
	})

	t.Run("--node-ip is optional on an agent", func(t *testing.T) {
		// B338: this Mac's mesh address is the control plane's to assign and the
		// join returns it, so requiring the flag here made every agent install
		// start by guessing a value only the server's allocator knew.
		if _, err := parseInstallFlags([]string{"--agent", "--server", "192.0.2.10"}); err != nil {
			t.Fatalf("an agent install without --node-ip was refused: %v", err)
		}
	})

	t.Run("a server-only flag with --agent is refused by name", func(t *testing.T) {
		join := []string{"--agent", "--server", "192.0.2.10", "--node-ip", "100.64.0.7"}
		for _, tc := range []struct {
			flag string
			args []string
		}{
			{"service-cidr", []string{"--service-cidr", "10.44.0.0/16"}},
			{"data-volume", []string{"--data-volume"}},
			{"data-volume-size", []string{"--data-volume-size", "200g"}},
			{"data-volume-encrypt", []string{"--data-volume-encrypt"}},
			{"remove-old-data-root", []string{"--remove-old-data-root"}},
		} {
			_, err := parseInstallFlags(append(append([]string{}, join...), tc.args...))
			if err == nil {
				t.Errorf("--%s was accepted with --agent; it configures the control plane", tc.flag)
				continue
			}
			if !strings.Contains(err.Error(), "--"+tc.flag) {
				t.Errorf("error %q must name the flag that cannot be combined", err)
			}
		}
	})

	t.Run("the default --service-cidr does not trip the refusal", func(t *testing.T) {
		// The discriminator is what the operator PASSED, not what the flag
		// holds: --service-cidr has a non-empty default, so a value-based check
		// would refuse every agent install that ever existed.
		if _, err := parseInstallFlags([]string{"--agent", "--server", "192.0.2.10", "--node-ip", "100.64.0.7"}); err != nil {
			t.Fatalf("a plain agent install was refused: %v", err)
		}
	})

	t.Run("every name in a refusal list is a real flag of this command", func(t *testing.T) {
		// A refusal keyed on a name the FlagSet does not register can never fire,
		// so the list would rot in silence. --mesh-ip is the one deliberate
		// exception: it is listed ahead of the flag itself landing, so that the
		// refusal is already right on the day it does.
		for _, name := range append(append([]string{}, serverOnlyInstallFlags...), agentOnlyInstallFlags...) {
			if name == "mesh-ip" {
				continue
			}
			_, err := parseInstallFlags([]string{"--" + name})
			if err != nil && strings.Contains(err.Error(), "not defined") {
				t.Errorf("--%s is named in a refusal list but is not a flag of `k3sm install`", name)
			}
		}
	})

	t.Run("an agent-only flag without --agent is refused", func(t *testing.T) {
		for _, args := range [][]string{
			{"--server", "192.0.2.10"},
			{"--node-ip", "100.64.0.7"},
			{"--token-file", "/var/root/tok"},
		} {
			_, err := parseInstallFlags(args)
			if err == nil {
				t.Errorf("%v was accepted without --agent", args)
				continue
			}
			if !strings.Contains(err.Error(), "--agent") {
				t.Errorf("error %q must say that --agent is what these flags belong to", err)
			}
		}
	})
}

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
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
)

// inPlaceRequest is the Config the root helper's argv describes: an install
// from a staging directory naming no role, no join target, no token and no
// user.
func inPlaceRequest() Config {
	return Config{BinarySource: "/tmp/k3sm"}
}

func installedArgs(t *testing.T, f *fakeSystem, label string) []string {
	t.Helper()
	raw, ok := f.files[Config{}.withDefaults().plistPath(label)]
	if !ok {
		t.Fatalf("no %s plist on disk", label)
	}
	args, err := parseProgramArguments(raw)
	if err != nil {
		t.Fatalf("parse the %s plist: %v", label, err)
	}
	return args
}

// TestResolveInPlace is the gate for the in-place update: `install
// --from-staging <dir>` with no role flag, token or user reinstalls whatever
// the Mac already is, exactly as the explicit reinstall would, and refuses a
// Mac that carries nothing.
func TestResolveInPlace(t *testing.T) {
	t.Run("an installed agent is reinstalled with its --server and arguments, as the explicit reinstall", func(t *testing.T) {
		shrinkRestartBudgets(t)
		f := &fakeSystem{}
		seedJoinedAgent(t, f)
		first := agentCfg(t)
		local := "local"
		first.NodePortAddresses = &local
		if err := Install(context.Background(), f, first); err != nil {
			t.Fatalf("the first agent install: %v", err)
		}
		cfg, err := ResolveInPlace(f, inPlaceRequest(), nil)
		if err != nil {
			t.Fatalf("ResolveInPlace = %v", err)
		}
		if cfg.Role != RoleAgent || cfg.JoinServer != first.JoinServer || cfg.TokenFile != "" {
			t.Fatalf("resolved %v/%q/token %q, want the agent joining %s with no token", cfg.Role, cfg.JoinServer, cfg.TokenFile, first.JoinServer)
		}
		if err := Install(context.Background(), f, cfg); err != nil {
			t.Fatalf("the in-place agent install: %v", err)
		}
		inPlace := installedArgs(t, f, AgentLabel)
		explicit := Config{Role: RoleAgent, JoinServer: first.JoinServer, BinarySource: "/tmp/k3sm", TargetUser: "alice"}
		if err := Install(context.Background(), f, explicit); err != nil {
			t.Fatalf("the explicit agent reinstall: %v", err)
		}
		if want := installedArgs(t, f, AgentLabel); !slices.Equal(inPlace, want) {
			t.Errorf("in-place agent argv = %v, the explicit reinstall renders %v", inPlace, want)
		}
		if !slices.Contains(inPlace, "--nodeport-addresses=local") && !strings.Contains(strings.Join(inPlace, " "), "nodeport-addresses") {
			t.Errorf("in-place agent argv %v lost the recorded --nodeport-addresses", inPlace)
		}
	})

	t.Run("an installed server is reinstalled for the recorded kubeconfig's owner, as the explicit reinstall", func(t *testing.T) {
		shrinkRestartBudgets(t)
		f := &fakeSystem{}
		first := testConfig(t)
		first.MeshIP = "100.64.0.1"
		first.TLSSANs = []string{"api.example.com"}
		if err := Install(context.Background(), f, first); err != nil {
			t.Fatalf("the first server install: %v", err)
		}
		req := inPlaceRequest()
		req.DataRoot, req.ServerArgsRecord = first.DataRoot, first.ServerArgsRecord
		var asked string
		cfg, err := ResolveInPlace(f, req, func(p string) (string, error) { asked = p; return "alice", nil })
		if err != nil {
			t.Fatalf("ResolveInPlace = %v", err)
		}
		if cfg.Role != RoleServer || cfg.TargetUser != "alice" || asked != "/Users/alice/.kube/config" {
			t.Fatalf("resolved %v for %q (owner asked of %q), want the server for alice's recorded kubeconfig", cfg.Role, cfg.TargetUser, asked)
		}
		if err := Install(context.Background(), f, cfg); err != nil {
			t.Fatalf("the in-place server install: %v", err)
		}
		inPlace := serverArgsOf(t, f, cfg)
		explicit := testConfig(t)
		explicit.DataRoot, explicit.ServerArgsRecord = first.DataRoot, first.ServerArgsRecord
		if err := Install(context.Background(), f, explicit); err != nil {
			t.Fatalf("the explicit server reinstall: %v", err)
		}
		if want := serverArgsOf(t, f, explicit); !slices.Equal(inPlace, want) {
			t.Errorf("in-place server arguments = %v, the explicit reinstall carries %v", inPlace, want)
		}
		for _, w := range []string{"100.64.0.1", "api.example.com"} {
			if !strings.Contains(strings.Join(inPlace, " "), w) {
				t.Errorf("in-place server arguments %v lost %s", inPlace, w)
			}
		}
		if f.kubeUser != "alice" {
			t.Errorf("the admin kubeconfig was written for %q, want alice", f.kubeUser)
		}
	})

	t.Run("nothing installed refuses", func(t *testing.T) {
		if _, err := ResolveInPlace(&fakeSystem{}, inPlaceRequest(), nil); !errors.Is(err, ErrNothingToUpdate) {
			t.Fatalf("ResolveInPlace = %v, want ErrNothingToUpdate", err)
		}
	})

	t.Run("nothing installed with --user is the app's first install, unchanged", func(t *testing.T) {
		req := inPlaceRequest()
		req.TargetUser = "alice"
		cfg, err := ResolveInPlace(&fakeSystem{}, req, nil)
		if err != nil || cfg.Role != RoleServer || cfg.TargetUser != "alice" {
			t.Fatalf("ResolveInPlace = %+v, %v; want the request back as a server install", cfg.Role, err)
		}
	})

	t.Run("an agent without a node credential refuses", func(t *testing.T) {
		f := &fakeSystem{}
		f.putFile(Config{}.withDefaults().plistPath(AgentLabel), AgentPlist(agentCfg(t).withDefaults()))
		if _, err := ResolveInPlace(f, inPlaceRequest(), nil); err == nil || !strings.Contains(err.Error(), "node credential") {
			t.Fatalf("ResolveInPlace = %v, want the missing credential named", err)
		}
	})

	t.Run("a server with no recorded kubeconfig and no --user refuses", func(t *testing.T) {
		f := &fakeSystem{}
		cfg := testConfig(t)
		configureServerArgs(f, cfg)
		req := inPlaceRequest()
		req.DataRoot, req.ServerArgsRecord = cfg.DataRoot, cfg.ServerArgsRecord
		if _, err := ResolveInPlace(f, req, func(string) (string, error) { return "alice", nil }); err == nil || !strings.Contains(err.Error(), "--user") {
			t.Fatalf("ResolveInPlace = %v, want a refusal naming --user", err)
		}
	})

	t.Run("both roles on disk refuses", func(t *testing.T) {
		f := &fakeSystem{}
		configureServerArgs(f, testConfig(t))
		f.putFile(Config{}.withDefaults().plistPath(AgentLabel), AgentPlist(agentCfg(t).withDefaults()))
		if _, err := ResolveInPlace(f, inPlaceRequest(), nil); err == nil || !strings.Contains(err.Error(), "ambiguous") {
			t.Fatalf("ResolveInPlace = %v, want the ambiguous role refused", err)
		}
	})
}

// TestUpdateReleaseBaseIsRecordedAndCarried pins --update-release-base: it
// is rendered into the role's daemon arguments, replaced by a later value,
// and kept by an in-place update, which names none.
func TestUpdateReleaseBaseIsRecordedAndCarried(t *testing.T) {
	const base = "https://192.168.0.50:8443/releases"
	want := "--" + UpdateReleaseBaseFlag + "=" + base
	t.Run("server", func(t *testing.T) {
		shrinkRestartBudgets(t)
		f := &fakeSystem{}
		first := testConfig(t)
		first.UpdateReleaseBase = "https://192.168.0.9/old"
		if err := Install(context.Background(), f, first); err != nil {
			t.Fatalf("first install: %v", err)
		}
		second := testConfig(t)
		second.DataRoot, second.ServerArgsRecord = first.DataRoot, first.ServerArgsRecord
		second.UpdateReleaseBase = base
		if err := Install(context.Background(), f, second); err != nil {
			t.Fatalf("second install: %v", err)
		}
		req := inPlaceRequest()
		req.DataRoot, req.ServerArgsRecord = first.DataRoot, first.ServerArgsRecord
		cfg, err := ResolveInPlace(f, req, func(string) (string, error) { return "alice", nil })
		if err != nil {
			t.Fatalf("ResolveInPlace = %v", err)
		}
		if err := Install(context.Background(), f, cfg); err != nil {
			t.Fatalf("in-place install: %v", err)
		}
		args := serverArgsOf(t, f, cfg)
		if !slices.Contains(args, want) || strings.Contains(strings.Join(args, " "), "/old") {
			t.Errorf("server arguments %v, want exactly %s", args, want)
		}
	})
	t.Run("agent", func(t *testing.T) {
		shrinkRestartBudgets(t)
		f := &fakeSystem{}
		seedJoinedAgent(t, f)
		first := agentCfg(t)
		first.UpdateReleaseBase = base
		if err := Install(context.Background(), f, first); err != nil {
			t.Fatalf("first agent install: %v", err)
		}
		cfg, err := ResolveInPlace(f, inPlaceRequest(), nil)
		if err != nil {
			t.Fatalf("ResolveInPlace = %v", err)
		}
		if err := Install(context.Background(), f, cfg); err != nil {
			t.Fatalf("in-place agent install: %v", err)
		}
		if args := installedArgs(t, f, AgentLabel); !slices.Contains(args, want) {
			t.Errorf("agent arguments %v, want %s carried over", args, want)
		}
	})
}

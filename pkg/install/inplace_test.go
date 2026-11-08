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
	"bytes"
	"context"
	"errors"
	"log/slog"
	"slices"
	"strings"
	"testing"
)

// inPlaceRequest is the Config the root helper's argv describes: an install
// from a staging directory naming no role, no join target, no token and no
// user.
func inPlaceRequest(t testing.TB) Config {
	return Config{BinarySource: "/tmp/k3sm", InstallDir: testInstallDir(t)}
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
		f := newFakeSystem(t)
		seedJoinedAgent(t, f)
		first := agentCfg(t)
		local := "local"
		first.NodePortAddresses = &local
		if err := Install(context.Background(), f, first); err != nil {
			t.Fatalf("the first agent install: %v", err)
		}
		cfg, err := ResolveInPlace(f, inPlaceRequest(t), nil)
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
		explicit := Config{Role: RoleAgent, JoinServer: first.JoinServer, BinarySource: "/tmp/k3sm", TargetUser: "alice", InstallDir: first.InstallDir}
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
		f := newFakeSystem(t)
		first := testConfig(t)
		first.MeshIP = "100.64.0.1"
		first.TLSSANs = []string{"api.example.com"}
		if err := Install(context.Background(), f, first); err != nil {
			t.Fatalf("the first server install: %v", err)
		}
		req := inPlaceRequest(t)
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
		if _, err := ResolveInPlace(newFakeSystem(t), inPlaceRequest(t), nil); !errors.Is(err, ErrNothingToUpdate) {
			t.Fatalf("ResolveInPlace = %v, want ErrNothingToUpdate", err)
		}
	})

	t.Run("nothing installed with --user is the app's first install, unchanged", func(t *testing.T) {
		req := inPlaceRequest(t)
		req.TargetUser = "alice"
		cfg, err := ResolveInPlace(newFakeSystem(t), req, nil)
		if err != nil || cfg.Role != RoleServer || cfg.TargetUser != "alice" {
			t.Fatalf("ResolveInPlace = %+v, %v; want the request back as a server install", cfg.Role, err)
		}
	})

	t.Run("an agent without a node credential refuses", func(t *testing.T) {
		f := newFakeSystem(t)
		f.putFile(Config{}.withDefaults().plistPath(AgentLabel), AgentPlist(agentCfg(t).withDefaults()))
		if _, err := ResolveInPlace(f, inPlaceRequest(t), nil); err == nil || !strings.Contains(err.Error(), "node credential") {
			t.Fatalf("ResolveInPlace = %v, want the missing credential named", err)
		}
	})

	t.Run("a server with no recorded kubeconfig and no --user refuses", func(t *testing.T) {
		f := newFakeSystem(t)
		cfg := testConfig(t)
		configureServerArgs(f, cfg)
		req := inPlaceRequest(t)
		req.DataRoot, req.ServerArgsRecord = cfg.DataRoot, cfg.ServerArgsRecord
		if _, err := ResolveInPlace(f, req, func(string) (string, error) { return "alice", nil }); err == nil || !strings.Contains(err.Error(), "--user") {
			t.Fatalf("ResolveInPlace = %v, want a refusal naming --user", err)
		}
	})

	t.Run("both roles on disk refuses", func(t *testing.T) {
		f := newFakeSystem(t)
		configureServerArgs(f, testConfig(t))
		f.putFile(Config{}.withDefaults().plistPath(AgentLabel), AgentPlist(agentCfg(t).withDefaults()))
		if _, err := ResolveInPlace(f, inPlaceRequest(t), nil); err == nil || !strings.Contains(err.Error(), "ambiguous") {
			t.Fatalf("ResolveInPlace = %v, want the ambiguous role refused", err)
		}
	})
}

// TestUpdateReleaseBaseIsRecordedAndCarried pins --update-release-base: it
// is rendered into the role's daemon arguments, replaced by a later value,
// and kept by an in-place update, which names none.
func TestUpdateReleaseBaseIsRecordedAndCarried(t *testing.T) {
	const base = "https://192.0.2.50:8443/releases"
	want := "--" + UpdateReleaseBaseFlag + "=" + base
	t.Run("server", func(t *testing.T) {
		shrinkRestartBudgets(t)
		f := newFakeSystem(t)
		first := testConfig(t)
		first.UpdateReleaseBase = "https://192.0.2.9/old"
		if err := Install(context.Background(), f, first); err != nil {
			t.Fatalf("first install: %v", err)
		}
		second := testConfig(t)
		second.DataRoot, second.ServerArgsRecord = first.DataRoot, first.ServerArgsRecord
		second.UpdateReleaseBase = base
		if err := Install(context.Background(), f, second); err != nil {
			t.Fatalf("second install: %v", err)
		}
		req := inPlaceRequest(t)
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
		f := newFakeSystem(t)
		seedJoinedAgent(t, f)
		first := agentCfg(t)
		first.UpdateReleaseBase = base
		if err := Install(context.Background(), f, first); err != nil {
			t.Fatalf("first agent install: %v", err)
		}
		cfg, err := ResolveInPlace(f, inPlaceRequest(t), nil)
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

// TestInPlaceUpdateReportsAServiceRangeReset is the B1404 gate: an in-place
// update over a node whose netd plist records a non-default Service range (as
// an earlier release that took --service-cidr wrote it) still rewrites netd to
// the default, the range the apiserver uses, and says so: one Warn naming the
// old and the new range, and the update's own "updating ... in place" line
// names the reset. An update over the default range says nothing about it.
func TestInPlaceUpdateReportsAServiceRangeReset(t *testing.T) {
	const old = "10.96.0.0/16"
	for _, tc := range []struct {
		name     string
		recorded string
	}{
		{name: "a non-default range is reset and reported", recorded: old},
		{name: "the default range is updated silently", recorded: DefaultServiceCIDR},
	} {
		t.Run(tc.name, func(t *testing.T) {
			shrinkRestartBudgets(t)
			f := newFakeSystem(t)
			first := testConfig(t)
			if err := Install(context.Background(), f, first); err != nil {
				t.Fatalf("the first server install: %v", err)
			}
			if tc.recorded != DefaultServiceCIDR {
				recordServiceCIDR(t, f, first, tc.recorded)
			}
			var logs bytes.Buffer
			req := inPlaceRequest(t)
			req.DataRoot, req.ServerArgsRecord = first.DataRoot, first.ServerArgsRecord
			req.Logger = slog.New(slog.NewTextHandler(&logs, nil))
			cfg, err := ResolveInPlace(f, req, func(string) (string, error) { return "alice", nil })
			if err != nil {
				t.Fatalf("ResolveInPlace = %v", err)
			}
			if err := Install(context.Background(), f, cfg); err != nil {
				t.Fatalf("the in-place server install: %v", err)
			}
			if got := flagValue(installedArgs(t, f, NetdLabel), "service-cidr"); got != DefaultServiceCIDR {
				t.Errorf("netd's --service-cidr after the in-place update = %q, want the default %s", got, DefaultServiceCIDR)
			}
			var warns, updating []string
			for _, l := range strings.Split(logs.String(), "\n") {
				if strings.Contains(l, "level=WARN") && strings.Contains(l, "Service range") {
					warns = append(warns, l)
				}
				if strings.Contains(l, "updating the installed server in place") {
					updating = append(updating, l)
				}
			}
			if len(updating) != 1 {
				t.Fatalf("want one \"updating the installed server in place\" line, got %q:\n%s", updating, logs.String())
			}
			if tc.recorded == DefaultServiceCIDR {
				if len(warns) != 0 || strings.Contains(updating[0], "service-cidr") {
					t.Errorf("an update over the default range reported a reset: %q %q", warns, updating)
				}
				return
			}
			if len(warns) != 1 {
				t.Fatalf("want one Warn naming the Service range reset, got %q:\n%s", warns, logs.String())
			}
			for _, want := range []string{"old=" + old, "new=" + DefaultServiceCIDR} {
				if !strings.Contains(warns[0], want) {
					t.Errorf("the reset Warn lacks %q: %s", want, warns[0])
				}
			}
			if !strings.Contains(updating[0], "service-cidr-reset=\""+old+" -> "+DefaultServiceCIDR+"\"") {
				t.Errorf("the update's output does not name the reset: %s", updating[0])
			}
		})
	}
}

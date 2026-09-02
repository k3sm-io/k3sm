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
	"slices"
	"strings"
	"testing"
)

// The three reinstall defects observed live across four install cycles on the
// lab rig, each pinned here:
//
//  1. the run dir was left root-owned by whichever daemon created it first
//     (netd), so the _k3sm server could not bind its runtimed control socket;
//  2. a reinstall re-rendered the stock server plist over the operator's
//     --mesh-ip / --registry-port, which then had to be repaired by hand; and
//  3. the admin kubeconfig hardcoded loopback and skipped verification, so on a
//     mesh server it addressed nothing and verified nothing.

// TestInstallEnsuresRunDir proves the installer prepares the run dir for the
// SERVICE USER, at the path derived from the data root, BEFORE anything that
// could create it root-owned: the vm socket dir underneath it, and either daemon
// bootstrapping.
func TestInstallEnsuresRunDir(t *testing.T) {
	for _, tc := range []struct {
		name     string
		dataRoot string
		want     string
	}{
		{name: "default data root", dataRoot: "", want: "/var/lib/k3sm/run"},
		{name: "custom data root", dataRoot: "/opt/k3sm-lab", want: "/opt/k3sm-lab/run"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := &fakeSystem{}
			cfg := Config{BinarySource: "/tmp/k3sm", TargetUser: "alice", DataRoot: tc.dataRoot}
			if err := Install(context.Background(), f, cfg); err != nil {
				t.Fatalf("Install: %v", err)
			}
			ensure := idx(f.calls, "EnsureRunDir:"+tc.want)
			if ensure < 0 {
				t.Fatalf("no EnsureRunDir for %q; calls = %v", tc.want, f.calls)
			}
			// The leaf must be prepared after its parent, or MkdirAll of the leaf
			// creates the parent under the wrong owner.
			if vm := idx(f.calls, "EnsureVMRunDir:"+VMRunDir); tc.dataRoot == "" && ensure > vm {
				t.Errorf("run dir must be ensured before the vm socket dir under it (%d > %d)", ensure, vm)
			}
			// The whole point: no daemon may reach the run dir first.
			for _, label := range []string{NetdLabel, ServerLabel} {
				if boot := idx(f.calls, "Bootstrap:"+label); ensure > boot {
					t.Errorf("run dir must be ensured before %s bootstraps (%d > %d)", label, ensure, boot)
				}
			}
		})
	}
}

// TestRunDirDerivation pins RunDir against the constants the installer's other
// run-dir paths are composed from. The cross-package half of this invariant —
// that RunDir is the DIRECTORY provider.RuntimedSocketPath binds inside — is
// pinned in rundir_pin_test.go, which can import the provider without the cycle
// this package would take on.
func TestRunDirDerivation(t *testing.T) {
	if got := RunDir(""); got != DefaultRunDir {
		t.Errorf("RunDir(\"\") = %q, want the default run dir %q", got, DefaultRunDir)
	}
	for _, path := range []string{DefaultNetdSocket, MeshKeyDir, VMRunDir} {
		if !strings.HasPrefix(path, DefaultRunDir+"/") {
			t.Errorf("%q must live under the run dir %q", path, DefaultRunDir)
		}
	}
	if got, want := RunDir("/opt/lab"), "/opt/lab/run"; got != want {
		t.Errorf("RunDir(%q) = %q, want %q", "/opt/lab", got, want)
	}
}

// TestPreservedServerArgs is the unit table for defect 2's core decision: which
// arguments of an installed plist survive a re-render.
func TestPreservedServerArgs(t *testing.T) {
	for _, tc := range []struct {
		name      string
		installed []string
		want      []string
	}{
		{
			name: "fresh install: nothing installed, nothing preserved",
		},
		{
			name:      "stock template: every argument is install-managed",
			installed: []string{"/Library/k3sm/k3sm", "server", "--runtime", "runtimed", "--token", "k3sm-old"},
		},
		{
			name:      "operator flags after the managed set are preserved in order",
			installed: []string{"/Library/k3sm/k3sm", "server", "--runtime", "runtimed", "--token", "k3sm-old", "--mesh-ip", "100.64.0.1", "--registry-port", "6450"},
			want:      []string{"--mesh-ip", "100.64.0.1", "--registry-port", "6450"},
		},
		{
			name:      "operator flags BEFORE the managed set are preserved too",
			installed: []string{"/Library/k3sm/k3sm", "server", "--mesh-ip", "100.64.0.1", "--runtime", "runtimed", "--token", "k3sm-old"},
			want:      []string{"--mesh-ip", "100.64.0.1"},
		},
		{
			name:      "inline managed values are dropped without eating a neighbour",
			installed: []string{"/Library/k3sm/k3sm", "server", "--token=k3sm-old", "--mesh-ip", "100.64.0.1"},
			want:      []string{"--mesh-ip", "100.64.0.1"},
		},
		{
			name:      "single-dash spellings are the same flags",
			installed: []string{"/Library/k3sm/k3sm", "server", "-token", "k3sm-old", "-mesh-ip=100.64.0.1"},
			want:      []string{"-mesh-ip=100.64.0.1"},
		},
		{
			name:      "a boolean operator flag is not mistaken for a value carrier",
			installed: []string{"/Library/k3sm/k3sm", "server", "--runtime", "runtimed", "--disable-agent", "--mesh-ip", "100.64.0.1"},
			want:      []string{"--disable-agent", "--mesh-ip", "100.64.0.1"},
		},
		{
			name:      "a truncated plist with only the program and subcommand",
			installed: []string{"/Library/k3sm/k3sm", "server"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := preservedServerArgs(tc.installed); !slices.Equal(got, tc.want) {
				t.Errorf("preservedServerArgs(%v) = %v, want %v", tc.installed, got, tc.want)
			}
		})
	}
}

// TestInstallPreservesServerArgsAcrossReinstall drives the whole flow against a
// single fake — Install, hand-edit the installed plist the way an operator does,
// Install again — so the carry-over is proven through the real render/parse round
// trip rather than against a hand-written argv.
func TestInstallPreservesServerArgsAcrossReinstall(t *testing.T) {
	f := &fakeSystem{}
	cfg := Config{BinarySource: "/tmp/k3sm", TargetUser: "alice"}
	plist := cfg.withDefaults().plistPath(ServerLabel)

	// (1) FRESH: no plist on disk, so the render is exactly the stock template.
	if err := Install(context.Background(), f, cfg); err != nil {
		t.Fatalf("first Install: %v", err)
	}
	first, err := parseProgramArguments(f.files[plist])
	if err != nil {
		t.Fatalf("parse first-install plist: %v", err)
	}
	if got := preservedServerArgs(first); len(got) != 0 {
		t.Errorf("a fresh install must render the bare template, got extra args %v", got)
	}
	firstToken := flagValue(first, "token")
	if firstToken == "" {
		t.Fatal("the rendered plist must carry a --token")
	}

	// (2) The operator configures the node — the PlistBuddy repair that had to be
	//     redone after every reinstall.
	f.putFile(plist, ServerPlist(Config{
		AdminToken:      firstToken,
		ExtraServerArgs: []string{"--mesh-ip", "100.64.0.1", "--registry-port", "6450"},
	}))

	// (3) REINSTALL: the operator's arguments survive; the token does not.
	if err := Install(context.Background(), f, cfg); err != nil {
		t.Fatalf("reinstall: %v", err)
	}
	second, err := parseProgramArguments(f.files[plist])
	if err != nil {
		t.Fatalf("parse reinstalled plist: %v", err)
	}
	if got, want := preservedServerArgs(second), []string{"--mesh-ip", "100.64.0.1", "--registry-port", "6450"}; !slices.Equal(got, want) {
		t.Errorf("reinstall preserved %v, want %v (the operator's flags must survive)", got, want)
	}
	if got := flagValue(second, "mesh-ip"); got != "100.64.0.1" {
		t.Errorf("reinstalled plist --mesh-ip = %q, want 100.64.0.1", got)
	}
	// --token is install-managed: re-minted, never carried over, and in lockstep
	// with the kubeconfig the same run writes.
	newToken := flagValue(second, "token")
	if newToken == "" || newToken == firstToken {
		t.Errorf("--token must be re-minted on reinstall (was %q, now %q)", firstToken, newToken)
	}
	if strings.Contains(f.kubeContent, firstToken) || !strings.Contains(f.kubeContent, newToken) {
		t.Error("the admin kubeconfig must carry the re-minted token, not the superseded one")
	}
	// The managed set still leads the argv — a preserved argument may never
	// displace one the renderer owns.
	if len(second) < 6 || second[1] != "server" || second[2] != "--runtime" {
		t.Errorf("reinstalled argv = %v, want the managed set first", second)
	}
}

// TestInstallRefusesUnparsableServerPlist proves the reinstall FAILS rather than
// silently re-rendering the stock template over a plist it could not read — the
// silent-loss failure mode this whole path exists to remove. The message must
// name the file so the operator can act on it.
func TestInstallRefusesUnparsableServerPlist(t *testing.T) {
	f := &fakeSystem{}
	cfg := Config{BinarySource: "/tmp/k3sm", TargetUser: "alice"}
	plist := cfg.withDefaults().plistPath(ServerLabel)
	f.putFile(plist, []byte("<plist><dict><key>Label</key><string>io.k3sm.server</string></dict></plist>"))

	err := Install(context.Background(), f, cfg)
	if err == nil {
		t.Fatal("Install must refuse a server plist whose arguments it cannot read")
	}
	if !strings.Contains(err.Error(), plist) {
		t.Errorf("error %q must name the offending plist %q", err, plist)
	}
	// It must fail BEFORE writing anything over the file it could not read.
	if idx(f.calls, "WriteLaunchDaemon:"+plist) >= 0 {
		t.Error("Install wrote the server plist after failing to read it")
	}
}

// TestParseProgramArguments pins the plist reader against the renderer's own
// output and against the shapes a hand-edited plist takes.
func TestParseProgramArguments(t *testing.T) {
	t.Run("round-trips the renderer's output, escaping included", func(t *testing.T) {
		args := []string{"--mesh-ip", "100.64.0.1", "--label", "a&b<c"}
		got, err := parseProgramArguments(ServerPlist(Config{AdminToken: "k3sm-tok", ExtraServerArgs: args}))
		if err != nil {
			t.Fatalf("parseProgramArguments: %v", err)
		}
		want := []string{"/Library/k3sm/k3sm", "server", "--runtime", "runtimed", "--token", "k3sm-tok"}
		want = append(want, args...)
		if !slices.Equal(got, want) {
			t.Errorf("round trip = %v, want %v", got, want)
		}
	})
	t.Run("a plist with no ProgramArguments is an error, not an empty argv", func(t *testing.T) {
		if _, err := parseProgramArguments(NetdPlist(Config{})); err != nil {
			t.Fatalf("the netd plist HAS ProgramArguments: %v", err)
		}
		for _, bad := range []string{
			`<plist><dict><key>Label</key><string>x</string></dict></plist>`,
			`<plist><dict><key>ProgramArguments</key><string>not-an-array</string></dict></plist>`,
			`<plist><dict><key>ProgramArguments</key><array><string>x</string>`,
		} {
			if _, err := parseProgramArguments([]byte(bad)); err == nil {
				t.Errorf("expected an error for %q", bad)
			}
		}
	})
}

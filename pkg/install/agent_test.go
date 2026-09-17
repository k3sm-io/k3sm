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
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"k3sm.io/k3sm/pkg/dataroot"
)

// agentCfg is the Config an agent install is asked for: the role, where to
// join, this node's own mesh address, and the file the token is in.
func agentCfg(t *testing.T) Config {
	t.Helper()
	return Config{
		Role:             RoleAgent,
		JoinServer:       "192.0.2.10",
		NodeIP:           "100.64.0.7",
		TokenFile:        operatorTokenFile,
		BinarySource:     "/tmp/k3sm",
		TargetUser:       "alice",
		AgentArgsRecord:  dataroot.DefaultAgentArgsRecordPath,
		ServerArgsRecord: dataroot.DefaultServerArgsRecordPath,
	}
}

// theJoinToken is a token value a test plants where a token must never appear.
// It is deliberately a realistic K10 shape, so a renderer that put the token on
// the argv would be caught by its own spelling rather than by a placeholder.
const theJoinToken = "K10abc123::node:s3cr3t"

// operatorTokenFile is the path the OPERATOR writes their token to: root-owned,
// in root's home, which is exactly the file the service user cannot read and
// the reason the installer stages a copy.
const operatorTokenFile = "/var/root/k3sm-join-token"

// seedOperatorToken puts the operator's token file in the fake root filesystem.
// Install reads it as root, which is the only party that can.
func seedOperatorToken(f *fakeSystem) {
	f.putFile(operatorTokenFile, []byte(theJoinToken+"\n"))
}

// seedJoinedAgent is seedOperatorToken plus the credential a completed join
// leaves in the agent work dir — the posture a SUCCESSFUL agent install is in
// by the time the verification runs. It returns the token the operator's file
// holds, which is the token that pins that credential's cluster: install checks
// the two against each other (verifyAgentJoined), so a token and a credential
// minted independently would correctly read as a worker that never joined.
func seedJoinedAgent(t *testing.T, f *fakeSystem) string {
	t.Helper()
	cred := mintNodeCredential(t, Config{}.withDefaults().agentWorkDir())
	cred.seed(f)
	f.putFile(operatorTokenFile, []byte(cred.token+"\n"))
	return cred.token
}

// TestInstallRendersAgentDaemonWhenJoining is the gate for the agent role: a
// Mac that joins an existing cluster gets a supervised io.k3sm.agent
// LaunchDaemon from `k3sm install --agent`, instead of the hand-daemonized
// foreground `k3sm agent` that was the only way to run a worker before.
//
// Five properties, each of which was a way to get this wrong:
//
//   - the agent role renders netd AND io.k3sm.agent, and NOT the control plane
//     (a worker that also bootstrapped io.k3sm.server would present a second,
//     apiserver-less node out of the same data root);
//   - the join token reaches the daemon as a --token-file PATH and the plist
//     bytes contain no token anywhere (the plist is root-owned 0644);
//   - uninstall removes the agent daemon and its plist, and keeps the record;
//   - installing either role over the other is REFUSED before a byte is
//     written, so a role change is uninstall-then-install and never a merge;
//   - the SERVER role's manifest and plist are byte-for-byte what they were.
func TestInstallRendersAgentDaemonWhenJoining(t *testing.T) {
	t.Run("an agent install renders netd and io.k3sm.agent, never the server", func(t *testing.T) {
		shrinkRestartBudgets(t)
		f := &fakeSystem{}
		seedJoinedAgent(t, f)
		cfg := agentCfg(t)
		if err := Install(context.Background(), f, cfg); err != nil {
			t.Fatalf("Install: %v", err)
		}
		dc := cfg.withDefaults()
		written := toSet(recorded(f.calls, "WriteLaunchDaemon:"))
		for _, path := range []string{dc.plistPath(NetdLabel), dc.plistPath(AgentLabel)} {
			if !written[path] {
				t.Errorf("agent install did not write %s (wrote %v)", path, recorded(f.calls, "WriteLaunchDaemon:"))
			}
		}
		if written[dc.plistPath(ServerLabel)] {
			t.Error("agent install wrote the control-plane plist: a worker runs no control plane")
		}
		bootstrapped := toSet(recorded(f.calls, "Bootstrap:"))
		if !bootstrapped[AgentLabel] || !bootstrapped[NetdLabel] {
			t.Errorf("both netd and the agent must be bootstrapped, got %v", recorded(f.calls, "Bootstrap:"))
		}
		if bootstrapped[ServerLabel] {
			t.Error("agent install bootstrapped io.k3sm.server")
		}
		// netd first: the agent reaches the helper over its socket.
		if idx(f.calls, "Bootstrap:"+NetdLabel) >= idx(f.calls, "Bootstrap:"+AgentLabel) {
			t.Error("netd must be bootstrapped before the agent")
		}

		plist := string(f.files[dc.plistPath(AgentLabel)])
		for _, needle := range []string{
			"<key>Label</key>\n  <string>io.k3sm.agent</string>",
			"<key>UserName</key>\n  <string>_k3sm</string>",
			"<string>agent</string>",
			"<string>--server</string>",
			"<string>192.0.2.10</string>",
			"<string>--node-ip</string>",
			"<string>100.64.0.7</string>",
			"<string>--token-file</string>",
			"<string>/var/lib/k3sm/agent/join-token</string>",
			"<key>RunAtLoad</key>\n  <true/>",
			"<key>KeepAlive</key>\n  <true/>",
			"<key>ThrottleInterval</key>\n  <integer>10</integer>",
			"<key>ExitTimeOut</key>\n  <integer>60</integer>",
			"<key>StandardOutPath</key>\n  <string>/var/log/k3sm/agent.log</string>",
			// The same fd-table raise the control plane gets: a worker hosts the
			// Service proxy and the UDP relay, whose flow budget sizes against
			// RLIMIT_NOFILE and would floor at launchd's 256-fd default.
			"<key>SoftResourceLimits</key>",
			"<key>HardResourceLimits</key>",
			"<integer>131072</integer>",
		} {
			mustContain(t, plist, needle)
		}
		if strings.Contains(plist, operatorTokenFile) {
			t.Errorf("the plist names the OPERATOR's token file, which the service user cannot read:\n%s", plist)
		}
	})

	t.Run("the token is staged where the unprivileged daemon can read it", func(t *testing.T) {
		shrinkRestartBudgets(t)
		f := &fakeSystem{}
		joinToken := seedJoinedAgent(t, f)
		cfg := agentCfg(t)
		if err := Install(context.Background(), f, cfg); err != nil {
			t.Fatalf("Install: %v", err)
		}
		// The whole point: the daemon runs as _k3sm, the operator's file is
		// root-only, so root copies the token to the service user's own tree at
		// 0600 in a 0700 directory. The fake records exactly what was asked for.
		want := "WriteServiceUserFile:" + cfg.withDefaults().agentTokenPath() + ":0600:0700:271"
		if !slices.Contains(f.calls, want) {
			t.Fatalf("install did not stage the join token as %q (calls: %v)", want, f.calls)
		}
		staged, ok := f.files[cfg.withDefaults().agentTokenPath()]
		if !ok {
			t.Fatal("nothing was written at the staged token path")
		}
		if strings.TrimSpace(string(staged)) != joinToken {
			t.Errorf("staged token = %q, want the operator's token, trimmed", staged)
		}
		// Staged BEFORE the plist that names it is written, and before the
		// daemon that reads it is bootstrapped.
		if idx(f.calls, want) >= idx(f.calls, "WriteLaunchDaemon:"+cfg.withDefaults().plistPath(AgentLabel)) {
			t.Error("the token must be staged before the plist that points at it")
		}
	})

	t.Run("an install with no token file stages nothing", func(t *testing.T) {
		shrinkRestartBudgets(t)
		f := &fakeSystem{}
		cfg := agentCfg(t)
		cfg.TokenFile = ""
		// A joined node reinstalling: it presents its stored credential, so
		// there is no token to stage and none to wait for.
		if err := Install(context.Background(), f, cfg); err != nil {
			t.Fatalf("Install: %v", err)
		}
		for _, c := range f.calls {
			if strings.HasPrefix(c, "WriteServiceUserFile:") {
				t.Errorf("an install with no --token-file wrote %q", c)
			}
		}
		// The argv still names the staged path: it is where a token is read
		// from whenever there is one, and the agent treats its absence as "no
		// token" rather than as a failure.
		mustContain(t, string(f.files[cfg.withDefaults().plistPath(AgentLabel)]),
			"<string>"+cfg.withDefaults().agentTokenPath()+"</string>")
	})

	t.Run("an empty operator token file is refused", func(t *testing.T) {
		shrinkRestartBudgets(t)
		f := &fakeSystem{}
		f.putFile(operatorTokenFile, []byte("  \n"))
		err := Install(context.Background(), f, agentCfg(t))
		if err == nil {
			t.Fatal("install accepted an empty join token file")
		}
		if !strings.Contains(err.Error(), operatorTokenFile) {
			t.Errorf("error %q does not name the file to fix", err)
		}
	})

	t.Run("a token file that is not a join token is refused before anything is staged", func(t *testing.T) {
		shrinkRestartBudgets(t)
		f := &fakeSystem{}
		// A plausible mistake: the operator pasted the node-password, a
		// kubeconfig line, or half a token. It can never complete a join, and
		// it carries no cluster-CA pin — which is what the installer compares
		// the stored node credential against — so it is refused here, where a
		// human is still watching, rather than backed off from forever.
		f.putFile(operatorTokenFile, []byte("K10-no-separator-here\n"))
		err := Install(context.Background(), f, agentCfg(t))
		if err == nil {
			t.Fatal("install accepted a token file that does not hold a join token")
		}
		for _, want := range []string{operatorTokenFile, "K10<cluster-CA hash>::<user>:<secret>"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("error %q must carry %q — the operator needs the file and the shape it should hold", err, want)
			}
		}
		if strings.Contains(err.Error(), "no-separator-here") {
			t.Errorf("the refusal echoes the contents of the token file: %q", err)
		}
		// Refused BEFORE a byte of it is written anywhere.
		for _, c := range f.calls {
			if strings.HasPrefix(c, "WriteServiceUserFile:") || strings.HasPrefix(c, "WriteLaunchDaemon:") {
				t.Errorf("a malformed token was staged anyway: %q", c)
			}
		}
	})

	t.Run("an operator token file anyone can read is refused", func(t *testing.T) {
		shrinkRestartBudgets(t)
		f := &fakeSystem{}
		seedOperatorToken(f)
		// The same refusal `k3sm agent` applies to the file it is pointed at,
		// applied to the source: copying a world-readable token into a 0600
		// destination would launder an exposure rather than report it.
		f.putFileMode(operatorTokenFile, 0o644)
		err := Install(context.Background(), f, agentCfg(t))
		if err == nil {
			t.Fatal("install accepted a world-readable join token file")
		}
		if !strings.Contains(err.Error(), "chmod 600") || !strings.Contains(err.Error(), operatorTokenFile) {
			t.Errorf("error %q must name the file and the remedy", err)
		}
		for _, c := range f.calls {
			if strings.HasPrefix(c, "WriteServiceUserFile:") {
				t.Errorf("a refused token was staged anyway: %q", c)
			}
		}
	})

	t.Run("a staged token that never becomes a credential fails the install", func(t *testing.T) {
		shrinkRestartBudgets(t)
		f := &fakeSystem{}
		seedOperatorToken(f)
		cfg := agentCfg(t)
		// The daemon is up and the join never completes: a rejected token puts
		// `k3sm agent` in its terminal backoff, where launchd reports a healthy
		// pid indefinitely. Nothing seeds a credential here, so this Mac has
		// never joined anything and the install must say so.
		err := Install(context.Background(), f, cfg)
		if err == nil {
			t.Fatal("install reported success with an agent that never joined")
		}
		for _, want := range []string{AgentLogPath(), "k3sm token create"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("error %q does not name %q, so it does not say where to look or what to do", err, want)
			}
		}
	})

	t.Run("a join that produces a credential is a success", func(t *testing.T) {
		shrinkRestartBudgets(t)
		f := &fakeSystem{}
		seedJoinedAgent(t, f)
		// The healthy first join: the node holds a credential for the cluster
		// the staged token pins, and nothing was recorded against this install.
		if err := Install(context.Background(), f, agentCfg(t)); err != nil {
			t.Fatalf("Install: %v", err)
		}
		// READ, not stat. The credential is verified by parsing it and
		// comparing its cluster CA with the token's pin — a file that merely
		// exists is what the 2026-09-17 install was satisfied by.
		if !slices.Contains(f.calls, "ReadFile:"+AgentCredentialPath("")) {
			t.Errorf("install never read the node credential (calls: %v)", f.calls)
		}
	})

	t.Run("the plist carries a token PATH and no token", func(t *testing.T) {
		shrinkRestartBudgets(t)
		f := &fakeSystem{}
		seedJoinedAgent(t, f)
		cfg := agentCfg(t)
		// The token exists on this Mac, in the operator's file and in the
		// environment the install was run from. Neither may reach the plist.
		cfg.AdminToken = theJoinToken
		raw := AgentPlist(cfg)
		if bytes.Contains(raw, []byte(theJoinToken)) {
			t.Fatalf("the agent plist carries the join token itself:\n%s", raw)
		}
		if bytes.Contains(raw, []byte("<string>--token</string>")) {
			t.Errorf("the agent plist renders --token; a root-owned 0644 plist publishes its argv to every account on the Mac:\n%s", raw)
		}
		if err := Install(context.Background(), f, cfg); err != nil {
			t.Fatalf("Install: %v", err)
		}
		installed := f.files[cfg.withDefaults().plistPath(AgentLabel)]
		if bytes.Contains(installed, []byte(theJoinToken)) || bytes.Contains(installed, []byte("<string>--token</string>")) {
			t.Errorf("the INSTALLED agent plist carries a token:\n%s", installed)
		}
	})

	t.Run("uninstall removes the agent daemon and keeps the record", func(t *testing.T) {
		shrinkRestartBudgets(t)
		f := &fakeSystem{}
		seedJoinedAgent(t, f)
		cfg := agentCfg(t)
		if err := Install(context.Background(), f, cfg); err != nil {
			t.Fatalf("Install: %v", err)
		}
		dc := cfg.withDefaults()
		if _, ok := f.files[dc.AgentArgsRecord]; !ok {
			t.Fatalf("the agent install wrote no agent-arguments record at %s", dc.AgentArgsRecord)
		}
		// Uninstall is run from the DEFAULT config, exactly as `k3sm uninstall`
		// runs it: it must find the agent daemon by reading the disk, not by
		// being told which role this Mac is.
		if err := Uninstall(context.Background(), f, Config{}); err != nil {
			t.Fatalf("Uninstall: %v", err)
		}
		if !toSet(recorded(f.calls, "Bootout:"))[AgentLabel] {
			t.Error("uninstall did not boot out io.k3sm.agent")
		}
		if _, ok := f.files[dc.plistPath(AgentLabel)]; ok {
			t.Error("the agent plist LEAKED: a booted-out label with a KeepAlive plist still on disk")
		}
		if _, ok := f.files[dc.AgentArgsRecord]; !ok {
			t.Error("uninstall removed the agent-arguments record; it must survive so the next install carries the flags over")
		}
		// The staged token is a credential with no further use: unlike the rest
		// of the data root it does NOT survive an uninstall.
		if _, ok := f.files[dc.agentTokenPath()]; ok {
			t.Error("the staged join token survived the uninstall")
		}
	})

	t.Run("a cross-role install is refused before anything is written", func(t *testing.T) {
		for _, tc := range []struct {
			name     string
			onDisk   string
			cfg      func(*testing.T) Config
			wantWord string
		}{
			{"agent over a server", ServerLabel, agentCfg, "server"},
			{"server over an agent", AgentLabel, func(t *testing.T) Config {
				return Config{BinarySource: "/tmp/k3sm", TargetUser: "alice"}
			}, "agent"},
		} {
			t.Run(tc.name, func(t *testing.T) {
				f := &fakeSystem{}
				cfg := tc.cfg(t)
				f.putFile(cfg.withDefaults().plistPath(tc.onDisk), []byte("<plist/>"))
				err := Install(context.Background(), f, cfg)
				if err == nil {
					t.Fatal("Install accepted a second role over an installed one")
				}
				if !strings.Contains(err.Error(), tc.wantWord) || !strings.Contains(err.Error(), "k3sm uninstall") {
					t.Errorf("error %q must name the installed role and the remedy (`k3sm uninstall`)", err)
				}
				// NOTHING was written: every recorded call is a read.
				for _, c := range f.calls {
					if !strings.HasPrefix(c, "ReadFile:") {
						t.Errorf("the refusal happened after %q; it must precede every write", c)
					}
				}
			})
		}
	})

	t.Run("the agent record round-trips across uninstall then install", func(t *testing.T) {
		shrinkRestartBudgets(t)
		f := &fakeSystem{}
		seedJoinedAgent(t, f)
		cfg := agentCfg(t)
		// An operator's own flag, arriving the only way one can: on the agent
		// plist already installed, which is what they edit and kickstart.
		seeded := cfg
		seeded.ExtraAgentArgs = []string{"--mesh-port", "51821"}
		f.putFile(cfg.withDefaults().plistPath(AgentLabel), AgentPlist(seeded))
		if err := Install(context.Background(), f, cfg); err != nil {
			t.Fatalf("first Install: %v", err)
		}
		if got := f.agentArgs[cfg.AgentArgsRecord].Args; strings.Join(got, " ") != "--mesh-port 51821" {
			t.Fatalf("the recorded agent arguments = %v, want the operator's own flag and nothing the renderer owns", got)
		}
		if err := Uninstall(context.Background(), f, Config{}); err != nil {
			t.Fatalf("Uninstall: %v", err)
		}
		// The plist is gone, so the SECOND install has only the record to read.
		second := agentCfg(t)
		if err := Install(context.Background(), f, second); err != nil {
			t.Fatalf("second Install: %v", err)
		}
		plist := string(f.files[second.withDefaults().plistPath(AgentLabel)])
		mustContain(t, plist, "<string>--mesh-port</string>")
		mustContain(t, plist, "<string>51821</string>")

		t.Run("and a record naming --token is refused", func(t *testing.T) {
			if err := dataroot.ValidateAgentArgs([]string{"--token", theJoinToken}); err == nil {
				t.Fatal("an agent-arguments record carrying --token was accepted")
			}
			bad := &fakeSystem{}
			data, err := dataroot.EncodeAgentArgsRecord(dataroot.AgentArgsRecord{Args: []string{"--mesh-port", "51821"}})
			if err != nil {
				t.Fatalf("encode: %v", err)
			}
			// Hand-edit the encoded record into one that sets --token, which is
			// what a restored or synced file could be.
			bad.putFile(dataroot.DefaultAgentArgsRecordPath,
				[]byte(strings.Replace(string(data), `"--mesh-port"`, `"--token"`, 1)))
			if err := Install(context.Background(), bad, agentCfg(t)); err == nil {
				t.Fatal("install accepted a record that sets --token")
			}
		})
	})

	t.Run("the server role is unchanged", func(t *testing.T) {
		// Captured from THIS build, but asserted against a manifest and a render
		// that must not have moved: the agent role is additive, and the control
		// plane an operator already has installed re-renders identically.
		// The golden file is the server plist this build renders for a fixed
		// Config, captured while the agent role was added. ServerPlist itself was
		// not touched by that work, and this is the assertion that keeps it true:
		// every operator with a control plane installed re-renders byte-for-byte
		// what they already have, so `k3sm install` on an existing server is still
		// the no-op-shaped upgrade it was.
		//
		// It moved ONCE since, deliberately: the admin token left the argv for a
		// staged file, so the golden now shows --token-file and the path (B249,
		// gated by TestServerPlistCarriesNoToken). A render that moves for any
		// other reason is still the regression this pins.
		want, err := os.ReadFile(filepath.Join("testdata", "server.plist.golden"))
		if err != nil {
			t.Fatalf("read the server plist golden: %v", err)
		}
		got := ServerPlist(Config{BinarySource: "/tmp/k3sm", TargetUser: "alice", AdminToken: "k3sm-fixed"})
		if !bytes.Equal(got, want) {
			t.Errorf("ServerPlist bytes moved:\n--- got ---\n%s\n--- want ---\n%s", got, want)
		}

		// And the server manifest still names the control plane, no agent entry.
		var labels []string
		for _, a := range artifactManifest(Config{BinarySource: "/tmp/k3sm", TargetUser: "alice"}) {
			if a.kind == kindDaemon {
				labels = append(labels, a.label)
			}
		}
		if strings.Join(labels, ",") != NetdLabel+","+ServerLabel {
			t.Errorf("server-role daemons = %v, want netd then the control plane", labels)
		}
	})
}

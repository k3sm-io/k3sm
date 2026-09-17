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
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"k3sm.io/k3sm/pkg/install"
)

// TestAgentTokenFile pins how `k3sm agent` is given a join token by file: the
// precedence over --token and $K3SM_TOKEN, and the refusal of a file any other
// account can read.
//
// The mode check is the reason the flag is worth having. A supervised agent's
// argv sits in a root-owned 0644 LaunchDaemon plist, so the daemon is told
// WHERE its token is and never what it is — which only helps if the file is not
// itself readable by everyone.
func TestAgentTokenFile(t *testing.T) {
	write := func(t *testing.T, name, content string, mode os.FileMode) string {
		t.Helper()
		path := filepath.Join(t.TempDir(), name)
		if err := os.WriteFile(path, []byte(content), mode); err != nil {
			t.Fatalf("write %s: %v", path, err)
		}
		// WriteFile applies the umask, so the mode is set explicitly.
		if err := os.Chmod(path, mode); err != nil {
			t.Fatalf("chmod %s: %v", path, err)
		}
		return path
	}

	t.Run("the flag is registered", func(t *testing.T) {
		fs := flag.NewFlagSet("agent", flag.ContinueOnError)
		var opts agentOptions
		registerAgentFlags(fs, &opts)
		if fs.Lookup("token-file") == nil {
			t.Fatal("`k3sm agent` has no --token-file flag")
		}
		if err := fs.Parse([]string{"--token-file", "/var/root/tok"}); err != nil {
			t.Fatalf("parse: %v", err)
		}
		if opts.tokenFile != "/var/root/tok" {
			t.Errorf("tokenFile = %q, want the path", opts.tokenFile)
		}
	})

	t.Run("the file wins over --token and the environment", func(t *testing.T) {
		path := write(t, "tok", "K10abc::node:from-the-file\n", 0o600)
		opts := agentOptions{tokenFile: path, token: "K10abc::node:from-the-flag"}
		absent, err := applyTokenFile(&opts)
		if err != nil {
			t.Fatalf("applyTokenFile: %v", err)
		}
		if absent {
			t.Error("a file that is there was reported absent")
		}
		if opts.token != "K10abc::node:from-the-file" {
			t.Errorf("token = %q, want the file's contents, trimmed", opts.token)
		}
	})

	t.Run("no file leaves --token alone", func(t *testing.T) {
		opts := agentOptions{token: "K10abc::node:from-the-flag"}
		if _, err := applyTokenFile(&opts); err != nil {
			t.Fatalf("applyTokenFile: %v", err)
		}
		if opts.token != "K10abc::node:from-the-flag" {
			t.Errorf("token = %q, want the flag's value untouched", opts.token)
		}
	})

	t.Run("a group- or world-readable file is refused", func(t *testing.T) {
		for _, mode := range []os.FileMode{0o640, 0o644, 0o604, 0o660, 0o666} {
			path := write(t, "tok", "K10abc::node:secret\n", mode)
			opts := agentOptions{tokenFile: path}
			_, err := applyTokenFile(&opts)
			if err == nil {
				t.Errorf("mode %#o was accepted: a join token is a credential", mode)
				continue
			}
			if !strings.Contains(err.Error(), "chmod 600") {
				t.Errorf("error %q must name the remedy", err)
			}
			if strings.Contains(err.Error(), "secret") {
				t.Errorf("the refusal echoed the token itself: %q", err)
			}
			if opts.token != "" {
				t.Errorf("a refused file still set the token to %q", opts.token)
			}
		}
	})

	t.Run("an empty file is an error, not an empty token", func(t *testing.T) {
		empty := write(t, "tok", "   \n", 0o600)
		if _, err := applyTokenFile(&agentOptions{tokenFile: empty}); err == nil {
			t.Error("an empty token file was accepted as a token")
		}
	})
}

// TestAgentTokenFileMissingIsNotTerminal is the regression for what the
// documented cleanup used to do to a joined worker.
//
// The agent is told to delete its token file once the node is Ready, and the
// installed daemon still carries --token-file on its argv, so the steady state
// of a healthy worker is a token file that is not there. When that was
// terminal, every later restart of a perfectly healthy node backed off and
// exited, forever, over a credential it did not need: the node holds its own.
//
// The three rows are the whole decision. Only the first two changed; the third
// is here because it is what must NOT change — a file that exists and cannot be
// used is still a refusal.
func TestAgentTokenFileMissingIsNotTerminal(t *testing.T) {
	t.Parallel()

	missing := func(t *testing.T) string {
		t.Helper()
		return filepath.Join(t.TempDir(), "join-token")
	}

	t.Run("missing file and a valid credential: the node reuses what it holds", func(t *testing.T) {
		t.Parallel()
		res, _, _ := nodeCredFixture(t, nodeCredClientTTL, nodeCredClientTTL)
		store := savedStore(t, res)
		status, cred, err := store.Status(time.Now())
		if err != nil {
			t.Fatalf("Status: %v", err)
		}

		opts := agentOptions{tokenFile: missing(t)}
		absent, err := applyTokenFile(&opts)
		if err != nil {
			t.Fatalf("a missing token file was terminal: %v", err)
		}
		if !absent {
			t.Fatal("a missing token file was not reported absent")
		}
		if opts.token != "" {
			t.Errorf("token = %q, want none: an absent file contributes no token", opts.token)
		}
		plan, err := agentStartPlan(status, strings.TrimSpace(opts.token) != "", false, "", cred.ClusterCAPin)
		if err != nil {
			t.Fatalf("agentStartPlan: %v", err)
		}
		if plan != startModeReuseCredential {
			t.Errorf("plan = %v, want the credential reuse a joined node restarts with", plan)
		}
	})

	t.Run("missing file and no credential: terminal, naming both facts", func(t *testing.T) {
		t.Parallel()
		path := missing(t)
		opts := agentOptions{tokenFile: path}
		absent, err := applyTokenFile(&opts)
		if err != nil || !absent {
			t.Fatalf("applyTokenFile = (%v, %v), want (true, nil)", absent, err)
		}
		_, planErr := agentStartPlan(credentialAbsent, false, false, "", "")
		if planErr == nil {
			t.Fatal("a start with no credential and no token was accepted")
		}
		got := missingTokenFileNote(planErr, path)
		if !errors.Is(got, errNoCredentialNoToken) {
			t.Errorf("the note broke the sentinel chain: %v", got)
		}
		if !strings.Contains(got.Error(), path) {
			t.Errorf("error %q does not name the token file that is missing", got)
		}
		if !strings.Contains(got.Error(), "k3sm token create") {
			t.Errorf("error %q does not keep the remedy", got)
		}
	})

	t.Run("a file that IS there and cannot be used stays terminal", func(t *testing.T) {
		t.Parallel()
		path := filepath.Join(t.TempDir(), "join-token")
		if err := os.WriteFile(path, []byte("K10abc::node:secret\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, 0o644); err != nil {
			t.Fatal(err)
		}
		absent, err := applyTokenFile(&agentOptions{tokenFile: path})
		if err == nil {
			t.Fatal("a group- and world-readable token file was accepted")
		}
		if absent {
			t.Error("a file that exists was reported absent; only a missing file is tolerated")
		}
	})
}

// TestInstallerWatchesTheCredentialTheAgentWrites binds the two halves of the
// agent install's verification, which live in packages that cannot see each
// other.
//
// pkg/install waits for AgentCredentialPath to appear before it calls an agent
// install successful, because a pid proves only that launchd spawned the
// daemon: an agent whose token the cluster rejected backs off on a 30-second
// loop with a healthy pid. pkg/install cannot import cmd/k3sm, so it states
// that path itself — and if the credential store ever writes somewhere else,
// the installer would be watching a file nothing produces and would fail every
// join. This is the assertion that turns that into a red test instead.
func TestInstallerWatchesTheCredentialTheAgentWrites(t *testing.T) {
	t.Parallel()
	const dataRoot = "/var/lib/k3sm"
	store := nodeCredentialStore{dir: filepath.Join(dataRoot, "agent")}
	if got, want := install.AgentCredentialPath(dataRoot), store.kubeconfigPath(); got != want {
		t.Errorf("install.AgentCredentialPath = %q, but the agent writes its credential to %q", got, want)
	}
	// And the default data root resolves to the same file, since that is what the
	// installed daemon actually uses.
	if got, want := install.AgentCredentialPath(""), store.kubeconfigPath(); got != want {
		t.Errorf("install.AgentCredentialPath(\"\") = %q, want the default data root's %q", got, want)
	}
	// The agent's own default --work-dir must be that same directory, or the
	// installed daemon would keep its credential somewhere the installer is not
	// watching.
	fs := flag.NewFlagSet("agent", flag.ContinueOnError)
	var opts agentOptions
	registerAgentFlags(fs, &opts)
	if err := fs.Parse(nil); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if opts.workDir != store.dir {
		t.Errorf("`k3sm agent` defaults --work-dir to %q, but the installer watches %q", opts.workDir, store.dir)
	}
}

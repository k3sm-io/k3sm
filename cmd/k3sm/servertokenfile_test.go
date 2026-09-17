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
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestServerTokenFile pins how `k3sm server` is given its static admin token by
// file — the control-plane half of TestAgentTokenFile, resolved through the
// SAME reader.
//
// The flag is what keeps a system:masters bearer token off the server
// LaunchDaemon's argv, where the plist, `ps` and launchd's own job description
// each published it to every account on the Mac. The mode refusal is what makes
// "the token is in a file" an improvement rather than a relocation.
func TestServerTokenFile(t *testing.T) {
	write := func(t *testing.T, content string, mode os.FileMode) string {
		t.Helper()
		path := filepath.Join(t.TempDir(), "token")
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
		fs := flag.NewFlagSet("server", flag.ContinueOnError)
		var opts serverOptions
		_ = registerServerFlags(fs, &opts)
		if fs.Lookup("token-file") == nil {
			t.Fatal("`k3sm server` has no --token-file flag")
		}
		if err := fs.Parse([]string{"--token-file", "/var/lib/k3sm/server/token"}); err != nil {
			t.Fatalf("parse: %v", err)
		}
		if opts.tokenFile != "/var/lib/k3sm/server/token" {
			t.Errorf("tokenFile = %q, want the path", opts.tokenFile)
		}
	})

	t.Run("the file wins over --token and the environment", func(t *testing.T) {
		path := write(t, "k3sm-from-the-file\n", 0o600)
		opts := serverOptions{tokenFile: path, token: "k3sm-from-the-flag"}
		absent, err := resolveTokenFile(opts.tokenFile, &opts.token)
		if err != nil {
			t.Fatalf("resolveTokenFile: %v", err)
		}
		if absent {
			t.Error("a file that is there was reported absent")
		}
		if opts.token != "k3sm-from-the-file" {
			t.Errorf("token = %q, want the file's contents, trimmed", opts.token)
		}
	})

	t.Run("an absent file is a posture, not a failure", func(t *testing.T) {
		// The installed daemon always names a path, and a control plane brought
		// up before the file exists must still start: the executor then generates
		// its own token, which is what a bare `k3sm server` has always done.
		opts := serverOptions{tokenFile: filepath.Join(t.TempDir(), "not-there")}
		absent, err := resolveTokenFile(opts.tokenFile, &opts.token)
		if err != nil || !absent {
			t.Fatalf("resolveTokenFile = (%v, %v), want (true, nil)", absent, err)
		}
		if opts.token != "" {
			t.Errorf("an absent file contributed the token %q", opts.token)
		}
	})

	t.Run("a group- or world-readable file is refused", func(t *testing.T) {
		for _, mode := range []os.FileMode{0o640, 0o644, 0o604, 0o660, 0o666} {
			opts := serverOptions{tokenFile: write(t, "k3sm-adm1n-s3cr3t\n", mode)}
			_, err := resolveTokenFile(opts.tokenFile, &opts.token)
			if err == nil {
				t.Errorf("mode %#o was accepted: the admin token is a credential", mode)
				continue
			}
			if strings.Contains(err.Error(), "s3cr3t") {
				t.Errorf("the refusal echoed the token itself: %q", err)
			}
			if opts.token != "" {
				t.Errorf("a refused file still set the token to %q", opts.token)
			}
		}
	})

	t.Run("both roles resolve through one reader", func(t *testing.T) {
		// applyTokenFile is resolveTokenFile with the agent's options bound to
		// it. Asserting that here is what keeps a second reader (and a second set
		// of refusals) from growing on the server side.
		path := write(t, "K10abc::node:one-reader\n", 0o600)
		agent := agentOptions{tokenFile: path}
		if _, err := applyTokenFile(&agent); err != nil {
			t.Fatalf("applyTokenFile: %v", err)
		}
		server := serverOptions{tokenFile: path}
		if _, err := resolveTokenFile(server.tokenFile, &server.token); err != nil {
			t.Fatalf("resolveTokenFile: %v", err)
		}
		if agent.token != server.token {
			t.Errorf("the two roles read %q and %q from one file", agent.token, server.token)
		}
	})
}

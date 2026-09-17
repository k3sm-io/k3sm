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
	"io/fs"
	"strings"
	"testing"
)

// theAdminToken is a static admin token planted where a token must never
// appear. It is a realistic value rather than a placeholder, so a renderer that
// put it back on the argv would be caught by its own spelling.
const theAdminToken = "k3sm-adm1n-t0ken-s3cr3t"

// legacyServerPlist is the plist shape k3sm installed BEFORE the token moved to
// a file: the admin token as a VALUE on the argv, in a world-readable file. It
// is what a Mac installed by any earlier build has on disk, and the thing a
// reinstall has to replace — both its contents and its mode.
func legacyServerPlist(cfg Config, token string) []byte {
	cfg = cfg.withDefaults()
	return renderPlist(launchdPlist{
		Label:            ServerLabel,
		UserName:         cfg.ServiceUser,
		ProgramArguments: []string{cfg.installedBinary(), "server", "--runtime", "runtimed", "--token", token},
		RunAtLoad:        true,
		KeepAlive:        true,
	})
}

// TestServerPlistCarriesNoToken is the gate for B249: the control plane's
// static admin token must not be on the server LaunchDaemon's argv.
//
// The token authenticates as system:masters. Rendered as a value, it was
// readable three ways at once by every account on the Mac — in the root-owned
// 0644 plist, in `ps` for the life of the daemon, and in launchd's own job
// description — so a local unprivileged process could read cluster-admin off
// disk. The daemon is now told WHERE its token is: `--token-file` names a copy
// staged by the installer at <data-root>/server/token, 0600 and owned by the
// service user, which is the same shape the agent role already used for its
// join token.
func TestServerPlistCarriesNoToken(t *testing.T) {
	cfg := Config{BinarySource: "/tmp/k3sm", TargetUser: "alice", AdminToken: theAdminToken}
	dc := cfg.withDefaults()

	t.Run("the render names the staged path and carries no token value", func(t *testing.T) {
		plist := ServerPlist(cfg)
		if strings.Contains(string(plist), theAdminToken) {
			t.Errorf("the rendered server plist carries the admin token value:\n%s", plist)
		}
		argv, err := parseProgramArguments(plist)
		if err != nil {
			t.Fatalf("parseProgramArguments: %v", err)
		}
		if got, want := flagValue(argv, "token-file"), dc.serverTokenPath(); got != want {
			t.Errorf("--token-file = %q, want the staged path %q", got, want)
		}
		if got := flagValue(argv, "token"); got != "" {
			t.Errorf("--token is still rendered (= %q); the value must never reach the argv", got)
		}
	})

	t.Run("install writes the server plist 0600 and the others 0644", func(t *testing.T) {
		f := &fakeSystem{}
		if err := Install(context.Background(), f, cfg); err != nil {
			t.Fatalf("Install: %v", err)
		}
		// root:wheel is the darwin implementation's (os.Chown(path, 0, 0)), which
		// a test without privilege cannot exercise; its mode and its repair of an
		// existing wider mode are pinned against a real filesystem by
		// TestWriteLaunchDaemonMode in install_darwin_test.go.
		if got, want := f.plistModes[dc.plistPath(ServerLabel)], ServerPlistMode; got != want {
			t.Errorf("server plist written %#o, want %#o (its argv carries the operator's own credentials, e.g. a datastore DSN)", got, want)
		}
		if got, want := f.plistModes[dc.plistPath(NetdLabel)], PlistMode; got != want {
			t.Errorf("netd plist written %#o, want the conventional %#o", got, want)
		}
	})

	t.Run("install stages the token 0600, owned by the service uid", func(t *testing.T) {
		f := &fakeSystem{}
		if err := Install(context.Background(), f, cfg); err != nil {
			t.Fatalf("Install: %v", err)
		}
		want := "WriteServiceUserFile:" + dc.serverTokenPath() + ":0600:0700:271"
		if !containsCall(f.calls, want) {
			t.Errorf("install did not stage the admin token as %q (calls: %v)", want, f.calls)
		}
		if got := strings.TrimSpace(string(f.files[dc.serverTokenPath()])); got != theAdminToken {
			t.Errorf("staged token = %q, want the admin token this install carried", got)
		}
		// The staging precedes the plist that names it: a daemon pointed at a
		// file nobody has written yet comes up with no credential at all.
		if idx(f.calls, want) >= idx(f.calls, "WriteLaunchDaemon:"+dc.plistPath(ServerLabel)) {
			t.Error("the token must be staged before the plist that names it is written")
		}
	})

	t.Run("a reinstall replaces an argv-token plist and its mode", func(t *testing.T) {
		f := &fakeSystem{}
		plistPath := dc.plistPath(ServerLabel)
		// The Mac as an earlier build left it: the token on the argv, 0644.
		f.putFile(plistPath, legacyServerPlist(cfg, "k3sm-the-old-admin-token"))
		f.plistModes = map[string]fs.FileMode{plistPath: PlistMode}

		if err := Install(context.Background(), f, cfg); err != nil {
			t.Fatalf("reinstall: %v", err)
		}
		got := string(f.files[plistPath])
		if strings.Contains(got, "k3sm-the-old-admin-token") {
			t.Errorf("the reinstalled plist still carries the superseded token value:\n%s", got)
		}
		if strings.Contains(got, theAdminToken) {
			t.Errorf("the reinstalled plist carries the admin token value:\n%s", got)
		}
		argv, err := parseProgramArguments([]byte(got))
		if err != nil {
			t.Fatalf("parseProgramArguments: %v", err)
		}
		if v := flagValue(argv, "token-file"); v != dc.serverTokenPath() {
			t.Errorf("reinstalled --token-file = %q, want %q", v, dc.serverTokenPath())
		}
		// The old --token is not carried over either: it is install-managed, so
		// the filter drops it rather than preserving it as an operator argument.
		if v := flagValue(argv, "token"); v != "" {
			t.Errorf("the reinstalled plist carries --token %q, carried over from the legacy argv", v)
		}
		if got, want := f.plistModes[plistPath], ServerPlistMode; got != want {
			t.Errorf("reinstalled plist mode = %#o, want %#o: a tightening install must not inherit the old wider mode", got, want)
		}
	})
}

// containsCall reports whether the recorded call log holds want exactly.
func containsCall(calls []string, want string) bool {
	for _, c := range calls {
		if c == want {
			return true
		}
	}
	return false
}

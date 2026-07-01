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
	"encoding/xml"
	"io"
	"strings"
	"testing"
)

// fakeSystem records every privileged seam call in order so a test can assert
// the install orchestration without any real privilege.
type fakeSystem struct {
	calls       []string
	kubeUser    string
	kubeContent string
	failBootout bool
}

func (f *fakeSystem) EnsureServiceUser(name string) (uint32, error) {
	f.calls = append(f.calls, "EnsureServiceUser:"+name)
	return 271, nil
}

func (f *fakeSystem) CopyToRootOwned(src, dstDir string) (string, error) {
	f.calls = append(f.calls, "CopyToRootOwned:"+dstDir)
	return dstDir + "/k3sm", nil
}

func (f *fakeSystem) WriteLaunchDaemon(plistPath string, _ []byte) error {
	f.calls = append(f.calls, "WriteLaunchDaemon:"+plistPath)
	return nil
}

func (f *fakeSystem) LaunchctlBootstrap(label string) error {
	f.calls = append(f.calls, "Bootstrap:"+label)
	return nil
}

func (f *fakeSystem) LaunchctlBootout(label string) error {
	f.calls = append(f.calls, "Bootout:"+label)
	return nil
}

func (f *fakeSystem) LaunchctlKickstart(label string) error {
	f.calls = append(f.calls, "Kickstart:"+label)
	return nil
}

func (f *fakeSystem) WriteUserKubeconfig(targetUser string, contents []byte) error {
	f.calls = append(f.calls, "WriteUserKubeconfig:"+targetUser)
	f.kubeUser = targetUser
	f.kubeContent = string(contents)
	return nil
}

func (f *fakeSystem) RemoveAll(path string) error {
	f.calls = append(f.calls, "RemoveAll:"+path)
	return nil
}

// TestInstallOrchestration proves the install drives the seam in the right
// ORDER: ensure _k3sm → copy binary root-owned → write both plists → bootstrap
// netd BEFORE server → write the admin kubeconfig to the HUMAN (not root).
func TestInstallOrchestration(t *testing.T) {
	f := &fakeSystem{}
	cfg := Config{BinarySource: "/tmp/k3sm", TargetUser: "alice"}
	if err := Install(context.Background(), f, cfg); err != nil {
		t.Fatalf("Install: %v", err)
	}

	want := []string{
		"EnsureServiceUser:_k3sm",
		"CopyToRootOwned:/Library/k3sm",
		"WriteLaunchDaemon:/Library/LaunchDaemons/io.k3sm.netd.plist",
		"WriteLaunchDaemon:/Library/LaunchDaemons/io.k3sm.server.plist",
		"Bootstrap:io.k3sm.netd",
		"Bootstrap:io.k3sm.server",
		"WriteUserKubeconfig:alice",
	}
	if len(f.calls) != len(want) {
		t.Fatalf("call sequence = %v, want %v", f.calls, want)
	}
	for i := range want {
		if f.calls[i] != want[i] {
			t.Errorf("call %d = %q, want %q", i, f.calls[i], want[i])
		}
	}

	// netd must be bootstrapped BEFORE the server (the server depends on the helper).
	if idx(f.calls, "Bootstrap:io.k3sm.netd") >= idx(f.calls, "Bootstrap:io.k3sm.server") {
		t.Error("netd must be bootstrapped before the server")
	}
	// The kubeconfig is owned by the human, never root.
	if f.kubeUser != "alice" || f.kubeUser == "root" {
		t.Errorf("kubeconfig owner = %q, want the human (alice), never root", f.kubeUser)
	}
	if !strings.Contains(f.kubeContent, "token:") {
		t.Error("admin kubeconfig must carry the shared bearer token")
	}
}

// TestInstallRequiresInputs proves the install fails fast without the binary
// source or the target user (no silent partial install).
func TestInstallRequiresInputs(t *testing.T) {
	if err := Install(context.Background(), &fakeSystem{}, Config{TargetUser: "alice"}); err == nil {
		t.Error("Install must require BinarySource")
	}
	if err := Install(context.Background(), &fakeSystem{}, Config{BinarySource: "/tmp/k3sm"}); err == nil {
		t.Error("Install must require TargetUser (the kubeconfig owner)")
	}
}

// TestUninstallIdempotent proves uninstall boots out BOTH daemons (server first,
// then netd) and removes the install dir, and that re-running is safe.
func TestUninstallIdempotent(t *testing.T) {
	f := &fakeSystem{}
	if err := Uninstall(context.Background(), f, Config{}); err != nil {
		t.Fatalf("Uninstall: %v", err)
	}
	want := []string{"Bootout:io.k3sm.server", "Bootout:io.k3sm.netd", "RemoveAll:/Library/k3sm"}
	if strings.Join(f.calls, ",") != strings.Join(want, ",") {
		t.Fatalf("uninstall calls = %v, want %v", f.calls, want)
	}
	// Second run is safe (bootout of a not-loaded label is a no-op in the real impl).
	if err := Uninstall(context.Background(), &fakeSystem{}, Config{}); err != nil {
		t.Errorf("second Uninstall must be idempotent, got %v", err)
	}
}

// TestNetdPlistXML proves the netd plist is root (NO UserName), execs `k3sm
// netd` with the Service CIDR, and is boot-surviving (RunAtLoad + KeepAlive).
func TestNetdPlistXML(t *testing.T) {
	x := string(NetdPlist(Config{}))
	mustContain(t, x, "<key>Label</key>\n  <string>io.k3sm.netd</string>")
	mustContain(t, x, "<string>netd</string>")
	mustContain(t, x, "<string>--service-cidr</string>")
	mustContain(t, x, "<key>RunAtLoad</key>\n  <true/>")
	mustContain(t, x, "<key>KeepAlive</key>\n  <true/>")
	if strings.Contains(x, "<key>UserName</key>") {
		t.Error("netd plist must NOT carry a UserName (it runs as root)")
	}
}

// TestServerPlistXML proves the server plist runs as the _k3sm user (UserName
// present), execs `k3sm server --runtime runtimed`, and is boot-surviving.
func TestServerPlistXML(t *testing.T) {
	x := string(ServerPlist(Config{}))
	mustContain(t, x, "<key>Label</key>\n  <string>io.k3sm.server</string>")
	mustContain(t, x, "<key>UserName</key>\n  <string>_k3sm</string>")
	mustContain(t, x, "<string>server</string>")
	mustContain(t, x, "<string>runtimed</string>")
	mustContain(t, x, "<key>RunAtLoad</key>\n  <true/>")
	mustContain(t, x, "<key>KeepAlive</key>\n  <true/>")
}

// TestServerPlistRaisesFileLimit proves the server plist raises RLIMIT_NOFILE so
// darwin-net's UDP flow budget (B48, rl.Cur/2) sizes against a real fd table, not
// launchd's 256 default. The load-bearing assertion is well-formedness: a
// hand-rolled unbalanced/mis-nested <dict> would still pass the substring checks
// yet make launchd REJECT the plist at bootstrap (a non-loading control plane),
// so the generated XML is decoded to EOF. The raise is server-ONLY (netd is not
// the UDP-relay host), which the NetdPlist negative assertion pins.
func TestServerPlistRaisesFileLimit(t *testing.T) {
	x := ServerPlist(Config{})

	// (1) Well-formedness (load-bearing): the whole plist must PARSE as XML. A
	// mis-nested <dict> from the hand-rolled builder would fail here even though
	// the substring checks in (2) would still pass on a corrupt plist.
	dec := xml.NewDecoder(bytes.NewReader(x))
	for {
		_, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("ServerPlist is not well-formed XML: %v\n--- plist ---\n%s", err, x)
		}
	}

	// (2) Soft + Hard NumberOfFiles = 131072, correctly nested as <integer>.
	s := string(x)
	for _, needle := range []string{
		"<key>SoftResourceLimits</key>",
		"<key>HardResourceLimits</key>",
		"<key>NumberOfFiles</key>",
		"<integer>131072</integer>",
	} {
		mustContain(t, s, needle)
	}

	// (3) Server-ONLY: netd is not the UDP-relay host, so its plist carries no
	// resource limits. This also proves SoftFileLimit is conditional (not emitted
	// for every plist) — the field is honored, not hard-wired into renderPlist.
	if n := string(NetdPlist(Config{})); strings.Contains(n, "SoftResourceLimits") {
		t.Error("NetdPlist must NOT raise file limits (the raise is server-only)")
	}
}

// TestPlistEscaping proves string values are XML-escaped (a token with an &
// cannot corrupt the plist).
func TestPlistEscaping(t *testing.T) {
	x := string(ServerPlist(Config{AdminToken: "a&b<c", BinarySource: "/tmp/k3sm", TargetUser: "alice"}))
	if strings.Contains(x, "a&b<c") {
		t.Error("plist string values must be XML-escaped")
	}
	mustContain(t, x, "a&amp;b&lt;c")
}

func idx(calls []string, want string) int {
	for i, c := range calls {
		if c == want {
			return i
		}
	}
	return -1
}

func mustContain(t *testing.T, haystack, needle string) {
	t.Helper()
	if !strings.Contains(haystack, needle) {
		t.Errorf("plist missing %q\n--- plist ---\n%s", needle, haystack)
	}
}

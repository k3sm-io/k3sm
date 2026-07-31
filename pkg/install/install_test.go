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
	"net/netip"
	"path/filepath"
	"strings"
	"testing"

	"k3sm.io/k3sm/pkg/executor"
)

// fakeSystem records every privileged seam call in order so a test can assert
// the install orchestration without any real privilege.
type fakeSystem struct {
	calls       []string
	kubeUser    string
	kubeContent string
	failBootout bool
	// pid is the launchd-reported pid of the labelled job; a kickstart advances it.
	pid int
}

func (f *fakeSystem) EnsureServiceUser(name string) (uint32, error) {
	f.calls = append(f.calls, "EnsureServiceUser:"+name)
	return 271, nil
}

func (f *fakeSystem) EnsureLogDir(dir string, uid uint32) error {
	f.calls = append(f.calls, "EnsureLogDir:"+dir)
	return nil
}

func (f *fakeSystem) ReapOrphans(binPrefix string) error {
	f.calls = append(f.calls, "ReapOrphans:"+binPrefix)
	return nil
}

func (f *fakeSystem) CopyToRootOwned(src, dst string) error {
	// Record the EXACT dst the installer requested — the contract under test: the
	// destination must be the fixed installedBinary() path, never src's basename
	// (the live M2-gate failure: a `k3sm-m2` artifact landed at
	// /Library/k3sm/k3sm-m2 while the plists exec'd /Library/k3sm/k3sm, and
	// launchd invalidated both daemons with "Missing executable").
	f.calls = append(f.calls, "CopyToRootOwned:"+dst)
	return nil
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
	// A kickstart replaces the running instance, so the fake's reported pid moves —
	// the discriminator `k3sm certificate rotate` uses to tell the NEW control plane
	// from the old one still draining its listeners.
	f.pid++
	return nil
}

func (f *fakeSystem) LaunchctlServicePID(label string) (int, error) {
	f.calls = append(f.calls, "ServicePID:"+label)
	return f.pid, nil
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

func (f *fakeSystem) FlushLo0Aliases(prefixes []netip.Prefix) error {
	strs := make([]string, len(prefixes))
	for i, p := range prefixes {
		strs[i] = p.String()
	}
	f.calls = append(f.calls, "FlushLo0Aliases:"+strings.Join(strs, ","))
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
		"EnsureLogDir:/var/log/k3sm",
		"CopyToRootOwned:/Library/k3sm/k3sm",
		"CopyToRootOwned:/Library/k3sm/k3sm-execshim",
		"CopyToRootOwned:/Library/k3sm/libk3sm_pathrebase_shim.dylib",
		"CopyToRootOwned:/Library/k3sm/libk3sm_getaddrinfo_shim.dylib",
		"CopyToRootOwned:/Library/k3sm/bin/kube-apiserver",
		"CopyToRootOwned:/Library/k3sm/bin/kube-scheduler",
		"CopyToRootOwned:/Library/k3sm/bin/kube-controller-manager",
		"CopyToRootOwned:/Library/k3sm/bin/kubectl",
		"CopyToRootOwned:/Library/k3sm/bin/kine",
		"WriteLaunchDaemon:/Library/LaunchDaemons/io.k3sm.netd.plist",
		"WriteLaunchDaemon:/Library/LaunchDaemons/io.k3sm.server.plist",
		"Bootout:io.k3sm.netd",
		"Bootstrap:io.k3sm.netd",
		"Bootout:io.k3sm.server",
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
	// Each daemon is BOOTED OUT before it is (re)bootstrapped, so a reinstall/upgrade
	// always restarts the FRESH on-disk binary instead of leaving a stale daemon
	// (launchctl bootstrap does not re-exec an updated binary on an already-loaded job).
	for _, label := range []string{"io.k3sm.netd", "io.k3sm.server"} {
		if idx(f.calls, "Bootout:"+label) >= idx(f.calls, "Bootstrap:"+label) {
			t.Errorf("%s must be booted out before it is bootstrapped (fresh-binary restart)", label)
		}
	}
	// The kubeconfig is owned by the human, never root.
	if f.kubeUser != "alice" || f.kubeUser == "root" {
		t.Errorf("kubeconfig owner = %q, want the human (alice), never root", f.kubeUser)
	}
	if !strings.Contains(f.kubeContent, "token:") {
		t.Error("admin kubeconfig must carry the shared bearer token")
	}
}

// TestInstallBinaryLandsAtFixedPath is the regression for the live M2-gate
// failure: the gate builds the binary as `k3sm-m2`, and the old CopyToRootOwned
// derived the destination from the SOURCE basename — landing /Library/k3sm/k3sm-m2
// while both plists exec /Library/k3sm/k3sm, so launchd invalidated both daemons
// with the unrecoverable "Missing executable". The installer must request the
// EXACT installedBinary() destination regardless of the artifact's name.
func TestInstallBinaryLandsAtFixedPath(t *testing.T) {
	f := &fakeSystem{}
	cfg := Config{BinarySource: "/tmp/build/k3sm-m2", TargetUser: "alice"}
	if err := Install(context.Background(), f, cfg); err != nil {
		t.Fatalf("Install: %v", err)
	}
	var dsts []string
	for _, c := range f.calls {
		if strings.HasPrefix(c, "CopyToRootOwned:") {
			dsts = append(dsts, strings.TrimPrefix(c, "CopyToRootOwned:"))
		}
	}
	fixedHead := []string{"/Library/k3sm/k3sm", "/Library/k3sm/k3sm-execshim", "/Library/k3sm/" + PathShimName, "/Library/k3sm/" + DNSShimName}
	if len(dsts) < len(fixedHead) {
		t.Fatalf("only %d copies %v, want at least the fixed head %v (never the source basename)", len(dsts), dsts, fixedHead)
	}
	for i, want := range fixedHead {
		if dsts[i] != want {
			t.Errorf("copy %d landed at %q, want the fixed head %q (never the source basename)", i, dsts[i], want)
		}
	}
	// The payload set lands at InstallDir/bin/<name> — one copy per
	// executor.PayloadBinaries entry, in order, after the binary + exec-shim + shims.
	head := len(fixedHead)
	if want := head + len(executor.PayloadBinaries()); len(dsts) != want {
		t.Errorf("%d copies, want %d (binary + exec-shim + path-shim + dns-shim + the payload set)", len(dsts), want)
	}
	for i, name := range executor.PayloadBinaries() {
		if got, want := dsts[head+i], "/Library/k3sm/bin/"+name; got != want {
			t.Errorf("payload copy %d landed at %q, want %q", i, got, want)
		}
	}
	// The shim/payload sources default to SIBLINGS of BinarySource — the
	// gate/goreleaser stage all artifacts side by side.
	if got := cfg.withDefaults().ExecShimSource; got != "/tmp/build/k3sm-execshim" {
		t.Errorf("ExecShimSource default = %q, want the BinarySource sibling /tmp/build/k3sm-execshim", got)
	}
	if got := cfg.withDefaults().PayloadSource; got != "/tmp/build/cp-payload" {
		t.Errorf("PayloadSource default = %q, want the BinarySource sibling dir /tmp/build/cp-payload", got)
	}
	if got := cfg.withDefaults().PathShimSource; got != "/tmp/build/"+PathShimName {
		t.Errorf("PathShimSource default = %q, want the BinarySource sibling /tmp/build/%s", got, PathShimName)
	}
	if got := cfg.withDefaults().DNSShimSource; got != "/tmp/build/"+DNSShimName {
		t.Errorf("DNSShimSource default = %q, want the BinarySource sibling /tmp/build/%s", got, DNSShimName)
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
// then netd), REMOVES both leaked plists (the B62 fix), and sweeps the install
// dir — in reverse install order — and that re-running is safe.
func TestUninstallIdempotent(t *testing.T) {
	f := &fakeSystem{}
	if err := Uninstall(context.Background(), f, Config{}); err != nil {
		t.Fatalf("Uninstall: %v", err)
	}
	want := []string{
		"Bootout:io.k3sm.server",
		"RemoveAll:/Library/LaunchDaemons/io.k3sm.server.plist",
		"Bootout:io.k3sm.netd",
		"RemoveAll:/Library/LaunchDaemons/io.k3sm.netd.plist",
		"RemoveAll:/Library/k3sm",
		"ReapOrphans:/var/lib/k3sm/server/bin",
		// The lo0 flush covers the pinned pod aggregate + the Service CIDR — the
		// pod /32s, the API/DNS VIPs, and the node mesh-egress .1 (which the pod
		// stale-sweep deliberately never touches) all fall inside these two.
		"FlushLo0Aliases:100.64.0.0/10,10.43.0.0/16",
	}
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
	// B116/B133 — the plist must render NO --node-ip. netdsvc's node-address
	// authorizer branch (a <1024 bind on the node's OWN InternalIP, authorized by
	// a declaring LoadBalancer Service) is DORMANT BY CONFIGURATION, not by
	// construction: the code is still there, and passing --node-ip would re-arm
	// it. Since B116 the ingress/svclb listeners bind the wildcard in-process and
	// never ask netd for a node-address bind, so re-adding the flag would widen
	// the root helper's authorized surface with no consumer. Adding it must
	// redden HERE; B133 owns the decision to wire it back or retire the branch.
	if strings.Contains(x, "--node-ip") {
		t.Error("netd plist must NOT render --node-ip: the node-address authorizer branch is dormant by configuration (B116/B133); re-arming it needs a deliberate decision, not a plist edit")
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
	// ExitTimeOut > launchd's 20s default so Stop()'s serial control-plane
	// teardown finishes before SIGKILL (else the stragglers orphan).
	mustContain(t, x, "<key>ExitTimeOut</key>\n  <integer>45</integer>")
	if strings.Contains(string(NetdPlist(Config{})), "ExitTimeOut") {
		t.Error("netd plist should NOT set ExitTimeOut (it has no child processes to reap)")
	}
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

// recorded returns the arguments of every fake seam call whose "Op:arg" string
// carries prefix (e.g. "RemoveAll:").
func recorded(calls []string, prefix string) []string {
	var out []string
	for _, c := range calls {
		if rest, ok := strings.CutPrefix(c, prefix); ok {
			out = append(out, rest)
		}
	}
	return out
}

func toSet(xs []string) map[string]bool {
	s := make(map[string]bool, len(xs))
	for _, x := range xs {
		s[x] = true
	}
	return s
}

func daemonByPath(m []artifact, path string) (artifact, bool) {
	for _, a := range m {
		if a.kind == kindDaemon && a.path == path {
			return a, true
		}
	}
	return artifact{}, false
}

func fileDispByPath(m []artifact, path string) (disposition, bool) {
	for _, a := range m {
		if (a.kind == kindFile || a.kind == kindDir) && a.path == path {
			return a.disp, true
		}
	}
	return 0, false
}

// uninstallGaps returns, for a REAL Install run (installCalls) and a REAL
// Uninstall run (uninstallCalls) recorded by the fake, the install-created
// artifacts the uninstall FAILS to tear down — classified through the manifest.
// An install artifact absent from the manifest is itself a gap: an off-manifest
// lay-down line is the exact future regression the gate must catch, which a
// manifest-vs-manifest tautology never would.
func uninstallGaps(cfg Config, installCalls, uninstallCalls []string) []string {
	cfg = cfg.withDefaults()
	m := artifactManifest(cfg)
	removed := toSet(recorded(uninstallCalls, "RemoveAll:"))
	bootedOut := toSet(recorded(uninstallCalls, "Bootout:"))
	installDirSwept := removed[cfg.InstallDir]

	var gaps []string

	// Files copied in by CopyToRootOwned (the recorded value IS the installed path).
	for _, path := range recorded(installCalls, "CopyToRootOwned:") {
		disp, known := fileDispByPath(m, path)
		if !known {
			gaps = append(gaps, "off-manifest install: "+path)
			continue
		}
		switch disp {
		case dispInstallDirCovered:
			if !installDirSwept && !removed[path] {
				gaps = append(gaps, "installDir artifact not swept: "+path)
			}
		case dispRemove:
			if !removed[path] {
				gaps = append(gaps, "artifact not removed: "+path)
			}
		}
	}

	// Daemons written by WriteLaunchDaemon (each: Bootout(label) + RemoveAll(plist)).
	for _, plist := range recorded(installCalls, "WriteLaunchDaemon:") {
		a, known := daemonByPath(m, plist)
		if !known {
			gaps = append(gaps, "off-manifest plist: "+plist)
			continue
		}
		if a.disp != dispRemove {
			continue
		}
		if !bootedOut[a.label] {
			gaps = append(gaps, "daemon not booted out: "+a.label)
		}
		if !removed[a.path] {
			gaps = append(gaps, "plist leaked: "+a.path)
		}
	}
	return gaps
}

// TestUninstallManifestCoversInstall is the B62 gate. It asserts over the seam
// calls RECORDED from a REAL Install run + a REAL Uninstall run against the fake
// (never the manifest against itself — that tautology would never catch a future
// off-manifest install line, the exact bug): forward coverage, bidirectional
// no-over-broad-removal, the preserve set untouched, and idempotency.
func TestUninstallManifestCoversInstall(t *testing.T) {
	cfg := Config{BinarySource: "/tmp/k3sm", TargetUser: "alice"}
	dc := cfg.withDefaults()

	inst := &fakeSystem{}
	if err := Install(context.Background(), inst, cfg); err != nil {
		t.Fatalf("Install: %v", err)
	}
	uninst := &fakeSystem{}
	if err := Uninstall(context.Background(), uninst, cfg); err != nil {
		t.Fatalf("Uninstall: %v", err)
	}
	installCalls := inst.calls
	uninstallCalls := uninst.calls
	removed := toSet(recorded(uninstallCalls, "RemoveAll:"))
	bootedOut := toSet(recorded(uninstallCalls, "Bootout:"))

	t.Run("coverage: uninstall tears down everything install laid down", func(t *testing.T) {
		if gaps := uninstallGaps(cfg, installCalls, uninstallCalls); len(gaps) != 0 {
			t.Errorf("uninstall leaves install artifacts behind: %v", gaps)
		}
	})

	t.Run("both leaked plists are now removed (the B62 fix)", func(t *testing.T) {
		for _, label := range []string{ServerLabel, NetdLabel} {
			plist := dc.plistPath(label)
			if !bootedOut[label] {
				t.Errorf("daemon %s not booted out", label)
			}
			if !removed[plist] {
				t.Errorf("plist LEAKED (not removed on uninstall): %s", plist)
			}
		}
	})

	t.Run("RED: an off-manifest install line is caught", func(t *testing.T) {
		// Simulate a future regression: an install laying a binary into a path the
		// manifest does not know. The gate MUST flag it — proving non-vacuity (a
		// manifest-vs-manifest check would silently pass).
		rogue := append(append([]string{}, installCalls...), "CopyToRootOwned:/Library/rogue")
		gaps := uninstallGaps(cfg, rogue, uninstallCalls)
		if len(gaps) == 0 {
			t.Fatal("expected an off-manifest install to be flagged, got none")
		}
		found := false
		for _, g := range gaps {
			if strings.Contains(g, "/Library/rogue") {
				found = true
			}
		}
		if !found {
			t.Errorf("gaps %v do not name the rogue artifact", gaps)
		}
	})

	t.Run("bidirectional: uninstall removes only install-created paths", func(t *testing.T) {
		// Every path uninstall RemoveAll's must be one install created: a written
		// plist, or the InstallDir tree (the CopyToRootOwned dst). Catches a
		// RemoveAll reaching into /Library or a home dir for a path k3sm never made.
		created := toSet(recorded(installCalls, "WriteLaunchDaemon:"))
		for _, path := range recorded(installCalls, "CopyToRootOwned:") {
			created[filepath.Dir(path)] = true // the InstallDir tree (the sweep root)
		}
		for _, p := range recorded(uninstallCalls, "RemoveAll:") {
			if !created[p] {
				t.Errorf("uninstall removed %q, which install never created (over-broad removal)", p)
			}
		}
		bootstrapped := toSet(recorded(installCalls, "Bootstrap:"))
		for _, l := range recorded(uninstallCalls, "Bootout:") {
			if !bootstrapped[l] {
				t.Errorf("uninstall booted out %q, which install never bootstrapped", l)
			}
		}
	})

	t.Run("preserve set untouched: DataRoot, LogDir, kubeconfig, _k3sm home", func(t *testing.T) {
		// Table-driven over the manifest's dispPreserve entries: none may be removed.
		for _, a := range artifactManifest(dc) {
			if a.disp != dispPreserve || a.path == "" {
				continue
			}
			if removed[a.path] {
				t.Errorf("uninstall removed PRESERVED artifact %q", a.path)
			}
		}
		// The admin kubeconfig (preserve; its ~/.kube/config path is resolved in the
		// darwin impl) — no removal may touch a kube path.
		for _, p := range recorded(uninstallCalls, "RemoveAll:") {
			if strings.Contains(p, "/.kube/") {
				t.Errorf("uninstall removed a kubeconfig path %q (may hold other clusters)", p)
			}
		}
		// The _k3sm user's home IS DataRoot; asserting DataRoot survives keeps the
		// service user's state intact (there is no user-removal seam to invoke).
		if removed[dc.DataRoot] {
			t.Error("the _k3sm user's home (DataRoot) must be preserved")
		}
	})

	t.Run("idempotency: a second uninstall over removed state returns nil", func(t *testing.T) {
		second := &fakeSystem{}
		if err := Uninstall(context.Background(), second, cfg); err != nil {
			t.Errorf("second Uninstall must be a no-op success (partial-install recovery), got %v", err)
		}
	})

	t.Run("forward-declared cp-payload items are InstallDir-covered, existence not asserted", func(t *testing.T) {
		for _, a := range artifactManifest(dc) {
			if a.assertExists || a.disp != dispInstallDirCovered {
				continue
			}
			if !strings.HasPrefix(a.path, dc.InstallDir+"/") {
				t.Errorf("forward-declared artifact %q must live under InstallDir %q", a.path, dc.InstallDir)
			}
		}
	})
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

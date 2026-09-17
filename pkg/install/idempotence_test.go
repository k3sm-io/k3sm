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
	"encoding/base64"
	"net"
	"slices"
	"strings"
	"testing"
	"time"

	"k3sm.io/k3sm/pkg/certs"
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

// TestReinstallRelinksIdempotently proves a SECOND install over the first asks
// for the same launcher link and succeeds. The installer asks unconditionally —
// it does not read the link and decide — because an upgrade that changed the
// install prefix must re-point the launcher, and "already correct" is the real
// implementation's no-op, not a case the orchestration has to know about.
func TestReinstallRelinksIdempotently(t *testing.T) {
	f := &fakeSystem{}
	cfg := Config{BinarySource: "/tmp/k3sm", TargetUser: "alice"}
	for i := 1; i <= 2; i++ {
		if err := Install(context.Background(), f, cfg); err != nil {
			t.Fatalf("Install %d: %v", i, err)
		}
	}
	want := "EnsureSymlink:/Library/k3sm/k3sm->/usr/local/bin/k3sm"
	n := 0
	for _, c := range f.calls {
		if c == want {
			n++
		}
	}
	if n != 2 {
		t.Errorf("recorded %d %q calls across two installs, want 2 (the same link, asked for again)", n, want)
	}
	if got := f.links["/usr/local/bin/k3sm"]; got != "/Library/k3sm/k3sm" {
		t.Errorf("link target after reinstall = %q, want %q", got, "/Library/k3sm/k3sm")
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
	// The token is read out of the STAGED FILE, not off the argv: the plist
	// carries only the path to it. The two must agree, which is the render half
	// of the same property TestServerPlistCarriesNoToken gates.
	tokenPath := cfg.withDefaults().serverTokenPath()
	if got := flagValue(first, "token-file"); got != tokenPath {
		t.Fatalf("the rendered plist must carry --token-file %s, got %q", tokenPath, got)
	}
	firstToken := strings.TrimSpace(string(f.files[tokenPath]))
	if firstToken == "" {
		t.Fatal("install must stage the admin token at the path the plist names")
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
	// The admin token is install-managed: re-minted, never carried over, and in
	// lockstep with the kubeconfig the same run writes. It is re-minted in the
	// STAGED FILE now; the argv only ever names the path, which does not change.
	newToken := strings.TrimSpace(string(f.files[tokenPath]))
	if newToken == "" || newToken == firstToken {
		t.Errorf("the staged admin token must be re-minted on reinstall (was %q, now %q)", firstToken, newToken)
	}
	if got := flagValue(second, "token-file"); got != tokenPath {
		t.Errorf("reinstalled plist --token-file = %q, want %s (rendered exactly once)", got, tokenPath)
	}
	if flagValue(second, "token") != "" {
		t.Error("the reinstalled plist carries a --token value: the admin token must never be on the argv")
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
		cfg := Config{AdminToken: "k3sm-tok", ExtraServerArgs: args}
		got, err := parseProgramArguments(ServerPlist(cfg))
		if err != nil {
			t.Fatalf("parseProgramArguments: %v", err)
		}
		want := []string{"/Library/k3sm/k3sm", "server", "--runtime", "runtimed", "--token-file", cfg.withDefaults().serverTokenPath()}
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

// TestAdminKubeconfigServerURL is defect 3's table: where the admin kubeconfig
// points, and what it trusts, under each server posture.
func TestAdminKubeconfigServerURL(t *testing.T) {
	ca := []byte("-----BEGIN CERTIFICATE-----\nclusterca\n-----END CERTIFICATE-----\n")
	for _, tc := range []struct {
		name       string
		extraArgs  []string
		clusterCA  []byte
		wantServer string
		wantTLS    string
		absentTLS  string
	}{
		{
			name:       "single-node: loopback, self-signed serving cert, skip verify",
			wantServer: `server: "https://127.0.0.1:6444"`,
			wantTLS:    "insecure-skip-tls-verify: true",
			absentTLS:  "certificate-authority-data",
		},
		{
			name:       "mesh with the cluster CA on disk: mesh URL, verified",
			extraArgs:  []string{"--mesh-ip", "100.64.0.1", "--registry-port", "6450"},
			clusterCA:  ca,
			wantServer: `server: "https://100.64.0.1:6444"`,
			wantTLS:    "certificate-authority-data: " + base64.StdEncoding.EncodeToString(ca),
			absentTLS:  "insecure-skip-tls-verify",
		},
		{
			name:       "mesh before the CA exists: mesh URL, skip verify (first install)",
			extraArgs:  []string{"--mesh-ip", "100.64.0.1"},
			wantServer: `server: "https://100.64.0.1:6444"`,
			wantTLS:    "insecure-skip-tls-verify: true",
			absentTLS:  "certificate-authority-data",
		},
		{
			name:       "inline --mesh-ip= spelling is read the same way",
			extraArgs:  []string{"--mesh-ip=100.64.0.2"},
			wantServer: `server: "https://100.64.0.2:6444"`,
			wantTLS:    "insecure-skip-tls-verify: true",
		},
		{
			name:       "an IPv6 mesh IP is bracketed",
			extraArgs:  []string{"--mesh-ip", "fd00::1"},
			wantServer: `server: "https://[fd00::1]:6444"`,
			wantTLS:    "insecure-skip-tls-verify: true",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out := string(AdminKubeconfig(Config{
				AdminToken:      "k3sm-tok",
				ExtraServerArgs: tc.extraArgs,
				ClusterCA:       tc.clusterCA,
			}))
			if !strings.Contains(out, tc.wantServer) {
				t.Errorf("kubeconfig missing %q\n--- kubeconfig ---\n%s", tc.wantServer, out)
			}
			if !strings.Contains(out, tc.wantTLS) {
				t.Errorf("kubeconfig missing %q\n--- kubeconfig ---\n%s", tc.wantTLS, out)
			}
			if tc.absentTLS != "" && strings.Contains(out, tc.absentTLS) {
				t.Errorf("kubeconfig must not carry %q under this posture\n--- kubeconfig ---\n%s", tc.absentTLS, out)
			}
			if !strings.Contains(out, "token: k3sm-tok") {
				t.Error("kubeconfig must carry the shared bearer token")
			}
		})
	}
}

// TestInstallKubeconfigFollowsThePreservedMeshIP is the end-to-end of defect 3:
// the URL and the trust anchor both come from the state of the install, so a
// reinstall over a mesh node produces a kubeconfig that connects AND verifies —
// without anyone editing it afterwards.
func TestInstallKubeconfigFollowsThePreservedMeshIP(t *testing.T) {
	cfg := Config{BinarySource: "/tmp/k3sm", TargetUser: "alice"}
	dc := cfg.withDefaults()
	caPath := certs.ClusterCACertPath(dc.serverWorkDir())
	ca := []byte("-----BEGIN CERTIFICATE-----\nclusterca\n-----END CERTIFICATE-----\n")

	t.Run("single-node install does not read a CA and stays on loopback", func(t *testing.T) {
		f := &fakeSystem{}
		f.putFile(caPath, ca) // present but irrelevant: the apiserver self-signs on loopback
		if err := Install(context.Background(), f, cfg); err != nil {
			t.Fatalf("Install: %v", err)
		}
		if idx(f.calls, "ReadFile:"+caPath) >= 0 {
			t.Error("a single-node install must not pin a CA that does not anchor the self-signed serving cert")
		}
		if !strings.Contains(f.kubeContent, "https://127.0.0.1:6444") {
			t.Errorf("single-node kubeconfig must address loopback:\n%s", f.kubeContent)
		}
	})

	t.Run("mesh reinstall addresses the mesh IP and pins the cluster CA", func(t *testing.T) {
		f := &fakeSystem{}
		f.putFile(dc.plistPath(ServerLabel), ServerPlist(Config{
			AdminToken:      "k3sm-old",
			ExtraServerArgs: []string{"--mesh-ip", "100.64.0.1"},
		}))
		f.putFile(caPath, ca)
		if err := Install(context.Background(), f, cfg); err != nil {
			t.Fatalf("Install: %v", err)
		}
		if !strings.Contains(f.kubeContent, "https://100.64.0.1:6444") {
			t.Errorf("mesh kubeconfig must address the mesh IP:\n%s", f.kubeContent)
		}
		want := "certificate-authority-data: " + base64.StdEncoding.EncodeToString(ca)
		if !strings.Contains(f.kubeContent, want) {
			t.Errorf("mesh kubeconfig must pin the cluster CA:\n%s", f.kubeContent)
		}
		if strings.Contains(f.kubeContent, "insecure-skip-tls-verify") {
			t.Errorf("mesh kubeconfig must verify the apiserver:\n%s", f.kubeContent)
		}
	})

	t.Run("mesh reinstall with no CA yet degrades to skip-verify, never to loopback", func(t *testing.T) {
		f := &fakeSystem{}
		f.putFile(dc.plistPath(ServerLabel), ServerPlist(Config{
			AdminToken:      "k3sm-old",
			ExtraServerArgs: []string{"--mesh-ip", "100.64.0.1"},
		}))
		if err := Install(context.Background(), f, cfg); err != nil {
			t.Fatalf("Install: %v", err)
		}
		if !strings.Contains(f.kubeContent, "https://100.64.0.1:6444") {
			t.Errorf("the URL must follow the mesh IP even without a CA:\n%s", f.kubeContent)
		}
		if !strings.Contains(f.kubeContent, "insecure-skip-tls-verify: true") {
			t.Errorf("an absent CA must degrade to skip-verify, not fail the install:\n%s", f.kubeContent)
		}
	})
}

// selfSignedAPIServerCert mints what kube-apiserver writes into its own --cert-dir
// when nothing hands it a serving keypair: a leaf carrying ipSANs, followed by the
// self-signed CA that issued it. It is a REAL certificate, not a PEM-shaped string,
// because the installer parses it to decide whether pinning it would leave kubectl
// able to connect — a fixture that cannot be parsed would prove nothing about that.
func selfSignedAPIServerCert(t *testing.T, ipSANs ...string) []byte {
	t.Helper()
	ca, err := certs.NewCA("kube-apiserver-self-signed")
	if err != nil {
		t.Fatalf("mint the self-signed CA: %v", err)
	}
	var ips []net.IP
	for _, s := range ipSANs {
		ip := net.ParseIP(s)
		if ip == nil {
			t.Fatalf("bad fixture IP SAN %q", s)
		}
		ips = append(ips, ip)
	}
	leaf, _, err := ca.IssueServing("kube-apiserver", []string{"localhost"}, ips, time.Hour)
	if err != nil {
		t.Fatalf("issue the serving leaf: %v", err)
	}
	return append(leaf, ca.CertPEM...)
}

// TestAdminKubeconfigPinsServingCA is the gate on the loopback endpoint's trust
// anchor: a single-node admin kubeconfig VERIFIES the apiserver instead of trusting
// whatever answers on the port.
//
// The port matters because it is bindable by any unprivileged local user — the
// control plane itself runs as the unprivileged service user — so a kubeconfig that
// skipped verification would hand the admin bearer token to whoever grabbed the port
// during an outage, and believe that impostor's readiness. Which certificate to pin
// is settled by the posture: single-node, nothing supplies --tls-cert-file, so
// kube-apiserver self-signs into its own --cert-dir and that file (leaf + its
// issuing CA) is the only anchor for what the listener presents.
//
// The two fallback rows are as load-bearing as the pin: an install that wrote a
// kubeconfig kubectl cannot connect through is worse than an unverified one, so
// "no certificate yet" and "the certificate does not name the loopback address"
// both keep skip-verify, loudly.
func TestAdminKubeconfigPinsServingCA(t *testing.T) {
	cfg := Config{BinarySource: "/tmp/k3sm", TargetUser: "alice"}
	anchorPath := apiServerSelfSignedCertPath(cfg.withDefaults().serverWorkDir())

	t.Run("a reinstall pins the certificate the loopback listener serves", func(t *testing.T) {
		anchor := selfSignedAPIServerCert(t, "127.0.0.1")
		f := &fakeSystem{}
		f.putFile(anchorPath, anchor)
		var log bytes.Buffer
		c := cfg
		c.Logger = testLogger(&log)
		if err := Install(context.Background(), f, c); err != nil {
			t.Fatalf("Install: %v", err)
		}
		if idx(f.calls, "ReadFile:"+anchorPath) < 0 {
			t.Errorf("the install must read the apiserver's self-signed certificate at %s; calls =\n%v", anchorPath, f.calls)
		}
		want := "certificate-authority-data: " + base64.StdEncoding.EncodeToString(anchor)
		if !strings.Contains(f.kubeContent, want) {
			t.Errorf("the loopback kubeconfig must pin the serving certificate:\n%s", f.kubeContent)
		}
		if strings.Contains(f.kubeContent, "insecure-skip-tls-verify") {
			t.Errorf("a pinned kubeconfig must not also skip verification (whoever holds the port would still be trusted):\n%s", f.kubeContent)
		}
		if !strings.Contains(f.kubeContent, "https://127.0.0.1:6444") {
			t.Errorf("the single-node kubeconfig must still address loopback:\n%s", f.kubeContent)
		}
	})

	t.Run("a first install has nothing to pin and says so", func(t *testing.T) {
		f := &fakeSystem{}
		var log bytes.Buffer
		c := cfg
		c.Logger = testLogger(&log)
		if err := Install(context.Background(), f, c); err != nil {
			t.Fatalf("Install: %v", err)
		}
		if !strings.Contains(f.kubeContent, "insecure-skip-tls-verify: true") {
			t.Errorf("an absent certificate must degrade to skip-verify, not fail the install:\n%s", f.kubeContent)
		}
		if strings.Contains(f.kubeContent, "certificate-authority-data") {
			t.Errorf("nothing on disk anchors this endpoint yet:\n%s", f.kubeContent)
		}
		if out := log.String(); !strings.Contains(out, "has not self-signed") || !strings.Contains(out, anchorPath) {
			t.Errorf("the operator must be told which file is missing and that the next install picks it up; log =\n%s", out)
		}
	})

	t.Run("a certificate that does not name loopback is not pinned", func(t *testing.T) {
		f := &fakeSystem{}
		f.putFile(anchorPath, selfSignedAPIServerCert(t, "10.0.0.7"))
		var log bytes.Buffer
		c := cfg
		c.Logger = testLogger(&log)
		if err := Install(context.Background(), f, c); err != nil {
			t.Fatalf("Install: %v", err)
		}
		if !strings.Contains(f.kubeContent, "insecure-skip-tls-verify: true") {
			t.Errorf("a leaf without the loopback SAN must keep skip-verify — pinning it would make kubectl fail the SAN check:\n%s", f.kubeContent)
		}
		if strings.Contains(f.kubeContent, "certificate-authority-data") {
			t.Errorf("the certificate on disk does not anchor this endpoint:\n%s", f.kubeContent)
		}
		if out := log.String(); !strings.Contains(out, "missing-ip-san=127.0.0.1") {
			t.Errorf("the warning must name the SAN that is missing; log =\n%s", out)
		}
	})

	t.Run("only a later block naming loopback does not make the leaf name it", func(t *testing.T) {
		// The file's FIRST certificate is what the listener presents and what a
		// client checks its address against; a trailing block is an anchor at most.
		// A check that scanned the whole file would pin this one and leave kubectl
		// failing the SAN check against a leaf that names 10.0.0.7 only.
		f := &fakeSystem{}
		f.putFile(anchorPath, slices.Concat(
			selfSignedAPIServerCert(t, "10.0.0.7"),
			selfSignedAPIServerCert(t, "127.0.0.1"),
		))
		var log bytes.Buffer
		c := cfg
		c.Logger = testLogger(&log)
		if err := Install(context.Background(), f, c); err != nil {
			t.Fatalf("Install: %v", err)
		}
		if strings.Contains(f.kubeContent, "certificate-authority-data") {
			t.Errorf("the presented leaf does not name loopback; a later block that does is not the identity kubectl checks:\n%s", f.kubeContent)
		}
		if !strings.Contains(f.kubeContent, "insecure-skip-tls-verify: true") {
			t.Errorf("this must keep skip-verify:\n%s", f.kubeContent)
		}
		if out := log.String(); !strings.Contains(out, "missing-ip-san=127.0.0.1") {
			t.Errorf("the warning must name the SAN that is missing; log =\n%s", out)
		}
	})

	t.Run("a mesh install reads the cluster CA, never the self-signed file", func(t *testing.T) {
		f := &fakeSystem{}
		dc := cfg.withDefaults()
		f.putFile(dc.plistPath(ServerLabel), ServerPlist(Config{
			AdminToken:      "k3sm-old",
			ExtraServerArgs: []string{"--mesh-ip", "100.64.0.1"},
		}))
		ca := []byte("-----BEGIN CERTIFICATE-----\nclusterca\n-----END CERTIFICATE-----\n")
		f.putFile(certs.ClusterCACertPath(dc.serverWorkDir()), ca)
		f.putFile(anchorPath, selfSignedAPIServerCert(t, "127.0.0.1"))
		if err := Install(context.Background(), f, cfg); err != nil {
			t.Fatalf("Install: %v", err)
		}
		if idx(f.calls, "ReadFile:"+anchorPath) >= 0 {
			t.Error("a mesh apiserver never self-signs; that file anchors nothing it presents")
		}
		want := "certificate-authority-data: " + base64.StdEncoding.EncodeToString(ca)
		if !strings.Contains(f.kubeContent, want) {
			t.Errorf("the mesh kubeconfig must still pin the cluster CA:\n%s", f.kubeContent)
		}
	})
}

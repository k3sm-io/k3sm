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

package executor

import (
	"errors"
	"net"
	"net/url"
	"slices"
	"strings"
	"testing"

	"k3sm.io/k3sm/pkg/certs"
)

// etcdTestConfig is a defaulted etcd-posture Config. The mesh BindAddress is set on
// purpose: the peer URLs must ride the node IP, never the mesh address.
func etcdTestConfig(role EtcdRole, peerIP string) Config {
	return Config{
		WorkDir:     "/wd",
		KinePort:    32379,
		NodeIP:      peerIP,
		BindAddress: "198.51.100.10",
		Etcd: &EtcdConfig{
			Role:           role,
			Name:           "studio",
			PeerIP:         peerIP,
			InitialCluster: "laptop=https://192.168.0.11:2380,studio=https://192.0.2.10:2380",
		},
	}.withDefaults()
}

// urlHost returns the host part of raw, failing the test on a malformed URL.
func urlHost(t *testing.T, raw string) (scheme, host string) {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse %q: %v", raw, err)
	}
	return u.Scheme, u.Hostname()
}

// TestEtcdChildArgs is the named gate for the etcd member's argv.
func TestEtcdChildArgs(t *testing.T) {
	ca, err := certs.NewCA("k3sm-cluster-ca")
	if err != nil {
		t.Fatal(err)
	}
	pin := ca.PinHash()
	const peerIP = "192.0.2.10"

	cases := []struct {
		name         string
		role         EtcdRole
		memberExists bool
		reset        bool
		heartbeat    bool
		wantState    string // "" = no initial-cluster flags at all
		wantInitial  string
	}{
		{name: "init first boot forms a cluster of itself", role: EtcdInit, wantState: "new", wantInitial: "studio=https://192.0.2.10:2380"},
		{name: "join first boot starts existing with the route's set", role: EtcdJoin, wantState: "existing",
			wantInitial: "laptop=https://192.168.0.11:2380,studio=https://192.0.2.10:2380"},
		{name: "init restart renders no initial-cluster flag", role: EtcdInit, memberExists: true},
		{name: "join restart renders no initial-cluster flag", role: EtcdJoin, memberExists: true},
		{name: "reset forces a new cluster from the existing member", role: EtcdInit, memberExists: true, reset: true},
		{name: "test-only timings are rendered when set", role: EtcdInit, heartbeat: true, wantState: "new", wantInitial: "studio=https://192.0.2.10:2380"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := etcdTestConfig(tc.role, peerIP)
			cfg.Etcd.Reset = tc.reset
			in := etcdArgsInputFor(cfg, pin, tc.memberExists)
			if tc.heartbeat {
				in.HeartbeatMS, in.ElectionMS = 250, 2500
			}
			args := etcdArgs(in)
			joined := " " + strings.Join(args, " ") + " "
			p := certs.EtcdCertPaths("/wd")

			// Identity and data dir.
			if got := flagValue(args, "--name"); got != "studio" {
				t.Errorf("--name = %q", got)
			}
			if got := flagValue(args, "--data-dir"); got != "/wd/etcd" {
				t.Errorf("--data-dir = %q, want /wd/etcd", got)
			}

			// Both TLS pairs, both trust anchors, both client-cert-auth switches.
			for flag, want := range map[string]string{
				"--cert-file":            p.ServerClientCert,
				"--key-file":             p.ServerClientKey,
				"--trusted-ca-file":      p.ServerCACert,
				"--peer-cert-file":       p.PeerServerClientCert,
				"--peer-key-file":        p.PeerServerClientKey,
				"--peer-trusted-ca-file": p.PeerCACert,
			} {
				if got := flagValue(args, flag); got != want {
					t.Errorf("%s = %q, want %q", flag, got, want)
				}
			}
			for _, sw := range []string{"--client-cert-auth=true", "--peer-client-cert-auth=true"} {
				if !slices.Contains(args, sw) {
					t.Errorf("missing %s", sw)
				}
			}

			// Client URLs: https on loopback only, at the per-server datastore port.
			for _, flag := range []string{"--listen-client-urls", "--advertise-client-urls"} {
				vals := flagValues(args, flag)
				if len(vals) != 1 {
					t.Fatalf("%s rendered %d times", flag, len(vals))
				}
				for _, u := range strings.Split(vals[0], ",") {
					scheme, host := urlHost(t, u)
					if scheme != "https" || host != "127.0.0.1" || !strings.HasSuffix(u, ":32379") {
						t.Errorf("%s = %q, want https://127.0.0.1:32379 only", flag, u)
					}
				}
			}

			// Peer URLs: https on the node IP, never loopback, never the mesh IP.
			for _, flag := range []string{"--listen-peer-urls", "--initial-advertise-peer-urls"} {
				vals := flagValues(args, flag)
				if len(vals) != 1 {
					t.Fatalf("%s rendered %d times", flag, len(vals))
				}
				for _, u := range strings.Split(vals[0], ",") {
					scheme, host := urlHost(t, u)
					ip := net.ParseIP(host)
					if scheme != "https" || host != peerIP || ip == nil || ip.IsLoopback() || host == cfg.BindAddress {
						t.Errorf("%s = %q, want https://%s:2380 (node IP, not loopback, not the mesh IP %s)", flag, u, peerIP, cfg.BindAddress)
					}
				}
			}

			// Metrics: plain HTTP is acceptable only because it is loopback.
			if got := flagValue(args, "--listen-metrics-urls"); got != "http://127.0.0.1:2381" {
				t.Errorf("--listen-metrics-urls = %q, want http://127.0.0.1:2381", got)
			}

			// Never emitted.
			for _, banned := range []string{"--auto-tls", "--peer-auto-tls", "--listen-client-http-urls", "--enable-v2", "--enable-pprof"} {
				if strings.Contains(joined, banned) {
					t.Errorf("argv must never carry %s: %v", banned, args)
				}
			}
			for i, a := range args {
				if !strings.HasPrefix(a, "--") || i+1 >= len(args) {
					continue
				}
				if a == "--listen-metrics-urls" {
					continue
				}
				if strings.Contains(args[i+1], "http://") {
					t.Errorf("%s carries a plaintext URL %q", a, args[i+1])
				}
			}
			if got := strings.Contains(joined, " --force-new-cluster "); got != tc.reset {
				t.Errorf("--force-new-cluster present = %v, want %v (only under Reset)", got, tc.reset)
			}

			// First boot vs restart.
			if tc.wantState == "" {
				for _, f := range []string{"--initial-cluster", "--initial-cluster-state", "--initial-cluster-token"} {
					if slices.Contains(args, f) {
						t.Errorf("a restart must not render %s: %v", f, args)
					}
				}
			} else {
				if got := flagValue(args, "--initial-cluster-state"); got != tc.wantState {
					t.Errorf("--initial-cluster-state = %q, want %q", got, tc.wantState)
				}
				if got := flagValue(args, "--initial-cluster"); got != tc.wantInitial {
					t.Errorf("--initial-cluster = %q, want %q", got, tc.wantInitial)
				}
				if got, want := flagValue(args, "--initial-cluster-token"), "k3sm-"+pin[:16]; got != want {
					t.Errorf("--initial-cluster-token = %q, want %q (from the cluster CA pin)", got, want)
				}
			}

			hb, el := flagValue(args, "--heartbeat-interval"), flagValue(args, "--election-timeout")
			if tc.heartbeat && (hb != "250" || el != "2500") {
				t.Errorf("timings = %q/%q, want 250/2500", hb, el)
			}
			if !tc.heartbeat && (hb != "" || el != "") {
				t.Errorf("timings must be omitted by default, got %q/%q", hb, el)
			}
		})
	}
}

// TestApiserverEtcdServersTLS: the etcd posture points the apiserver at the local
// member over TLS with the etcd client identity; the kine posture's --etcd-servers is
// the unchanged plaintext loopback URL with no etcd TLS flag.
func TestApiserverEtcdServersTLS(t *testing.T) {
	cfg := etcdTestConfig(EtcdInit, "192.0.2.10")
	args := apiServerArgs(cfg)
	p := certs.EtcdCertPaths(cfg.WorkDir)
	for flag, want := range map[string]string{
		"--etcd-servers":  "https://127.0.0.1:32379",
		"--etcd-cafile":   p.ServerCACert,
		"--etcd-certfile": p.ClientCert,
		"--etcd-keyfile":  p.ClientKey,
	} {
		if got := flagValues(args, flag); len(got) != 1 || got[0] != want {
			t.Errorf("etcd posture %s = %v, want [%q]", flag, got, want)
		}
	}

	kine := apiServerArgs(Config{WorkDir: "/wd", KinePort: 2379})
	if got := flagValue(kine, "--etcd-servers"); got != "http://127.0.0.1:2379" {
		t.Errorf("kine posture --etcd-servers = %q, want http://127.0.0.1:2379", got)
	}
	if kine[0] != "--etcd-servers" || kine[1] != "http://127.0.0.1:2379" || kine[2] != "--service-cluster-ip-range" {
		t.Errorf("kine posture argv head moved: %v", kine[:3])
	}
	for _, f := range []string{"--etcd-cafile", "--etcd-certfile", "--etcd-keyfile"} {
		if slices.Contains(kine, f) {
			t.Errorf("kine posture must not carry %s", f)
		}
	}
}

// TestEtcdNeedsNonLoopbackNodeIP: the etcd posture refuses a peer address no other
// member could reach.
func TestEtcdNeedsNonLoopbackNodeIP(t *testing.T) {
	for _, ip := range []string{"", "127.0.0.1", "::1", "not-an-ip", "0.0.0.0"} {
		for _, role := range []EtcdRole{EtcdInit, EtcdJoin} {
			cfg := Config{Etcd: &EtcdConfig{Role: role, Name: "n", PeerIP: ip}}
			if err := cfg.Validate(); !errors.Is(err, ErrEtcdNeedsNodeIP) {
				t.Errorf("role %v PeerIP %q: Validate = %v, want ErrEtcdNeedsNodeIP", role, ip, err)
			}
		}
	}
	ok := Config{Etcd: &EtcdConfig{Role: EtcdInit, Name: "n", PeerIP: "192.0.2.10"}}
	if err := ok.Validate(); err != nil {
		t.Errorf("a LAN peer IP must validate, got %v", err)
	}
	if err := (Config{Etcd: &EtcdConfig{Name: "n", PeerIP: "192.0.2.10"}}).Validate(); !errors.Is(err, ErrEtcdRole) {
		t.Errorf("a role-less etcd posture: Validate = %v, want ErrEtcdRole", err)
	}
}

// TestEncryptionRefusedWithEtcdRole: secrets encryption is single-server only, and
// both etcd roles are HA.
func TestEncryptionRefusedWithEtcdRole(t *testing.T) {
	for _, role := range []EtcdRole{EtcdInit, EtcdJoin} {
		cfg := Config{
			EncryptionProviderConfig: "/wd/encryption-config.yaml",
			Etcd:                     &EtcdConfig{Role: role, Name: "n", PeerIP: "192.0.2.10"},
		}
		if err := cfg.Validate(); !errors.Is(err, ErrEncryptionHA) {
			t.Errorf("role %v + encryption: Validate = %v, want ErrEncryptionHA", role, err)
		}
	}
}

// TestEtcdConfigDefaultsDoNotWriteThrough: withDefaults fills the etcd ports on a copy.
func TestEtcdConfigDefaultsDoNotWriteThrough(t *testing.T) {
	e := &EtcdConfig{Role: EtcdInit, Name: "n", PeerIP: "192.0.2.10"}
	c := Config{Etcd: e}.withDefaults()
	if c.Etcd.PeerPort != DefaultEtcdPeerPort || c.Etcd.MetricsPort != DefaultEtcdMetricsPort {
		t.Errorf("defaults = %d/%d, want %d/%d", c.Etcd.PeerPort, c.Etcd.MetricsPort, DefaultEtcdPeerPort, DefaultEtcdMetricsPort)
	}
	if e.PeerPort != 0 || e.MetricsPort != 0 {
		t.Error("withDefaults wrote through the caller's EtcdConfig")
	}
}

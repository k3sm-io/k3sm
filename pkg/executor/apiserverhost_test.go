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
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"testing"

	"k8s.io/client-go/tools/clientcmd"
)

// hostOf returns the host of a kubeconfig/probe server URL, failing the test if it
// is not a URL. Hostname() unwraps IPv6 brackets, so an IPv6 bind compares as the
// bare address the apiserver was told to bind.
func hostOf(t *testing.T, server string) string {
	t.Helper()
	u, err := url.Parse(server)
	if err != nil {
		t.Fatalf("parse server URL %q: %v", server, err)
	}
	return u.Hostname()
}

// bindHostCase is one posture of the apiserver bind: the Config a server boots with
// and the host every in-process client and the healthz probe must dial to reach it.
type bindHostCase struct {
	name string
	cfg  Config
	// wantHost is the address the apiserver actually binds (== --bind-address).
	wantHost string
	// wantURL is the FULL rendered URL. The single-node row pins it byte-for-byte:
	// that string is the compatibility contract this whole change must not move.
	wantURL string
}

// bindHostCases are the postures shared by every leg below.
//
// The mesh rows are the defect (lab D1): cmd/k3sm/server.go sets BindAddress to the
// wireguard mesh IP and the apiserver then binds THAT interface only, so a probe or
// a kubeconfig hardcoded to loopback dials an address nothing is listening on and
// bring-up wedges at the healthz wait. The loopback rows are the compatibility
// contract — a single-node boot must render exactly what it always rendered.
func bindHostCases() []bindHostCase {
	const meshIP = "100.64.0.1"
	return []bindHostCase{
		{
			name:     "single-node default: loopback, byte-unchanged",
			cfg:      Config{WorkDir: "/wd", KinePort: 2379, APIServerPort: 6444, NodeIP: "127.0.0.1"},
			wantHost: "127.0.0.1",
			wantURL:  "https://127.0.0.1:6444",
		},
		{
			name:     "zero Config: withDefaults fills loopback",
			cfg:      Config{WorkDir: "/wd"},
			wantHost: "127.0.0.1",
			wantURL:  "https://127.0.0.1:" + strconv.Itoa(DefaultAPIServerPort),
		},
		{
			name:     "mesh: BindAddress and NodeIP are both the mesh IP",
			cfg:      Config{WorkDir: "/wd", KinePort: 2379, APIServerPort: 6444, NodeIP: meshIP, BindAddress: meshIP},
			wantHost: meshIP,
			wantURL:  "https://" + meshIP + ":6444",
		},
		{
			name:     "explicit BindAddress wins over NodeIP",
			cfg:      Config{WorkDir: "/wd", KinePort: 2379, APIServerPort: 6444, NodeIP: "192.168.7.20", BindAddress: meshIP},
			wantHost: meshIP,
			wantURL:  "https://" + meshIP + ":6444",
		},
		{
			name:     "NodeIP fallback rung: no BindAddress, routable NodeIP",
			cfg:      Config{WorkDir: "/wd", KinePort: 2379, APIServerPort: 6444, NodeIP: "192.168.7.20"},
			wantHost: "192.168.7.20",
			wantURL:  "https://192.168.7.20:6444",
		},
	}
}

// TestAPIServerHostChain pins the self-defaulting chain itself — BindAddress, then
// NodeIP, then loopback — on RAW Configs (never run through withDefaults, so the
// third rung is actually reachable), plus the IPv6 bracketing a naive
// host + ":" + port concatenation gets wrong.
func TestAPIServerHostChain(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name     string
		cfg      Config
		wantHost string
		wantURL  string
	}{
		{"BindAddress wins", Config{BindAddress: "100.64.0.1", NodeIP: "192.168.7.20", APIServerPort: 6444}, "100.64.0.1", "https://100.64.0.1:6444"},
		{"NodeIP is the second rung", Config{NodeIP: "192.168.7.20", APIServerPort: 6444}, "192.168.7.20", "https://192.168.7.20:6444"},
		{"loopback is the last rung", Config{APIServerPort: 6444}, "127.0.0.1", "https://127.0.0.1:6444"},
		{"an IPv6 bind is bracketed", Config{BindAddress: "::1", APIServerPort: 6444}, "::1", "https://[::1]:6444"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := apiServerHost(tc.cfg); got != tc.wantHost {
				t.Errorf("apiServerHost = %q, want %q", got, tc.wantHost)
			}
			if got := apiServerURL(tc.cfg); got != tc.wantURL {
				t.Errorf("apiServerURL = %q, want %q", got, tc.wantURL)
			}
			if got := flagValue(apiServerArgs(tc.cfg), "--bind-address"); got != tc.wantHost {
				t.Errorf("--bind-address = %q, want %q: apiServerArgs must render from the SAME chain", got, tc.wantHost)
			}
		})
	}
}

// TestAPIServerClientsFollowEffectiveBind is the B222 (lab D1) contract: the URL the
// in-process clients dial tracks the address the apiserver ACTUALLY BINDS, which is
// the same self-defaulting chain apiServerArgs renders --bind-address from
// (BindAddress -> NodeIP -> loopback).
//
// The identity assertion against --bind-address is the load-bearing one: a second,
// independent derivation is exactly how a mesh server came to probe a dead loopback
// address while binding its mesh IP.
func TestAPIServerClientsFollowEffectiveBind(t *testing.T) {
	t.Parallel()
	for _, tc := range bindHostCases() {
		t.Run(tc.name, func(t *testing.T) {
			s := NewSupervised(tc.cfg)
			server, _ := s.RESTConfigToken()
			if server != tc.wantURL {
				t.Errorf("RESTConfigToken server = %q, want %q", server, tc.wantURL)
			}
			if got := hostOf(t, server); got != tc.wantHost {
				t.Errorf("in-process client host = %q, want the effective bind %q", got, tc.wantHost)
			}
			bind := flagValue(apiServerArgs(s.cfg), "--bind-address")
			if got := hostOf(t, server); got != bind {
				t.Errorf("client host %q != apiserver --bind-address %q: the probe and the kubeconfigs must dial the address the apiserver binds, from ONE derivation", got, bind)
			}
		})
	}
}

// TestAdminKubeconfigServerFollowsEffectiveBind proves the admin kubeconfig the
// executor writes points at the effective bind. On the single-node row the rendered
// server string is pinned byte-for-byte.
func TestAdminKubeconfigServerFollowsEffectiveBind(t *testing.T) {
	t.Parallel()
	for _, tc := range bindHostCases() {
		t.Run(tc.name, func(t *testing.T) {
			cfg := tc.cfg
			cfg.WorkDir = t.TempDir()
			cfg = cfg.withDefaults()
			if err := writeKubeconfig(cfg, "k3sm-testtoken"); err != nil {
				t.Fatalf("write kubeconfig: %v", err)
			}
			kc, err := clientcmd.LoadFromFile(kubeconfigPath(cfg.WorkDir))
			if err != nil {
				t.Fatalf("load kubeconfig: %v", err)
			}
			cl := kc.Clusters["k3sm"]
			if cl == nil {
				t.Fatalf("kubeconfig has no k3sm cluster")
			}
			if cl.Server != tc.wantURL {
				t.Errorf("admin kubeconfig server = %q, want %q", cl.Server, tc.wantURL)
			}
			bind := flagValue(apiServerArgs(cfg), "--bind-address")
			if got := hostOf(t, cl.Server); got != bind {
				t.Errorf("admin kubeconfig host %q != apiserver --bind-address %q", got, bind)
			}
		})
	}
}

// TestComponentKubeconfigServersFollowEffectiveBind proves the SAME for the
// per-component client-cert kubeconfigs (scheduler + controller-manager). They are
// re-issued on every boot by provisionComponentCerts, so a mesh server that pointed
// them at loopback would start both components against a dead address.
func TestComponentKubeconfigServersFollowEffectiveBind(t *testing.T) {
	t.Parallel()
	for _, tc := range bindHostCases() {
		t.Run(tc.name, func(t *testing.T) {
			cfg := tc.cfg
			cfg.WorkDir = t.TempDir()
			s := NewSupervised(cfg)
			if err := s.provisionComponentCerts(); err != nil {
				t.Fatalf("provision component certs: %v", err)
			}
			for _, path := range []string{
				schedulerKubeconfigPath(s.cfg.WorkDir),
				controllerManagerKubeconfigPath(s.cfg.WorkDir),
			} {
				kc, err := clientcmd.LoadFromFile(path)
				if err != nil {
					t.Fatalf("load %s: %v", path, err)
				}
				cl := kc.Clusters["k3sm"]
				if cl == nil {
					t.Fatalf("%s has no k3sm cluster", path)
				}
				if cl.Server != tc.wantURL {
					t.Errorf("%s server = %q, want %q", path, cl.Server, tc.wantURL)
				}
			}
		})
	}
}

// TestReadyProbesEffectiveBindAddress is the end-to-end half: Ready must reach an
// apiserver that is NOT on 127.0.0.1.
//
// The listener is on ::1 rather than a routable address on purpose — IPv6 loopback
// is present on lo0 by default, so this proves "the probe follows the configured
// bind, and does not dial a hardcoded 127.0.0.1" with NO root and no lo0 alias. It
// also pins the IPv6 bracketing of the rendered URL, which a naive host+":"+port
// concatenation gets wrong.
func TestReadyProbesEffectiveBindAddress(t *testing.T) {
	t.Parallel()
	ln, err := net.Listen("tcp", "[::1]:0")
	if err != nil {
		t.Skipf("IPv6 loopback unavailable on this host: %v", err)
	}
	const token = "k3sm-readyprobe"
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/healthz" || r.Header.Get("Authorization") != "Bearer "+token {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		_, _ = w.Write([]byte("ok"))
	}))
	_ = srv.Listener.Close()
	srv.Listener = ln
	srv.StartTLS()
	defer srv.Close()

	port := ln.Addr().(*net.TCPAddr).Port
	s := NewSupervised(Config{WorkDir: t.TempDir(), APIServerPort: port, BindAddress: "::1", NodeIP: "::1", Token: token})
	if !s.Ready(context.Background()) {
		server, _ := s.RESTConfigToken()
		t.Errorf("Ready = false against a healthy apiserver bound to [::1]:%d — the probe dialled %q instead of the configured bind", port, server)
	}
}

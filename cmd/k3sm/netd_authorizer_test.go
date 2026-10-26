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
	"context"
	"io"
	"log/slog"
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	"k3sm.io/k3sm/pkg/dataroot"
	"k3sm.io/k3sm/pkg/ingresshost"
	"k3sm.io/k3sm/pkg/install"
	"k3sm.io/k3sm/pkg/netdsvc"
	"k3sm.io/k3sm/pkg/svclb"
)

func quietLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// TestBuildServiceSetDenyAllUntilReady proves that when the kubeconfig does not yet
// exist (netd is bootstrapped by launchd BEFORE the _k3sm server writes it), the
// authorizer returns NON-nil predicates that DENY (fail-safe) rather than nil.
// The prior code returned nil predicates permanently, which left every <1024
// infra-VIP bind denied for the daemon's whole life — cluster DNS never came up.
func TestBuildServiceSetDenyAllUntilReady(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	missing := filepath.Join(t.TempDir(), "does-not-exist.kubeconfig")
	declares, lbDeclarers, synced, _ := buildServiceSet(ctx, missing, quietLogger())

	// The predicates must be non-nil: a nil PortAuthorizer input can never later
	// authorize, so the async swap-in only works if the closures exist up front.
	if declares == nil || lbDeclarers == nil {
		t.Fatal("buildServiceSet returned nil predicates for a not-yet-present kubeconfig; must be non-nil deny-all so the async authorizer can swap in")
	}
	// Deny-all while the lister is nil (the boot window before the swap).
	if synced() {
		t.Fatal("synced() = true before the first Service sync; the refusal would say no service declares the port")
	}
	if declares(443) || len(lbDeclarers(53)) != 0 {
		t.Fatal("expected deny (no declarers) before the Service authorizer syncs")
	}
}

// TestCanonicalLBServiceIsTheIngressService pins the ONE identity the netd
// node-address allowlist is bound to. The assembler must name the very
// Service pkg/ingresshost provisions — a drifted or widened ref here would hand
// the root helper's node-address bind to some other Service, which is exactly
// the permissiveness the allowlist removed.
func TestCanonicalLBServiceIsTheIngressService(t *testing.T) {
	ref := canonicalLBService()
	if ref.Namespace != ingresshost.ServiceNamespace || ref.Name != ingresshost.ServiceName {
		t.Fatalf("canonicalLBService() = %s, want %s/%s (pkg/ingresshost is the single source)",
			ref, ingresshost.ServiceNamespace, ingresshost.ServiceName)
	}
	if ref.String() != "kube-system/k3sm-ingress" {
		t.Errorf("canonical node-address subject = %s, want kube-system/k3sm-ingress", ref)
	}
}

// TestBuildServiceSetEmptyKubeconfigDenies keeps the documented posture: no
// --kubeconfig configured → nil predicates (netd denies every <1024 bind, the
// existing "no authoritative Service set" contract).
func TestBuildServiceSetEmptyKubeconfigDenies(t *testing.T) {
	declares, lbDeclarers, synced, _ := buildServiceSet(context.Background(), "", quietLogger())
	if declares != nil || lbDeclarers != nil || synced != nil {
		t.Fatal("empty --kubeconfig must yield nil predicates (deny-all, no authoritative set)")
	}
}

// TestStartServiceInformerRetryableOnMissingKubeconfig proves the informer bring-up
// returns a retryable error (does NOT hang) when the kubeconfig is absent — the
// exact boot-race condition activateServiceAuthorizer loops on.
func TestStartServiceInformerRetryableOnMissingKubeconfig(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	done := make(chan error, 1)
	go func() {
		_, err := startServiceInformer(ctx, filepath.Join(t.TempDir(), "absent.kubeconfig"))
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("expected an error for a missing kubeconfig")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("startServiceInformer hung on a missing kubeconfig; must return a retryable error")
	}
}

// TestServerLANOffIngressBindsAdmittedByNetd drives the server shape end to
// end through netd's authorizer: the canonical ingress Service on 80/443, LAN
// access off, the node address the server's mesh .1 (netd runs with no
// --node-ip, so the bind reaches the host-address class), the default port
// list. Every address the ingress host binds for each port (the LAN switch's
// local set, less loopback below 1024) must be admitted, and so must the LAN-on
// wildcard; before the fix the node-address binds were refused as an
// ingress-owned port and `k3sm network lan off` rolled back.
func TestServerLANOffIngressBindsAdmittedByNetd(t *testing.T) {
	node := netip.MustParseAddr("100.64.0.1")
	lan := netip.MustParseAddr("192.0.2.20")
	sw := &lanSwitch{
		hostAddrs: func() ([]netip.Addr, error) {
			return []netip.Addr{lan, netip.MustParseAddr("127.0.0.1"), node}, nil
		},
		node: node,
	}
	off, err := sw.resolve(install.LANOff)
	if err != nil {
		t.Fatalf("resolve LAN off: %v", err)
	}
	on, err := sw.resolve(install.LANOn)
	if err != nil {
		t.Fatalf("resolve LAN on: %v", err)
	}

	lbPorts, err := dataroot.ParseLBPrivilegedPorts(dataroot.DefaultLBPrivilegedPorts)
	if err != nil {
		t.Fatalf("parse the default port list: %v", err)
	}
	canonical := canonicalLBService()
	cfg, err := netdsvc.BuildConfig(netdsvc.Options{
		NodePodCIDR: netip.MustParsePrefix("100.64.0.0/24"),
		ServiceCIDR: netip.MustParsePrefix("10.43.0.0/16"),
		Declares:    func(int) bool { return false },
		LBDeclarers: func(port int) []netdsvc.ServiceRef {
			if port == 80 || port == 443 {
				return []netdsvc.ServiceRef{canonical}
			}
			return nil
		},
		NodeAddressService: canonical,
		LBPrivilegedPorts:  lbPorts,
		InterfaceAddrs: func() (map[netip.Addr]string, error) {
			return map[netip.Addr]string{
				netip.MustParseAddr("127.0.0.1"): "lo0",
				node:                             "lo0",
				lan:                              "en0",
			}, nil
		},
	})
	if err != nil {
		t.Fatalf("BuildConfig: %v", err)
	}

	for _, port := range []uint16{80, 443} {
		binds := svclb.EffectiveBindAddrs(off.listeners, port)
		if len(binds) == 0 {
			t.Fatalf("LAN off leaves the ingress host no address for port %d (set %v)", port, off.listeners)
		}
		for _, a := range binds {
			if a.IsLoopback() {
				t.Errorf("the ingress host would bind %s:%d; loopback is left out below 1024", a, port)
			}
			if err := cfg.PortAuthorizer.Authorize(context.Background(), int(port), a.String()); err != nil {
				t.Errorf("LAN off: netd refused the ingress host's %s:%d: %v", a, port, err)
			}
		}
		for _, a := range svclb.EffectiveBindAddrs(on.listeners, port) {
			if err := cfg.PortAuthorizer.Authorize(context.Background(), int(port), a.String()); err != nil {
				t.Errorf("LAN on: netd refused the ingress host's %s:%d: %v", a, port, err)
			}
		}
	}
}

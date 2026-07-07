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

package netserve

import (
	"bytes"
	"context"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/kubernetes/fake"
)

// syncBuffer is a mutex-guarded bytes.Buffer usable as a slog handler's writer
// while the test concurrently reads it (the watcher goroutine logs through it).
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// TestNetworkPolicyHosting proves the M10.4 k3sm slice: netserve CONSTRUCTS the
// NetworkPolicy verdict table with the always-allow seeds (node InternalIP, this
// node's mesh-egress /32, the construction-time peer mesh-egress /32s), WIRES it
// into the proxy via proxy.WithPolicyTable, and HOSTS the PolicyWatcher beside
// the Service watcher in Run so a resolved policy flows through to a table
// verdict. The policy SEMANTICS (selector resolution, union-of-allows, widening)
// are proven in darwin-net's policy_test.go/policywatch_test.go — this is a
// hosting test against darwin-net's exported surface. The wired-into-the-proxy
// assertion is observable: proxy.New overwrites the table's logger with the
// proxy's own (Config.Logger) exactly when WithPolicyTable was applied, so the
// table's unknown-source fail-open Warn landing in OUR buffer proves the option
// was passed. Maps to M10.4-a1.
func TestNetworkPolicyHosting(t *testing.T) {
	podIP := func(name, ip string, labels map[string]string) *corev1.Pod {
		return &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "default", Labels: labels},
			Status:     corev1.PodStatus{PodIP: ip},
		}
	}
	port8080 := intstr.FromInt32(8080)
	policy := &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "allow-client-to-web", Namespace: "default"},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "web"}},
			Ingress: []networkingv1.NetworkPolicyIngressRule{{
				From:  []networkingv1.NetworkPolicyPeer{{PodSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"role": "client"}}}},
				Ports: []networkingv1.NetworkPolicyPort{{Port: &port8080}},
			}},
		},
	}
	client := fake.NewClientset(
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "default"}},
		podIP("web", "100.64.1.10", map[string]string{"app": "web"}),
		podIP("client", "100.64.1.11", map[string]string{"role": "client"}),
		podIP("stranger", "100.64.1.12", map[string]string{"role": "stranger"}),
		policy,
	)

	logBuf := &syncBuffer{}
	s := New(Config{
		Client:            client,
		WorkDir:           t.TempDir(),
		ClusterDomain:     "cluster.local",
		NodeIP:            "192.168.64.20",
		PodCIDR:           "100.64.1.0/24",
		MeshEgressIP:      "100.64.1.1",
		PeerMeshEgressIPs: []string{"100.64.2.1"},
		Logger:            slog.New(slog.NewTextHandler(logBuf, nil)),
	})
	if s.policy == nil {
		t.Fatal("New must construct the NetworkPolicy verdict table (policy hosting is unconditional on the datapath)")
	}
	if s.policyWatch == nil {
		t.Fatal("New must construct the PolicyWatcher beside the Service watcher")
	}

	// Host the full datapath lifecycle: Run supervises the proxy, the Service
	// watcher, AND the PolicyWatcher in one errgroup (DNSVIP is empty so the
	// resolver leg is skipped — no privileged binds in a unit test).
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.Run(ctx) }()
	defer func() {
		cancel()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Error("Run did not stop after ctx cancel")
		}
	}()

	web := netip.MustParseAddr("100.64.1.10")
	clientIP := netip.MustParseAddr("100.64.1.11")
	stranger := netip.MustParseAddr("100.64.1.12")

	// A resolved policy flows through to a table verdict: once the watcher's
	// informers sync and the debounced recompute installs, the selected backend
	// denies the non-matching known pod and admits the matching one. Before the
	// install the table is empty (allow-everything, the documented fail-open), so
	// poll for the deny to appear.
	deadline := time.Now().Add(10 * time.Second)
	for {
		if !s.policy.Allow(stranger, web, 8080) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("resolved NetworkPolicy never flowed through to a table verdict (stranger→web still allowed)")
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !s.policy.Allow(clientIP, web, 8080) {
		t.Error("Allow(client→web:8080) = false, want true (the policy's from-peer must be admitted)")
	}

	// The always-allow seeds: node InternalIP, this node's mesh-egress /32, and
	// the construction-time peer mesh-egress /32. Each must pass against the
	// SELECTED backend, and must do so via the seed set, not the unknown-source
	// fail-open — no "UNKNOWN source" Warn may have been emitted yet.
	for _, seed := range []string{"192.168.64.20", "100.64.1.1", "100.64.2.1"} {
		if !s.policy.Allow(netip.MustParseAddr(seed), web, 8080) {
			t.Errorf("Allow(seed %s→web:8080) = false, want true (always-allow seed must never be policy-denied)", seed)
		}
	}
	if strings.Contains(logBuf.String(), "UNKNOWN source") {
		t.Error("seed sources tripped the unknown-source fail-open Warn — they were not seeded into the always-allow set")
	}

	// Wired into the proxy (the WithPolicyTable observable): a genuinely unknown
	// source fails open WITH the throttled Warn, and that Warn must land in OUR
	// logger — proxy.New rewires the table's logger to the proxy's exactly when
	// the option was applied, so its presence here proves the wiring.
	if !s.policy.Allow(netip.MustParseAddr("100.64.9.9"), web, 8080) {
		t.Error("Allow(unknown→web:8080) = false, want true (unknown sources fail open per the hint contract)")
	}
	if !strings.Contains(logBuf.String(), "UNKNOWN source") {
		t.Error("unknown-source fail-open Warn missing from the configured logger — WithPolicyTable was not wired into the proxy netserve constructs")
	}
}

// TestM10_4_LimitationsDocKeepsLoadBearingPhrases is the M10.4-a1 line-assert:
// docs/user/limitations.md must keep the load-bearing honest-limit phrases of
// the NetworkPolicy section so the doc cannot silently lose them. Markdown
// emphasis (backticks/asterisks) is stripped before matching so formatting
// tweaks don't defeat the check while a factual edit still does.
func TestM10_4_LimitationsDocKeepsLoadBearingPhrases(t *testing.T) {
	t.Parallel()
	raw, err := os.ReadFile(filepath.Join("..", "..", "docs", "user", "limitations.md"))
	if err != nil {
		t.Fatalf("read limitations.md: %v", err)
	}
	doc := strings.NewReplacer("`", "", "*", "").Replace(string(raw))
	for _, phrase := range []string{
		"bypasses it completely",
		"NOT a security boundary",
		"vm RuntimeClass",
	} {
		if !strings.Contains(doc, phrase) {
			t.Errorf("limitations.md lost the load-bearing phrase %q", phrase)
		}
	}
}

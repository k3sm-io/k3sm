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
	"sort"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes/fake"
	kubeletapis "k8s.io/kubelet/pkg/apis"

	"k3sm.io/k3sm/pkg/provider"
	"k3sm.io/k3sm/pkg/provider/vkadapter"
)

// nodeRestrictionAllowedLabels is the FIXED half of the NodeRestriction kubelet
// label allowlist — the exact keys a `system:node:<name>` identity may set on its
// own Node object, beyond the two open namespaces in
// nodeRestrictionAllowedLabelNamespaces below.
//
// Derived from k8s.io/kubelet/pkg/apis/well_known_labels.go:35-48 (`kubeletLabels`,
// vendored v0.35.0), which the v1.36.2 NodeRestriction admission plugin consults via
// kubeletapis.IsKubeletLabel — see k8s.io/kubernetes@v1.36.2
// plugin/pkg/admission/noderestriction/admission.go:601-620 (getForbiddenLabels).
//
// It is written out rather than derived so a reader can see the set, and it is
// asserted equal to the live kubeletapis.KubeletLabels() by the first subtest — a
// k8s dependency bump that adds or drops a key fails there, loudly, instead of
// quietly widening what this test believes is safe.
var nodeRestrictionAllowedLabels = []string{
	"beta.kubernetes.io/arch",
	"beta.kubernetes.io/os",
	"failure-domain.beta.kubernetes.io/region",
	"failure-domain.beta.kubernetes.io/zone",
	"kubernetes.io/arch",
	"kubernetes.io/hostname",
	"kubernetes.io/os",
	"node.kubernetes.io/instance-type",
	"beta.kubernetes.io/instance-type",
	"topology.kubernetes.io/region",
	"topology.kubernetes.io/zone",
}

// nodeRestrictionAllowedLabelNamespaces is the OPEN half of the allowlist: any key
// in these namespaces (or a subdomain of one) is kubelet-settable. Same source,
// well_known_labels.go:50-53 (`kubeletLabelNamespaces`).
var nodeRestrictionAllowedLabelNamespaces = []string{
	"kubelet.kubernetes.io",
	"node.kubernetes.io",
}

// nodeRestrictionForbids reports whether the v1.36.2 NodeRestriction admission
// plugin would reject a `system:node:<name>` identity setting key on its own Node.
//
// It is the upstream rule, re-expressed over the upstream predicate rather than over
// a copied key list: getForbiddenLabels (admission.go:601-620) forbids a key iff its
// namespace is (a subdomain of) node-restriction.kubernetes.io, OR the key is
// kubernetes.io/k8s.io-namespaced and kubeletapis.IsKubeletLabel says no. Calling
// IsKubeletLabel here — instead of consulting nodeRestrictionAllowedLabels — is what
// makes this test track a k8s bump automatically.
func nodeRestrictionForbids(key string) bool {
	ns := labelNamespaceForTest(key)
	if ns == corev1.LabelNamespaceNodeRestriction || strings.HasSuffix(ns, "."+corev1.LabelNamespaceNodeRestriction) {
		return true
	}
	if isKubernetesLabelNamespace(ns) && !kubeletapis.IsKubeletLabel(key) {
		return true
	}
	return false
}

// labelNamespaceForTest mirrors the plugin's getLabelNamespace (admission.go:591-596):
// the part before the first "/", or "" for an unprefixed key.
func labelNamespaceForTest(key string) string {
	if parts := strings.SplitN(key, "/", 2); len(parts) == 2 {
		return parts[0]
	}
	return ""
}

// isKubernetesLabelNamespace mirrors the plugin's isKubernetesLabel
// (admission.go:581-589): the reserved kubernetes.io / k8s.io namespaces and their
// subdomains. Everything else (k3sm.io/*, mlx.k3sm.io/*, the bare "type" key) is
// outside NodeRestriction's reach entirely.
func isKubernetesLabelNamespace(ns string) bool {
	return ns == "kubernetes.io" || strings.HasSuffix(ns, ".kubernetes.io") ||
		ns == "k8s.io" || strings.HasSuffix(ns, ".k8s.io")
}

// TestConfigureNodeStampsNoForbiddenLabels is the B225 (lab defect D4) regression
// gate: a JOINED WORKER registers as `system:node:<name>`, so every label on the
// Node object it creates — and re-asserts on every status tick — passes through
// NodeRestriction. One forbidden key rejects the whole create/patch and the worker
// never registers.
//
// The defect was inherited, not authored: nodeutil.NewNode hard-codes
// kubernetes.io/role=agent into its default Node object
// (virtual-kubelet@v1.12.0 node/nodeutil/controller.go:296-302), configureNode runs
// AFTER that defaulting (vkadapter.go:169-171), and kubernetes.io/role is not a
// kubelet-settable label. The in-process server node escapes only because it acts as
// system:masters, which NodeRestriction does not apply to.
//
// So the assertion is deliberately NOT "kubernetes.io/role is absent". It enumerates
// the labels the VENDORED library actually defaults today — read off the real
// production wiring, not a fixture — and requires each to be either allowed by
// NodeRestriction or removed by configureNode. A virtual-kubelet bump that adds
// another kubernetes.io-namespaced default label therefore reopens the defect
// LOUDLY here rather than silently on a lab worker.
//
// Not t.Parallel: the subtests call configureNode, which reads the package-level
// host-fact seams other tests in this package swap.
func TestConfigureNodeStampsNoForbiddenLabels(t *testing.T) {
	t.Run("the documented allowlist still matches upstream", func(t *testing.T) {
		got := kubeletapis.KubeletLabels()
		want := append([]string(nil), nodeRestrictionAllowedLabels...)
		sort.Strings(got)
		sort.Strings(want)
		if strings.Join(got, ",") != strings.Join(want, ",") {
			t.Errorf("kubeletapis.KubeletLabels() = %v,\n want %v\n"+
				"(the k8s dependency changed the NodeRestriction allowlist: re-derive "+
				"nodeRestrictionAllowedLabels from k8s.io/kubelet/pkg/apis/well_known_labels.go "+
				"and re-check every label configureNode stamps)", got, want)
		}
		gotNS := kubeletapis.KubeletLabelNamespaces()
		wantNS := append([]string(nil), nodeRestrictionAllowedLabelNamespaces...)
		sort.Strings(gotNS)
		sort.Strings(wantNS)
		if strings.Join(gotNS, ",") != strings.Join(wantNS, ",") {
			t.Errorf("kubeletapis.KubeletLabelNamespaces() = %v, want %v", gotNS, wantNS)
		}
	})

	// The vendored defaults + the stamped result, both read off the SHIPPED wiring
	// (vkadapter.NewNode → nodeutil.NewNode defaulting → cfg.ConfigureNode), so a
	// library bump changes what this test sees.
	defaulted, stamped := stampNodeThroughProductionWiring(t, "k3sm-worker")

	t.Run("every label the vendored library defaults is allowed or removed", func(t *testing.T) {
		if len(defaulted) == 0 {
			t.Fatal("captured no default labels from nodeutil.NewNode: the capture seam broke, " +
				"so this test would pass vacuously")
		}
		for _, key := range sortedKeys(defaulted) {
			if !nodeRestrictionForbids(key) {
				continue // NodeRestriction permits it; configureNode may keep it
			}
			if _, kept := stamped[key]; kept {
				t.Errorf("nodeutil defaults label %q=%q, NodeRestriction forbids a node from "+
					"setting it, and configureNode did NOT remove it: a joined worker's Node "+
					"create/patch is rejected and the node never registers. Delete the label in "+
					"configureNode.", key, defaulted[key])
			}
		}
	})

	t.Run("no label configureNode leaves on the node is forbidden", func(t *testing.T) {
		for _, key := range sortedKeys(stamped) {
			if nodeRestrictionForbids(key) {
				t.Errorf("configureNode leaves label %q=%q on the Node object; NodeRestriction "+
					"forbids a system:node identity from setting it", key, stamped[key])
			}
		}
	})

	// The multi-tick leg. configureNode itself runs exactly ONCE, at registration
	// (nodeutil.NewNode calls newProvider once, controller.go:349-355) — but the label
	// map it leaves behind is re-asserted to the apiserver on EVERY status tick:
	// NodeStatusProvider republishes a DeepCopy of that bootstrap node
	// (pkg/provider/nodestatus.go:257-268), the VK node controller assigns the
	// published Labels wholesale over its own copy (node.go:375) and includes them in
	// each three-way status patch (node.go:520-521, simplestObjectMetadata). So a
	// forbidden key is not a one-shot registration failure — it is a permanently
	// failing heartbeat. This leg drives the real publication loop and checks every
	// tick, not just the first.
	t.Run("every republished tick carries no forbidden label", func(t *testing.T) {
		node := &corev1.Node{}
		node.Name = "k3sm-worker"
		node.Labels = maps(stamped)

		nsp, err := provider.NewNodeStatusProvider(provider.NodeStatusConfig{
			Node:     node,
			DataRoot: t.TempDir(),
			Interval: time.Millisecond,
		})
		if err != nil {
			t.Fatalf("NewNodeStatusProvider: %v", err)
		}

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		const wantTicks = 3
		published := make(chan map[string]string, wantTicks)
		nsp.NotifyNodeStatus(ctx, func(n *corev1.Node) {
			select {
			case published <- maps(n.Labels):
			default: // enough samples collected; never block the publisher
			}
		})
		go func() { _ = nsp.Run(ctx) }()

		deadline := time.After(30 * time.Second)
		for i := 0; i < wantTicks; i++ {
			select {
			case labels := <-published:
				if len(labels) == 0 {
					t.Fatalf("tick %d republished a node with no labels: the status provider "+
						"dropped the registration labels", i)
				}
				for _, key := range sortedKeys(labels) {
					if nodeRestrictionForbids(key) {
						t.Errorf("tick %d republishes forbidden label %q=%q; every status patch "+
							"carries the label set, so NodeRestriction rejects the heartbeat too",
							i, key, labels[key])
					}
				}
			case <-deadline:
				t.Fatalf("only %d of %d status publications arrived", i, wantTicks)
			}
		}
	})
}

// stampNodeThroughProductionWiring builds a VK node exactly as `k3sm node` does and
// returns (the labels nodeutil defaulted, the labels configureNode left). Capturing
// from the shipped constructor — rather than hand-writing the vendored default map —
// is the whole point: the defaults move when the dependency moves.
func stampNodeThroughProductionWiring(t *testing.T, name string) (defaulted, stamped map[string]string) {
	t.Helper()
	if _, err := vkadapter.NewNode(name, vkadapter.NodeConfig{
		Client: fake.NewSimpleClientset(),
		// A zero-value VKProvider satisfies the VK provider contract and is only
		// STORED by the constructor — nothing here runs a pod, so no runtimed
		// connection, no sandbox and no privilege is needed.
		Provider:       &provider.VKProvider{},
		HTTPListenAddr: nodeKubeletListen,
		ConfigureNode: func(n *corev1.Node) {
			defaulted = maps(n.Labels)
			configureNode(n, name, "10.0.0.1", nodeKubeletListen, provider.NodeCapabilities{})
			stamped = maps(n.Labels)
		},
	}); err != nil {
		t.Fatalf("vkadapter.NewNode: %v", err)
	}
	if stamped == nil {
		t.Fatal("ConfigureNode was never invoked: the capture seam broke")
	}
	return defaulted, stamped
}

// maps returns a copy of m (nil-safe), so a captured snapshot cannot alias — and be
// mutated by — the live node object.
func maps(m map[string]string) map[string]string {
	out := make(map[string]string, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

// sortedKeys gives the deterministic iteration order test failures need.
func sortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

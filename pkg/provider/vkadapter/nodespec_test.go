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

package vkadapter

import (
	"bytes"
	"flag"
	"os"
	"path/filepath"
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/yaml"
)

var updateGolden = flag.Bool("update", false, "rewrite the testdata goldens from the current code")

// nodeSpecGolden is the Node object the node registers, captured from the
// Virtual Kubelet nodeutil builder before the adapter took over the assembly.
const nodeSpecGolden = "testdata/registered-node.golden.yaml"

// TestNewNodeSpecParity pins the Node object a k3sm node registers: the default
// labels, phase and condition set the node starts from, with ConfigureNode's
// stamp applied on top. The golden was captured from nodeutil.NewNode, so any
// assembly that replaces it must register the byte-identical object.
// Timestamps are zeroed; nothing else is normalised.
func TestNewNodeSpecParity(t *testing.T) {
	const name = "k3sm-golden"
	h := newNodeHarness(t)
	n, err := NewNode(name, NodeConfig{
		Client:         h.cs,
		Provider:       newRecordingProvider(),
		HTTPListenAddr: "127.0.0.1:0",
		NumWorkers:     1,
		ConfigureNode: func(nd *corev1.Node) {
			nd.Labels["k3sm.io/stamped"] = "true"
			nd.Status.Capacity = corev1.ResourceList{corev1.ResourcePods: resource.MustParse("110")}
		},
	})
	if err != nil {
		t.Fatalf("NewNode: %v", err)
	}
	runNode(t, n)

	got := h.registeredNode()
	if got == nil {
		t.Fatal("no Node create was recorded: the capture reactor never fired")
	}
	got.CreationTimestamp = metav1.Time{}
	for i := range got.Status.Conditions {
		got.Status.Conditions[i].LastHeartbeatTime = metav1.Time{}
		got.Status.Conditions[i].LastTransitionTime = metav1.Time{}
	}
	out, err := yaml.Marshal(got)
	if err != nil {
		t.Fatalf("marshal node: %v", err)
	}

	path := filepath.FromSlash(nodeSpecGolden)
	if *updateGolden {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, out, 0o644); err != nil {
			t.Fatal(err)
		}
		t.Logf("wrote %s", path)
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read golden (regenerate with -update only in a reviewed commit): %v", err)
	}
	if !bytes.Equal(out, want) {
		t.Errorf("registered Node differs from %s\n--- got ---\n%s\n--- want ---\n%s", path, out, want)
	}
}

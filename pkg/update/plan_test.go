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

package update

import (
	"bytes"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"k3sm.io/k3sm/pkg/status"
	"k3sm.io/k3sm/pkg/version"
)

func planNode(name string, server bool, kubelet string) corev1.Node {
	n := corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: name, Labels: map[string]string{}}}
	if server {
		n.Labels[controlPlaneLabel] = "true"
	}
	n.Status.NodeInfo.KubeletVersion = kubelet
	return n
}

// TestRollOrder pins the controller's order: workers by name, the other
// servers by name, the controller's own server last.
func TestRollOrder(t *testing.T) {
	nodes := []corev1.Node{planNode("s-b", true, ""), planNode("w-b", false, ""), planNode("s-a", true, ""), planNode("w-a", false, "")}
	for _, tc := range []struct {
		name, controller string
		want             []string
	}{
		{"controller known", "s-a", []string{"w-a", "w-b", "s-b", "s-a"}},
		{"controller unknown", "", []string{"w-a", "w-b", "s-a", "s-b"}},
		{"controller not a node", "gone", []string{"w-a", "w-b", "s-a", "s-b"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var got []string
			for _, n := range RollOrder(nodes, tc.controller) {
				got = append(got, n.Name)
			}
			if strings.Join(got, ",") != strings.Join(tc.want, ",") {
				t.Errorf("order = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestPlanRender pins the plan a person confirms: the target, the policies,
// and the nodes in roll order with their versions and states.
func TestPlanRender(t *testing.T) {
	behind := version.Info{KubeVersion: "v1.36.2", Version: "0.1.7"}.NodeVersion()
	p := NewPlan("v0.2.0", []corev1.Node{planNode("node-a", true, behind), planNode("laptop\x1b[2J", false, behind)}, "node-a", true, "required", false)
	if len(p.Nodes) != 2 || p.Nodes[1].Name != "node-a" || p.Nodes[0].State != status.UpdateBehind {
		t.Fatalf("plan = %+v", p)
	}
	var b bytes.Buffer
	p.Render(&b)
	out := b.String()
	for _, want := range []string{"target            v0.2.0", "drain             yes", "signature         required", "allow downgrade   no", "1       laptop[2J", "2       node-a"} {
		if !strings.Contains(out, want) {
			t.Errorf("plan output lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "\x1b") || strings.Contains(out, "not known") {
		t.Errorf("plan output:\n%s", out)
	}
}

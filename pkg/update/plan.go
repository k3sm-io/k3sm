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
	"fmt"
	"io"
	"sort"
	"text/tabwriter"

	corev1 "k8s.io/api/core/v1"

	"k3sm.io/k3sm/pkg/status"
)

// controlPlaneLabel marks a server Node.
const controlPlaneLabel = "node-role.kubernetes.io/control-plane"

// RollOrder is the order the update controller (pkg/updatectl) visits nodes
// in: every node that is not a server by name, then every other server by
// name, then controllerNode, the server the controller runs on, last. An
// empty or absent controllerNode leaves every server in name order. It must
// stay the controller's order, which the plan a person confirms describes.
func RollOrder(nodes []corev1.Node, controllerNode string) []corev1.Node {
	var workers, servers []corev1.Node
	var self *corev1.Node
	for i := range nodes {
		n := nodes[i]
		_, cp := n.Labels[controlPlaneLabel]
		switch {
		case controllerNode != "" && n.Name == controllerNode:
			self = &n
		case cp:
			servers = append(servers, n)
		default:
			workers = append(workers, n)
		}
	}
	byName := func(s []corev1.Node) {
		sort.Slice(s, func(i, j int) bool { return s[i].Name < s[j].Name })
	}
	byName(workers)
	byName(servers)
	out := append(workers, servers...)
	if self != nil {
		out = append(out, *self)
	}
	return out
}

// PlanNode is one node of a Plan.
type PlanNode struct {
	Name string `json:"name"`
	// Version is status.nodeInfo.kubeletVersion as the node reports it.
	Version string `json:"version"`
	// State is how Version compares with the target: status.UpdateCurrent,
	// UpdateBehind, UpdateAhead or UpdateUnknown.
	State string `json:"state"`
}

// Plan is what `k3sm update apply` asks a person to confirm.
type Plan struct {
	// Target is the release every node moves to.
	Target string `json:"target"`
	// Nodes are the nodes in roll order.
	Nodes []PlanNode `json:"nodes"`
	// ControllerNode is the server the update controller runs on, which goes
	// last; empty when it is not known.
	ControllerNode string `json:"controllerNode,omitempty"`
	// Drain is spec.strategy.drain.
	Drain bool `json:"drain"`
	// Signature is spec.verify.signature.
	Signature string `json:"signature"`
	// AllowDowngrade is spec.allowDowngrade.
	AllowDowngrade bool `json:"allowDowngrade"`
}

// NewPlan is the plan to move nodes to target, in RollOrder.
func NewPlan(target string, nodes []corev1.Node, controllerNode string, drain bool, signature string, allowDowngrade bool) Plan {
	p := Plan{Target: target, ControllerNode: controllerNode, Drain: drain, Signature: signature, AllowDowngrade: allowDowngrade, Nodes: []PlanNode{}}
	for _, n := range RollOrder(nodes, controllerNode) {
		v := n.Status.NodeInfo.KubeletVersion
		p.Nodes = append(p.Nodes, PlanNode{Name: n.Name, Version: v, State: status.NodeReleaseState(v, target)})
	}
	return p
}

// Render prints the plan for a person. Node names and versions are what each
// node says of itself, so they are control-stripped first.
func (p Plan) Render(w io.Writer) {
	tw := tabwriter.NewWriter(w, 0, 0, 3, ' ', 0)
	fmt.Fprintf(tw, "target\t%s\n", status.ClipText(p.Target, 128))
	fmt.Fprintf(tw, "drain\t%s\n", yesNo(p.Drain))
	fmt.Fprintf(tw, "signature\t%s\n", p.Signature)
	fmt.Fprintf(tw, "allow downgrade\t%s\n", yesNo(p.AllowDowngrade))
	fmt.Fprintf(tw, "\nORDER\tNODE\tVERSION\tSTATE\n")
	for i, n := range p.Nodes {
		fmt.Fprintf(tw, "%d\t%s\t%s\t%s\n", i+1, status.ClipText(n.Name, 253), status.ClipText(n.Version, 128), n.State)
	}
	_ = tw.Flush()
	if p.ControllerNode == "" {
		fmt.Fprintln(w, "\nThe server that runs the update controller goes last; which one it is was not known, so the servers are listed by name.")
	}
}

func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

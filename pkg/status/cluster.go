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

package status

import (
	"net"
	"sort"
	"strconv"
	"strings"

	corev1 "k8s.io/api/core/v1"

	"k3sm.io/k3sm/pkg/dataroot"
	"k3sm.io/k3sm/pkg/install"
)

// controlPlaneNodeLabel is the well-known label that marks a control-plane
// Node. NodeRestriction forbids a node identity to set any
// node-role.kubernetes.io/ key on itself, so only a cluster admin can have
// written it; a label the node could write would let a worker claim a role.
const controlPlaneNodeLabel = "node-role.kubernetes.io/control-plane"

// Worker is one other node of the cluster a server reports: its name, its
// role, and the version its kubelet reports.
type Worker struct {
	Name string `json:"name"`
	// Role is "server" when the Node carries controlPlaneNodeLabel, "agent"
	// otherwise.
	Role dataroot.Role `json:"role"`
	// Version is Node.Status.NodeInfo.KubeletVersion as the node reports it:
	// the Kubernetes version with the k3sm release as semver build metadata
	// (version.Info.NodeVersion), for example v1.36.2+k3sm.0.1.7.
	Version string `json:"version"`
}

// workers lists every node of nodes except this Mac's own, sorted by name.
//
// The result is a pointer so the JSON can tell the two answers apart: nil (the
// key is omitted) means "not known", and a pointer to an empty slice (encoded
// as []) means the read succeeded and this server has no other nodes. It is
// nil on an agent, when the node list was not read (no client, an apiserver
// that is not serving), when the read failed, and when this Mac's own node
// cannot be picked out of a non-empty list, because a list that might include
// this server itself is not a list of the others.
func (c Collector) workers(role dataroot.Role, read bool, nodes []corev1.Node, nodesErr error) *[]Worker {
	if role == dataroot.RoleAgent || !read || nodesErr != nil {
		return nil
	}
	out := []Worker{}
	if len(nodes) == 0 {
		return &out
	}
	mine, ok := PickNode(nodes, c.Hostname)
	if !ok {
		return nil
	}
	for i := range nodes {
		n := &nodes[i]
		if n.Name == mine.Name {
			continue
		}
		w := Worker{Name: n.Name, Role: dataroot.RoleAgent, Version: n.Status.NodeInfo.KubeletVersion}
		if _, cp := n.Labels[controlPlaneNodeLabel]; cp {
			w.Role = dataroot.RoleServer
		}
		out = append(out, w)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return &out
}

// joinTarget is the bootstrap endpoint (host:port) this agent joined, or ""
// when this Mac is not an agent or the target cannot be read.
//
// The host comes from the AgentJoinServer seam, which returns ONLY the --server
// value of the installed agent's argv; no other argument (the token-file path
// among them) ever reaches this function. The port is the fixed bootstrap port
// the join dials. A value that is not a bare host is refused rather than
// reported, so a malformed argv never reaches the JSON.
func (c Collector) joinTarget(role dataroot.Role) string {
	if role != dataroot.RoleAgent || c.AgentJoinServer == nil {
		return ""
	}
	host, err := c.AgentJoinServer()
	if err != nil {
		return ""
	}
	host = strings.TrimSpace(host)
	if host == "" || strings.ContainsAny(host, " \t/@[]") {
		return ""
	}
	if _, _, err := net.SplitHostPort(host); err == nil {
		return "" // already carries a port: not the bare host the join dials
	}
	return net.JoinHostPort(host, strconv.Itoa(install.JoinBootstrapPort))
}

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
	"net/netip"
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
	// (version.Info.NodeVersion), for example v1.36.2+k3sm.0.1.7. It is the
	// node's own claim, not an attestation, and it is omitted while the
	// kubelet has reported none: a reader treats a missing version as unknown.
	Version string `json:"version,omitempty"`
}

// workers lists every node of nodes except this Mac's own, sorted by name.
//
// The result is a pointer so the JSON can tell the two answers apart: nil (the
// key is omitted) means "not known", and a pointer to an empty slice (encoded
// as []) means the read succeeded and this server has no other nodes. It is
// nil on an agent, when the node list was not read (no client, an apiserver
// that is not serving), when the read failed, and whenever this Mac's own node
// is not in the list BY NAME. It deliberately does not use PickNode's
// single-node fallback: a lone node that does not carry this Mac's name may be
// another Mac's, and reporting "no other nodes" then would be a false success
// an update client acts on.
func (c Collector) workers(role dataroot.Role, read bool, nodes []corev1.Node, nodesErr error) *[]Worker {
	if role == dataroot.RoleAgent || !read || nodesErr != nil {
		return nil
	}
	mine, ok := matchNodeByName(nodes, c.Hostname)
	if !ok {
		return nil
	}
	out := []Worker{}
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
// the join dials. Only a host joinHostValid accepts is reported, so a malformed
// argv never reaches the JSON.
func (c Collector) joinTarget(role dataroot.Role) string {
	if role != dataroot.RoleAgent || c.AgentJoinServer == nil {
		return ""
	}
	host, err := c.AgentJoinServer()
	if err != nil {
		return ""
	}
	if !joinHostValid(host) {
		return ""
	}
	return net.JoinHostPort(host, strconv.Itoa(install.JoinBootstrapPort))
}

// maxHostLen is the longest DNS name, in its dotted text form.
const maxHostLen = 253

// joinHostValid reports whether host is one this report will print as a join
// target: an IPv4 address, or a DNS name of letters, digits, '-' and '.' with
// no empty label, no label over 63 bytes, no label that starts or ends with
// '-', and not made of digits and dots alone. Everything else is refused,
// which covers control characters, spaces, '?', '#', '/', '@', a value that
// already carries a port, and IPv6 literals (the join's own preflight accepts
// those, but the report keeps one strict shape rather than a second address
// grammar).
func joinHostValid(host string) bool {
	if host == "" || len(host) > maxHostLen {
		return false
	}
	if a, err := netip.ParseAddr(host); err == nil {
		return a.Is4()
	}
	if strings.Trim(host, "0123456789.") == "" {
		return false // dotted digits that are not an IPv4 address
	}
	for _, label := range strings.Split(strings.TrimSuffix(host, "."), ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for i := 0; i < len(label); i++ {
			ch := label[i]
			if !(ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' || ch >= '0' && ch <= '9' || ch == '-') {
				return false
			}
		}
	}
	return true
}

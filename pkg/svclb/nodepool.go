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

package svclb

import (
	"net/netip"
	"slices"
	"strings"

	corev1 "k8s.io/api/core/v1"
)

// The node-pool keys. All live under svclb.k3sm.io: no svccontroller.k3s.cattle.io
// key is read or written, so a cluster migrated from k3s relabels one-to-one
// (enablelb, lbpool, and the multi-pool form) instead of having two vocabularies
// silently disagree.
const (
	// EnableLBLabel on a Node turns allow-list mode on once ANY Node carries it
	// with the value "true"; then only Nodes labelled "true" host. Any other
	// value, on any number of Nodes, leaves allow-list mode off: a node cannot
	// flip the whole cluster into allow-list mode (and starve every other host)
	// by labelling itself "false".
	EnableLBLabel = "svclb.k3sm.io/enablelb"
	// LBPoolLabel on a Service restricts its hosts to the Nodes in pool <value>.
	// On a Node it is the single-pool membership form.
	LBPoolLabel = "svclb.k3sm.io/lbpool"
	// LBPoolNodeLabelPrefix is the multi-pool membership form: a Node label
	// lbpool.svclb.k3sm.io/<pool>=true puts the Node in <pool>, OR'd with the
	// single-pool form, so one Node can sit in several pools.
	LBPoolNodeLabelPrefix = "lbpool.svclb.k3sm.io/"
)

// The two annotations the decider and the hosters exchange.
const (
	// HostsAnnotation is the decider's stamp on a claimed Service: the sorted,
	// comma-joined names of the Nodes that must bind it. The empty value means
	// "claimed, no eligible host"; an absent annotation means no multi-node
	// decider has decided it, and a hoster then binds nothing.
	HostsAnnotation = "svclb.k3sm.io/hosts"
	// BoundAnnotation is each hoster's report on its OWN Node: the Services
	// whose every TCP port it holds, as "<incarnation>;<ns>/<name>:<uid>,...".
	// The node writes it with its own identity (the Node authorizer and
	// NodeRestriction admit a node's annotation patch on its own Node), so the
	// report needs no Service write grant. It can only narrow the decider's
	// decision: a node absent from a Service's stamp is never advertised, whatever
	// it reports.
	BoundAnnotation = "svclb.k3sm.io/bound"
)

// maxBoundBytes caps the bound report. A report that would exceed it lists the
// first entries in sort order and the hoster warns; the decider then treats an
// unlisted Service as not bound on that node, which keeps it pending there
// rather than advertising a listener nobody vouched for.
const maxBoundBytes = 64 << 10

// allowListMode reports whether any Node carries EnableLBLabel=true.
func allowListMode(nodes []*corev1.Node) bool {
	for _, n := range nodes {
		if n != nil && n.Labels[EnableLBLabel] == "true" {
			return true
		}
	}
	return false
}

// inPool reports whether n is a member of pool, by either membership form.
func inPool(n *corev1.Node, pool string) bool {
	return n.Labels[LBPoolLabel] == pool || n.Labels[LBPoolNodeLabelPrefix+pool] == "true"
}

// advertisable reports whether a is an address status may publish.
func advertisable(a netip.Addr) bool {
	return a.IsValid() && !a.IsLoopback() && !a.IsUnspecified()
}

// selectHosts returns the sorted names of the Nodes that must host svc. It
// mirrors k3s' node-pool affinity over the k3sm keys:
//
//	allowList := any node has enablelb=true
//	eligible(n) := (!allowList || n.enablelb == "true")
//	            && (svc has no lbpool || n in pool, by either form)
//	            && addrs[n] is advertisable
//
// addrs is SERVER-HELD data (each node's mesh address from its MeshPeer record,
// plus the server's own derived address), never Node.status.addresses, which the
// node writes itself: a node with no server-held address is never selected.
// Cordon and Ready do not remove a host from the stamp, matching a DaemonSet;
// Ready gates only the status (computeIngress).
func selectHosts(nodes []*corev1.Node, svc *corev1.Service, addrs map[string]netip.Addr) []string {
	allowList := allowListMode(nodes)
	pool, hasPool := svc.Labels[LBPoolLabel]
	var hosts []string
	for _, n := range nodes {
		if n == nil {
			continue
		}
		if allowList && n.Labels[EnableLBLabel] != "true" {
			continue
		}
		if hasPool && !inPool(n, pool) {
			continue
		}
		if !advertisable(addrs[n.Name]) {
			continue
		}
		hosts = append(hosts, n.Name)
	}
	slices.Sort(hosts)
	return hosts
}

// formatHosts renders a host set as the HostsAnnotation value.
func formatHosts(hosts []string) string { return strings.Join(hosts, ",") }

// parseHosts reads a Service's stamp. present is false when the annotation is
// absent (no decider has decided this Service).
func parseHosts(svc *corev1.Service) (hosts map[string]bool, present bool) {
	v, ok := svc.Annotations[HostsAnnotation]
	if !ok {
		return nil, false
	}
	hosts = make(map[string]bool)
	for _, h := range strings.Split(v, ",") {
		if h = strings.TrimSpace(h); h != "" {
			hosts[h] = true
		}
	}
	return hosts, true
}

// reportEntry is svc's entry in a bound report. The uid binds the entry to one
// incarnation of the Service, so a deleted and recreated Service is not
// advertised on a report its predecessor earned.
func reportEntry(svc *corev1.Service) string {
	return svc.Namespace + "/" + svc.Name + ":" + string(svc.UID)
}

// boundReport is a decoded BoundAnnotation.
type boundReport struct {
	// incarnation names the hoster process (and own-Ready period) that wrote the
	// report. The decider uses it to tell a report written after a node's Ready
	// transition from one left over from before it.
	incarnation string
	entries     map[string]bool
}

// formatBound renders a bound report. Entries are sorted; the result is capped
// at maxBoundBytes, and truncated reports that the cap dropped is true.
func formatBound(incarnation string, entries []string) (value string, truncated bool) {
	sorted := slices.Clone(entries)
	slices.Sort(sorted)
	var b strings.Builder
	b.WriteString(incarnation)
	b.WriteByte(';')
	for i, e := range sorted {
		sep := 0
		if i > 0 {
			sep = 1
		}
		if b.Len()+sep+len(e) > maxBoundBytes {
			return b.String(), true
		}
		if sep == 1 {
			b.WriteByte(',')
		}
		b.WriteString(e)
	}
	return b.String(), false
}

// parseBound decodes a BoundAnnotation value. ok is false for a value without
// the incarnation separator, which no hoster writes; it is treated as no report.
func parseBound(v string) (boundReport, bool) {
	inc, list, found := strings.Cut(v, ";")
	if !found || inc == "" {
		return boundReport{}, false
	}
	r := boundReport{incarnation: inc, entries: make(map[string]bool)}
	for _, e := range strings.Split(list, ",") {
		if e != "" {
			r.entries[e] = true
		}
	}
	return r, true
}

// nodeReady reports whether n's Ready condition is True.
func nodeReady(n *corev1.Node) bool {
	for _, c := range n.Status.Conditions {
		if c.Type == corev1.NodeReady {
			return c.Status == corev1.ConditionTrue
		}
	}
	return false
}

// computeIngress is the whole status.loadBalancer.ingress slice for svc: one
// entry per host that is Ready AND whose trusted report lists this incarnation
// of svc, at its server-held address, sorted by address. The decider REPLACES
// the slice with it on every write (k3s semantics), so a node leaving a pool
// loses only its own entry and a previous life's address is never stranded.
// An empty result is the honest pending state.
func computeIngress(nodes []*corev1.Node, svc *corev1.Service, hosts []string, addrs map[string]netip.Addr, reports map[string]boundReport) []corev1.LoadBalancerIngress {
	byName := make(map[string]*corev1.Node, len(nodes))
	for _, n := range nodes {
		if n != nil {
			byName[n.Name] = n
		}
	}
	entry := reportEntry(svc)
	var ips []netip.Addr
	for _, h := range hosts {
		n := byName[h]
		if n == nil || !nodeReady(n) {
			continue
		}
		r, ok := reports[h]
		if !ok || !r.entries[entry] {
			continue
		}
		a := addrs[h]
		if !advertisable(a) {
			continue
		}
		ips = append(ips, a)
	}
	slices.SortFunc(ips, func(a, b netip.Addr) int { return a.Compare(b) })
	ips = slices.Compact(ips)
	out := make([]corev1.LoadBalancerIngress, 0, len(ips))
	for _, a := range ips {
		out = append(out, corev1.LoadBalancerIngress{IP: a.String()})
	}
	return out
}

// ingressEqual reports whether the live slice is exactly want (IP-only entries,
// same order). Any extra field on a live entry counts as a difference, so the
// replace-on-reconcile write also repairs a foreign shape.
func ingressEqual(live, want []corev1.LoadBalancerIngress) bool {
	if len(live) != len(want) {
		return false
	}
	for i := range live {
		l := live[i]
		if l.IP != want[i].IP || l.Hostname != "" || l.IPMode != nil || len(l.Ports) != 0 {
			return false
		}
	}
	return true
}

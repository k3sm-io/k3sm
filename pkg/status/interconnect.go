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
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"sort"
	"strings"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"

	netv1alpha1 "k3sm.io/apis/net/v1alpha1"
)

// RowInterconnect is the cluster's interconnect: whether an admin armed it, how
// many cabled nodes are up, and which pods hold an interconnect address.
const RowInterconnect = "interconnect"

// Interconnect is the report's interconnect block: the row's facts as fields,
// and the attached pods one by one. It is present only when the cluster has an
// Interconnect object this report could read.
type Interconnect struct {
	// Name is the Interconnect's name (its medium, e.g. "thunderbolt").
	Name string `json:"name"`
	// Armed is whether an admin enabled it. Nothing gets an interconnect
	// address until one does.
	Armed bool `json:"armed"`
	// ArmedBy is the identity recorded when it was armed.
	ArmedBy string `json:"armedBy,omitempty"`
	// Plaintext is true whenever it is armed: opted-in pod traffic crosses the
	// cable unencrypted, and any device on a cabled port can reach and spoof
	// interconnect addresses.
	Plaintext bool `json:"plaintext"`
	// Members is how many cabled nodes the server resolved, and Up how many of
	// them are usable.
	Members int `json:"members"`
	Up      int `json:"up"`
	// Segments is how many islands of mutually reachable members there are.
	Segments int `json:"segments"`
	// OutOfRange names the cabled nodes whose cluster index is above
	// netv1alpha1.MaxInterconnectNodeIndex, which get no interconnect address.
	OutOfRange []string `json:"outOfRange,omitempty"`
	// Pods are the pods holding an interconnect address, from their
	// k3sm.io/InterconnectAttached condition.
	Pods []InterconnectPod `json:"pods,omitempty"`
}

// InterconnectPod is one pod holding an interconnect address.
type InterconnectPod struct {
	Namespace string `json:"namespace"`
	Pod       string `json:"pod"`
	Node      string `json:"node"`
	Address   string `json:"address"`
}

// interconnectPath is the apiserver path of the one Interconnect a cluster has
// (named for its medium).
var interconnectPath = "/apis/" + netv1alpha1.SchemeGroupVersion.Group + "/" +
	netv1alpha1.SchemeGroupVersion.Version + "/interconnects/" + netv1alpha1.MediumThunderbolt

// ReadInterconnect reads the cluster's Interconnect through kube. A cluster that
// has none (no node ever reported a cable, so the server never created it) is
// (nil, nil); every other failure is returned as it stands.
func ReadInterconnect(ctx context.Context, kube Kube) (*netv1alpha1.Interconnect, error) {
	raw, err := kube.RawGet(ctx, interconnectPath)
	if apierrors.IsNotFound(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if len(raw) == 0 {
		return nil, nil
	}
	var ic netv1alpha1.Interconnect
	if err := json.Unmarshal(raw, &ic); err != nil {
		return nil, fmt.Errorf("decode the interconnect: %w", err)
	}
	return &ic, nil
}

// InterconnectPods returns the pods whose k3sm.io/InterconnectAttached
// condition is True, sorted by namespace and name. The provider writes the
// medium as the reason and the address as the message; a message that is not
// an interconnect address is reported as an empty address rather than quoted.
func InterconnectPods(pods []corev1.Pod) []InterconnectPod {
	cidr := netip.MustParsePrefix(netv1alpha1.InterconnectCIDR)
	var out []InterconnectPod
	for _, p := range pods {
		for _, c := range p.Status.Conditions {
			if string(c.Type) != netv1alpha1.ConditionInterconnectAttached || c.Status != corev1.ConditionTrue {
				continue
			}
			addr := ""
			if a, err := netip.ParseAddr(strings.TrimSpace(c.Message)); err == nil && cidr.Contains(a) {
				addr = a.String()
			}
			out = append(out, InterconnectPod{Namespace: p.Namespace, Pod: p.Name, Node: p.Spec.NodeName, Address: addr})
			break
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Namespace != out[j].Namespace {
			return out[i].Namespace < out[j].Namespace
		}
		return out[i].Pod < out[j].Pod
	})
	return out
}

// InterconnectRow builds the interconnect row and block from the Interconnect
// and the cluster's pods. podsErr is the pod list's error, which leaves the pod
// count unknown rather than zero.
//
// Disarmed is a SKIP: it is the default, and arming is an admin's trust
// decision, not a repair. Armed with every member up is ok; armed with a member
// down, or a cabled node outside the index ceiling, is a WARN with the next
// step. The row is advisory (advisoryRows): the interconnect is an opt-in
// network beside the mesh, and a node that is not using the cable is not a
// degraded cluster.
func InterconnectRow(ic *netv1alpha1.Interconnect, pods []corev1.Pod, podsErr error) (Row, *Interconnect) {
	block := &Interconnect{
		Name:      ic.Name,
		Armed:     ic.Spec.Enabled,
		ArmedBy:   ic.Status.ArmedBy,
		Plaintext: ic.Spec.Enabled,
		Members:   len(ic.Status.Members),
		Segments:  len(ic.Status.Segments),
	}
	if block.Name == "" {
		block.Name = netv1alpha1.MediumThunderbolt
	}
	var down []string
	for _, m := range ic.Status.Members {
		switch {
		case m.Index > netv1alpha1.MaxInterconnectNodeIndex:
			block.OutOfRange = append(block.OutOfRange, m.Node)
		case m.State == netv1alpha1.InterconnectMemberUp:
			block.Up++
		default:
			down = append(down, fmt.Sprintf("%s (%s)", m.Node, m.State))
		}
	}
	sort.Strings(block.OutOfRange)
	sort.Strings(down)
	block.Pods = InterconnectPods(pods)

	row := Row{Name: RowInterconnect, Wide: map[string]string{}}
	for _, p := range block.Pods {
		row.Wide["pod "+p.Namespace+"/"+p.Pod] = strings.TrimSpace(p.Node + " " + p.Address)
	}
	if ic.Status.ArmedAt != nil {
		row.Wide["armed-at"] = ic.Status.ArmedAt.UTC().Format("2006-01-02T15:04:05Z")
	}

	if !block.Armed {
		row.State, row.Severity = StateDisabled, SeveritySkip
		row.Detail = fmt.Sprintf("%s: disarmed, so nothing has an interconnect address (%s reported a cable); an admin arms it with `k3sm interconnect enable`",
			block.Name, plural(block.Members, "node"))
		return row, block
	}

	attached := plural(len(block.Pods), "pod") + " attached"
	if podsErr != nil {
		attached = "attached pods unknown (" + firstLine(podsErr.Error()) + ")"
	}
	who := block.ArmedBy
	if who == "" {
		who = "an unrecorded identity"
	}
	detail := fmt.Sprintf("%s: %d up, %s, %s (plaintext), armed by %s",
		block.Name, block.Up, plural(block.Segments, "segment"), attached, who)
	var remedy []string
	if len(down) > 0 {
		detail += "; not up: " + strings.Join(down, ", ")
		remedy = append(remedy, "k3sm doctor   # on each cabled Mac that is not up: bridge0, its address, its peers")
	}
	if len(block.OutOfRange) > 0 {
		detail += fmt.Sprintf("; cluster index above %d, so no interconnect address: %s",
			netv1alpha1.MaxInterconnectNodeIndex, strings.Join(block.OutOfRange, ", "))
		remedy = append(remedy, fmt.Sprintf(
			`k3sm kubectl patch interconnect %s --type merge -p '{"spec":{"excludedNodes":["%s"]}}'   # or cable only nodes with cluster index 0..%d`,
			block.Name, block.OutOfRange[0], netv1alpha1.MaxInterconnectNodeIndex))
	}
	row.Detail, row.Remedy = detail, strings.Join(remedy, "\n")
	switch {
	case len(remedy) == 0 && block.Up > 0:
		row.State, row.Severity = StateOK, SeverityOK
	case block.Up > 0:
		row.State, row.Severity = StatePartial, SeverityWarn
	default:
		row.State, row.Severity = StateDown, SeverityWarn
		if len(remedy) == 0 {
			row.Remedy = "k3sm doctor   # on each cabled Mac: bridge0, its address, its peers"
		}
	}
	return row, block
}

// interconnectReadErrorRow is the row for an Interconnect this report could not
// read. A refusal is the ordinary answer on a worker, whose node credential is
// deliberately given no access to the object: a SKIP that says where to look,
// never a fault.
func interconnectReadErrorRow(err error) Row {
	if apierrors.IsForbidden(err) || apierrors.IsUnauthorized(err) {
		return Row{Name: RowInterconnect, State: StateSkip, Severity: SeveritySkip,
			Detail: "this credential may not read the Interconnect (a worker's node credential never can); run `k3sm status` on a control-plane Mac"}
	}
	return Row{Name: RowInterconnect, State: StateUnknown, Severity: SeverityUnknown,
		Detail: "could not read the Interconnect: " + firstLine(err.Error())}
}

// interconnectRow is Collect's interconnect row and block: present only when
// the apiserver is serving, the Interconnect seam is wired, and the cluster has
// an Interconnect (or this credential was refused one).
func (c Collector) interconnectRow(ctx context.Context, serving bool) (Row, *Interconnect, bool) {
	if !serving || c.Interconnect == nil || c.Kube == nil {
		return Row{}, nil, false
	}
	ic, err := c.Interconnect(ctx)
	if err != nil {
		return interconnectReadErrorRow(err), nil, true
	}
	if ic == nil {
		return Row{}, nil, false
	}
	pods, podsErr := c.Kube.Pods(ctx)
	row, block := InterconnectRow(ic, pods, podsErr)
	return row, block, true
}

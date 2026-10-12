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
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"

	netv1alpha1 "k3sm.io/apis/net/v1alpha1"

	"k3sm.io/k3sm/pkg/install"
	"k3sm.io/k3sm/pkg/status"
)

// interconnectKube answers the interconnect GET and the pod list over the
// staged Mac's production client seam, and hands every other call to it. The
// Interconnect is served as the apiserver would: JSON at its path, a NotFound
// when the cluster has none, or the error the case names.
type interconnectKube struct {
	status.Kube
	ic    *netv1alpha1.Interconnect
	icErr error
	pods  []corev1.Pod
	gets  *[]string
}

func (k interconnectKube) RawGet(ctx context.Context, path string) ([]byte, error) {
	if !strings.HasPrefix(path, "/apis/net.k3sm.io/") {
		return k.Kube.RawGet(ctx, path)
	}
	*k.gets = append(*k.gets, path)
	switch {
	case k.icErr != nil:
		return nil, k.icErr
	case k.ic == nil:
		return nil, apierrors.NewNotFound(schema.GroupResource{Group: "net.k3sm.io", Resource: "interconnects"}, netv1alpha1.MediumThunderbolt)
	}
	return json.Marshal(k.ic)
}

func (k interconnectKube) Pods(context.Context) ([]corev1.Pod, error) { return k.pods, nil }

// icPod is a pod on node whose attach condition is True with addr, exactly as
// the provider records it (the medium as reason, the address as message).
func icPod(ns, name, node, addr string) corev1.Pod {
	p := corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name}}
	p.Spec.NodeName = node
	p.Status.Phase = corev1.PodRunning
	p.Status.Conditions = []corev1.PodCondition{{
		Type:    corev1.PodConditionType(netv1alpha1.ConditionInterconnectAttached),
		Status:  corev1.ConditionTrue,
		Reason:  netv1alpha1.MediumThunderbolt,
		Message: addr,
	}}
	return p
}

// armedInterconnect is an armed thunderbolt Interconnect with the given members
// in one segment.
func armedInterconnect(members ...netv1alpha1.InterconnectMember) *netv1alpha1.Interconnect {
	at := metav1.NewTime(time.Date(2026, 10, 12, 9, 0, 0, 0, time.UTC))
	ic := &netv1alpha1.Interconnect{
		ObjectMeta: metav1.ObjectMeta{Name: netv1alpha1.MediumThunderbolt},
		Spec:       netv1alpha1.InterconnectSpec{Medium: netv1alpha1.MediumThunderbolt, Enabled: true},
		Status:     netv1alpha1.InterconnectStatus{Members: members, ArmedBy: "alice", ArmedAt: &at},
	}
	var nodes []string
	for _, m := range members {
		if m.State == netv1alpha1.InterconnectMemberUp {
			nodes = append(nodes, m.Node)
		}
	}
	if len(nodes) > 0 {
		ic.Status.Segments = []netv1alpha1.InterconnectSegment{{ID: "s0", Nodes: nodes}}
	}
	return ic
}

// collectInterconnect runs the whole status report for a staged control plane
// whose apiserver serves ic (and pods), with the Interconnect read through the
// production wiring, statusInterconnect.
func collectInterconnect(t *testing.T, ic *netv1alpha1.Interconnect, icErr error, pods []corev1.Pod) (status.Report, []string) {
	t.Helper()
	mac := stageNodeMac(t, macOpts{role: install.RoleServer, serverWorkDir: true})
	var gets []string
	rep, _, err := collectFrom(t, mac, install.RoleServer, true, func(c *status.Collector) {
		c.Kube = interconnectKube{Kube: c.Kube, ic: ic, icErr: icErr, pods: pods, gets: &gets}
		c.Interconnect = statusInterconnect(c.Kube)
	})
	if err != nil {
		t.Fatalf("resolve the staged control plane's credentials: %v", err)
	}
	return rep, gets
}

// TestStatusInterconnectRow is the status gate of the interconnect: `k3sm
// status` carries a row and a JSON block for the cluster's Interconnect. The
// row says whether it is armed, by whom, how many cabled nodes are up, how many
// segments and attached pods there are, and that the traffic is plaintext; the
// block lists every attached pod with its node and address. A cabled node beyond
// the index ceiling is named and never fails the cluster's verdict.
func TestStatusInterconnectRow(t *testing.T) {
	t.Run("disarmed", func(t *testing.T) {
		ic := armedInterconnect(netv1alpha1.InterconnectMember{Node: "k3sm-mac", Index: 0, State: netv1alpha1.InterconnectMemberDown})
		ic.Spec.Enabled = false
		ic.Status.ArmedBy, ic.Status.ArmedAt = "", nil
		rep, gets := collectInterconnect(t, ic, nil, nil)

		if len(gets) != 1 {
			t.Fatalf("the Interconnect was read %d times, want once: %v", len(gets), gets)
		}
		row, ok := rep.Row(status.RowInterconnect)
		if !ok {
			t.Fatalf("no interconnect row:\n%s", status.Render(rep, status.Style{}))
		}
		if row.State != status.StateDisabled || row.Severity != status.SeveritySkip {
			t.Errorf("row = %s/%s, want disabled/skip (disarmed is the default, not a fault)", row.State, row.Severity)
		}
		for _, want := range []string{"thunderbolt: disarmed", "k3sm interconnect enable"} {
			if !strings.Contains(row.Detail, want) {
				t.Errorf("detail %q does not say %q", row.Detail, want)
			}
		}
		if strings.Contains(row.Detail, "plaintext") {
			t.Errorf("a disarmed interconnect carries no traffic, yet the row says plaintext: %q", row.Detail)
		}
		if rep.Interconnect == nil || rep.Interconnect.Armed || rep.Interconnect.Plaintext {
			t.Errorf("block = %+v, want present, armed false, plaintext false", rep.Interconnect)
		}
		if rep.Verdict != status.VerdictRunning {
			t.Errorf("verdict = %v (%s): a disarmed interconnect must not move it", rep.Verdict, rep.Summary)
		}
	})

	t.Run("armed with members and pods", func(t *testing.T) {
		ic := armedInterconnect(
			netv1alpha1.InterconnectMember{Node: "k3sm-mac", Index: 0, Address: "169.254.0.1", State: netv1alpha1.InterconnectMemberUp, Segment: "s0"},
			netv1alpha1.InterconnectMember{Node: "studio", Index: 1, Address: "169.254.0.9", State: netv1alpha1.InterconnectMemberUp, Segment: "s0"},
		)
		pods := []corev1.Pod{
			icPod("mlx", "llama-0", "k3sm-mac", "169.254.0.2"),
			icPod("mlx", "llama-1", "studio", "169.254.0.10"),
			icPod("default", "bench", "studio", "169.254.0.11"),
			// Not attached: no condition, and a False one.
			{ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "web"}, Spec: corev1.PodSpec{NodeName: "k3sm-mac"}},
			func() corev1.Pod {
				p := icPod("default", "fell-back", "k3sm-mac", "")
				p.Status.Conditions[0].Status, p.Status.Conditions[0].Reason = corev1.ConditionFalse, netv1alpha1.ReasonInterconnectSlotsExhausted
				return p
			}(),
		}
		rep, _ := collectInterconnect(t, ic, nil, pods)

		row, ok := rep.Row(status.RowInterconnect)
		if !ok {
			t.Fatalf("no interconnect row:\n%s", status.Render(rep, status.Style{}))
		}
		if row.State != status.StateOK || row.Severity != status.SeverityOK {
			t.Errorf("row = %s/%s (%q), want ok/ok", row.State, row.Severity, row.Detail)
		}
		if want := "thunderbolt: 2 up, 1 segment, 3 pods attached (plaintext), armed by alice"; row.Detail != want {
			t.Errorf("detail = %q, want %q", row.Detail, want)
		}
		wantPods := []status.InterconnectPod{
			{Namespace: "default", Pod: "bench", Node: "studio", Address: "169.254.0.11"},
			{Namespace: "mlx", Pod: "llama-0", Node: "k3sm-mac", Address: "169.254.0.2"},
			{Namespace: "mlx", Pod: "llama-1", Node: "studio", Address: "169.254.0.10"},
		}
		want := &status.Interconnect{Name: "thunderbolt", Armed: true, ArmedBy: "alice", Plaintext: true, Members: 2, Up: 2, Segments: 1, Pods: wantPods}
		if !reflect.DeepEqual(rep.Interconnect, want) {
			t.Errorf("block = %+v\nwant    %+v", rep.Interconnect, want)
		}

		// The default screen carries the row, and the cluster view lists the
		// pods with their node and address.
		if screen := status.Render(rep, status.Style{}); !strings.Contains(screen, "interconnect") || !strings.Contains(screen, "3 pods attached (plaintext)") {
			t.Errorf("the overview does not carry the interconnect row:\n%s", screen)
		}
		cluster := status.RenderCluster(rep, status.Style{})
		for _, p := range wantPods {
			if !strings.Contains(cluster, "pod "+p.Namespace+"/"+p.Pod) || !strings.Contains(cluster, p.Node+" "+p.Address) {
				t.Errorf("the cluster view does not list %s/%s on %s at %s:\n%s", p.Namespace, p.Pod, p.Node, p.Address, cluster)
			}
		}

		// -o json carries the block under "interconnect", each pod's four keys.
		raw, err := json.Marshal(rep)
		if err != nil {
			t.Fatal(err)
		}
		var doc struct {
			Interconnect struct {
				Plaintext bool `json:"plaintext"`
				Pods      []map[string]string
			} `json:"interconnect"`
		}
		if err := json.Unmarshal(raw, &doc); err != nil {
			t.Fatal(err)
		}
		if !doc.Interconnect.Plaintext || len(doc.Interconnect.Pods) != 3 || doc.Interconnect.Pods[0]["address"] != "169.254.0.11" || doc.Interconnect.Pods[0]["node"] != "studio" {
			t.Errorf("JSON interconnect block = %s", raw)
		}
	})

	t.Run("an out-of-range node", func(t *testing.T) {
		ic := armedInterconnect(
			netv1alpha1.InterconnectMember{Node: "k3sm-mac", Index: 0, Address: "169.254.0.1", State: netv1alpha1.InterconnectMemberUp, Segment: "s0"},
			netv1alpha1.InterconnectMember{Node: "studio", Index: 1, Address: "169.254.0.9", State: netv1alpha1.InterconnectMemberUp, Segment: "s0"},
			netv1alpha1.InterconnectMember{Node: "far-mac", Index: 31, State: netv1alpha1.InterconnectMemberDown},
		)
		rep, _ := collectInterconnect(t, ic, nil, nil)
		row, ok := rep.Row(status.RowInterconnect)
		if !ok {
			t.Fatal("no interconnect row")
		}
		if row.Severity != status.SeverityWarn || row.State != status.StatePartial {
			t.Errorf("row = %s/%s, want partial/warn", row.State, row.Severity)
		}
		for _, want := range []string{"2 up", "cluster index above 30", "far-mac"} {
			if !strings.Contains(row.Detail, want) {
				t.Errorf("detail %q does not say %q", row.Detail, want)
			}
		}
		if strings.Contains(row.Detail, "not up: far-mac") {
			t.Errorf("an out-of-range node is reported as a down member, not by its reason: %q", row.Detail)
		}
		if !strings.Contains(row.Remedy, `"excludedNodes":["far-mac"]`) {
			t.Errorf("remedy %q does not offer to exclude far-mac", row.Remedy)
		}
		if want := []string{"far-mac"}; rep.Interconnect == nil || !reflect.DeepEqual(rep.Interconnect.OutOfRange, want) || rep.Interconnect.Up != 2 {
			t.Errorf("block = %+v, want outOfRange %v and 2 up", rep.Interconnect, want)
		}
		if rep.Verdict != status.VerdictRunning {
			t.Errorf("verdict = %v (%s): a node beyond the ceiling never fails the cluster", rep.Verdict, rep.Summary)
		}
	})

	t.Run("no Interconnect and a refused read", func(t *testing.T) {
		rep, gets := collectInterconnect(t, nil, nil, nil)
		if len(gets) != 1 {
			t.Errorf("the Interconnect was read %d times, want once", len(gets))
		}
		if _, ok := rep.Row(status.RowInterconnect); ok || rep.Interconnect != nil {
			t.Errorf("a cluster with no Interconnect got a row or a block: %+v", rep.Interconnect)
		}

		forbidden := apierrors.NewForbidden(schema.GroupResource{Group: "net.k3sm.io", Resource: "interconnects"}, "thunderbolt", nil)
		rep, _ = collectInterconnect(t, nil, forbidden, nil)
		row, ok := rep.Row(status.RowInterconnect)
		if !ok || row.Severity != status.SeveritySkip || !strings.Contains(row.Detail, "control-plane Mac") {
			t.Errorf("a refused read = %+v, want a skip row pointing at the control plane", row)
		}
	})
}

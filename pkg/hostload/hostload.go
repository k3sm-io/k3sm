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

// Package hostload turns a node's busy host CPU into a scheduling preference.
//
// A k3sm node shares its Mac with the operator's own work. The scheduler scores
// nodes on pod requests against a static allocatable, so a Mac whose host
// processes hold every core still looks empty to it, and new pods keep landing
// there while another Mac idles. The node reports what it sees as the
// HostCPUBusy condition (pkg/provider), and the Reconciler here, on the server,
// adds the TaintKey PreferNoSchedule taint to a node while that condition is
// True and removes it otherwise.
//
// The split is forced: NodeRestriction forbids a node from changing its own
// taints, so the node can only report, and a server identity applies.
//
// PreferNoSchedule is upstream's soft effect. The TaintToleration score plugin
// scores a node with an untolerated PreferNoSchedule taint below one without,
// and no filter reads it, so a pod still lands on a busy node when it is the
// only feasible one: a pod pinned by nodeName or nodeSelector, a DaemonSet pod,
// or any pod when every node is busy. Nothing is evicted or refused.
package hostload

import (
	"slices"

	corev1 "k8s.io/api/core/v1"
)

const (
	// ConditionHostCPUBusy is the node condition the provider publishes: True
	// while the host's smoothed CPU utilization, every process on the Mac and
	// not only pods, is past the busy threshold.
	ConditionHostCPUBusy corev1.NodeConditionType = "HostCPUBusy"

	// TaintKey is the taint the Reconciler applies, always with
	// corev1.TaintEffectPreferNoSchedule.
	TaintKey = "k3sm.io/host-cpu-busy"
)

// Condition reasons. ReasonBusy and ReasonAvailable are the two published
// verdicts; a node that has not yet measured a rate publishes no condition.
const (
	ReasonBusy      = "HostCPUBusy"
	ReasonAvailable = "HostCPUAvailable"
)

// Busy reports whether n currently publishes HostCPUBusy=True. A missing
// condition (an older node, or one that has not measured a rate yet) is not
// busy.
func Busy(n *corev1.Node) bool {
	c := condition(n)
	return c != nil && c.Status == corev1.ConditionTrue
}

// Reported reports whether n publishes a HostCPUBusy condition at all.
func Reported(n *corev1.Node) bool { return condition(n) != nil }

func condition(n *corev1.Node) *corev1.NodeCondition {
	for i := range n.Status.Conditions {
		if n.Status.Conditions[i].Type == ConditionHostCPUBusy {
			return &n.Status.Conditions[i]
		}
	}
	return nil
}

// DesiredTaints returns n's taints with the TaintKey taint present when want is
// true and absent when it is false, and whether that differs from n's taints.
// Every other taint is kept as it is, in order, including a TaintKey taint
// with another effect, which this package never wrote.
func DesiredTaints(n *corev1.Node, want bool) ([]corev1.Taint, bool) {
	out := make([]corev1.Taint, 0, len(n.Spec.Taints)+1)
	have := false
	for _, t := range n.Spec.Taints {
		if isOurs(t) {
			if want && !have {
				out = append(out, t)
			}
			have = true
			continue
		}
		out = append(out, t)
	}
	if want && !have {
		out = append(out, corev1.Taint{Key: TaintKey, Effect: corev1.TaintEffectPreferNoSchedule})
	}
	return out, !slices.EqualFunc(out, n.Spec.Taints, func(a, b corev1.Taint) bool { return a.MatchTaint(&b) })
}

// isOurs reports whether t is the taint this package manages: our key and
// effect with no value. A taint on our key with a value was written by someone
// else and is left alone.
func isOurs(t corev1.Taint) bool {
	return t.Key == TaintKey && t.Effect == corev1.TaintEffectPreferNoSchedule && t.Value == ""
}

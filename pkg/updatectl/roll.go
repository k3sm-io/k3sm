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

package updatectl

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	updatesv1alpha1 "k3sm.io/apis/updates/v1alpha1"
)

// CordonedAnnotation marks a Node this controller cordoned, so it lifts only
// its own cordon and never one an operator set. It is private to the
// controller: the node-side never reads or writes it.
const CordonedAnnotation = "k3sm.io/update-cordoned"

// controlPlaneLabel marks a server Node.
const controlPlaneLabel = "node-role.kubernetes.io/control-plane"

// maxNodes is the CRD's bound on status.nodes.
const maxNodes = 64

// The condition types beside updatesv1alpha1.UpdateConditionReconciled.
const (
	ConditionProgressing = "Progressing"
	ConditionSucceeded   = "Succeeded"
	ConditionFailed      = "Failed"
)

// The condition reasons this controller writes.
const (
	ReasonSingleton = "Singleton"
	ReasonRolling   = "Rolling"
	ReasonRetrying  = "Retrying"
	ReasonSucceeded = "Succeeded"
	ReasonFailed    = "Failed"
	ReasonCancelled = "Cancelled"
)

// Payload is the JSON value of the k3sm.io/update-payload Node annotation: what
// the node-side downloads and the proof it must check before installing.
type Payload struct {
	// URL is the darwin/arm64 release archive.
	URL string `json:"url"`
	// SHA256 is the archive's lowercase hex sha256, from the release's
	// checksums file.
	SHA256 string `json:"sha256"`
	// Signature is the code-signature policy (Spec.Verify.Signature, defaulted
	// to if-signed).
	Signature updatesv1alpha1.UpdateSignaturePolicy `json:"signature"`
	// AllowDowngrade is Spec.AllowDowngrade.
	AllowDowngrade bool `json:"allowDowngrade,omitempty"`
}

// rollFailure is a definitive failure that ends the roll before the current
// node is touched.
type rollFailure struct{ err error }

func (f rollFailure) Error() string { return f.err.Error() }
func (f rollFailure) Unwrap() error { return f.err }

// roll advances the singleton as far as it can go without waiting and returns
// when the next pass is due. It mutates only u.Status (and the Nodes through
// the API).
func (c *Controller) roll(ctx context.Context, u *updatesv1alpha1.Update) time.Duration {
	now := c.cfg.Now().UTC().Truncate(time.Second)
	st := &u.Status
	st.ObservedGeneration = u.Generation
	c.setCondition(u, updatesv1alpha1.UpdateConditionReconciled, metav1.ConditionTrue, ReasonSingleton,
		"this is the Update the controller rolls")
	if finished(u) {
		return idleResync
	}

	list, err := c.cfg.Client.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	if err != nil {
		c.progress(u, ReasonRetrying, fmt.Sprintf("list nodes: %v", err))
		return errorBackoff
	}
	byName := make(map[string]*corev1.Node, len(list.Items))
	for i := range list.Items {
		byName[list.Items[i].Name] = &list.Items[i]
	}
	if len(st.Nodes) == 0 {
		if err := c.plan(u, list.Items); err != nil {
			c.fail(u, err.Error())
			return idleResync
		}
	}

	for i := range st.Nodes {
		e := &st.Nodes[i]
		switch e.Phase {
		case updatesv1alpha1.UpdateNodePhaseDone, updatesv1alpha1.UpdateNodePhaseSkipped, updatesv1alpha1.UpdateNodePhaseCancelled:
			continue
		case updatesv1alpha1.UpdateNodePhaseFailed:
			c.fail(u, fmt.Sprintf("node %s: %s", e.Name, e.Message))
			return idleResync
		case "", updatesv1alpha1.UpdateNodePhasePending:
			if u.Spec.Cancel {
				c.cancelFrom(u, i)
				return idleResync
			}
		}
		if err := c.advance(ctx, u, e, byName[e.Name], now); err != nil {
			var rf rollFailure
			if errors.As(err, &rf) {
				c.fail(u, rf.Error())
				return idleResync
			}
			c.progress(u, ReasonRetrying, fmt.Sprintf("node %s: %v", e.Name, err))
			return errorBackoff
		}
		switch e.Phase {
		case updatesv1alpha1.UpdateNodePhaseDone, updatesv1alpha1.UpdateNodePhaseSkipped:
			continue
		case updatesv1alpha1.UpdateNodePhaseFailed:
			c.fail(u, fmt.Sprintf("node %s: %s", e.Name, e.Message))
			return idleResync
		case updatesv1alpha1.UpdateNodePhaseCancelled:
			c.cancelFrom(u, i+1)
			return idleResync
		}
		c.progress(u, ReasonRolling, fmt.Sprintf("node %s: %s", e.Name, e.Phase))
		return c.cfg.Poll
	}
	c.succeed(u)
	return idleResync
}

// plan records the node order and each node's starting release in status, and
// refuses a request that cannot start: an unusable tag, too many nodes, or a
// downgrade the spec does not allow.
func (c *Controller) plan(u *updatesv1alpha1.Update, nodes []corev1.Node) error {
	tag := u.Spec.Version
	if !validTag(tag) {
		return fmt.Errorf("spec.version %q is not a usable release tag", tag)
	}
	if len(nodes) == 0 {
		return errors.New("the cluster has no nodes")
	}
	if len(nodes) > maxNodes {
		return fmt.Errorf("the cluster has %d nodes; an Update records at most %d", len(nodes), maxNodes)
	}
	ordered := c.order(nodes)
	if !u.Spec.AllowDowngrade {
		for _, n := range ordered {
			if from := fromRelease(n); isDowngrade(from, tag) {
				return fmt.Errorf("node %s runs %s and %s is older; set spec.allowDowngrade to move it back", n.Name, from, tag)
			}
		}
	}
	u.Status.Nodes = make([]updatesv1alpha1.UpdateNodeStatus, 0, len(ordered))
	for _, n := range ordered {
		u.Status.Nodes = append(u.Status.Nodes, updatesv1alpha1.UpdateNodeStatus{
			Name: n.Name, From: fromRelease(n), To: tag, Phase: updatesv1alpha1.UpdateNodePhasePending,
		})
	}
	u.Status.Phase = updatesv1alpha1.UpdatePhasePending
	return nil
}

// order is workers-then-server: every node that is not a server by name, then
// every other server by name, then this controller's own server last.
func (c *Controller) order(nodes []corev1.Node) []*corev1.Node {
	var workers, servers []*corev1.Node
	var self *corev1.Node
	for i := range nodes {
		n := &nodes[i]
		_, cp := n.Labels[controlPlaneLabel]
		switch {
		case n.Name == c.cfg.ServerNode:
			self = n
		case cp:
			servers = append(servers, n)
		default:
			workers = append(workers, n)
		}
	}
	byName := func(s []*corev1.Node) {
		sort.Slice(s, func(i, j int) bool { return s[i].Name < s[j].Name })
	}
	byName(workers)
	byName(servers)
	out := append(workers, servers...)
	if self != nil {
		out = append(out, self)
	}
	return out
}

// advance moves one node entry as far as it can go now. A returned error is
// transient (an API call failed) unless it is a rollFailure.
func (c *Controller) advance(ctx context.Context, u *updatesv1alpha1.Update, e *updatesv1alpha1.UpdateNodeStatus, n *corev1.Node, now time.Time) error {
	tag := u.Spec.Version
	at := metav1.NewTime(now)
	if e.Phase == "" || e.Phase == updatesv1alpha1.UpdateNodePhasePending {
		if n == nil {
			e.Phase, e.Message, e.FinishedAt = updatesv1alpha1.UpdateNodePhaseFailed, "the node no longer exists", &at
			return nil
		}
		if onTarget(n, tag) {
			e.Phase, e.Message, e.FinishedAt = updatesv1alpha1.UpdateNodePhaseSkipped, "already runs "+tag, &at
			return nil
		}
		if err := c.ensureResolved(ctx, u); err != nil {
			return err
		}
		e.From = fromRelease(n)
		e.StartedAt = &at
		e.Phase, e.Message = updatesv1alpha1.UpdateNodePhaseCordoning, "cordoning"
	}
	if n == nil {
		e.Phase, e.Message, e.FinishedAt = updatesv1alpha1.UpdateNodePhaseFailed, "the node was deleted during its update", &at
		return nil
	}
	if e.StartedAt == nil {
		e.StartedAt = &at
	}
	elapsed := now.Sub(e.StartedAt.Time)

	handover := false
	switch e.Phase {
	case updatesv1alpha1.UpdateNodePhaseCordoning, updatesv1alpha1.UpdateNodePhaseDraining:
		if u.Spec.Cancel {
			// Not handed over yet: the cancel lifts this node's cordon and the
			// roll stops here.
			if _, err := c.uncordon(ctx, n); err != nil {
				return err
			}
			e.Phase, e.Message, e.FinishedAt = updatesv1alpha1.UpdateNodePhaseCancelled, "cancelled before the node was handed over", &at
			return nil
		}
		var err error
		if n, err = c.cordon(ctx, n); err != nil {
			return err
		}
		if !u.Spec.Strategy.Drain {
			handover = true
			break
		}
		e.Phase = updatesv1alpha1.UpdateNodePhaseDraining
		remaining, err := c.drain(ctx, n.Name)
		if err != nil {
			return err
		}
		if len(remaining) > 0 {
			if elapsed > c.cfg.DrainTimeout {
				e.Phase, e.FinishedAt = updatesv1alpha1.UpdateNodePhaseFailed, &at
				e.Message = fmt.Sprintf("drain did not finish within %s; %d pods remain: %s",
					c.cfg.DrainTimeout, len(remaining), strings.Join(remaining, ", "))
				return nil
			}
			e.Message = fmt.Sprintf("evicting %d pods", len(remaining))
			return nil
		}
		handover = true
	}
	if handover {
		var err error
		if n, err = c.handover(ctx, u, n); err != nil {
			return err
		}
		e.Phase, e.Message = updatesv1alpha1.UpdateNodePhaseDownloading, "handed to the node; waiting for it to report"
	}
	if !nodeSidePhase(e.Phase) {
		return fmt.Errorf("unknown node phase %q", e.Phase)
	}

	if n.Annotations[updatesv1alpha1.AnnotationUpdateVersion] != tag {
		// Someone moved the request; hand the node this Update's again.
		var err error
		if n, err = c.handover(ctx, u, n); err != nil {
			return err
		}
	}
	reported, msg := parsePhase(n.Annotations[updatesv1alpha1.AnnotationUpdatePhase])
	switch {
	case reported == updatesv1alpha1.UpdateNodePhaseFailed:
		if msg == "" {
			msg = "the node reported Failed"
		}
		e.Phase, e.Message, e.FinishedAt = updatesv1alpha1.UpdateNodePhaseFailed, msg, &at
		return nil
	case reported == updatesv1alpha1.UpdateNodePhaseDone && onTarget(n, tag):
		if _, err := c.uncordon(ctx, n); err != nil {
			return err
		}
		e.Phase, e.Message, e.FinishedAt, e.To = updatesv1alpha1.UpdateNodePhaseDone, "", &at, tag
		return nil
	case reported == updatesv1alpha1.UpdateNodePhaseDone:
		e.Message = "the node reported Done; waiting for its kubeletVersion to carry " + tag
	case nodeSidePhase(reported):
		e.Phase, e.Message = reported, msg
	}
	if elapsed > c.cfg.NodeTimeout {
		e.Phase, e.FinishedAt = updatesv1alpha1.UpdateNodePhaseFailed, &at
		e.Message = fmt.Sprintf("the node did not finish within %s (last: %s)", c.cfg.NodeTimeout, e.Message)
	}
	return nil
}

// nodeSidePhase reports whether p is a step the node-side reports while it
// applies the release.
func nodeSidePhase(p updatesv1alpha1.UpdateNodePhase) bool {
	switch p {
	case updatesv1alpha1.UpdateNodePhaseDownloading, updatesv1alpha1.UpdateNodePhaseVerifying,
		updatesv1alpha1.UpdateNodePhaseInstalling, updatesv1alpha1.UpdateNodePhaseRestarting:
		return true
	}
	return false
}

// parsePhase splits the k3sm.io/update-phase value "<phase>[: <message>]".
func parsePhase(v string) (updatesv1alpha1.UpdateNodePhase, string) {
	p, msg, _ := strings.Cut(v, ":")
	return updatesv1alpha1.UpdateNodePhase(strings.TrimSpace(p)), strings.TrimSpace(msg)
}

// ensureResolved resolves the target once and records it in status.resolved.
func (c *Controller) ensureResolved(ctx context.Context, u *updatesv1alpha1.Update) error {
	if r := u.Status.Resolved; r != nil && r.Version == u.Spec.Version && r.Digest != "" {
		return nil
	}
	rel, err := c.cfg.Resolver.Resolve(ctx, u.Spec.Version)
	if err != nil {
		if errors.Is(err, ErrRelease) {
			return rollFailure{fmt.Errorf("resolve %s: %w", u.Spec.Version, err)}
		}
		return fmt.Errorf("resolve %s: %w", u.Spec.Version, err)
	}
	if !isSHA256Hex(rel.SHA256) {
		return rollFailure{fmt.Errorf("resolve %s: %w: malformed sha256", u.Spec.Version, ErrRelease)}
	}
	u.Status.Resolved = &updatesv1alpha1.UpdateResolved{Version: u.Spec.Version, Digest: "sha256:" + rel.SHA256}
	return nil
}

// payload is the node annotation value, rebuilt from status.resolved.
func (c *Controller) payload(u *updatesv1alpha1.Update) (string, error) {
	r := u.Status.Resolved
	if r == nil || !strings.HasPrefix(r.Digest, "sha256:") {
		return "", errors.New("the release has not been resolved")
	}
	url, err := c.cfg.Resolver.AssetURL(u.Spec.Version)
	if err != nil {
		return "", err
	}
	sig := u.Spec.Verify.Signature
	if sig == "" {
		sig = updatesv1alpha1.UpdateSignatureIfSigned
	}
	b, err := json.Marshal(Payload{
		URL: url, SHA256: strings.TrimPrefix(r.Digest, "sha256:"), Signature: sig, AllowDowngrade: u.Spec.AllowDowngrade,
	})
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// handover asks the node for the release: the version and payload annotations
// are set and any earlier phase report is cleared, in one patch.
func (c *Controller) handover(ctx context.Context, u *updatesv1alpha1.Update, n *corev1.Node) (*corev1.Node, error) {
	p, err := c.payload(u)
	if err != nil {
		return nil, err
	}
	return c.patchNode(ctx, n.Name, map[string]any{
		"metadata": map[string]any{"annotations": map[string]any{
			updatesv1alpha1.AnnotationUpdateVersion: u.Spec.Version,
			updatesv1alpha1.AnnotationUpdatePayload: p,
			updatesv1alpha1.AnnotationUpdatePhase:   nil,
		}},
	})
}

// cordon marks the node unschedulable, unless it already is (then the cordon
// is either ours from an earlier pass or the operator's, and stays as it is).
func (c *Controller) cordon(ctx context.Context, n *corev1.Node) (*corev1.Node, error) {
	if n.Spec.Unschedulable {
		return n, nil
	}
	return c.patchNode(ctx, n.Name, map[string]any{
		"metadata": map[string]any{"annotations": map[string]any{CordonedAnnotation: "true"}},
		"spec":     map[string]any{"unschedulable": true},
	})
}

// uncordon lifts a cordon this controller made, and only that.
func (c *Controller) uncordon(ctx context.Context, n *corev1.Node) (*corev1.Node, error) {
	if n.Annotations[CordonedAnnotation] != "true" {
		return n, nil
	}
	return c.patchNode(ctx, n.Name, map[string]any{
		"metadata": map[string]any{"annotations": map[string]any{CordonedAnnotation: nil}},
		"spec":     map[string]any{"unschedulable": false},
	})
}

func (c *Controller) patchNode(ctx context.Context, name string, patch map[string]any) (*corev1.Node, error) {
	b, err := json.Marshal(patch)
	if err != nil {
		return nil, err
	}
	n, err := c.cfg.Client.CoreV1().Nodes().Patch(ctx, name, types.MergePatchType, b, metav1.PatchOptions{})
	if err != nil {
		return nil, fmt.Errorf("patch node %s: %w", name, err)
	}
	return n, nil
}

// finished reports whether the Update has reached an end state.
func finished(u *updatesv1alpha1.Update) bool {
	p := meta.FindStatusCondition(u.Status.Conditions, ConditionProgressing)
	if p == nil || p.Status != metav1.ConditionFalse {
		return false
	}
	switch p.Reason {
	case ReasonSucceeded, ReasonFailed, ReasonCancelled:
		return true
	}
	return false
}

// progress records an in-flight roll.
func (c *Controller) progress(u *updatesv1alpha1.Update, reason, msg string) {
	u.Status.Phase = updatesv1alpha1.UpdatePhasePending
	for _, e := range u.Status.Nodes {
		if e.Phase != "" && e.Phase != updatesv1alpha1.UpdateNodePhasePending {
			u.Status.Phase = updatesv1alpha1.UpdatePhaseRolling
			break
		}
	}
	c.setCondition(u, ConditionProgressing, metav1.ConditionTrue, reason, msg)
	c.setCondition(u, ConditionSucceeded, metav1.ConditionFalse, ReasonRolling, "the roll has not finished")
	c.setCondition(u, ConditionFailed, metav1.ConditionFalse, ReasonRolling, "no node has failed")
}

// fail ends the roll Failed. Nodes not reached stay Pending.
func (c *Controller) fail(u *updatesv1alpha1.Update, msg string) {
	u.Status.Phase = updatesv1alpha1.UpdatePhaseFailed
	c.setCondition(u, ConditionProgressing, metav1.ConditionFalse, ReasonFailed, msg)
	c.setCondition(u, ConditionSucceeded, metav1.ConditionFalse, ReasonFailed, msg)
	c.setCondition(u, ConditionFailed, metav1.ConditionTrue, ReasonFailed, msg)
}

// cancelFrom marks every entry from i on that has not started Cancelled and
// ends the roll Cancelled.
func (c *Controller) cancelFrom(u *updatesv1alpha1.Update, i int) {
	for j := i; j < len(u.Status.Nodes); j++ {
		e := &u.Status.Nodes[j]
		if e.Phase == "" || e.Phase == updatesv1alpha1.UpdateNodePhasePending {
			e.Phase, e.Message = updatesv1alpha1.UpdateNodePhaseCancelled, "cancelled before it started"
		}
	}
	msg := "spec.cancel stopped the roll"
	u.Status.Phase = updatesv1alpha1.UpdatePhaseCancelled
	c.setCondition(u, ConditionProgressing, metav1.ConditionFalse, ReasonCancelled, msg)
	c.setCondition(u, ConditionSucceeded, metav1.ConditionFalse, ReasonCancelled, msg)
	c.setCondition(u, ConditionFailed, metav1.ConditionFalse, ReasonCancelled, msg)
}

// succeed ends the roll Succeeded.
func (c *Controller) succeed(u *updatesv1alpha1.Update) {
	msg := "every node runs " + u.Spec.Version
	u.Status.Phase = updatesv1alpha1.UpdatePhaseSucceeded
	c.setCondition(u, ConditionProgressing, metav1.ConditionFalse, ReasonSucceeded, msg)
	c.setCondition(u, ConditionSucceeded, metav1.ConditionTrue, ReasonSucceeded, msg)
	c.setCondition(u, ConditionFailed, metav1.ConditionFalse, ReasonSucceeded, msg)
}

// setCondition sets one condition; its transition time moves only when its
// status does.
func (c *Controller) setCondition(u *updatesv1alpha1.Update, typ string, status metav1.ConditionStatus, reason, msg string) {
	meta.SetStatusCondition(&u.Status.Conditions, metav1.Condition{
		Type: typ, Status: status, Reason: reason, Message: msg, ObservedGeneration: u.Generation,
		LastTransitionTime: metav1.NewTime(c.cfg.Now().UTC().Truncate(time.Second)),
	})
}

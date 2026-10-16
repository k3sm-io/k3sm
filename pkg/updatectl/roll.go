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
	"k3sm.io/k3sm/pkg/update"
)

// The controller's own Node annotations. They are private to the controller:
// the node-side never reads or writes them. Each holds what a restarted
// controller needs to resume.
const (
	// CordonedAnnotation marks a Node this controller cordoned, so it lifts
	// only its own cordon and never one an operator set.
	CordonedAnnotation = "k3sm.io/update-cordoned"
	// HandedOverAnnotation is when the node was handed the release (RFC3339);
	// the node timeout counts from it.
	HandedOverAnnotation = "k3sm.io/update-handed-over-at"
	// ReadyAtAnnotation is when the node was first seen done and Ready
	// (RFC3339); the settle period counts from it.
	ReadyAtAnnotation = "k3sm.io/update-ready-at"
)

// SettlePeriod is how long a node must stay done and Ready before it is
// uncordoned and the roll moves on.
const SettlePeriod = 60 * time.Second

// ResolveBound is how long transient release-index failures are retried
// before the Update fails.
const ResolveBound = 10 * time.Minute

// controlPlaneLabel marks a server Node.
const controlPlaneLabel = "node-role.kubernetes.io/control-plane"

// maxNodes is the CRD's bound on status.nodes.
const maxNodes = 64

// The condition types beside updatesv1alpha1.UpdateConditionReconciled.
const (
	ConditionProgressing = "Progressing"
	ConditionSucceeded   = "Succeeded"
	ConditionFailed      = "Failed"
	ConditionResolved    = "Resolved"
)

// The condition reasons this controller writes.
const (
	ReasonSingleton = "Singleton"
	ReasonRolling   = "Rolling"
	ReasonRetrying  = "Retrying"
	ReasonSucceeded = "Succeeded"
	ReasonFailed    = "Failed"
	ReasonCancelled = "Cancelled"
	ReasonResolved  = "Resolved"
)

// Payload is the JSON value of the k3sm.io/update-payload Node annotation, the
// one pkg/update defines, encodes (update.EncodePayload) and verifies.
type Payload = update.Payload

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
				c.cancelFrom(u, i, byName)
				return idleResync
			}
		}
		from := e.Phase
		oldBase, oldAt := splitProgress(e.Message)
		err := c.advance(ctx, u, e, byName[e.Name], now)
		base, _ := splitProgress(e.Message)
		at := oldAt
		if e.Phase != from || base != oldBase || at == "" {
			at = now.Format(time.RFC3339)
		}
		e.Message = withProgress(base, at)
		if err != nil {
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
			c.cancelFrom(u, i+1, byName)
			return idleResync
		}
		c.progress(u, ReasonRolling, fmt.Sprintf("node %s: %s%s%s", e.Name, e.Phase, progressMark, at))
		return c.cfg.Poll
	}
	c.succeed(u)
	return idleResync
}

// progressMark separates a node message from its last-progress time. The
// time is the last moment the node's phase or message changed, so a stalled
// node is visible without a status field for it.
const progressMark = "; last progress "

// splitProgress splits a node message into its text and its last-progress
// time ("" when it carries none).
func splitProgress(msg string) (base, at string) {
	if msg == "" {
		return "", ""
	}
	if strings.HasPrefix(msg, "last progress ") {
		return "", strings.TrimPrefix(msg, "last progress ")
	}
	if i := strings.LastIndex(msg, progressMark); i >= 0 {
		return msg[:i], msg[i+len(progressMark):]
	}
	return msg, ""
}

// withProgress is base with its last-progress time.
func withProgress(base, at string) string {
	if base == "" {
		return "last progress " + at
	}
	return base + progressMark + at
}

// transition reports one node's phase change: an Event on the Update and on
// the Node, and an Info log line.
func (c *Controller) transition(u *updatesv1alpha1.Update, e *updatesv1alpha1.UpdateNodeStatus, from updatesv1alpha1.UpdateNodePhase, n *corev1.Node) {
	base, _ := splitProgress(e.Message)
	c.log.Info("update controller: node phase", "update", u.Name, "version", u.Spec.Version,
		"node", e.Name, "from", string(from), "to", string(e.Phase), "message", base)
	if c.cfg.Recorder == nil {
		return
	}
	typ := corev1.EventTypeNormal
	if e.Phase == updatesv1alpha1.UpdateNodePhaseFailed {
		typ = corev1.EventTypeWarning
	}
	reason := "Node" + string(e.Phase)
	detail := string(e.Phase)
	if base != "" {
		detail += ": " + base
	}
	c.cfg.Recorder.Eventf(&corev1.ObjectReference{
		APIVersion: updatesv1alpha1.SchemeGroupVersion.String(), Kind: "Update", Name: u.Name, UID: u.UID,
	}, typ, reason, "node %s: %s", e.Name, detail)
	ref := &corev1.ObjectReference{APIVersion: "v1", Kind: "Node", Name: e.Name}
	if n != nil {
		ref.UID = n.UID
	}
	c.cfg.Recorder.Eventf(ref, typ, reason, "update to %s: %s", u.Spec.Version, detail)
}

// plan records the node order and each node's starting release in status, and
// refuses a request that cannot start: an unusable tag, too many nodes, a
// drain with nowhere to move pods, or a downgrade the spec does not allow.
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
	if u.Spec.Strategy.Drain && len(nodes) == 1 {
		return errors.New("spec.strategy.drain needs another node to move pods to, and this cluster has one node; create the Update without drain")
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

// advance moves one node entry as far as it can go now, reporting every phase
// it passes through (one pass can go Pending, Cordoning, Draining,
// Downloading). It writes e.Message without its last-progress time (roll adds
// it). A returned error is transient (an API call failed) unless it is a
// rollFailure.
func (c *Controller) advance(ctx context.Context, u *updatesv1alpha1.Update, e *updatesv1alpha1.UpdateNodeStatus, n *corev1.Node, now time.Time) error {
	tag := u.Spec.Version
	at := metav1.NewTime(now)
	last, node := e.Phase, n
	mark := func() {
		if e.Phase != last {
			c.transition(u, e, last, node)
			last = e.Phase
		}
	}
	defer mark()
	if e.Phase == "" || e.Phase == updatesv1alpha1.UpdateNodePhasePending {
		if n == nil {
			e.Phase, e.Message, e.FinishedAt = updatesv1alpha1.UpdateNodePhaseFailed, "the node no longer exists", &at
			return nil
		}
		if onTarget(n, tag) {
			e.Phase, e.Message, e.FinishedAt = updatesv1alpha1.UpdateNodePhaseSkipped, "already runs "+tag, &at
			return nil
		}
		if err := c.ensureResolved(ctx, u, now); err != nil {
			return err
		}
		e.From = fromRelease(n)
		e.StartedAt = &at
		e.Phase, e.Message = updatesv1alpha1.UpdateNodePhaseCordoning, "cordoning"
		mark()
	}
	if n == nil {
		e.Phase, e.Message, e.FinishedAt = updatesv1alpha1.UpdateNodePhaseFailed, "the node was deleted during its update", &at
		return nil
	}
	if e.StartedAt == nil {
		e.StartedAt = &at
	}

	handover := false
	switch e.Phase {
	case updatesv1alpha1.UpdateNodePhaseCordoning, updatesv1alpha1.UpdateNodePhaseDraining:
		if u.Spec.Cancel {
			// Not handed over yet: the cancel lifts this node's cordon and the
			// roll stops here.
			if _, err := c.release(ctx, n); err != nil {
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
		if n.Name == c.cfg.ServerNode {
			// The server is never drained: the install recreates its native
			// pods on the new binary, and evicting them would only move the
			// cluster's control-plane-adjacent pods for nothing.
			handover = true
			break
		}
		e.Phase, e.Message = updatesv1alpha1.UpdateNodePhaseDraining, "draining"
		mark()
		remaining, bare, err := c.drain(ctx, n.Name)
		if err != nil {
			return err
		}
		if len(bare) > 0 {
			e.Phase, e.FinishedAt = updatesv1alpha1.UpdateNodePhaseFailed, &at
			e.Message = fmt.Sprintf("not drained: %d pods have no controller and would not come back: %s; move or delete them, then create a new Update",
				len(bare), strings.Join(bare, ", "))
			return nil
		}
		if len(remaining) > 0 {
			if now.Sub(e.StartedAt.Time) > c.cfg.DrainTimeout {
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
		if n, err = c.handover(ctx, u, n, now); err != nil {
			return err
		}
		e.Phase, e.Message = updatesv1alpha1.UpdateNodePhaseDownloading, "handed to the node; waiting for it to report"
		mark()
	}
	if !nodeSidePhase(e.Phase) {
		return fmt.Errorf("unknown node phase %q", e.Phase)
	}

	if n.Annotations[updatesv1alpha1.AnnotationUpdateVersion] != tag {
		// Someone moved the request; hand the node this Update's again.
		var err error
		if n, err = c.handover(ctx, u, n, now); err != nil {
			return err
		}
	}
	handedAt, ok := annotationTime(n, HandedOverAnnotation)
	if !ok {
		handedAt = e.StartedAt.Time
	}
	ready := nodeReady(n)
	reported, msg := parsePhase(n.Annotations[updatesv1alpha1.AnnotationUpdatePhase])
	switch {
	case reported == updatesv1alpha1.UpdateNodePhaseFailed:
		if msg == "" {
			msg = "the node reported Failed"
		}
		e.Phase, e.Message, e.FinishedAt = updatesv1alpha1.UpdateNodePhaseFailed, msg, &at
		return nil
	case reported == updatesv1alpha1.UpdateNodePhaseDone && onTarget(n, tag) && ready:
		readyAt, settling := annotationTime(n, ReadyAtAnnotation)
		if !settling {
			var err error
			if n, err = c.patchNode(ctx, n.Name, annotations(map[string]any{ReadyAtAnnotation: now.Format(time.RFC3339)})); err != nil {
				return err
			}
			readyAt = now
		}
		if now.Sub(readyAt) >= SettlePeriod {
			if _, err := c.release(ctx, n); err != nil {
				return err
			}
			e.Phase, e.Message, e.FinishedAt, e.To = updatesv1alpha1.UpdateNodePhaseDone, "runs "+tag, &at, tag
			return nil
		}
		e.Message = fmt.Sprintf("runs %s and is Ready; settling until %s", tag, readyAt.Add(SettlePeriod).Format(time.RFC3339))
	case reported == updatesv1alpha1.UpdateNodePhaseDone && onTarget(n, tag):
		if _, settling := n.Annotations[ReadyAtAnnotation]; settling {
			// It went NotReady while settling: the settle starts over.
			if _, err := c.patchNode(ctx, n.Name, annotations(map[string]any{ReadyAtAnnotation: nil})); err != nil {
				return err
			}
		}
		e.Message = "runs " + tag + "; waiting for the node to be Ready"
	case reported == updatesv1alpha1.UpdateNodePhaseDone:
		e.Message = "the node reported Done; waiting for its kubeletVersion to carry " + tag
	case nodeSidePhase(reported):
		e.Phase, e.Message = reported, msg
	}
	if !ready && !strings.Contains(e.Message, "NotReady") {
		e.Message += "; the node is NotReady"
	}
	if now.Sub(handedAt) > c.cfg.NodeTimeout {
		e.Phase, e.FinishedAt = updatesv1alpha1.UpdateNodePhaseFailed, &at
		e.Message = fmt.Sprintf("the node did not finish within %s of its handover (last: %s)", c.cfg.NodeTimeout, e.Message)
	}
	return nil
}

// nodeReady reports whether the Node's Ready condition is True.
func nodeReady(n *corev1.Node) bool {
	for _, c := range n.Status.Conditions {
		if c.Type == corev1.NodeReady {
			return c.Status == corev1.ConditionTrue
		}
	}
	return false
}

// annotationTime reads an RFC3339 time the controller recorded on the Node.
func annotationTime(n *corev1.Node, key string) (time.Time, bool) {
	v, ok := n.Annotations[key]
	if !ok {
		return time.Time{}, false
	}
	t, err := time.Parse(time.RFC3339, v)
	if err != nil {
		return time.Time{}, false
	}
	return t, true
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
// A transient failure is retried for ResolveBound, counted from the first
// failure (the Resolved condition's transition time, so the bound survives a
// restart); past it the roll fails with the last error.
func (c *Controller) ensureResolved(ctx context.Context, u *updatesv1alpha1.Update, now time.Time) error {
	if r := u.Status.Resolved; r != nil && r.Version == u.Spec.Version && r.Digest != "" {
		return nil
	}
	rel, err := c.cfg.Resolver.Resolve(ctx, u.Spec.Version)
	if err == nil && !isSHA256Hex(rel.SHA256) {
		err = fmt.Errorf("%w: malformed sha256", ErrRelease)
	}
	if err != nil {
		err = fmt.Errorf("resolve %s: %w", u.Spec.Version, err)
		if errors.Is(err, ErrRelease) {
			return rollFailure{err}
		}
		prev := meta.FindStatusCondition(u.Status.Conditions, ConditionResolved)
		c.setCondition(u, ConditionResolved, metav1.ConditionFalse, ReasonRetrying, err.Error())
		if prev != nil && prev.Status == metav1.ConditionFalse && now.Sub(prev.LastTransitionTime.Time) > ResolveBound {
			return rollFailure{fmt.Errorf("the release did not resolve within %s; last error: %w", ResolveBound, err)}
		}
		return err
	}
	u.Status.Resolved = &updatesv1alpha1.UpdateResolved{Version: u.Spec.Version, Digest: "sha256:" + rel.SHA256}
	c.setCondition(u, ConditionResolved, metav1.ConditionTrue, ReasonResolved, rel.URL+" sha256:"+rel.SHA256)
	return nil
}

// payload is the canonical node annotation value, rebuilt from
// status.resolved.
func (c *Controller) payload(u *updatesv1alpha1.Update) ([]byte, error) {
	r := u.Status.Resolved
	if r == nil || !strings.HasPrefix(r.Digest, "sha256:") {
		return nil, errors.New("the release has not been resolved")
	}
	url, err := c.cfg.Resolver.AssetURL(u.Spec.Version)
	if err != nil {
		return nil, err
	}
	sig := u.Spec.Verify.Signature
	if sig == "" {
		sig = updatesv1alpha1.UpdateSignatureIfSigned
	}
	return update.EncodePayload(Payload{
		Version: u.Spec.Version, URL: url, SHA256: strings.TrimPrefix(r.Digest, "sha256:"), Signature: sig, AllowDowngrade: u.Spec.AllowDowngrade,
	})
}

// handover asks the node for the release: the version, the payload, its
// signature and the signer certificate are set, any earlier phase report and
// settle mark are cleared, and the handover time is recorded (the node timeout
// counts from it), in one patch. The signature is what authorises the node's
// root helper to install: a node can write its own annotations, but not sign.
func (c *Controller) handover(ctx context.Context, u *updatesv1alpha1.Update, n *corev1.Node, now time.Time) (*corev1.Node, error) {
	p, err := c.payload(u)
	if err != nil {
		return nil, err
	}
	sig, err := update.SignPayload(c.cfg.Signer, p)
	if err != nil {
		return nil, err
	}
	return c.patchNode(ctx, n.Name, annotations(map[string]any{
		updatesv1alpha1.AnnotationUpdateVersion: u.Spec.Version,
		update.AnnotationUpdatePayload:          string(p),
		update.AnnotationUpdatePayloadSig:       sig,
		update.AnnotationUpdateSigner:           string(c.cfg.Signer.CertPEM),
		updatesv1alpha1.AnnotationUpdatePhase:   nil,
		HandedOverAnnotation:                    now.Format(time.RFC3339),
		ReadyAtAnnotation:                       nil,
	}))
}

// annotations is a merge patch of Node annotations (a nil value removes one).
func annotations(a map[string]any) map[string]any {
	return map[string]any{"metadata": map[string]any{"annotations": a}}
}

// cordon marks the node unschedulable, unless it already is (then the cordon
// is either ours from an earlier pass or the operator's, and stays as it is).
func (c *Controller) cordon(ctx context.Context, n *corev1.Node) (*corev1.Node, error) {
	if n.Spec.Unschedulable {
		return n, nil
	}
	patch := annotations(map[string]any{CordonedAnnotation: "true"})
	patch["spec"] = map[string]any{"unschedulable": true}
	return c.patchNode(ctx, n.Name, patch)
}

// release ends the controller's hold on a node: it removes the controller's
// own annotations and lifts the cordon if the controller made it (an
// operator's cordon stays). The update-version, -payload and -phase
// annotations stay: they record what the node was asked for and reported.
func (c *Controller) release(ctx context.Context, n *corev1.Node) (*corev1.Node, error) {
	patch := annotations(map[string]any{CordonedAnnotation: nil, HandedOverAnnotation: nil, ReadyAtAnnotation: nil})
	if n.Annotations[CordonedAnnotation] == "true" {
		patch["spec"] = map[string]any{"unschedulable": false}
	}
	return c.patchNode(ctx, n.Name, patch)
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
func (c *Controller) cancelFrom(u *updatesv1alpha1.Update, i int, nodes map[string]*corev1.Node) {
	at := c.cfg.Now().UTC().Truncate(time.Second).Format(time.RFC3339)
	for j := i; j < len(u.Status.Nodes); j++ {
		e := &u.Status.Nodes[j]
		if e.Phase == "" || e.Phase == updatesv1alpha1.UpdateNodePhasePending {
			from := e.Phase
			e.Phase, e.Message = updatesv1alpha1.UpdateNodePhaseCancelled, withProgress("cancelled before it started", at)
			c.transition(u, e, from, nodes[e.Name])
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

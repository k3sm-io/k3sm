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
	"log/slog"
	"sort"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	updatesv1alpha1 "k3sm.io/apis/updates/v1alpha1"
	"k3sm.io/k3sm/pkg/certs"
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

// AdminTokenRotatedAnnotation is the one update annotation a node writes for
// the controller outside its phase report: a control plane whose in-place
// install minted a new admin token (the installed one was missing, corrupt or
// untrusted) sets it, once Ready again, to "<version> <RFC3339>": the release
// that install put on the node and the install's time.
//
// The controller records it on the node's status (AdminTokenRotated) when the
// node carries the control-plane label and the version is the release the
// node entry moves the node to (To). The version decides first: the time is
// the node's clock and the handover the controller's, so a lagging
// control-plane clock would otherwise hide a real rotation. Only a mark naming
// another version (an unstamped or hand-installed build) falls back to the
// time, and is logged. A mark is cleared at the node's next handover, and by
// `k3sm update abort` once it has recorded it.
const AdminTokenRotatedAnnotation = "k3sm.io/update-admin-token-rotated-at"

// AdminTokenRotatedMessage is what a node's message says once its status
// carries AdminTokenRotated: every copy of the admin kubeconfig taken from the
// control plane before the update is now refused.
const AdminTokenRotatedMessage = "the admin credential was re-minted: copy the admin kubeconfig again"

// ParseAdminTokenRotatedMark splits an AdminTokenRotatedAnnotation value into
// the release version and the install's time. ok is false for anything that
// is not exactly "<version> <RFC3339>".
func ParseAdminTokenRotatedMark(v string) (version string, at time.Time, ok bool) {
	version, ts, found := strings.Cut(v, " ")
	if !found || version == "" || strings.ContainsAny(ts, " ") {
		return "", time.Time{}, false
	}
	at, err := time.Parse(time.RFC3339, ts)
	if err != nil {
		return "", time.Time{}, false
	}
	return version, at, true
}

// NoteAdminTokenRotations sets AdminTokenRotated on every node entry of u that
// the node behind it has reported a rotation for (see
// AdminTokenRotatedAnnotation), and appends the remedy to a finished entry's
// message. Only entries past their handover are read: the handover clears any
// earlier mark, so a mark on a node that has not been handed over belongs to
// an earlier roll. A flag once set stays set. The controller calls it on every
// pass of the newest Update, while it rolls and after it Succeeded; `k3sm
// update abort` calls it before it clears the annotations, so neither end of a
// roll loses the report. It reports whether it set a flag.
//
// A mark counts when it is a control plane's and its version is the entry's
// To. A mark naming another version (an unstamped or hand-installed build) is
// logged, and counts only when its time is at or after the node's handover
// (the handover annotation, or the entry's start once that is gone): the
// clocks of the node and the controller decide only when the version cannot.
func NoteAdminTokenRotations(u *updatesv1alpha1.Update, nodes []corev1.Node, log *slog.Logger) bool {
	byName := make(map[string]*corev1.Node, len(nodes))
	for i := range nodes {
		byName[nodes[i].Name] = &nodes[i]
	}
	noted := false
	for i := range u.Status.Nodes {
		e := &u.Status.Nodes[i]
		if e.AdminTokenRotated || !handedOverPhase(e.Phase) || !rotationReported(byName[e.Name], e, log) {
			continue
		}
		e.AdminTokenRotated, noted = true, true
		if e.Phase == updatesv1alpha1.UpdateNodePhaseDone || e.Phase == updatesv1alpha1.UpdateNodePhaseFailed {
			base, at := splitProgress(e.Message)
			base = withRotation(e, base)
			if at == "" {
				e.Message = base
			} else {
				e.Message = withProgress(base, at)
			}
		}
	}
	return noted
}

// rotationReported reports whether n is a control plane whose mark counts for
// entry e (see NoteAdminTokenRotations). The versions are compared as the
// node's kubeletVersion carries them, so "v0.2.0" and the stamped "0.2.0"
// agree. A worker's mark is ignored: a worker has no admin token to rotate.
func rotationReported(n *corev1.Node, e *updatesv1alpha1.UpdateNodeStatus, log *slog.Logger) bool {
	if n == nil || e.To == "" {
		return false
	}
	if _, cp := n.Labels[controlPlaneLabel]; !cp {
		return false
	}
	version, at, ok := ParseAdminTokenRotatedMark(n.Annotations[AdminTokenRotatedAnnotation])
	if !ok {
		return false
	}
	if buildMetadata(version) == buildMetadata(e.To) {
		return true
	}
	floor, ok := annotationTime(n, HandedOverAnnotation)
	if !ok && e.StartedAt != nil {
		floor, ok = e.StartedAt.Time, true
	}
	if ok && !at.Before(floor) {
		log.Warn("update controller: a control plane reported an admin token rotation for another release than it was moved to; recording it, since it was made after the handover",
			"node", e.Name, "mark_version", version, "to", e.To, "at", at.Format(time.RFC3339))
		return true
	}
	log.Warn("update controller: ignoring an admin token rotation mark for another release than the node was moved to, made before its handover",
		"node", e.Name, "mark_version", version, "to", e.To, "at", at.Format(time.RFC3339))
	return false
}

// handedOverPhase reports whether an entry in phase p has been handed the
// release.
func handedOverPhase(p updatesv1alpha1.UpdateNodePhase) bool {
	return nodeSidePhase(p) || p == updatesv1alpha1.UpdateNodePhaseDone || p == updatesv1alpha1.UpdateNodePhaseFailed
}

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
// node is touched. reason is the Failed condition's reason; empty means
// ReasonFailed.
type rollFailure struct {
	err    error
	reason string
}

func (f rollFailure) Error() string { return f.err.Error() }
func (f rollFailure) Unwrap() error { return f.err }

// roll advances the singleton as far as it can go without waiting and returns
// when the next pass is due. It mutates only u.Status (and the Nodes through
// the API). newest is whether no other Update was created after u: a
// Succeeded Update keeps recording a control plane's late admin token
// rotation report only while it is the newest.
func (c *Controller) roll(ctx context.Context, u *updatesv1alpha1.Update, newest bool) time.Duration {
	now := c.cfg.Now().UTC().Truncate(time.Second)
	st := &u.Status
	st.ObservedGeneration = u.Generation
	c.setCondition(u, updatesv1alpha1.UpdateConditionReconciled, metav1.ConditionTrue, ReasonSingleton,
		"this is the Update the controller rolls")
	if finished(u) {
		if newest && endedAs(u, ReasonSucceeded) {
			c.noteLateRotations(ctx, u)
		}
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
		if err := c.plan(ctx, u, list.Items, now); err != nil {
			var rf rollFailure
			if errors.As(err, &rf) {
				c.failWith(u, rf.reason, rf.Error())
				return idleResync
			}
			c.progress(u, ReasonRetrying, err.Error())
			return errorBackoff
		}
	}
	// Every pass, before any entry advances or the roll ends, so a rotation a
	// control plane reports late (after it settled, or while the roll fails or
	// is cancelled) still reaches its entry.
	NoteAdminTokenRotations(u, list.Items, c.log)

	for i := range st.Nodes {
		e := &st.Nodes[i]
		switch e.Phase {
		case updatesv1alpha1.UpdateNodePhaseDone, updatesv1alpha1.UpdateNodePhaseSkipped, updatesv1alpha1.UpdateNodePhaseCancelled:
			continue
		case updatesv1alpha1.UpdateNodePhaseFailed:
			c.failWith(u, failedNodeReason(e), fmt.Sprintf("node %s: %s", e.Name, e.Message))
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
				c.failWith(u, rf.reason, rf.Error())
				return idleResync
			}
			c.progress(u, ReasonRetrying, fmt.Sprintf("node %s: %v", e.Name, err))
			return errorBackoff
		}
		switch e.Phase {
		case updatesv1alpha1.UpdateNodePhaseDone, updatesv1alpha1.UpdateNodePhaseSkipped:
			continue
		case updatesv1alpha1.UpdateNodePhaseFailed:
			c.failWith(u, failedNodeReason(e), fmt.Sprintf("node %s: %s", e.Name, e.Message))
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

// noteLateRotations records on a Succeeded Update an admin token rotation a
// control plane reported after its entry finished, and names the node in the
// Succeeded condition. A failed node list is retried on the next pass.
func (c *Controller) noteLateRotations(ctx context.Context, u *updatesv1alpha1.Update) {
	list, err := c.cfg.Client.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	if err != nil {
		c.log.Warn("update controller: list nodes for a late admin token rotation report", "err", err)
		return
	}
	if NoteAdminTokenRotations(u, list.Items, c.log) {
		c.succeed(u)
	}
}

// endedAs reports whether u ended with the given Progressing reason.
func endedAs(u *updatesv1alpha1.Update, reason string) bool {
	p := meta.FindStatusCondition(u.Status.Conditions, ConditionProgressing)
	return p != nil && p.Status == metav1.ConditionFalse && p.Reason == reason
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
// drain with nowhere to move pods, a downgrade the spec does not allow, or a
// node outside the release's compatibility window. Unless every node already
// runs the target, it resolves the release and reads its payload manifest
// first, since the window and the order come from the manifest. Every refusal
// is a rollFailure, returned before any node is cordoned; any other error is
// transient and the plan is retried.
func (c *Controller) plan(ctx context.Context, u *updatesv1alpha1.Update, nodes []corev1.Node, now time.Time) error {
	tag := u.Spec.Version
	refuse := func(format string, args ...any) error { return rollFailure{err: fmt.Errorf(format, args...)} }
	if !validTag(tag) {
		return refuse("spec.version %q is not a usable release tag", tag)
	}
	if len(nodes) == 0 {
		return refuse("the cluster has no nodes")
	}
	if len(nodes) > maxNodes {
		return refuse("the cluster has %d nodes; an Update records at most %d", len(nodes), maxNodes)
	}
	if u.Spec.Strategy.Drain && len(nodes) == 1 {
		return refuse("spec.strategy.drain needs another node to move pods to, and this cluster has one node; create the Update without drain")
	}
	var pending []*corev1.Node
	for i := range nodes {
		n := &nodes[i]
		if !u.Spec.AllowDowngrade {
			if from := fromRelease(n); isDowngrade(from, tag) {
				return refuse("node %s runs %s and %s is older; set spec.allowDowngrade to move it back", n.Name, from, tag)
			}
		}
		if !onTarget(n, tag) {
			pending = append(pending, n)
		}
	}
	serverFirst := false
	if len(pending) > 0 {
		if err := c.ensureResolved(ctx, u, now); err != nil {
			return err
		}
		m, err := c.ensureManifest(ctx, u)
		if err != nil {
			return err
		}
		if err := checkWindow(m.m, pending); err != nil {
			return rollFailure{err: err, reason: ReasonOutsideCompatibilityWindow}
		}
		serverFirst = kubeMinorRises(m.m, pending)
	}
	ordered := c.order(nodes, serverFirst)
	u.Status.Nodes = make([]updatesv1alpha1.UpdateNodeStatus, 0, len(ordered))
	for _, n := range ordered {
		u.Status.Nodes = append(u.Status.Nodes, updatesv1alpha1.UpdateNodeStatus{
			Name: n.Name, From: fromRelease(n), To: tag, Phase: updatesv1alpha1.UpdateNodePhasePending,
		})
	}
	u.Status.Phase = updatesv1alpha1.UpdatePhasePending
	return nil
}

// order is the roll order. By default it is workers-then-server: every node
// that is not a server by name, then every other server by name, then this
// controller's own server last, so the controller and its signer are never
// down while a worker is mid-roll and a bad payload is caught on a worker.
// With serverFirst (the release raises the Kubernetes minor, and the upstream
// skew policy forbids a kubelet newer than its apiserver) it is reversed:
// this controller's server first, then every other server by name, then every
// worker by name. The order is recorded in status, so a controller that
// restarts on its own server resumes it.
func (c *Controller) order(nodes []corev1.Node, serverFirst bool) []*corev1.Node {
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
	out := make([]*corev1.Node, 0, len(nodes))
	if serverFirst {
		if self != nil {
			out = append(out, self)
		}
		out = append(out, servers...)
		return append(out, workers...)
	}
	out = append(out, workers...)
	out = append(out, servers...)
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
	if code, halt := haltCode(msg); halt && (reported == updatesv1alpha1.UpdateNodePhaseFailed || nodeSidePhase(reported)) {
		// Rolled back, refused or without its data root: the roll stops at
		// this node, whatever phase it reports, and it stays cordoned.
		e.Phase, e.Message, e.FinishedAt = updatesv1alpha1.UpdateNodePhaseFailed, haltMessage(code, msg), &at
		return nil
	}
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
			e.Phase, e.Message, e.FinishedAt, e.To = updatesv1alpha1.UpdateNodePhaseDone, withRotation(e, "runs "+tag), &at, tag
			return nil
		}
		e.Message = withRotation(e, fmt.Sprintf("runs %s and is Ready; settling until %s", tag, readyAt.Add(SettlePeriod).Format(time.RFC3339)))
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

// withRotation is msg with the admin credential remedy appended when the
// node's status carries AdminTokenRotated.
func withRotation(e *updatesv1alpha1.UpdateNodeStatus, msg string) string {
	if !e.AdminTokenRotated {
		return msg
	}
	if strings.Contains(msg, AdminTokenRotatedMessage) {
		return msg
	}
	if msg == "" {
		return AdminTokenRotatedMessage
	}
	return msg + "; " + AdminTokenRotatedMessage
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
	required, pinRequired := u.Annotations[ReleasePinRequiredAnnotation]
	var rel Release
	var err error
	if pinRequired && required != u.Spec.Version {
		err = pinError("the Update was pinned for %q but targets %q", required, u.Spec.Version)
	} else {
		rel, err = c.cfg.Resolver.Resolve(ctx, u.Spec.Version)
	}
	if err == nil && !isSHA256Hex(rel.SHA256) {
		err = fmt.Errorf("%w: malformed sha256", ErrRelease)
	}
	if err == nil && pinRequired && !rel.Pinned {
		err = pinError("the Update requires a release pin for %s and no trusted pin for it matched", u.Spec.Version)
	}
	if err != nil {
		err = fmt.Errorf("resolve %s: %w", u.Spec.Version, err)
		if errors.Is(err, ErrReleasePinMismatch) {
			c.setCondition(u, ConditionResolved, metav1.ConditionFalse, ReasonReleasePinMismatch, err.Error())
			return rollFailure{err: err, reason: ReasonReleasePinMismatch}
		}
		if errors.Is(err, ErrRelease) {
			return rollFailure{err: err}
		}
		prev := meta.FindStatusCondition(u.Status.Conditions, ConditionResolved)
		c.setCondition(u, ConditionResolved, metav1.ConditionFalse, ReasonRetrying, err.Error())
		if prev != nil && prev.Status == metav1.ConditionFalse && now.Sub(prev.LastTransitionTime.Time) > ResolveBound {
			return rollFailure{err: fmt.Errorf("the release did not resolve within %s; last error: %w", ResolveBound, err)}
		}
		return err
	}
	u.Status.Resolved = &updatesv1alpha1.UpdateResolved{Version: u.Spec.Version, Digest: "sha256:" + rel.SHA256}
	reason := ReasonResolved
	if rel.Pinned {
		reason = ReasonResolvedPinned
	}
	c.setCondition(u, ConditionResolved, metav1.ConditionTrue, reason, rel.URL+" sha256:"+rel.SHA256)
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
// signature, the release's payload manifest and its signature (both by the
// one signer) and the signer certificate are set, any earlier phase report and
// settle mark are cleared, and the handover time is recorded (the node timeout
// counts from it), in one patch. A rotation mark an earlier install left is
// cleared in the same patch, so a mark the node carries after it is this
// handover's. The signature is what authorises the node's
// root helper to install: a node can write its own annotations, but not sign.
func (c *Controller) handover(ctx context.Context, u *updatesv1alpha1.Update, n *corev1.Node, now time.Time) (*corev1.Node, error) {
	p, err := c.payload(u)
	if err != nil {
		return nil, err
	}
	signer, err := c.currentSigner()
	if err != nil {
		return nil, err
	}
	sig, err := update.SignPayload(signer, p)
	if err != nil {
		return nil, err
	}
	m, err := c.ensureManifest(ctx, u)
	if err != nil {
		return nil, err
	}
	manifest, manifestSig, err := signManifest(signer, m)
	if err != nil {
		return nil, err
	}
	return c.patchNode(ctx, n.Name, annotations(map[string]any{
		updatesv1alpha1.AnnotationUpdateVersion: u.Spec.Version,
		update.AnnotationUpdatePayload:          string(p),
		update.AnnotationUpdatePayloadSig:       sig,
		update.AnnotationUpdateSigner:           string(signer.CertPEM),
		update.AnnotationUpdateManifest:         manifest,
		update.AnnotationUpdateManifestSig:      manifestSig,
		updatesv1alpha1.AnnotationUpdatePhase:   nil,
		HandedOverAnnotation:                    now.Format(time.RFC3339),
		ReadyAtAnnotation:                       nil,
		AdminTokenRotatedAnnotation:             nil,
	}))
}

// currentSigner is the signer for the next handover: the one held while it
// has at least certs.UpdateSignerRenewBefore left at the controller's clock,
// else a freshly issued one.
func (c *Controller) currentSigner() (*certs.UpdateSigner, error) {
	if s := c.signer; s != nil && s.Cert != nil && s.Cert.NotAfter.Sub(c.cfg.Now()) >= certs.UpdateSignerRenewBefore {
		return s, nil
	}
	s, err := c.cfg.IssueSigner()
	if err != nil {
		return nil, fmt.Errorf("issue the update signer: %w", err)
	}
	if s == nil || s.Key == nil || s.Cert == nil || len(s.CertPEM) == 0 {
		return nil, errors.New("issue the update signer: an incomplete signer")
	}
	c.signer = s
	c.log.Info("issued a fresh update signer", "not-after", s.Cert.NotAfter.UTC().Format(time.RFC3339))
	return s, nil
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
// annotations stay: they record what the node was asked for and reported. So
// does a rotation mark: the status that records it is written after this
// patch, and a failed status write must find the mark again on the next pass;
// the next handover clears it.
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

// failWith ends the roll Failed (nodes not reached stay Pending) with reason on the Failed condition (empty
// means ReasonFailed). Progressing and Succeeded keep ReasonFailed, the end
// state every reader of the Update tests for.
func (c *Controller) failWith(u *updatesv1alpha1.Update, reason, msg string) {
	if reason == "" {
		reason = ReasonFailed
	}
	u.Status.Phase = updatesv1alpha1.UpdatePhaseFailed
	c.setCondition(u, ConditionProgressing, metav1.ConditionFalse, ReasonFailed, msg)
	c.setCondition(u, ConditionSucceeded, metav1.ConditionFalse, ReasonFailed, msg)
	c.setCondition(u, ConditionFailed, metav1.ConditionTrue, reason, msg)
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

// succeed ends the roll Succeeded. The message names every node whose admin
// credential was re-minted, since each copy of the admin kubeconfig taken
// before the roll is refused until it is copied again.
func (c *Controller) succeed(u *updatesv1alpha1.Update) {
	msg := "every node runs " + u.Spec.Version
	var rotated []string
	for _, e := range u.Status.Nodes {
		if e.AdminTokenRotated {
			rotated = append(rotated, e.Name)
		}
	}
	if len(rotated) > 0 {
		msg += "; admin credential re-minted on " + strings.Join(rotated, ", ")
	}
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

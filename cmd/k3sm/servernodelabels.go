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
	"errors"
	"fmt"
	"log/slog"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/util/retry"
)

// staleNodeRoleLabel is the label Virtual Kubelet's default Node carries
// (kubernetes.io/role=agent) and configureNode deletes. NodeRestriction forbids a
// node identity to set, change or REMOVE it.
const staleNodeRoleLabel = "kubernetes.io/role"

// vkLastAppliedObjectMetaAnnotation is where Virtual Kubelet records the Node
// metadata it last applied; its three-way status patch removes every label that
// annotation lists and the provider no longer sets.
const vkLastAppliedObjectMetaAnnotation = "virtual-kubelet.io/last-applied-object-meta"

// stripStaleNodeRoleLabel removes a stale kubernetes.io/role label from the server's
// own Node, through the ADMIN client, before the node starts.
//
// Why it exists: a server Node registered while the in-process node still ran as
// system:masters can carry kubernetes.io/role both as a live label and inside the
// Virtual Kubelet last-applied annotation. The node now runs as system:node:<name>;
// its first status patch would try to remove that label (the provider no longer
// sets it), NodeRestriction would refuse it, and every status write after that would
// be a 403. The admin client, which is not subject to NodeRestriction, removes it
// once here, so the node starts from metadata it is allowed to keep in sync.
//
// It acts only when the annotation lists the label, i.e. when the label is the
// node's own stale record. A kubernetes.io/role an operator set by hand appears
// only as a live label, is never in the node's patch, and is left alone. A Node
// that does not exist yet (first boot) is not an error. It reports whether it
// changed the Node.
func stripStaleNodeRoleLabel(ctx context.Context, nodes corev1client.NodeInterface, nodeName string) (bool, error) {
	changed := false
	err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		changed = false
		n, err := nodes.Get(ctx, nodeName, metav1.GetOptions{})
		if apierrors.IsNotFound(err) {
			return nil
		}
		if err != nil {
			return err
		}
		raw, ok := n.Annotations[vkLastAppliedObjectMetaAnnotation]
		if !ok {
			return nil
		}
		// A generic map, so fields this code does not know survive the rewrite.
		var meta map[string]any
		if err := json.Unmarshal([]byte(raw), &meta); err != nil {
			return nil // not ours to repair; Virtual Kubelet reports it on its own patch
		}
		labels, _ := meta["labels"].(map[string]any)
		if _, stale := labels[staleNodeRoleLabel]; !stale {
			return nil
		}
		delete(labels, staleNodeRoleLabel)
		b, err := json.Marshal(meta)
		if err != nil {
			return fmt.Errorf("re-encode %s: %w", vkLastAppliedObjectMetaAnnotation, err)
		}
		n.Annotations[vkLastAppliedObjectMetaAnnotation] = string(b)
		delete(n.Labels, staleNodeRoleLabel)
		if _, err := nodes.Update(ctx, n, metav1.UpdateOptions{}); err != nil {
			return err
		}
		changed = true
		return nil
	})
	if err != nil {
		return false, fmt.Errorf("strip the stale %s label from node %s: %w", staleNodeRoleLabel, nodeName, err)
	}
	return changed, nil
}

// controlPlaneNodeLabel marks a server's Node, with the value
// controlPlaneNodeLabelValue, exactly as k3s marks its servers. The server sets it
// on its OWN Node through the admin client: NodeRestriction forbids a node
// identity to set any node-role.kubernetes.io/ key, so a worker can never claim
// the role, and no worker code path writes it. pkg/status reads it to report a
// node's role, and the embedded metrics-server add-on pins to it by node
// affinity.
//
// There is no removal path because there is no role change in place: a Mac
// changes role by uninstalling, which deregisters its Node (the MeshPeer and the
// Node object are deleted), so a re-installed worker registers a fresh Node that
// never carried the label.
const controlPlaneNodeLabel = "node-role.kubernetes.io/control-plane"

// controlPlaneNodeLabelValue is the value k3s writes for controlPlaneNodeLabel.
const controlPlaneNodeLabelValue = "true"

// errNodeNotRegistered: the Node does not exist yet, so there is nothing to label.
var errNodeNotRegistered = errors.New("node is not registered yet")

// ensureControlPlaneLabel sets controlPlaneNodeLabel=controlPlaneNodeLabelValue on
// the server's own Node through the admin client, and reports whether it wrote.
// It is idempotent: a Node already carrying the label with that value is not
// written. It patches only that one label (a JSON merge patch), so every other
// label, an operator's included, is left alone. A Node that does not exist yet
// returns errNodeNotRegistered.
func ensureControlPlaneLabel(ctx context.Context, nodes corev1client.NodeInterface, nodeName string) (bool, error) {
	n, err := nodes.Get(ctx, nodeName, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return false, errNodeNotRegistered
	}
	if err != nil {
		return false, fmt.Errorf("get node %s: %w", nodeName, err)
	}
	if v, ok := n.Labels[controlPlaneNodeLabel]; ok && v == controlPlaneNodeLabelValue {
		return false, nil
	}
	patch, err := json.Marshal(map[string]any{"metadata": map[string]any{"labels": map[string]string{controlPlaneNodeLabel: controlPlaneNodeLabelValue}}})
	if err != nil {
		return false, fmt.Errorf("encode the %s label patch: %w", controlPlaneNodeLabel, err)
	}
	if _, err := nodes.Patch(ctx, nodeName, types.MergePatchType, patch, metav1.PatchOptions{}); err != nil {
		return false, fmt.Errorf("label node %s %s=%s: %w", nodeName, controlPlaneNodeLabel, controlPlaneNodeLabelValue, err)
	}
	return true, nil
}

// controlPlaneLabelRetry is how often labelServerNode retries while the server's
// Node is not registered yet or the apiserver refused the write.
const controlPlaneLabelRetry = 5 * time.Second

// labelServerNode runs ensureControlPlaneLabel until it succeeds or ctx ends. On a
// first boot the Node does not exist when the server prepares it (the Virtual
// Kubelet registers it moments later), so the label is applied as soon as the
// Node appears; on every later boot the first attempt finds it. A failure is
// logged once per distinct message, never returned: the control plane serves
// without the label, and only the server-pinned add-ons wait for it.
func labelServerNode(ctx context.Context, nodes corev1client.NodeInterface, nodeName string, every time.Duration, logger *slog.Logger) {
	var last string
	for {
		changed, err := ensureControlPlaneLabel(ctx, nodes, nodeName)
		switch {
		case err == nil:
			if changed {
				logger.Info("labelled this server's node with its role", "node", nodeName, "label", controlPlaneNodeLabel+"="+controlPlaneNodeLabelValue)
			}
			return
		case errors.Is(err, errNodeNotRegistered):
		case err.Error() != last:
			logger.Warn("could not label this server's node with its role; retrying", "node", nodeName, "err", err)
			last = err.Error()
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(every):
		}
	}
}

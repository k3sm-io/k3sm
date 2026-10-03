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
	"fmt"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
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

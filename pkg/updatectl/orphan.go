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
	"errors"
	"fmt"
	"slices"
	"strings"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	updatesv1alpha1 "k3sm.io/apis/updates/v1alpha1"
)

// rollAnnotationPrefix is the prefix of every Node annotation a roll leaves,
// the same set `k3sm update abort` clears.
const rollAnnotationPrefix = "k3sm.io/update-"

// ReasonOrphanReleased is the Event a Node gets when the controller clears
// update annotations no Update accounts for.
const ReasonOrphanReleased = "UpdateOrphanReleased"

// releaseOrphans clears the update annotations no Update accounts for, and
// lifts the cordon where the controller made it. current is the singleton this
// pass read and wrote, nil when there is none. A live roll is left alone: its
// entries are only as new as the last status write, so the entry of a node
// handed over just before a restart can still read Pending.
//
// It runs from every reconcile, so a leader that starts on an orphan releases
// it on its first pass. A node it cannot patch does not stop the others, and
// the returned error brings the next pass round on the error backoff.
func (c *Controller) releaseOrphans(ctx context.Context, current *updatesv1alpha1.Update) error {
	if current != nil && !finished(current) {
		return nil
	}
	list, err := c.cfg.Client.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("list nodes for orphaned update annotations: %w", err)
	}
	var errs []error
	for i := range list.Items {
		n := &list.Items[i]
		keys := orphanedAnnotations(current, n)
		if len(keys) == 0 {
			continue
		}
		if err := c.releaseOrphan(ctx, n, keys); err != nil && !apierrors.IsNotFound(err) {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// orphanedAnnotations is which of n's update annotations current, a finished
// Update or nil, does not account for. A finished Update accounts for two
// things while it stands:
//
//   - its failed node, whole: a failed step leaves the node as it was for the
//     operator, until `k3sm update abort` or a delete of the Update. An abort
//     ends the Update Cancelled, which accounts for none of this, so the
//     controller finishes a node the abort could not patch;
//   - the record on a node it moved: the release asked for, its payload and the
//     phase reported, with any late admin token rotation mark. release has
//     already taken the rest, and the record goes with its Update.
func orphanedAnnotations(current *updatesv1alpha1.Update, n *corev1.Node) []string {
	var keys []string
	for k := range n.Annotations {
		if strings.HasPrefix(k, rollAnnotationPrefix) {
			keys = append(keys, k)
		}
	}
	if len(keys) == 0 {
		return nil
	}
	if current != nil {
		for i := range current.Status.Nodes {
			e := &current.Status.Nodes[i]
			if e.Name != n.Name {
				continue
			}
			switch {
			case e.Phase == updatesv1alpha1.UpdateNodePhaseFailed && endedAs(current, ReasonFailed):
				return nil
			case e.Phase == updatesv1alpha1.UpdateNodePhaseDone && n.Annotations[updatesv1alpha1.AnnotationUpdateVersion] == current.Spec.Version:
				return nil
			}
			break
		}
	}
	slices.Sort(keys)
	return keys
}

// releaseOrphan removes keys from n in one patch, and lifts a cordon the
// controller's own annotation claims. A cordon without that annotation is an
// operator's and stays.
func (c *Controller) releaseOrphan(ctx context.Context, n *corev1.Node, keys []string) error {
	drop := make(map[string]any, len(keys))
	for _, k := range keys {
		drop[k] = nil
	}
	patch := annotations(drop)
	uncordon := n.Annotations[CordonedAnnotation] == "true" && n.Spec.Unschedulable
	if uncordon {
		patch["spec"] = map[string]any{"unschedulable": false}
	}
	if _, err := c.patchNode(ctx, n.Name, patch); err != nil {
		return err
	}
	still := n.Spec.Unschedulable && !uncordon
	if !uncordon {
		// Nothing was held: the roll's leftovers went, which is bookkeeping.
		c.log.Debug("update controller: cleared update annotations no Update accounts for",
			"node", n.Name, "cleared", keys, "still_cordoned", still)
		return nil
	}
	c.log.Info("update controller: a finished or deleted Update had held this node; lifted its cordon",
		"node", n.Name, "cleared", keys)
	if c.cfg.Recorder != nil {
		c.cfg.Recorder.Eventf(&corev1.ObjectReference{APIVersion: "v1", Kind: "Node", Name: n.Name, UID: n.UID},
			corev1.EventTypeNormal, ReasonOrphanReleased,
			"node %s was held by an update that has finished or been deleted; its cordon was lifted", n.Name)
	}
	return nil
}

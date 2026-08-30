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

package operator

import (
	"context"
	"encoding/json"
	"fmt"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"

	"k3sm.io/k3sm/pkg/mlx"
)

// applyOptions are the patch options every serving-object apply uses.
//
// Force is set for the same reason pkg/addons sets it: without it, a field some
// other manager has claimed — a `kubectl scale`, an edited probe — wedges
// convergence permanently, and the only symptom is a StatefulSet that quietly
// stops tracking its MLXModel. Because server-side apply takes ownership only of
// the fields the render actually sets, an operator's genuinely additive edits
// elsewhere in the object still survive.
func applyOptions() metav1.PatchOptions {
	return metav1.PatchOptions{FieldManager: FieldManager, Force: ptr.To(true)}
}

// apply server-side-applies the three objects that serve one model.
//
// The StatefulSet goes LAST. Both Services are addressed by name from the
// StatefulSet (the governing Service by serviceName, the ClusterIP one by every
// client), so creating the workload before the Services exist would start
// replicas whose DNS identity does not resolve yet — briefly, but visibly, as a
// pod that cannot be reached at the name its own status advertises.
func (c *Controller) apply(ctx context.Context, objs *mlx.Objects) error {
	if err := c.applyService(ctx, objs.HeadlessService); err != nil {
		return err
	}
	if err := c.applyService(ctx, objs.ClusterIPService); err != nil {
		return err
	}
	return c.applyStatefulSet(ctx, objs.StatefulSet)
}

// applyService applies one rendered Service.
func (c *Controller) applyService(ctx context.Context, svc *corev1.Service) error {
	body, err := json.Marshal(svc)
	if err != nil {
		return fmt.Errorf("encode service %s/%s: %w", svc.Namespace, svc.Name, err)
	}
	if _, err := c.client.CoreV1().Services(svc.Namespace).
		Patch(ctx, svc.Name, types.ApplyPatchType, body, applyOptions()); err != nil {
		return fmt.Errorf("apply service %s/%s: %w", svc.Namespace, svc.Name, err)
	}
	return nil
}

// applyStatefulSet applies the rendered StatefulSet.
func (c *Controller) applyStatefulSet(ctx context.Context, sts *appsv1.StatefulSet) error {
	body, err := json.Marshal(sts)
	if err != nil {
		return fmt.Errorf("encode statefulset %s/%s: %w", sts.Namespace, sts.Name, err)
	}
	if _, err := c.client.AppsV1().StatefulSets(sts.Namespace).
		Patch(ctx, sts.Name, types.ApplyPatchType, body, applyOptions()); err != nil {
		return fmt.Errorf("apply statefulset %s/%s: %w", sts.Namespace, sts.Name, err)
	}
	return nil
}

// stampPullSecret adds the conventional image-pull Secret to the rendered pod
// template, but ONLY when that Secret exists in the model's namespace.
//
// The existence check is the whole design. The serving image is a private
// registry digest, so without a pull secret the kubelet pulls anonymously and
// fails at materialize — but naming a Secret that does not exist is ALSO a pull
// failure, so stamping unconditionally would break every deployment serving a
// public image in order to serve the private one. Looking first makes the private
// case work without making the public case worse.
//
// A read failure other than NotFound is logged and treated as absent rather than
// aborting the reconcile: a pod with no pull secret fails visibly at pull time
// with a legible message, whereas an aborted reconcile applies nothing at all and
// says so only in the operator's own log.
func (c *Controller) stampPullSecret(ctx context.Context, objs *mlx.Objects, namespace string) {
	_, err := c.client.CoreV1().Secrets(namespace).Get(ctx, c.pullName, metav1.GetOptions{})
	switch {
	case apierrors.IsNotFound(err):
		return
	case err != nil:
		c.log.Warn("could not read the mlx image-pull secret; rendering without it",
			"namespace", namespace, "secret", c.pullName, "err", err)
		return
	}
	spec := &objs.StatefulSet.Spec.Template.Spec
	for _, ref := range spec.ImagePullSecrets {
		if ref.Name == c.pullName {
			return // idempotent: a re-render must not accumulate duplicates
		}
	}
	spec.ImagePullSecrets = append(spec.ImagePullSecrets, corev1.LocalObjectReference{Name: c.pullName})
}

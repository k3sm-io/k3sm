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

package policy

import (
	"context"
	"fmt"
	"log/slog"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	admissionregistrationv1beta1 "k8s.io/api/admissionregistration/v1beta1"
	corev1 "k8s.io/api/core/v1"
	apiequality "k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/util/retry"
)

// managedLabel marks every object this package provisions as k3sm-owned. Its
// semantics are unchanged by the create-or-update path below: it is stamped at
// CREATE and never removed, added, or selected on afterwards.
const managedLabel = "k3sm.io/managed"

// managedObject is the ONE create-or-update provisioning path for every object
// this package lays down. It exists because create-if-absent — the shape every
// Ensure* here used to have — makes a policy's CONTENT frozen at the moment its
// object first appeared: a changed CEL expression, a changed allowed uid, or a
// changed LimitRange default is INERT on any cluster whose datastore already holds
// the old object, and a server restart never repairs it. That is not a theoretical
// staleness: the foreign-user fix changed both the provisioning set AND the
// policy expression's parameter, so without this path it would have landed green
// in CI and done nothing on every existing cluster.
//
// The contract, deliberately narrow:
//
//   - CREATE when absent, stamping the desired object verbatim (labels included);
//   - GET + compare the SPEC when present, and Update ONLY on divergence — an
//     already-current object makes NO write, so a server restart is not a cluster
//     write storm and `resourceVersion` churn stays proportional to real change;
//   - the Update carries the STORED object with only its spec replaced, so
//     `resourceVersion`, `uid`, `creationTimestamp`, annotations, and any label an
//     operator added all survive. This is what makes it an Update rather than a
//     delete-and-recreate: a VAP delete/recreate window is a window with NO guard.
//
// It is generic over the object type (T is a pointer to the API struct, which
// satisfies metav1.Object through its embedded ObjectMeta); the typed wrappers
// below bind it to each client.
type managedObject[T metav1.Object] struct {
	// kind names the object in error and log messages (never an API decision).
	kind string
	// desired is the object this package wants to exist.
	desired T
	// get/create/update are the typed client's three verbs.
	get    func(context.Context, string, metav1.GetOptions) (T, error)
	create func(context.Context, T, metav1.CreateOptions) (T, error)
	update func(context.Context, T, metav1.UpdateOptions) (T, error)
	// specEqual reports whether the stored object's spec already equals desired's.
	specEqual func(stored, desired T) bool
	// setSpec copies desired's spec onto stored, touching nothing else.
	setSpec func(stored, desired T)
}

// ensure creates m.desired, or reconciles an existing object toward it. A
// Conflict on the Update is retried (another server in an HA set provisions the
// same objects on ITS restart); a NotFound between the create and the get means
// the object was deleted concurrently, and is answered with ONE re-create rather
// than an unbounded create→AlreadyExists→get loop.
func (m managedObject[T]) ensure(ctx context.Context) error {
	name := m.desired.GetName()
	if _, err := m.create(ctx, m.desired, metav1.CreateOptions{}); err == nil {
		return nil
	} else if !apierrors.IsAlreadyExists(err) {
		return fmt.Errorf("create %s %s: %w", m.kind, name, err)
	}
	if err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		stored, err := m.get(ctx, name, metav1.GetOptions{})
		if apierrors.IsNotFound(err) {
			if _, cerr := m.create(ctx, m.desired, metav1.CreateOptions{}); cerr != nil && !apierrors.IsAlreadyExists(cerr) {
				return fmt.Errorf("re-create %s %s after a concurrent delete: %w", m.kind, name, cerr)
			}
			return nil
		}
		if err != nil {
			return fmt.Errorf("get %s %s: %w", m.kind, name, err)
		}
		if m.specEqual(stored, m.desired) {
			return nil
		}
		m.setSpec(stored, m.desired)
		// The RAW error, so a Conflict stays visible to RetryOnConflict.
		if _, uerr := m.update(ctx, stored, metav1.UpdateOptions{}); uerr != nil {
			return uerr
		}
		slog.InfoContext(ctx, "reconciled a stale k3sm-managed object onto the current shape",
			"kind", m.kind, "name", name)
		return nil
	}); err != nil {
		return fmt.Errorf("reconcile %s %s: %w", m.kind, name, err)
	}
	return nil
}

// ensureValidatingAdmissionPolicy create-or-updates a ValidatingAdmissionPolicy.
func ensureValidatingAdmissionPolicy(ctx context.Context, cs kubernetes.Interface, p *admissionregistrationv1.ValidatingAdmissionPolicy) error {
	c := cs.AdmissionregistrationV1().ValidatingAdmissionPolicies()
	return managedObject[*admissionregistrationv1.ValidatingAdmissionPolicy]{
		kind: "validatingadmissionpolicy", desired: p,
		get: c.Get, create: c.Create, update: c.Update,
		specEqual: func(stored, desired *admissionregistrationv1.ValidatingAdmissionPolicy) bool {
			return apiequality.Semantic.DeepEqual(stored.Spec, desired.Spec)
		},
		setSpec: func(stored, desired *admissionregistrationv1.ValidatingAdmissionPolicy) { stored.Spec = desired.Spec },
	}.ensure(ctx)
}

// ensureValidatingAdmissionPolicyBinding create-or-updates a binding.
func ensureValidatingAdmissionPolicyBinding(ctx context.Context, cs kubernetes.Interface, b *admissionregistrationv1.ValidatingAdmissionPolicyBinding) error {
	c := cs.AdmissionregistrationV1().ValidatingAdmissionPolicyBindings()
	return managedObject[*admissionregistrationv1.ValidatingAdmissionPolicyBinding]{
		kind: "validatingadmissionpolicybinding", desired: b,
		get: c.Get, create: c.Create, update: c.Update,
		specEqual: func(stored, desired *admissionregistrationv1.ValidatingAdmissionPolicyBinding) bool {
			return apiequality.Semantic.DeepEqual(stored.Spec, desired.Spec)
		},
		setSpec: func(stored, desired *admissionregistrationv1.ValidatingAdmissionPolicyBinding) {
			stored.Spec = desired.Spec
		},
	}.ensure(ctx)
}

// ensureMutatingAdmissionPolicy create-or-updates the v1beta1 MutatingAdmissionPolicy.
func ensureMutatingAdmissionPolicy(ctx context.Context, cs kubernetes.Interface, p *admissionregistrationv1beta1.MutatingAdmissionPolicy) error {
	c := cs.AdmissionregistrationV1beta1().MutatingAdmissionPolicies()
	return managedObject[*admissionregistrationv1beta1.MutatingAdmissionPolicy]{
		kind: "mutatingadmissionpolicy", desired: p,
		get: c.Get, create: c.Create, update: c.Update,
		specEqual: func(stored, desired *admissionregistrationv1beta1.MutatingAdmissionPolicy) bool {
			return apiequality.Semantic.DeepEqual(stored.Spec, desired.Spec)
		},
		setSpec: func(stored, desired *admissionregistrationv1beta1.MutatingAdmissionPolicy) {
			stored.Spec = desired.Spec
		},
	}.ensure(ctx)
}

// ensureMutatingAdmissionPolicyBinding create-or-updates the v1beta1 binding.
func ensureMutatingAdmissionPolicyBinding(ctx context.Context, cs kubernetes.Interface, b *admissionregistrationv1beta1.MutatingAdmissionPolicyBinding) error {
	c := cs.AdmissionregistrationV1beta1().MutatingAdmissionPolicyBindings()
	return managedObject[*admissionregistrationv1beta1.MutatingAdmissionPolicyBinding]{
		kind: "mutatingadmissionpolicybinding", desired: b,
		get: c.Get, create: c.Create, update: c.Update,
		specEqual: func(stored, desired *admissionregistrationv1beta1.MutatingAdmissionPolicyBinding) bool {
			return apiequality.Semantic.DeepEqual(stored.Spec, desired.Spec)
		},
		setSpec: func(stored, desired *admissionregistrationv1beta1.MutatingAdmissionPolicyBinding) {
			stored.Spec = desired.Spec
		},
	}.ensure(ctx)
}

// ensureLimitRange create-or-updates a namespaced LimitRange.
func ensureLimitRange(ctx context.Context, cs kubernetes.Interface, lr *corev1.LimitRange) error {
	c := cs.CoreV1().LimitRanges(lr.Namespace)
	return managedObject[*corev1.LimitRange]{
		kind: "limitrange", desired: lr,
		get: c.Get, create: c.Create, update: c.Update,
		specEqual: func(stored, desired *corev1.LimitRange) bool {
			return apiequality.Semantic.DeepEqual(stored.Spec, desired.Spec)
		},
		setSpec: func(stored, desired *corev1.LimitRange) { stored.Spec = desired.Spec },
	}.ensure(ctx)
}

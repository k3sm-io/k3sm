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

package addons

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/client-go/dynamic"
)

// Posture is the server-side facts an embedded add-on may need before it can
// serve. The zero value is the most restrictive: every gated add-on is skipped.
type Posture struct {
	// ClusterCAKubeletServing reports that every kubelet serving cert in the
	// cluster chains to the CA published as kube-root-ca.crt. That holds on the
	// multi-node (mesh) posture, where the cluster CA issues the kubelet serving
	// certs and is the controller-manager's --root-ca-file. On a single-node
	// server the kubelet cert is self-signed and it does not hold.
	ClusterCAKubeletServing bool
	// VMUsable reports that this server can host vm guests, the runtime a Linux
	// add-on image runs in.
	VMUsable bool
}

// requirement returns why an add-on cannot serve under p, or "" when it can.
type requirement func(p Posture) string

// requirements gates embedded manifest files by their path in the tree. A file
// with no entry is always applied. A gated file whose requirement fails is not
// applied, and objects k3sm applied from it earlier are withdrawn (withdraw).
var requirements = map[string]requirement{
	"metrics-server.yaml": metricsServerRequirement,
}

// metricsServerRequirement is metrics-server's serving condition. Applied
// without it, the pod never becomes Ready, so the v1beta1.metrics.k8s.io
// APIService stays unavailable, which breaks aggregated discovery and wedges
// namespace deletion cluster-wide.
func metricsServerRequirement(p Posture) string {
	switch {
	case !p.ClusterCAKubeletServing:
		return "kubelet serving certs do not chain to the in-cluster CA (single-node posture), so metrics-server's verified kubelet scrape cannot succeed"
	case !p.VMUsable:
		return "the vm runtime is not usable on this server, so the Linux metrics-server pod cannot run"
	}
	return ""
}

// apiServiceKind is the kind withdrawn first: an APIService whose backend is
// gone is what breaks discovery and namespace deletion, so it never outlives
// the objects that serve it, not even for the length of one withdrawal.
const apiServiceKind = "APIService"

// withdraw removes the objects of a skipped add-on that k3sm applied: every
// APIService first, then the rest in reverse manifest order. It is the
// reconciler's only delete, and it is bounded the way doc.go § Converge-only
// requires of a safe prune: each object is named by the embedded manifest,
// resolved by an authoritative Get by name (never a LIST), and deleted only
// when its managedFields record an Apply by FieldManager, with a UID
// precondition so a same-named object created in between is never touched. An
// object of the same name that k3sm never applied is the operator's, and is
// left alone.
//
// It returns how many objects it deleted, how many it left because k3sm did not
// apply them, and the joined per-object failures.
func (r *Reconciler) withdraw(ctx context.Context, objs []*unstructured.Unstructured) (deleted, foreign int, err error) {
	ordered := make([]*unstructured.Unstructured, 0, len(objs))
	for _, o := range objs {
		if o.GetKind() == apiServiceKind {
			ordered = append(ordered, o)
		}
	}
	for i := len(objs) - 1; i >= 0; i-- {
		if objs[i].GetKind() != apiServiceKind {
			ordered = append(ordered, objs[i])
		}
	}
	var errs []error
	for _, o := range ordered {
		gone, owned, werr := r.withdrawOne(ctx, o)
		switch {
		case werr != nil:
			errs = append(errs, werr)
		case gone:
			deleted++
		case !owned:
			foreign++
		}
	}
	return deleted, foreign, errors.Join(errs...)
}

// withdrawOne deletes obj when k3sm applied it. gone is true when this call
// deleted it; owned is false when an object of that name exists but k3sm did
// not apply it. An absent object is neither, and is not an error.
func (r *Reconciler) withdrawOne(ctx context.Context, obj *unstructured.Unstructured) (gone, owned bool, err error) {
	ri, err := r.resourceFor(obj)
	if err != nil {
		return false, false, fmt.Errorf("withdraw: %w", err)
	}
	live, err := ri.Get(ctx, obj.GetName(), metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return false, true, nil
	}
	if err != nil {
		return false, false, fmt.Errorf("withdraw: get %s %s: %w", obj.GroupVersionKind(), describe(obj), err)
	}
	if !appliedByK3sm(live) {
		return false, false, nil
	}
	uid := live.GetUID()
	policy := metav1.DeletePropagationBackground
	err = ri.Delete(ctx, obj.GetName(), metav1.DeleteOptions{
		Preconditions:     &metav1.Preconditions{UID: &uid},
		PropagationPolicy: &policy,
	})
	switch {
	case apierrors.IsNotFound(err):
		return false, true, nil
	case err != nil:
		return false, true, fmt.Errorf("withdraw: delete %s %s: %w", obj.GroupVersionKind(), describe(obj), err)
	}
	return true, true, nil
}

// appliedByK3sm reports whether obj's managedFields record a server-side apply
// by this reconciler's FieldManager.
func appliedByK3sm(obj *unstructured.Unstructured) bool {
	for _, mf := range obj.GetManagedFields() {
		if mf.Manager == FieldManager && mf.Operation == metav1.ManagedFieldsOperationApply {
			return true
		}
	}
	return false
}

// resourceFor maps obj to its resource client, refusing a namespace on a
// cluster-scoped object and a missing one on a namespaced object, exactly as
// apply does.
func (r *Reconciler) resourceFor(obj *unstructured.Unstructured) (dynamic.ResourceInterface, error) {
	gvk := obj.GroupVersionKind()
	mapping, err := r.mapper.RESTMapping(gvk.GroupKind(), gvk.Version)
	if err != nil {
		return nil, fmt.Errorf("map %s %s: %w", gvk, describe(obj), err)
	}
	if mapping.Scope.Name() == meta.RESTScopeNameNamespace {
		if obj.GetNamespace() == "" {
			return nil, fmt.Errorf("%s %s: namespaced object declares no metadata.namespace", gvk, describe(obj))
		}
		return r.dyn.Resource(mapping.Resource).Namespace(obj.GetNamespace()), nil
	}
	if obj.GetNamespace() != "" {
		return nil, fmt.Errorf("%s %s: cluster-scoped object declares a metadata.namespace", gvk, describe(obj))
	}
	return r.dyn.Resource(mapping.Resource), nil
}

// logSkip records, once per Converge, why a gated add-on was not applied.
func (r *Reconciler) logSkip(ctx context.Context, file, reason string, deleted, foreign int) {
	logger := r.logger
	if logger == nil {
		logger = slog.Default()
	}
	logger.InfoContext(ctx, "embedded add-on not applied: its serving condition does not hold",
		"file", file, "reason", reason, "withdrawn", deleted, "leftNotAppliedByK3sm", foreign)
}

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
	"time"

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
	// Undecided, when set, says why the server could not establish the facts
	// above: a failed read, or a read that showed no Node at all (a stale LIST,
	// or the first start of a fresh cluster). Every gated add-on is then left
	// exactly as it is: neither applied nor withdrawn, because only positive
	// evidence may delete a working add-on.
	Undecided string
}

// outcome is what decide resolved for one gated file.
type outcome int

const (
	// outcomeApply: the guard allows it and the requirement holds; apply the file.
	outcomeApply outcome = iota
	// outcomeUntouched: foreign guard, unreadable guard, undecided posture, or a
	// failed requirement when withdrawal is not allowed this round.
	outcomeUntouched
	// outcomeWithdrawn: the requirement failed on positive evidence and k3sm's
	// objects were withdrawn.
	outcomeWithdrawn
)

// decision is decide's verdict, with the reason a skip logs.
type decision struct {
	outcome          outcome
	reason           string
	deleted, foreign int
	err              error
}

// decide resolves a gated file under p, before any of it is applied, in this
// order: an ownership guard held by someone else leaves it untouched; an
// Undecided posture leaves it untouched; a failed requirement withdraws what
// k3sm applied when mayWithdraw, and otherwise leaves it untouched.
func (r *Reconciler) decide(ctx context.Context, f manifestFile, p Posture, mayWithdraw bool) decision {
	req := requirements[f.path]
	foreignOwner, err := r.foreignGuard(ctx, f.path)
	if err != nil {
		return decision{outcome: outcomeUntouched, reason: "could not read its ownership guard; left untouched", err: err}
	}
	if foreignOwner {
		return decision{outcome: outcomeUntouched, reason: foreignMetricsReason}
	}
	if p.Undecided != "" {
		return decision{outcome: outcomeUntouched, reason: "serving condition undecided, left untouched: " + p.Undecided}
	}
	reason := req(p)
	if reason == "" {
		return decision{outcome: outcomeApply}
	}
	if !mayWithdraw {
		return decision{outcome: outcomeUntouched, reason: reason + " (not yet confirmed; left untouched)"}
	}
	deleted, foreign, err := r.withdraw(ctx, f.objs)
	return decision{outcome: outcomeWithdrawn, reason: reason, deleted: deleted, foreign: foreign, err: err}
}

// RegateInterval is how often a server re-evaluates the gated add-ons after its
// start-up Converge.
const RegateInterval = 2 * time.Minute

// Regate re-evaluates the gated add-ons after start-up, once per value received
// from ticks, until ctx ends; posture is read once per tick. It is the only
// thing that runs after Converge, and it touches gated files only:
//
//   - A file Converge (or an earlier tick) applied in full is done.
//   - A file whose guard is foreign, or whose posture is undecided, is retried
//     on the next tick.
//   - A file whose requirement holds is applied, and is then done.
//   - A file whose requirement fails is withdrawn only after TWO consecutive
//     ticks both read positive evidence, and at most once per process, so a
//     single stale read cannot remove it.
//
// It returns when ctx ends or ticks is closed, or at once when no gated file is
// left to decide. A skip reason is logged when it changes, not on every tick.
func (r *Reconciler) Regate(ctx context.Context, posture func(context.Context) Posture, ticks <-chan time.Time) {
	files, _ := r.loadFiles() // decode errors were reported by Converge
	type state struct {
		f          manifestFile
		streak     int // consecutive ticks with positive evidence against it
		withdrawn  bool
		lastReason string
	}
	var pending []*state
	r.mu.Lock()
	for _, f := range files {
		if _, gated := requirements[f.path]; gated && !r.applied[f.path] {
			pending = append(pending, &state{f: f})
		}
	}
	r.mu.Unlock()
	for len(pending) > 0 {
		select {
		case <-ctx.Done():
			return
		case _, ok := <-ticks:
			if !ok {
				return
			}
		}
		p := posture(ctx)
		next := pending[:0]
		for _, st := range pending {
			if p.Undecided == "" && requirements[st.f.path](p) != "" {
				st.streak++
			} else {
				st.streak = 0
			}
			d := r.decide(ctx, st.f, p, !st.withdrawn && st.streak >= 2)
			if d.err != nil {
				r.log().WarnContext(ctx, "re-evaluate embedded add-on", "file", st.f.path, "err", d.err)
			}
			switch d.outcome {
			case outcomeApply:
				_, errs := r.applyFile(ctx, st.f)
				if err := errors.Join(errs...); err != nil {
					r.log().WarnContext(ctx, "apply embedded add-on after re-evaluation", "file", st.f.path, "err", err)
					next = append(next, st)
					continue
				}
				r.log().InfoContext(ctx, "embedded add-on applied after re-evaluation", "file", st.f.path)
				continue // done
			case outcomeWithdrawn:
				st.withdrawn, st.streak = true, 0
			}
			if d.reason != st.lastReason {
				r.logSkip(ctx, st.f.path, d.reason, d.deleted, d.foreign)
				st.lastReason = d.reason
			}
			next = append(next, st)
		}
		pending = next
	}
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
// namespace deletion cluster-wide. The add-on is a native darwin pod, so it needs
// no particular node capability: only the verified kubelet scrape.
func metricsServerRequirement(p Posture) string {
	if !p.ClusterCAKubeletServing {
		return "kubelet serving certs do not chain to the in-cluster CA (single-node posture), so metrics-server's verified kubelet scrape cannot succeed"
	}
	return ""
}

// ownershipGuard names, per gated file, the object whose presence under another
// owner means the operator already runs that add-on. If it exists and k3sm did
// not apply it, the whole file is skipped: nothing is applied (so a forced
// apply never adopts the operator's objects) and nothing is withdrawn (so a
// later posture change can never delete them).
var ownershipGuard = map[string]*unstructured.Unstructured{
	"metrics-server.yaml": guardObject("apiregistration.k8s.io/v1", apiServiceKind, "v1beta1.metrics.k8s.io"),
}

// foreignMetricsReason is the skip reason when the guard object is foreign.
const foreignMetricsReason = "an existing metrics.k8s.io APIService not applied by k3sm"

func guardObject(apiVersion, kind, name string) *unstructured.Unstructured {
	o := &unstructured.Unstructured{}
	o.SetAPIVersion(apiVersion)
	o.SetKind(kind)
	o.SetName(name)
	return o
}

// foreignGuard reports whether file's guard object exists without a k3sm
// apply in its managedFields. An absent guard, or one k3sm applied, is not
// foreign. A read failure is returned, and the caller then leaves the file
// alone.
func (r *Reconciler) foreignGuard(ctx context.Context, file string) (bool, error) {
	g, ok := ownershipGuard[file]
	if !ok {
		return false, nil
	}
	ri, err := r.resourceFor(g)
	if err != nil {
		return false, fmt.Errorf("ownership guard for %s: %w", file, err)
	}
	live, err := ri.Get(ctx, g.GetName(), metav1.GetOptions{})
	switch {
	case apierrors.IsNotFound(err):
		return false, nil
	case err != nil:
		return false, fmt.Errorf("ownership guard for %s: get %s %s: %w", file, g.GetKind(), g.GetName(), err)
	}
	return !appliedByK3sm(live), nil
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
	r.log().InfoContext(ctx, "embedded add-on not applied",
		"file", file, "reason", reason, "withdrawn", deleted, "leftNotAppliedByK3sm", foreign)
}

// log is the Reconciler's logger: the test seam when set, else slog.Default().
func (r *Reconciler) log() *slog.Logger {
	logger := r.logger
	if logger == nil {
		logger = slog.Default()
	}
	return logger
}

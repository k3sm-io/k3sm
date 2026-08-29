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
	"bufio"
	"bytes"
	"context"
	"embed"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"path"

	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	utilyaml "k8s.io/apimachinery/pkg/util/yaml"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/restmapper"
)

// embedded is the compiled-in add-on manifest tree. The whole security shape of this
// package rests on this directive: the manifests are part of the signed binary, so
// there is no on-disk ingress a same-uid pod could write into and get applied with the
// system:masters admin client (see doc.go).
//
//go:embed manifests
var embedded embed.FS

// manifestRoot is the directory inside embedded that FS exposes as the tree root.
const manifestRoot = "manifests"

// FieldManager is the server-side-apply field manager every object this package applies
// is written under. It is deliberately NOT the bare "k3sm" manager, which is reserved for
// the queued embedded-CRD applier: two independent appliers sharing one manager name
// would each take ownership of the other's fields and fight over them on every boot.
const FieldManager = "k3sm-addons"

// FS returns the production embedded add-on manifest tree, rooted so that a manifest
// added at manifests/foo.yaml is walked as "foo.yaml". It ships EMPTY of product
// manifests today (only the authoring README lives there), so converging it is a no-op.
func FS() fs.FS {
	sub, err := fs.Sub(embedded, manifestRoot)
	if err != nil {
		// Unreachable: manifestRoot is a compile-time constant the //go:embed directive
		// above already proved is a valid embedded directory. Degrade to the un-subbed
		// tree rather than panic in library code — the walk is recursive, so every
		// manifest is still found, one path component deeper.
		return embedded
	}
	return sub
}

// Reconciler server-side-applies a set of embedded add-on manifests onto the cluster.
// It is converge-ONLY: it issues apply patches and nothing else — never a delete, never
// a list (see doc.go for why both bans are load-bearing).
//
// The fs.FS is a test seam. Production binds FS(); tests bind a fixture. It must never
// be bound to an operator-writable source.
type Reconciler struct {
	fsys   fs.FS
	dyn    dynamic.Interface
	mapper meta.RESTMapper
}

// New returns a Reconciler that converges the manifests in fsys onto the cluster
// reachable through dyn, mapping each document's GroupVersionKind to its resource with
// mapper.
func New(fsys fs.FS, dyn dynamic.Interface, mapper meta.RESTMapper) *Reconciler {
	return &Reconciler{fsys: fsys, dyn: dyn, mapper: mapper}
}

// NewFromConfig builds a Reconciler over the cluster cfg addresses, deriving the
// dynamic client and a discovery-backed RESTMapper from it. The mapper is snapshotted
// once at construction, which is why a CRD and its own custom resources cannot be
// applied in the same pass (doc.go § Known ceilings).
func NewFromConfig(fsys fs.FS, cfg *rest.Config) (*Reconciler, error) {
	dyn, err := dynamic.NewForConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("build dynamic client: %w", err)
	}
	dc, err := discovery.NewDiscoveryClientForConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("build discovery client: %w", err)
	}
	groups, err := restmapper.GetAPIGroupResources(dc)
	if err != nil {
		return nil, fmt.Errorf("discover api group resources: %w", err)
	}
	return New(fsys, dyn, restmapper.NewDiscoveryRESTMapper(groups)), nil
}

// Converge applies every manifest document in the embedded set, in the tree's lexical
// order, and returns the joined per-document failures. It is safe to call on every
// server start: server-side apply is idempotent, and re-applying the identical bytes
// under the same field manager is a no-op at the apiserver.
//
// A per-document failure never aborts the rest — the remaining documents are still
// applied — and the returned error is ADVISORY: the caller logs it and continues
// bring-up (doc.go § Failure posture). Converge deliberately does not log the errors it
// returns; the boundary that handles them does.
func (r *Reconciler) Converge(ctx context.Context) error {
	objs, errs := r.load()
	applied := 0
	for _, obj := range objs {
		if err := r.apply(ctx, obj); err != nil {
			errs = append(errs, err)
			continue
		}
		applied++
	}
	slog.DebugContext(ctx, "converged the embedded add-on manifest set",
		"fieldManager", FieldManager, "documents", len(objs), "applied", applied, "failed", len(errs))
	return errors.Join(errs...)
}

// load walks the manifest tree in lexical order and decodes every YAML document it
// finds, returning the decoded objects and the per-document decode failures separately
// so that one malformed document cannot suppress its siblings.
func (r *Reconciler) load() ([]*unstructured.Unstructured, []error) {
	var (
		objs []*unstructured.Unstructured
		errs []error
	)
	// fs.WalkDir visits lexically, which is what makes the applied order — and so the
	// recorded API traffic — deterministic across boots.
	walkErr := fs.WalkDir(r.fsys, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			errs = append(errs, fmt.Errorf("walk embedded add-on manifest %s: %w", p, err))
			return nil // a per-entry error skips that entry, never the whole tree
		}
		if d.IsDir() || !isManifest(p) {
			return nil
		}
		fileObjs, fileErrs := r.loadFile(p)
		objs = append(objs, fileObjs...)
		errs = append(errs, fileErrs...)
		return nil
	})
	if walkErr != nil {
		errs = append(errs, fmt.Errorf("walk embedded add-on manifests: %w", walkErr))
	}
	return objs, errs
}

// isManifest reports whether p names a manifest file. Only .yaml/.yml are manifests, so
// the authoring README (and any future note) lives beside them without being applied.
func isManifest(p string) bool {
	switch path.Ext(p) {
	case ".yaml", ".yml":
		return true
	default:
		return false
	}
}

// loadFile decodes every YAML document in the file at p. A document that fails to decode
// or fails the authoring contract is reported as an error and SKIPPED; the remaining
// documents in the same file are still returned.
func (r *Reconciler) loadFile(p string) ([]*unstructured.Unstructured, []error) {
	f, err := r.fsys.Open(p)
	if err != nil {
		return nil, []error{fmt.Errorf("open embedded add-on manifest %s: %w", p, err)}
	}
	defer func() { _ = f.Close() }() // read-only: nothing to flush, nothing to report

	var (
		objs []*unstructured.Unstructured
		errs []error
	)
	reader := utilyaml.NewYAMLReader(bufio.NewReader(f))
	for i := 0; ; i++ {
		raw, err := reader.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			// A split failure is positional, not per-document: the rest of THIS file is
			// unreadable, so stop here and keep what was already decoded.
			errs = append(errs, fmt.Errorf("read %s document %d: %w", p, i, err))
			break
		}
		obj, err := decodeDocument(raw)
		if err != nil {
			errs = append(errs, fmt.Errorf("decode %s document %d: %w", p, i, err))
			continue
		}
		if obj == nil {
			continue // an empty or comment-only document
		}
		objs = append(objs, obj)
	}
	return objs, errs
}

// decodeDocument converts one YAML document into an unstructured object and enforces the
// authoring contract server-side apply needs. It returns (nil, nil) for an empty or
// comment-only document.
func decodeDocument(raw []byte) (*unstructured.Unstructured, error) {
	if len(bytes.TrimSpace(raw)) == 0 {
		return nil, nil
	}
	jsonBytes, err := utilyaml.ToJSON(raw)
	if err != nil {
		return nil, fmt.Errorf("convert yaml to json: %w", err)
	}
	if bytes.Equal(bytes.TrimSpace(jsonBytes), []byte("null")) {
		return nil, nil // a comment-only document converts to a JSON null
	}
	obj := &unstructured.Unstructured{}
	if err := obj.UnmarshalJSON(jsonBytes); err != nil {
		return nil, fmt.Errorf("unmarshal object: %w", err)
	}
	if obj.GetAPIVersion() == "" || obj.GetKind() == "" {
		return nil, errors.New("object declares no apiVersion/kind")
	}
	// Server-side apply is keyed by name, so an unnamed object has no identity to
	// converge onto and generateName would mint a NEW object on every boot.
	if obj.GetName() == "" {
		return nil, fmt.Errorf("%s object declares no metadata.name", obj.GetKind())
	}
	if obj.GetGenerateName() != "" {
		return nil, fmt.Errorf("%s object uses metadata.generateName, which cannot be converged", obj.GetKind())
	}
	return obj, nil
}

// apply server-side-applies one object under FieldManager. Force is set: without it a
// field another manager has claimed wedges convergence forever, and because SSA only
// takes ownership of the fields the manifest actually sets, an operator's additions
// elsewhere in the object are still preserved.
//
// The namespace is taken from the object and never defaulted: a namespaced object that
// declares none, or a cluster-scoped object that declares one, is an authoring mistake
// refused outright rather than silently applied into the wrong place.
func (r *Reconciler) apply(ctx context.Context, obj *unstructured.Unstructured) error {
	gvk := obj.GroupVersionKind()
	mapping, err := r.mapper.RESTMapping(gvk.GroupKind(), gvk.Version)
	if err != nil {
		return fmt.Errorf("map %s %s: %w", gvk, describe(obj), err)
	}
	var ri dynamic.ResourceInterface
	if mapping.Scope.Name() == meta.RESTScopeNameNamespace {
		if obj.GetNamespace() == "" {
			return fmt.Errorf("apply %s %s: namespaced object declares no metadata.namespace", gvk, describe(obj))
		}
		ri = r.dyn.Resource(mapping.Resource).Namespace(obj.GetNamespace())
	} else {
		if obj.GetNamespace() != "" {
			return fmt.Errorf("apply %s %s: cluster-scoped object declares a metadata.namespace", gvk, describe(obj))
		}
		ri = r.dyn.Resource(mapping.Resource)
	}
	if _, err := ri.Apply(ctx, obj.GetName(), obj, metav1.ApplyOptions{FieldManager: FieldManager, Force: true}); err != nil {
		return fmt.Errorf("apply %s %s: %w", gvk, describe(obj), err)
	}
	return nil
}

// describe renders an object's namespace/name for an error message.
func describe(obj *unstructured.Unstructured) string {
	if ns := obj.GetNamespace(); ns != "" {
		return ns + "/" + obj.GetName()
	}
	return obj.GetName()
}

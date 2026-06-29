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

package provider

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"

	runtimev1 "k3sm.io/apis/runtime/v1"
	"k3sm.io/runtimed/pkg/mount"
)

// resolvePodBoxEnv flattens every container's env into LITERAL values before the
// PodBox is handed to runtimed, which reads only EnvVar.value: it never talks to
// the apiserver, so the provider (which holds the client via r) resolves
// downward-API fieldRefs, configMap/secretKeyRefs, and envFrom here. Resolution
// mutates the box's containers in place (clearing value_from / env_from) and is
// idempotent on an already-literal box.
//
// nodeName / nodeIP supply the spec.nodeName / status.hostIP downward-API values
// the PodBox itself cannot carry (the provider knows the node it runs on).
func resolvePodBoxEnv(ctx context.Context, box *runtimev1.PodBox, nodeName, nodeIP string, r mount.Resolver) error {
	ns := box.GetNamespace()
	for _, c := range box.GetInitContainers() {
		if err := resolveContainerEnv(ctx, c, ns, nodeName, nodeIP, box, r); err != nil {
			return fmt.Errorf("init container %s: %w", c.GetName(), err)
		}
	}
	for _, c := range box.GetContainers() {
		if err := resolveContainerEnv(ctx, c, ns, nodeName, nodeIP, box, r); err != nil {
			return fmt.Errorf("container %s: %w", c.GetName(), err)
		}
	}
	return nil
}

// resolveContainerEnv builds c's final literal env: envFrom-sourced vars first (in
// source order), then explicit env vars (which OVERRIDE envFrom on a name
// collision — the kubelet precedence). It clears value_from/env_from afterwards so
// the box carries only literal values.
func resolveContainerEnv(ctx context.Context, c *runtimev1.Container, ns, nodeName, nodeIP string, box *runtimev1.PodBox, r mount.Resolver) error {
	var ordered []*runtimev1.EnvVar
	idx := make(map[string]int)
	upsert := func(name, value string) {
		if i, ok := idx[name]; ok {
			ordered[i].Value = value
			ordered[i].ValueFrom = nil
			return
		}
		idx[name] = len(ordered)
		ordered = append(ordered, &runtimev1.EnvVar{Name: name, Value: value})
	}

	for _, ef := range c.GetEnvFrom() {
		if err := expandEnvFrom(ctx, ef, ns, r, upsert); err != nil {
			return err
		}
	}
	for _, e := range c.GetEnv() {
		val, skip, err := resolveEnvValue(ctx, e, ns, nodeName, nodeIP, box, r)
		if err != nil {
			return err
		}
		if skip {
			continue
		}
		upsert(e.GetName(), val)
	}

	c.Env = ordered
	c.EnvFrom = nil
	return nil
}

// expandEnvFrom expands a whole ConfigMap/Secret into env vars (sorted keys, with
// the source prefix). A missing optional source is skipped; a missing required one
// errors.
func expandEnvFrom(ctx context.Context, ef *runtimev1.EnvFromSource, ns string, r mount.Resolver, upsert func(name, value string)) error {
	prefix := ef.GetPrefix()
	if cm := ef.GetConfigMapRef(); cm != nil {
		data, skip, err := fetchData(ctx, r, kindConfigMap, ns, cm.GetName(), cm.GetOptional())
		if err != nil {
			return err
		}
		if !skip {
			applySorted(data, prefix, upsert)
		}
	}
	if sec := ef.GetSecretRef(); sec != nil {
		data, skip, err := fetchData(ctx, r, kindSecret, ns, sec.GetName(), sec.GetOptional())
		if err != nil {
			return err
		}
		if !skip {
			applySorted(data, prefix, upsert)
		}
	}
	return nil
}

// applySorted upserts every key of data (sorted for determinism) as prefix+key.
func applySorted(data map[string][]byte, prefix string, upsert func(name, value string)) {
	keys := make([]string, 0, len(data))
	for k := range data {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		upsert(prefix+k, string(data[k]))
	}
}

// resolveEnvValue resolves a single EnvVar to its literal value. skip is true when
// the var sources from an optional ConfigMap/Secret/key that is absent.
func resolveEnvValue(ctx context.Context, e *runtimev1.EnvVar, ns, nodeName, nodeIP string, box *runtimev1.PodBox, r mount.Resolver) (value string, skip bool, err error) {
	vf := e.GetValueFrom()
	if vf == nil {
		return e.GetValue(), false, nil
	}
	switch {
	case vf.GetFieldRef() != nil:
		v, err := resolveDownwardEnv(box, nodeName, nodeIP, vf.GetFieldRef().GetFieldPath())
		return v, false, err
	case vf.GetConfigMapKeyRef() != nil:
		sel := vf.GetConfigMapKeyRef()
		return resolveKeyRef(ctx, r, kindConfigMap, ns, sel.GetName(), sel.GetKey(), sel.GetOptional())
	case vf.GetSecretKeyRef() != nil:
		sel := vf.GetSecretKeyRef()
		return resolveKeyRef(ctx, r, kindSecret, ns, sel.GetName(), sel.GetKey(), sel.GetOptional())
	default:
		return e.GetValue(), false, nil
	}
}

// resolveKeyRef fetches a single ConfigMap/Secret key. An absent optional
// source/key is skipped; an absent required one errors.
func resolveKeyRef(ctx context.Context, r mount.Resolver, kind, ns, name, key string, optional bool) (string, bool, error) {
	data, skip, err := fetchData(ctx, r, kind, ns, name, optional)
	if err != nil || skip {
		return "", skip, err
	}
	v, ok := data[key]
	if !ok {
		if optional {
			return "", true, nil
		}
		return "", false, fmt.Errorf("%s %s/%s key %q not found", kind, ns, name, key)
	}
	return string(v), false, nil
}

const (
	kindConfigMap = "configMap"
	kindSecret    = "secret"
)

// fetchData fetches a ConfigMap's or Secret's key→bytes via the Resolver. skip is
// true when the source is optional and absent (Resolver reports os.ErrNotExist); a
// nil Resolver with a required data source fails closed.
func fetchData(ctx context.Context, r mount.Resolver, kind, ns, name string, optional bool) (map[string][]byte, bool, error) {
	if r == nil {
		if optional {
			return nil, true, nil
		}
		return nil, false, fmt.Errorf("%s %s/%s: no apiserver client configured to resolve it", kind, ns, name)
	}
	var (
		data map[string][]byte
		err  error
	)
	switch kind {
	case kindConfigMap:
		data, err = r.ConfigMap(ctx, ns, name)
	case kindSecret:
		data, err = r.Secret(ctx, ns, name)
	}
	if err != nil {
		if optional && errors.Is(err, os.ErrNotExist) {
			return nil, true, nil
		}
		return nil, false, fmt.Errorf("%s %s/%s: %w", kind, ns, name, err)
	}
	return data, false, nil
}

// resolveDownwardEnv resolves a downward-API field path for an env var. Unlike the
// runtimed volume path (which cannot carry spec.nodeName/status.hostIP), the
// provider supplies those from the node it runs on. Supported: metadata.name/
// namespace/uid, metadata.labels['k']/annotations['k'], spec.nodeName,
// status.podIP(s), status.hostIP. An unknown path errors (fail loud, not silent
// empty).
func resolveDownwardEnv(box *runtimev1.PodBox, nodeName, nodeIP, fieldPath string) (string, error) {
	if key, ok := subscript(fieldPath, "metadata.labels"); ok {
		return box.GetLabels()[key], nil
	}
	if key, ok := subscript(fieldPath, "metadata.annotations"); ok {
		return box.GetAnnotations()[key], nil
	}
	switch fieldPath {
	case "metadata.name":
		return box.GetName(), nil
	case "metadata.namespace":
		return box.GetNamespace(), nil
	case "metadata.uid":
		return box.GetPodId(), nil
	case "spec.nodeName":
		return nodeName, nil
	case "status.podIP", "status.podIPs":
		return box.GetPodIp(), nil
	case "status.hostIP", "status.hostIPs":
		return nodeIP, nil
	default:
		return "", fmt.Errorf("unsupported downward-API field path %q", fieldPath)
	}
}

// subscript parses a "prefix['key']" downward-API field path, returning the key
// and true when fieldPath has that prefix-with-subscript shape.
func subscript(fieldPath, prefix string) (string, bool) {
	if !strings.HasPrefix(fieldPath, prefix+"[") || !strings.HasSuffix(fieldPath, "]") {
		return "", false
	}
	inner := fieldPath[len(prefix)+1 : len(fieldPath)-1]
	inner = strings.Trim(inner, `'"`)
	return inner, true
}

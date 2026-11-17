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
	"k3sm.io/runtimed/pkg/image"
	"k3sm.io/runtimed/pkg/mount"
)

// resolvePodBoxEnv flattens every container's env into LITERAL values before the
// PodBox is handed to runtimed, which reads only EnvVar.value: it never talks to
// the apiserver, so the provider (which holds the client via r) resolves
// downward-API fieldRefs, configMap/secretKeyRefs, and envFrom here. Resolution
// mutates the box's containers in place (clearing value_from / env_from) and is
// idempotent on an already-literal box.
//
// facts supplies the downward-API values the PodBox itself cannot carry.
func resolvePodBoxEnv(ctx context.Context, box *runtimev1.PodBox, facts podFacts, r mount.Resolver) error {
	ns := box.GetNamespace()
	for _, c := range box.GetInitContainers() {
		if err := resolveContainerEnv(ctx, c, ns, facts, box, r); err != nil {
			return fmt.Errorf("init container %s: %w", c.GetName(), err)
		}
	}
	for _, c := range box.GetContainers() {
		if err := resolveContainerEnv(ctx, c, ns, facts, box, r); err != nil {
			return fmt.Errorf("container %s: %w", c.GetName(), err)
		}
	}
	for _, c := range box.GetEphemeralContainers() {
		if err := resolveContainerEnv(ctx, c, ns, facts, box, r); err != nil {
			return fmt.Errorf("ephemeral container %s: %w", c.GetName(), err)
		}
	}
	return nil
}

// podFacts is what the pod's environment can name that the PodBox does not
// carry: the node it runs on, that node's address, the service account it runs
// as (the downward API), the kubernetes Service VIP, and the pod's namespace
// service links (the service environment). The provider knows all of them at
// translation time.
type podFacts struct {
	nodeName       string
	nodeIP         string
	serviceAccount string
	apiServerVIP   string
	// serviceLinks is the pod's namespace service-links environment, resolved
	// once per pod at the translate boundary (namespaceServiceLinks) and
	// already empty when spec.enableServiceLinks is false. The per-container
	// loop only upserts it; it never lists Services itself.
	serviceLinks []*runtimev1.EnvVar
}

// apiServerServicePort is the port the kubernetes Service in the default
// namespace serves the API on. The value mirrors the Service the apiserver's
// own reconciler publishes (port 443, whatever the secure port behind it; k3sm's
// is 6444, behind the Service proxy) and derives from no k3sm code or flag: the
// kubelet renders the variables below from that Service, not from the endpoint.
const apiServerServicePort = "443"

// apiServerEnv is the service environment the kubelet gives EVERY container for
// the kubernetes Service, whatever enableServiceLinks says: the master service
// is always injected. It is what client-go's InClusterConfig reads
// (KUBERNETES_SERVICE_HOST and KUBERNETES_SERVICE_PORT), so a container without
// it cannot use in-cluster config at all, however reachable the VIP is. The
// docker-links spelling rides along because the kubelet emits it and a workload
// may read it.
//
// An empty VIP yields nothing: a node that publishes no API Service (a rootless
// dev tier) must not invent one.
func apiServerEnv(vip string) []*runtimev1.EnvVar {
	if vip == "" {
		return nil
	}
	link := "tcp://" + vip + ":" + apiServerServicePort
	return []*runtimev1.EnvVar{
		{Name: "KUBERNETES_SERVICE_HOST", Value: vip},
		{Name: "KUBERNETES_SERVICE_PORT", Value: apiServerServicePort},
		{Name: "KUBERNETES_SERVICE_PORT_HTTPS", Value: apiServerServicePort},
		{Name: "KUBERNETES_PORT", Value: link},
		{Name: "KUBERNETES_PORT_443_TCP", Value: link},
		{Name: "KUBERNETES_PORT_443_TCP_PROTO", Value: "tcp"},
		{Name: "KUBERNETES_PORT_443_TCP_PORT", Value: apiServerServicePort},
		{Name: "KUBERNETES_PORT_443_TCP_ADDR", Value: vip},
	}
}

// resolveContainerEnv builds c's final literal env in four layers, each
// OVERRIDING the one before on a name collision: the namespace service links,
// then the master (kubernetes) service, then envFrom-sourced vars (in source
// order), then explicit env vars. It clears value_from/env_from afterwards so
// the box carries only literal values.
//
// Layering the master service AFTER the namespace links is a stated decision:
// a Service named "kubernetes" in the pod's own namespace renders the same
// variable names, and here the master service deterministically wins that
// collision. Upstream builds both into one map, so which one wins there is
// not something a workload can rely on.
func resolveContainerEnv(ctx context.Context, c *runtimev1.Container, ns string, facts podFacts, box *runtimev1.PodBox, r mount.Resolver) error {
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

	for _, e := range facts.serviceLinks {
		upsert(e.GetName(), e.GetValue())
	}
	for _, e := range apiServerEnv(facts.apiServerVIP) {
		upsert(e.GetName(), e.GetValue())
	}
	for _, ef := range c.GetEnvFrom() {
		if err := expandEnvFrom(ctx, ef, ns, r, upsert); err != nil {
			return err
		}
	}
	for _, e := range c.GetEnv() {
		val, skip, err := resolveEnvValue(ctx, e, ns, facts, box, r)
		if err != nil {
			return err
		}
		if skip {
			continue
		}
		if e.GetValueFrom() == nil && strings.Contains(val, "$") {
			if val, err = expandEnvValue(e.GetName(), val, ordered); err != nil {
				return err
			}
		}
		upsert(e.GetName(), val)
	}

	c.Env = ordered
	c.EnvFrom = nil
	return nil
}

// maxContainerEnvBytes caps what $(VAR) expansion may grow one container's
// env to. It is macOS's kern.argmax, the most argv and envp together that one
// exec takes, so an env past it could never start anyway; the cap only moves
// that failure to pod creation, where it names the variable, and keeps an
// amplifying chain (each value referencing the one before twice) from asking
// the node daemon for gigabytes first.
const maxContainerEnvBytes = 1 << 20

// expandEnvValue expands the $(VAR) references in one literal env value by the
// kubelet's "dependent environment variables" rule: against every variable
// already in the container's env when the value is reached. That is the
// namespace service links, the master service, the envFrom keys, and the
// explicit env vars declared EARLIER in the list (a later declaration of a name
// is not yet visible, so a forward reference stays verbatim). Values that came
// from valueFrom or envFrom are never expanded themselves, as upstream; only a
// literal value is, and the caller calls this only for one containing "$". The
// grammar is runtimed's image.ExpandVarsLimit, the same copy command and args
// go through, and since runtimed reads this already-expanded env, command and
// args see the expanded values.
//
// Expansion must run once per value: a second pass would turn the "$(X)" that
// "$$(X)" produced into X's value. It does, because resolvePodBoxEnv runs only
// in buildBox, on a box freshly translated from the pod.
//
// The result may not take the container's env past maxContainerEnvBytes, unless
// it is no longer than the literal it came from: a value that does not grow
// never fails here, so a pod that started before expansion existed still does.
func expandEnvValue(name, val string, ordered []*runtimev1.EnvVar) (string, error) {
	lookup := make(map[string]string, len(ordered))
	used := 0
	for _, e := range ordered {
		lookup[e.GetName()] = e.GetValue()
		used += len(e.GetName()) + len(e.GetValue()) + 2 // "=" and the NUL
	}
	limit := max(maxContainerEnvBytes-used-len(name)-2, len(val))
	out, ok := image.ExpandVarsLimit(val, lookup, limit)
	if !ok {
		return "", fmt.Errorf("env %s: expanding its $(VAR) references takes the container's environment past %d bytes", name, maxContainerEnvBytes)
	}
	return out, nil
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
func resolveEnvValue(ctx context.Context, e *runtimev1.EnvVar, ns string, facts podFacts, box *runtimev1.PodBox, r mount.Resolver) (value string, skip bool, err error) {
	vf := e.GetValueFrom()
	if vf == nil {
		return e.GetValue(), false, nil
	}
	switch {
	case vf.GetFieldRef() != nil:
		v, err := resolveDownwardEnv(box, facts, vf.GetFieldRef().GetFieldPath())
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
		src mount.SourceData
		err error
	)
	switch kind {
	case kindConfigMap:
		src, err = r.ConfigMap(ctx, ns, name)
	case kindSecret:
		src, err = r.Secret(ctx, ns, name)
	}
	if err != nil {
		if optional && errors.Is(err, os.ErrNotExist) {
			return nil, true, nil
		}
		return nil, false, fmt.Errorf("%s %s/%s: %w", kind, ns, name, err)
	}
	return src.Data, false, nil
}

// resolveDownwardEnv resolves a downward-API field path for an env var. Unlike the
// runtimed volume path (which cannot carry spec.nodeName/status.hostIP), the
// provider supplies those from the node it runs on. Supported: metadata.name/
// namespace/uid, metadata.labels['k']/annotations['k'], spec.nodeName,
// status.podIP(s), status.hostIP. An unknown path errors (fail loud, not silent
// empty).
func resolveDownwardEnv(box *runtimev1.PodBox, facts podFacts, fieldPath string) (string, error) {
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
		return facts.nodeName, nil
	case "spec.serviceAccountName":
		return facts.serviceAccount, nil
	case "status.podIP", "status.podIPs":
		return box.GetPodIp(), nil
	case "status.hostIP", "status.hostIPs":
		return facts.nodeIP, nil
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

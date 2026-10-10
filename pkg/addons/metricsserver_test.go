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
	"io"
	"reflect"
	"slices"
	"sort"
	"strings"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"k3sm.io/k3sm/pkg/policy"
	"k3sm.io/k3sm/pkg/runtimeclass"
)

// metricsServerImage is the one image the add-on may run: upstream metrics-server
// v0.9.0's multi-arch index on registry.k8s.io, by digest. Changing it is a
// deliberate edit here AND in manifests/metrics-server.yaml.
const metricsServerImage = "registry.k8s.io/metrics-server/metrics-server@sha256:d9862115e7c7881280d3d75ca26bda8ffc0fc213315979575bf23ce9826205c0"

// metricsServerResolution is the pinned scrape interval (upstream's and k3s's).
const metricsServerResolution = "--metric-resolution=15s"

// objID names one object of the shipped set.
type objID struct {
	apiVersion, kind, namespace, name string
}

// wantMetricsServerObjects is EXACTLY the shipped set: upstream v0.9.0's
// components.yaml, object for object. Anything added to the embedded tree that is
// not here fails the gate.
var wantMetricsServerObjects = []objID{
	{"v1", "ServiceAccount", "kube-system", "metrics-server"},
	{"rbac.authorization.k8s.io/v1", "ClusterRole", "", "system:aggregated-metrics-reader"},
	{"rbac.authorization.k8s.io/v1", "ClusterRole", "", "system:metrics-server"},
	{"rbac.authorization.k8s.io/v1", "RoleBinding", "kube-system", "metrics-server-auth-reader"},
	{"rbac.authorization.k8s.io/v1", "ClusterRoleBinding", "", "metrics-server:system:auth-delegator"},
	{"rbac.authorization.k8s.io/v1", "ClusterRoleBinding", "", "system:metrics-server"},
	{"v1", "Service", "kube-system", "metrics-server"},
	{"apps/v1", "Deployment", "kube-system", "metrics-server"},
	{"apiregistration.k8s.io/v1", "APIService", "", "v1beta1.metrics.k8s.io"},
}

// TestMetricsServerAddonManifest is the B93 gate on the shipped add-on: the
// embedded tree decodes, holds exactly the approved objects, grants exactly
// upstream metrics-server's RBAC (no extra verb, resource or group, no
// nodes/proxy anywhere), schedules onto a Darwin node as a vm pod with a
// digest-pinned image and a pinned --metric-resolution, and registers the
// metrics.k8s.io APIService. Before B93 the tree shipped empty and every
// assertion below failed.
func TestMetricsServerAddonManifest(t *testing.T) {
	objs, errs := (&Reconciler{fsys: FS()}).load()
	for _, err := range errs {
		t.Errorf("decode the embedded tree: %v", err)
	}

	byID := map[objID]*unstructured.Unstructured{}
	var got []objID
	for _, o := range objs {
		id := objID{o.GetAPIVersion(), o.GetKind(), o.GetNamespace(), o.GetName()}
		got = append(got, id)
		byID[id] = o
	}
	if !reflect.DeepEqual(got, wantMetricsServerObjects) {
		t.Fatalf("embedded objects =\n  %v\nwant exactly\n  %v", got, wantMetricsServerObjects)
	}

	t.Run("RBAC is upstream's, verbatim", func(t *testing.T) {
		reader := clusterRole(t, byID, "system:aggregated-metrics-reader")
		for _, l := range []string{"view", "edit", "admin"} {
			if v := reader.Labels["rbac.authorization.k8s.io/aggregate-to-"+l]; v != "true" {
				t.Errorf("system:aggregated-metrics-reader aggregate-to-%s = %q, want \"true\"", l, v)
			}
		}
		wantRules(t, "system:aggregated-metrics-reader", reader.Rules, []rbacv1.PolicyRule{
			{APIGroups: []string{"metrics.k8s.io"}, Resources: []string{"pods", "nodes"}, Verbs: []string{"get", "list", "watch"}},
		})

		wantRules(t, "system:metrics-server", clusterRole(t, byID, "system:metrics-server").Rules, []rbacv1.PolicyRule{
			{APIGroups: []string{""}, Resources: []string{"nodes/metrics"}, Verbs: []string{"get"}},
			{APIGroups: []string{""}, Resources: []string{"pods", "nodes"}, Verbs: []string{"get", "list", "watch"}},
		})

		sa := []rbacv1.Subject{{Kind: "ServiceAccount", Name: "metrics-server", Namespace: "kube-system"}}
		var rb rbacv1.RoleBinding
		convert(t, byID[objID{"rbac.authorization.k8s.io/v1", "RoleBinding", "kube-system", "metrics-server-auth-reader"}], &rb)
		wantBinding(t, rb.Name, rb.RoleRef, rb.Subjects, rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "Role", Name: "extension-apiserver-authentication-reader"}, sa)
		for name, role := range map[string]string{
			"metrics-server:system:auth-delegator": "system:auth-delegator",
			"system:metrics-server":                "system:metrics-server",
		} {
			var crb rbacv1.ClusterRoleBinding
			convert(t, byID[objID{"rbac.authorization.k8s.io/v1", "ClusterRoleBinding", "", name}], &crb)
			wantBinding(t, name, crb.RoleRef, crb.Subjects, rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: role}, sa)
		}
	})

	t.Run("no object grants nodes/proxy, a wildcard, or a write verb", func(t *testing.T) {
		for id, o := range byID {
			if id.kind != "ClusterRole" && id.kind != "Role" {
				continue
			}
			var cr rbacv1.ClusterRole
			convert(t, o, &cr)
			for _, r := range cr.Rules {
				for _, res := range r.Resources {
					if res == "nodes/proxy" || strings.Contains(res, "*") {
						t.Errorf("%s grants resource %q", id.name, res)
					}
				}
				for _, v := range r.Verbs {
					if !slices.Contains([]string{"get", "list", "watch"}, v) {
						t.Errorf("%s grants verb %q", id.name, v)
					}
				}
				for _, g := range r.APIGroups {
					if strings.Contains(g, "*") {
						t.Errorf("%s grants api group %q", id.name, g)
					}
				}
				if len(r.NonResourceURLs) != 0 {
					t.Errorf("%s grants non-resource URLs %v", id.name, r.NonResourceURLs)
				}
			}
		}
		raw, err := FS().Open("metrics-server.yaml")
		if err != nil {
			t.Fatalf("open the manifest: %v", err)
		}
		defer raw.Close()
		buf := new(strings.Builder)
		if _, err := io.Copy(buf, raw); err != nil {
			t.Fatalf("read the manifest: %v", err)
		}
		if strings.Contains(buf.String(), "nodes/proxy") {
			t.Error("the manifest mentions nodes/proxy")
		}
	})

	t.Run("the Deployment runs the pinned Linux image as a vm pod on a Darwin node", func(t *testing.T) {
		var d appsv1.Deployment
		convert(t, byID[objID{"apps/v1", "Deployment", "kube-system", "metrics-server"}], &d)
		spec := d.Spec.Template.Spec
		if spec.RuntimeClassName == nil || *spec.RuntimeClassName != runtimeclass.Name {
			t.Errorf("runtimeClassName = %v, want %q", spec.RuntimeClassName, runtimeclass.Name)
		}
		if !reflect.DeepEqual(spec.NodeSelector, map[string]string{corev1.LabelOSStable: "darwin"}) {
			t.Errorf("nodeSelector = %v, want exactly kubernetes.io/os=darwin", spec.NodeSelector)
		}
		wantTol := []corev1.Toleration{{Key: policy.ProviderTaintKey, Operator: corev1.TolerationOpExists, Effect: corev1.TaintEffectNoSchedule}}
		if !reflect.DeepEqual(spec.Tolerations, wantTol) {
			t.Errorf("tolerations = %+v, want exactly %+v (never a blanket operator: Exists)", spec.Tolerations, wantTol)
		}
		if spec.ServiceAccountName != "metrics-server" {
			t.Errorf("serviceAccountName = %q, want metrics-server", spec.ServiceAccountName)
		}
		if spec.HostNetwork || spec.HostPID || spec.HostIPC {
			t.Error("the pod asks for a host namespace")
		}
		if psc := spec.SecurityContext; psc != nil && (psc.RunAsUser != nil || psc.RunAsGroup != nil || psc.FSGroup != nil || len(psc.SupplementalGroups) != 0) {
			t.Errorf("pod securityContext pins a uid/gid (%+v); k3sm admission refuses a foreign identity", psc)
		}
		if len(spec.Containers) != 1 || len(spec.InitContainers) != 0 {
			t.Fatalf("containers = %d (init %d), want exactly one", len(spec.Containers), len(spec.InitContainers))
		}
		c := spec.Containers[0]
		if c.Image != metricsServerImage {
			t.Errorf("image = %q, want the pinned digest %q", c.Image, metricsServerImage)
		}
		if sc := c.SecurityContext; sc == nil || sc.RunAsUser != nil || sc.RunAsGroup != nil {
			t.Errorf("container securityContext %+v: want present with no runAsUser/runAsGroup", sc)
		} else if sc.RunAsNonRoot == nil || !*sc.RunAsNonRoot {
			t.Error("container securityContext dropped runAsNonRoot")
		}
		n := 0
		for _, a := range c.Args {
			if strings.HasPrefix(a, "--metric-resolution") {
				n++
				if a != metricsServerResolution {
					t.Errorf("arg %q, want %q", a, metricsServerResolution)
				}
			}
			if strings.HasPrefix(a, "--kubelet-insecure-tls") {
				t.Errorf("arg %q disables kubelet serving-cert verification", a)
			}
		}
		if n != 1 {
			t.Errorf("--metric-resolution appears %d times, want exactly 1 (%v)", n, c.Args)
		}
	})

	t.Run("the APIService registers metrics.k8s.io on the Service", func(t *testing.T) {
		// Read as unstructured: k3sm takes no kube-aggregator dependency for one
		// object. The field set is checked exactly, so an unexpected field fails too.
		a := byID[objID{"apiregistration.k8s.io/v1", "APIService", "", "v1beta1.metrics.k8s.io"}]
		spec, _, err := unstructured.NestedMap(a.Object, "spec")
		if err != nil {
			t.Fatalf("APIService spec: %v", err)
		}
		want := map[string]any{
			"group":                 "metrics.k8s.io",
			"version":               "v1beta1",
			"groupPriorityMinimum":  int64(100),
			"versionPriority":       int64(100),
			"insecureSkipTLSVerify": true,
			"service":               map[string]any{"name": "metrics-server", "namespace": "kube-system"},
		}
		if !reflect.DeepEqual(spec, want) {
			t.Errorf("APIService spec = %v, want exactly %v", spec, want)
		}
	})

	t.Run("converging the shipped set issues one apply per object and nothing else", func(t *testing.T) {
		dc := newFakeDynamic(t)
		if err := New(FS(), dc, metricsServerMapper()).Converge(context.Background()); err != nil {
			t.Fatalf("converge: %v", err)
		}
		applies := verifyTrafficShape(t, dc.Actions())
		if len(applies) != len(wantMetricsServerObjects) {
			t.Fatalf("%d applies, want %d: %v", len(applies), len(wantMetricsServerObjects), applies)
		}
		for i, a := range applies {
			if want := wantMetricsServerObjects[i]; a.name != want.name || a.namespace != want.namespace {
				t.Errorf("apply %d = %s/%s, want %s/%s", i, a.namespace, a.name, want.namespace, want.name)
			}
		}
	})
}

// metricsServerMapper maps every kind the shipped set uses.
func metricsServerMapper() meta.RESTMapper {
	m := meta.NewDefaultRESTMapper(nil)
	for _, k := range []struct {
		gvk   schema.GroupVersionKind
		scope meta.RESTScope
	}{
		{schema.GroupVersionKind{Version: "v1", Kind: "ServiceAccount"}, meta.RESTScopeNamespace},
		{schema.GroupVersionKind{Version: "v1", Kind: "Service"}, meta.RESTScopeNamespace},
		{schema.GroupVersionKind{Group: "rbac.authorization.k8s.io", Version: "v1", Kind: "ClusterRole"}, meta.RESTScopeRoot},
		{schema.GroupVersionKind{Group: "rbac.authorization.k8s.io", Version: "v1", Kind: "ClusterRoleBinding"}, meta.RESTScopeRoot},
		{schema.GroupVersionKind{Group: "rbac.authorization.k8s.io", Version: "v1", Kind: "RoleBinding"}, meta.RESTScopeNamespace},
		{schema.GroupVersionKind{Group: "apps", Version: "v1", Kind: "Deployment"}, meta.RESTScopeNamespace},
		{schema.GroupVersionKind{Group: "apiregistration.k8s.io", Version: "v1", Kind: "APIService"}, meta.RESTScopeRoot},
	} {
		m.Add(k.gvk, k.scope)
	}
	return m
}

func clusterRole(t *testing.T, byID map[objID]*unstructured.Unstructured, name string) rbacv1.ClusterRole {
	t.Helper()
	var cr rbacv1.ClusterRole
	convert(t, byID[objID{"rbac.authorization.k8s.io/v1", "ClusterRole", "", name}], &cr)
	return cr
}

// wantRules asserts rules equal want exactly, comparing each rule's string sets
// order-insensitively.
func wantRules(t *testing.T, name string, got, want []rbacv1.PolicyRule) {
	t.Helper()
	norm := func(rs []rbacv1.PolicyRule) []rbacv1.PolicyRule {
		out := make([]rbacv1.PolicyRule, 0, len(rs))
		for _, r := range rs {
			r = *r.DeepCopy()
			for _, s := range [][]string{r.APIGroups, r.Resources, r.Verbs, r.ResourceNames, r.NonResourceURLs} {
				sort.Strings(s)
			}
			out = append(out, r)
		}
		return out
	}
	if !reflect.DeepEqual(norm(got), norm(want)) {
		t.Errorf("%s rules =\n  %+v\nwant exactly\n  %+v", name, got, want)
	}
}

func wantBinding(t *testing.T, name string, ref rbacv1.RoleRef, subjects []rbacv1.Subject, wantRef rbacv1.RoleRef, wantSubjects []rbacv1.Subject) {
	t.Helper()
	if ref != wantRef {
		t.Errorf("%s roleRef = %+v, want %+v", name, ref, wantRef)
	}
	if !reflect.DeepEqual(subjects, wantSubjects) {
		t.Errorf("%s subjects = %+v, want exactly %+v", name, subjects, wantSubjects)
	}
}

// convert decodes an unstructured object into a typed one, failing on any
// unknown field so a typo in the manifest cannot silently drop a setting.
func convert(t *testing.T, o *unstructured.Unstructured, into any) {
	t.Helper()
	if o == nil {
		t.Fatalf("object missing from the embedded set (want a %T)", into)
	}
	if err := runtime.DefaultUnstructuredConverter.FromUnstructuredWithValidation(o.Object, into, true); err != nil {
		t.Fatalf("decode %s %s into %T: %v", o.GetKind(), o.GetName(), into, err)
	}
}

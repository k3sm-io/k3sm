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
	"regexp"
	"slices"
	"sort"
	"strings"
	"testing"

	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// metricsServerResolution is the pinned scrape interval (upstream's and k3s's).
const metricsServerResolution = "--metric-resolution=15s"

// wantMetricsServerArgs is the container's argv, exactly upstream v0.9.0's. The
// kubelet half is the load-bearing part on k3sm:
//
//   - no --kubelet-insecure-tls and no --kubelet-certificate-authority: the scrape
//     verifies each node's :10250 serving cert against the pod's own in-cluster CA
//     bundle (kube-root-ca.crt). On a multi-node (mesh) cluster that bundle is the
//     cluster CA, which issues every node's kubelet serving cert with the node's
//     InternalIP as an IP SAN, so verification holds, as it does on k3s;
//   - InternalIP first: the address that serving cert names;
//   - --kubelet-use-node-status-port: the port each node publishes in
//     status.daemonEndpoints, not a hard-coded 10250;
//   - the scrape authenticates with the ServiceAccount token, which the node
//     admits on /metrics/resource after a TokenReview and a nodes/metrics
//     SubjectAccessReview (pkg/provider's delegated auth).
var wantMetricsServerArgs = []string{
	"--cert-dir=/tmp",
	"--secure-port=10250",
	"--kubelet-preferred-address-types=InternalIP,ExternalIP,Hostname",
	"--kubelet-use-node-status-port",
	metricsServerResolution,
}

// digestPinned matches a reference pinned by digest with no tag beside it, so
// the pulled bytes are the reviewed bytes and a tag move upstream cannot change
// them.
var digestPinned = regexp.MustCompile(`^[a-z0-9.-]+(/[a-z0-9._-]+)+@sha256:[0-9a-f]{64}$`)

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

// TestMetricsServerAddonManifest pins this contract on the shipped add-on: the
// embedded tree decodes, holds exactly the approved objects, grants exactly
// upstream metrics-server's RBAC (no extra verb, resource or group, no
// nodes/proxy anywhere), and registers the
// metrics.k8s.io APIService with upstream's insecureSkipTLSVerify posture (the
// aggregator does not verify metrics-server's self-generated serving cert; the
// proxy-client certificate still authenticates the apiserver to it). Before the add-on was added
// the tree shipped empty and every assertion below failed.
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
		if err := New(FS(), dc, metricsServerMapper()).WithPosture(servingPosture).Converge(context.Background()); err != nil {
			t.Fatalf("converge: %v", err)
		}
		applies := verifyTrafficShape(t, afterGuardRead(t, dc.Actions()))
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

// load is loadFiles flattened into one object list, in tree order.
func (r *Reconciler) load() ([]*unstructured.Unstructured, []error) {
	files, errs := r.loadFiles()
	var objs []*unstructured.Unstructured
	for _, f := range files {
		objs = append(objs, f.objs...)
	}
	return objs, errs
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

// TestMetricsServerLivenessProbeTolerance pins the liveness probe's room for a
// host stall. Upstream's chart sets neither timeoutSeconds (so the 1 s default
// applies) nor an initial delay; on a Mac a whole-host stall longer than one
// probe window killed a healthy metrics-server, so the shipped probe waits
// longer for an answer and starts after the process has had time to come up.
func TestMetricsServerLivenessProbeTolerance(t *testing.T) {
	objs, errs := (&Reconciler{fsys: FS()}).load()
	for _, err := range errs {
		t.Errorf("decode the embedded tree: %v", err)
	}
	for _, o := range objs {
		if o.GetKind() != "Deployment" || o.GetName() != "metrics-server" {
			continue
		}
		containers, found, err := unstructured.NestedSlice(o.Object, "spec", "template", "spec", "containers")
		if err != nil || !found || len(containers) != 1 {
			t.Fatalf("metrics-server containers = %v (found %v, err %v), want exactly one", containers, found, err)
		}
		c, ok := containers[0].(map[string]any)
		if !ok {
			t.Fatalf("container is %T, want a map", containers[0])
		}
		probe, found, err := unstructured.NestedMap(c, "livenessProbe")
		if err != nil || !found {
			t.Fatalf("livenessProbe missing (err %v)", err)
		}
		for field, want := range map[string]int64{"timeoutSeconds": 5, "initialDelaySeconds": 20} {
			got, _, err := unstructured.NestedInt64(probe, field)
			if err != nil {
				t.Fatalf("livenessProbe.%s: %v", field, err)
			}
			if got < want {
				t.Errorf("livenessProbe.%s = %d, want at least %d", field, got, want)
			}
		}
		return
	}
	t.Fatal("metrics-server Deployment not in the embedded tree")
}

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
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"testing"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
)

// ephemeralSubresource is the subresource `kubectl debug` writes through.
const ephemeralSubresource = "pods/ephemeralcontainers"

// TestForeignUserPolicyCoversEphemeralContainersUpdate pins that the foreign-user
// policy judges an ephemeral container appended through the
// pods/ephemeralcontainers subresource. A VAP rule on "pods" does not match a
// subresource, so without its own UPDATE rule the append is never evaluated, and
// a user allowed to update that subresource could start a debug container with
// any runAsUser inside the pod's sandbox.
//
// Red at main rests on the RULE assertion: before this change the policy matched
// only pods CREATE. The CEL rows are regression pins: they evaluate the
// expression the policy actually provisions over apiserver-shaped UPDATE objects
// (the whole Pod, ephemeralContainers populated, no initContainers key), so a
// later edit to the expression that stops judging the appended entry fails here.
func TestForeignUserPolicyCoversEphemeralContainersUpdate(t *testing.T) {
	ctx := context.Background()
	cs := fake.NewClientset()
	if err := EnsureNoForeignUserAdmission(ctx, cs, allowedTestUID); err != nil {
		t.Fatalf("EnsureNoForeignUserAdmission: %v", err)
	}
	pol, err := cs.AdmissionregistrationV1().ValidatingAdmissionPolicies().Get(ctx, foreignUserPolicyName, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get policy: %v", err)
	}

	rules := pol.Spec.MatchConstraints.ResourceRules
	var update, create int
	for _, r := range rules {
		core := slices.Equal(r.APIGroups, []string{""}) && slices.Equal(r.APIVersions, []string{"v1"})
		if core && slices.Equal(r.Resources, []string{ephemeralSubresource}) &&
			slices.Equal(r.Operations, []admissionregistrationv1.OperationType{admissionregistrationv1.Update}) {
			update++
		}
		if core && slices.Equal(r.Resources, []string{"pods"}) &&
			slices.Equal(r.Operations, []admissionregistrationv1.OperationType{admissionregistrationv1.Create}) {
			create++
		}
	}
	if update != 1 {
		t.Errorf("rules matching UPDATE on %s = %d, want exactly 1; rules = %+v", ephemeralSubresource, update, rules)
	}
	if create != 1 {
		t.Errorf("rules matching CREATE on pods = %d, want exactly 1 (the create guard must stay); rules = %+v", create, rules)
	}

	if len(pol.Spec.Validations) != 1 {
		t.Fatalf("validations = %d, want 1", len(pol.Spec.Validations))
	}
	prg := celProgram(t, pol.Spec.Validations[0].Expression)
	const foreign int64 = 4242
	allowed := allowedTestUID
	tests := []struct {
		name      string
		object    map[string]any
		wantAdmit bool
	}{
		{"a new ephemeral container with a foreign runAsUser is DENIED",
			foreignUserPod(nil, []map[string]any{nil}, nil, []map[string]any{{"runAsUser": foreign}}), false},
		{"a new ephemeral container with a foreign runAsGroup is DENIED",
			foreignUserPod(nil, []map[string]any{nil}, nil, []map[string]any{{"runAsGroup": foreign}}), false},
		{"the second ephemeral container's foreign runAsUser is DENIED",
			foreignUserPod(nil, []map[string]any{nil}, nil, []map[string]any{nil, {"runAsUser": foreign}}), false},
		{"a foreign pod-level fsGroup on the UPDATE object is DENIED",
			foreignUserPod(sc(map[string]any{"fsGroup": foreign}), []map[string]any{nil}, nil, []map[string]any{nil}), false},
		{"a clean ephemeral container appended to an admitted pod is ALLOWED",
			foreignUserPod(sc(map[string]any{"runAsUser": allowed}), []map[string]any{{"runAsGroup": allowed}}, nil, []map[string]any{nil}), true},
		{"an ephemeral container naming the allowed id is ALLOWED",
			foreignUserPod(nil, []map[string]any{nil}, nil, []map[string]any{{"runAsUser": allowed, "runAsGroup": allowed}}), true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, ok := tt.object["spec"].(map[string]any)["initContainers"]; ok {
				t.Fatal("fixture carries an initContainers key; the apiserver-shaped object for this pod has none")
			}
			out, _, err := prg.Eval(map[string]any{"object": tt.object})
			if err != nil {
				t.Fatalf("eval: %v", err)
			}
			admit, ok := out.Value().(bool)
			if !ok {
				t.Fatalf("CEL returned %T (%v), want bool", out.Value(), out.Value())
			}
			if admit != tt.wantAdmit {
				t.Errorf("admit = %v, want %v", admit, tt.wantAdmit)
			}
		})
	}
}

// ephemeralVerdict is a pod policy's answer to "does the pods/ephemeralcontainers
// subresource need to be matched?".
type ephemeralVerdict struct {
	// covers: the policy matches UPDATE on pods/ephemeralcontainers.
	covers bool
	// exemptFields are the pod fields the policy reads, none of which the
	// subresource can change, and why.
	exemptFields []string
	why          string
}

// subresourceWritesOnly is why every exempt verdict holds: the apiserver's
// ephemeralcontainers update strategy copies the stored pod and carries over
// spec.ephemeralContainers only, before validating admission runs.
const subresourceWritesOnly = "pods/ephemeralcontainers writes only spec.ephemeralContainers; every other field of the admitted object is the stored pod's"

// TestPodPoliciesHaveEphemeralContainersVerdict requires an explicit verdict for
// every managed admission policy this package provisions that matches pods:
// either it matches UPDATE on pods/ephemeralcontainers, or it is exempt because
// it reads only fields the subresource cannot change (named, and checked against
// the policy's own expressions).
//
// The universe is DERIVED, not listed: the package's non-test sources are parsed
// and every exported top-level Ensure* function must have a provisioner below. A
// new Ensure* without one fails, a provisioner for a function that no longer
// exists fails, a provisioned pod policy without a verdict fails, and a verdict
// naming a policy nothing provisioned fails.
//
// Two pod-scoped objects are judged here in prose because they are not admission
// policies:
//   - the default LimitRange (EnsureDefaultLimitRange) is applied by the
//     LimitRanger plugin to Pod CREATE and does not judge the subresource; it
//     needs no coverage because an ephemeral container runs inside the pod's
//     runtime memory ceiling: runtimed's memory sampler sums the footprint of
//     every live process the pod tracks (pod.containerPIDs over p.containers,
//     which holds the ephemeral containers too), against the limit fixed at
//     create;
//   - Pod Security Admission evaluates pods/ephemeralcontainers natively
//     (upstream's PodSecurity plugin checks ephemeral containers on that
//     subresource), so the PSA level needs no k3sm policy.
func TestPodPoliciesHaveEphemeralContainersVerdict(t *testing.T) {
	ctx := context.Background()

	provisioners := map[string]func(kubernetes.Interface) error{
		"EnsureRejectReservedLoadBalancerPort": func(cs kubernetes.Interface) error { return EnsureRejectReservedLoadBalancerPort(ctx, cs) },
		"EnsureRejectServiceDeniedLocalPort": func(cs kubernetes.Interface) error {
			return EnsureRejectServiceDeniedLocalPort(ctx, cs, []int{10250})
		},
		"EnsureEgressAnnotationWarn":           func(cs kubernetes.Interface) error { return EnsureEgressAnnotationWarn(ctx, cs) },
		"EnsureXcodeToolchainAnnotationWarn":   func(cs kubernetes.Interface) error { return EnsureXcodeToolchainAnnotationWarn(ctx, cs) },
		"EnsureDaemonSetTolerationMutation":    func(cs kubernetes.Interface) error { return EnsureDaemonSetTolerationMutation(ctx, cs) },
		"EnsureDarwinAdmission":                func(cs kubernetes.Interface) error { return EnsureDarwinAdmission(ctx, cs) },
		"EnsureNoForeignUserAdmission":         func(cs kubernetes.Interface) error { return EnsureNoForeignUserAdmission(ctx, cs, allowedTestUID) },
		"EnsureExternalTrafficPolicyLocalWarn": func(cs kubernetes.Interface) error { return EnsureExternalTrafficPolicyLocalWarn(ctx, cs) },
		"EnsureUDPServiceWarn":                 func(cs kubernetes.Interface) error { return EnsureUDPServiceWarn(ctx, cs) },
		"EnsureProviderTolerationWarn":         func(cs kubernetes.Interface) error { return EnsureProviderTolerationWarn(ctx, cs) },
		"EnsureDefaultLimitRange":              func(cs kubernetes.Interface) error { return EnsureDefaultLimitRange(ctx, cs) },
	}

	verdicts := map[string]ephemeralVerdict{
		foreignUserPolicyName: {covers: true},
		darwinPolicyName: {exemptFields: []string{"spec.nodeSelector"},
			why: subresourceWritesOnly + " (and nodeSelector is immutable after create)"},
		providerTolerationPolicyName: {exemptFields: []string{"spec.tolerations"},
			why: subresourceWritesOnly + "; tolerations change only through a pod update, never this subresource"},
		egressAnnotationPolicyName: {exemptFields: []string{"metadata.annotations", "metadata.labels"},
			why: subresourceWritesOnly + "; metadata is not carried over"},
		xcodeToolchainAnnotationPolicyName: {exemptFields: []string{"metadata.annotations", "metadata.labels"},
			why: subresourceWritesOnly + "; metadata is not carried over"},
		dsTolerationPolicyName: {exemptFields: []string{"metadata.ownerReferences", "spec.tolerations"},
			why: subresourceWritesOnly + "; it is a CREATE-time injector and the subresource cannot reach either field"},
	}

	// The universe: every exported top-level Ensure* in the package's sources.
	found := ensureFuncs(t)
	for _, name := range found {
		if _, ok := provisioners[name]; !ok {
			t.Errorf("%s is provisioned by the package but has no provisioner here; add it so its policies get a verdict", name)
		}
	}
	for name := range provisioners {
		if !slices.Contains(found, name) {
			t.Errorf("provisioner %s names no Ensure* function in the package; remove the stale entry", name)
		}
	}

	cs := fake.NewClientset()
	for name, provision := range provisioners {
		if err := provision(cs); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
	}
	managed := metav1.ListOptions{LabelSelector: managedLabel + "=true"}

	type podPolicy struct {
		rules       [][2][]string // per rule: operations, resources
		expressions []string
	}
	podPolicies := map[string]podPolicy{}

	vaps, err := cs.AdmissionregistrationV1().ValidatingAdmissionPolicies().List(ctx, managed)
	if err != nil {
		t.Fatalf("list VAPs: %v", err)
	}
	for _, p := range vaps.Items {
		var pp podPolicy
		if mc := p.Spec.MatchConstraints; mc != nil {
			for _, r := range mc.ResourceRules {
				if !slices.Contains(r.APIGroups, "") && !slices.Contains(r.APIGroups, "*") {
					continue
				}
				ops := make([]string, 0, len(r.Operations))
				for _, o := range r.Operations {
					ops = append(ops, string(o))
				}
				pp.rules = append(pp.rules, [2][]string{ops, r.Resources})
			}
		}
		for _, v := range p.Spec.Validations {
			pp.expressions = append(pp.expressions, v.Expression, v.MessageExpression)
		}
		for _, m := range p.Spec.MatchConditions {
			pp.expressions = append(pp.expressions, m.Expression)
		}
		for _, v := range p.Spec.Variables {
			pp.expressions = append(pp.expressions, v.Expression)
		}
		for _, a := range p.Spec.AuditAnnotations {
			pp.expressions = append(pp.expressions, a.ValueExpression)
		}
		if matchesPods(pp.rules) {
			podPolicies[p.Name] = pp
		}
	}
	maps, err := cs.AdmissionregistrationV1beta1().MutatingAdmissionPolicies().List(ctx, managed)
	if err != nil {
		t.Fatalf("list MAPs: %v", err)
	}
	for _, p := range maps.Items {
		var pp podPolicy
		if mc := p.Spec.MatchConstraints; mc != nil {
			for _, r := range mc.ResourceRules {
				if !slices.Contains(r.APIGroups, "") && !slices.Contains(r.APIGroups, "*") {
					continue
				}
				ops := make([]string, 0, len(r.Operations))
				for _, o := range r.Operations {
					ops = append(ops, string(o))
				}
				pp.rules = append(pp.rules, [2][]string{ops, r.Resources})
			}
		}
		for _, m := range p.Spec.MatchConditions {
			pp.expressions = append(pp.expressions, m.Expression)
		}
		for _, v := range p.Spec.Variables {
			pp.expressions = append(pp.expressions, v.Expression)
		}
		for _, m := range p.Spec.Mutations {
			if m.JSONPatch != nil {
				pp.expressions = append(pp.expressions, m.JSONPatch.Expression)
			}
			if m.ApplyConfiguration != nil {
				pp.expressions = append(pp.expressions, m.ApplyConfiguration.Expression)
			}
		}
		if matchesPods(pp.rules) {
			podPolicies[p.Name] = pp
		}
	}
	if len(podPolicies) == 0 {
		t.Fatal("no managed pod policy was provisioned; the enumeration is broken")
	}

	names := make([]string, 0, len(podPolicies))
	for n := range podPolicies {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, name := range names {
		pp := podPolicies[name]
		v, ok := verdicts[name]
		if !ok {
			t.Errorf("pod policy %s has no ephemeral-containers verdict; decide whether it must match UPDATE on %s or is exempt (name the field it reads)",
				name, ephemeralSubresource)
			continue
		}
		joined := strings.Join(pp.expressions, "\n")
		switch {
		case v.covers:
			if !hasRule(pp.rules, string(admissionregistrationv1.Update), ephemeralSubresource) {
				t.Errorf("%s: verdict covers, but no rule matches UPDATE on %s; rules = %v", name, ephemeralSubresource, pp.rules)
			}
		default:
			if len(v.exemptFields) == 0 || v.why == "" {
				t.Errorf("%s: an exempt verdict must name the fields read and why", name)
			}
			if strings.Contains(joined, "ephemeralContainers") {
				t.Errorf("%s: exempt, but its expressions read ephemeralContainers; it must cover %s instead", name, ephemeralSubresource)
			}
			// The named fields must be the ones the policy actually reads, or the
			// verdict is about some other policy.
			for _, f := range v.exemptFields {
				leaf := f[strings.LastIndex(f, ".")+1:]
				if !strings.Contains(joined, leaf) {
					t.Errorf("%s: exempt for %s, but its expressions never read %q", name, f, leaf)
				}
			}
		}
	}
	for name := range verdicts {
		if _, ok := podPolicies[name]; !ok {
			t.Errorf("verdict for %s names no provisioned pod policy; remove the stale row", name)
		}
	}
}

// ensureFuncs returns every exported top-level Ensure* function declared in the
// package's non-test sources.
func ensureFuncs(t *testing.T) []string {
	t.Helper()
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatalf("glob sources: %v", err)
	}
	fset := token.NewFileSet()
	var out []string
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		file, err := parser.ParseFile(fset, f, src, parser.SkipObjectResolution)
		if err != nil {
			t.Fatalf("parse %s: %v", f, err)
		}
		for _, d := range file.Decls {
			fn, ok := d.(*ast.FuncDecl)
			if !ok || fn.Recv != nil || !fn.Name.IsExported() || !strings.HasPrefix(fn.Name.Name, "Ensure") {
				continue
			}
			out = append(out, fn.Name.Name)
		}
	}
	if len(out) == 0 {
		t.Fatal("found no Ensure* function; the source scan is broken")
	}
	sort.Strings(out)
	return out
}

// matchesPods reports whether any core-group rule names pods or a pods
// subresource (or every resource).
func matchesPods(rules [][2][]string) bool {
	for _, r := range rules {
		for _, res := range r[1] {
			if res == "pods" || strings.HasPrefix(res, "pods/") || res == "*" || res == "*/*" {
				return true
			}
		}
	}
	return false
}

// hasRule reports whether some rule carries op (or "*") on resource.
func hasRule(rules [][2][]string, op, resource string) bool {
	for _, r := range rules {
		if (slices.Contains(r[0], op) || slices.Contains(r[0], "*")) && slices.Contains(r[1], resource) {
			return true
		}
	}
	return false
}

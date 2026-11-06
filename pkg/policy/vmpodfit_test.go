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
	"encoding/json"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/google/cel-go/cel"
	celtypes "github.com/google/cel-go/common/types"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apiserver/pkg/admission"
	plugincel "k8s.io/apiserver/pkg/admission/plugin/cel"
	"k8s.io/apiserver/pkg/admission/plugin/webhook/matchconditions"
	celconfig "k8s.io/apiserver/pkg/apis/cel"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/apiserver/pkg/cel/environment"
	"k8s.io/client-go/kubernetes/fake"

	mlxv1alpha1 "k3sm.io/apis/mlx/v1alpha1"
	runtimev1 "k3sm.io/apis/runtime/v1"
)

var (
	vmFitPodGVK = schema.GroupVersionKind{Version: "v1", Kind: "Pod"}
	vmFitPodGVR = schema.GroupVersionResource{Version: "v1", Resource: "pods"}
)

// vmFitExpr is the accessor the apiserver's compiler takes for an expression.
type vmFitExpr struct {
	expression string
	returns    []*cel.Type
}

func (e *vmFitExpr) GetExpression() string    { return e.expression }
func (e *vmFitExpr) ReturnTypes() []*cel.Type { return e.returns }

// vmFitVariable is the same for a named variable.
type vmFitVariable struct {
	vmFitExpr
	name string
}

func (v *vmFitVariable) GetName() string { return v.name }

// vmFitCompiled holds a policy compiled the way the apiserver compiles a stored one
// (compilePolicy in k8s.io/apiserver's policy/validating): one composited compiler,
// the variables stored first, then the match conditions, the validations and the
// message expressions. That package is not imported, because it would add modules to
// this one's graph; the compiler, the evaluators and the matcher are the apiserver's.
type vmFitCompiled struct {
	matcher     matchconditions.Matcher
	validations plugincel.ConditionEvaluator
	messages    plugincel.ConditionEvaluator
	match       plugincel.ConditionEvaluator
	rules       []admissionregistrationv1.Validation
}

func compileVMFit(t *testing.T, vars []admissionregistrationv1.Variable, conds []admissionregistrationv1.MatchCondition, rules []admissionregistrationv1.Validation) *vmFitCompiled {
	t.Helper()
	compiler, err := plugincel.NewCompositedCompiler(environment.MustBaseEnvSet(environment.DefaultCompatibilityVersion()))
	if err != nil {
		t.Fatalf("compiler: %v", err)
	}
	withAuthz := plugincel.OptionalVariableDeclarations{HasAuthorizer: true}
	for _, v := range vars {
		variable := &vmFitVariable{vmFitExpr{v.Expression, []*cel.Type{cel.AnyType, cel.DynType}}, v.Name}
		res := compiler.CompileAndStoreVariable(variable, withAuthz, environment.StoredExpressions)
		if res.Error != nil {
			t.Fatalf("variable %s does not compile: %v\nexpression:\n%s", v.Name, res.Error, v.Expression)
		}
	}
	c := &vmFitCompiled{rules: rules}
	if len(conds) > 0 {
		accessors := make([]plugincel.ExpressionAccessor, len(conds))
		for i := range conds {
			accessors[i] = (*matchconditions.MatchCondition)(&conds[i])
		}
		c.match = compiler.CompileCondition(accessors, withAuthz, environment.StoredExpressions)
		failFail := admissionregistrationv1.Fail
		c.matcher = matchconditions.NewMatcher(c.match, &failFail, "policy", "validate", vmPodFitPolicyName)
	}
	validations := make([]plugincel.ExpressionAccessor, len(rules))
	messages := make([]plugincel.ExpressionAccessor, len(rules))
	for i, r := range rules {
		validations[i] = &vmFitExpr{r.Expression, []*cel.Type{cel.BoolType}}
		if r.MessageExpression != "" {
			messages[i] = &vmFitExpr{r.MessageExpression, []*cel.Type{cel.StringType}}
		}
	}
	c.validations = compiler.CompileCondition(validations, withAuthz, environment.StoredExpressions)
	c.messages = compiler.CompileCondition(messages, plugincel.OptionalVariableDeclarations{}, environment.StoredExpressions)
	for _, ev := range []plugincel.ConditionEvaluator{c.match, c.validations, c.messages} {
		if ev == nil {
			continue
		}
		if errs := ev.CompilationErrors(); len(errs) > 0 {
			t.Fatalf("policy does not compile: %v", errs)
		}
	}
	return c
}

func compileVMFitPolicy(t *testing.T) *vmFitCompiled {
	t.Helper()
	return compileVMFit(t, VMPodFitVariables(), VMPodFitMatchConditions(), vmFitValidations())
}

func vmFitValidations() []admissionregistrationv1.Validation {
	rules := VMPodFitRules()
	out := make([]admissionregistrationv1.Validation, len(rules))
	for i, r := range rules {
		out[i] = r.Validation
	}
	return out
}

// vmFitRequest names an admission request. The zero value is a Pod CREATE.
type vmFitRequest struct {
	old         *corev1.Pod
	subResource string
}

func vmFitAttrs(t *testing.T, pod *corev1.Pod, req vmFitRequest) *admission.VersionedAttributes {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	op := admission.Create
	var oldObj runtime.Object
	var options runtime.Object = &metav1.CreateOptions{}
	if req.old != nil {
		op, oldObj, options = admission.Update, req.old, &metav1.UpdateOptions{}
	}
	attrs := admission.NewAttributesRecord(pod, oldObj, vmFitPodGVK, pod.Namespace, pod.Name, vmFitPodGVR,
		req.subResource, op, options, false, &user.DefaultInfo{Name: "tester"})
	versioned, err := admission.NewVersionedAttributes(attrs, vmFitPodGVK, admission.NewObjectInterfacesFromScheme(scheme))
	if err != nil {
		t.Fatalf("versioned attributes: %v", err)
	}
	return versioned
}

// vmFitOutcome is what evaluate decided: judged is false when a
// match condition left the request out, and refused maps a rule id to its message.
type vmFitOutcome struct {
	judged  bool
	refused map[string]string
}

// evaluate takes the steps of Validate in k8s.io/apiserver's policy/validating
// validator: the matcher, then the validations, then every message expression on
// what remains of the budget, then a message chosen for each refusal. An error is
// what failurePolicy Fail turns into a refusal with a CEL error in place of a reason.
func (c *vmFitCompiled) evaluate(t *testing.T, pod *corev1.Pod, req vmFitRequest, budget int64) (vmFitOutcome, error) {
	t.Helper()
	ctx := context.Background()
	attrs := vmFitAttrs(t, pod, req)
	out := vmFitOutcome{refused: map[string]string{}}
	if c.matcher != nil {
		res := c.matcher.Match(ctx, attrs, nil, nil)
		if res.Error != nil {
			return out, fmt.Errorf("match conditions: %w", res.Error)
		}
		if !res.Matches {
			return out, nil
		}
	}
	out.judged = true
	request := plugincel.CreateAdmissionRequest(attrs.Attributes, metav1.GroupVersionResource(vmFitPodGVR), metav1.GroupVersionKind(vmFitPodGVK))
	results, left, err := c.validations.ForInput(ctx, attrs, request, plugincel.OptionalVariableBindings{}, nil, budget)
	if err != nil {
		return out, fmt.Errorf("validations: %w", err)
	}
	messages, _, err := c.messages.ForInput(ctx, attrs, request, plugincel.OptionalVariableBindings{}, nil, left)
	if err != nil {
		return out, fmt.Errorf("message expressions: %w", err)
	}
	ids := VMPodFitRules()
	for i, r := range results {
		if r.Error != nil {
			return out, r.Error
		}
		if r.EvalResult != celtypes.True {
			out.refused[ids[i].ID] = vmFitMessage(messages[i], c.rules[i])
		}
	}
	return out, nil
}

// vmFitMessage chooses a refusal's text as the validator does: the rendered message,
// unless it failed, is over the size cap or holds a line break; then the static one.
func vmFitMessage(rendered plugincel.EvaluationResult, rule admissionregistrationv1.Validation) string {
	if rendered.Error == nil && rendered.EvalResult != nil {
		if text, ok := rendered.EvalResult.Value().(string); ok {
			text = strings.TrimSpace(text)
			if text != "" && len(text) <= celconfig.MaxEvaluatedMessageExpressionSizeBytes && !strings.Contains(text, "\n") {
				return text
			}
		}
	}
	return rule.Message
}

// review is evaluate for a request that must not error.
func (c *vmFitCompiled) review(t *testing.T, pod *corev1.Pod, req vmFitRequest, budget int64) vmFitOutcome {
	t.Helper()
	out, err := c.evaluate(t, pod, req, budget)
	if err != nil {
		t.Fatalf("evaluation error refuses the request under Fail: %v", err)
	}
	return out
}

func vmFitPod(mutate ...func(*corev1.Pod)) *corev1.Pod {
	vm := string(runtimev1.HandlerVM)
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "p", Namespace: "default"},
		Spec: corev1.PodSpec{
			RuntimeClassName: &vm,
			Containers:       []corev1.Container{{Name: "a", Image: "alpine"}},
		},
	}
	for _, m := range mutate {
		m(pod)
	}
	return pod
}

func withImages(images ...string) func(*corev1.Pod) {
	return func(p *corev1.Pod) {
		p.Spec.Containers = nil
		for i, img := range images {
			p.Spec.Containers = append(p.Spec.Containers, corev1.Container{Name: fmt.Sprintf("c%d", i), Image: img})
		}
	}
}

func withInit(image string) func(*corev1.Pod) {
	return func(p *corev1.Pod) {
		p.Spec.InitContainers = []corev1.Container{{Name: "init", Image: image}}
	}
}

func withVolume(name string, src corev1.VolumeSource) func(*corev1.Pod) {
	return func(p *corev1.Pod) {
		p.Spec.Volumes = append(p.Spec.Volumes, corev1.Volume{Name: name, VolumeSource: src})
	}
}

// withMounts gives the i-th main container the i-th list of mounts, adding
// containers on the base image as the lists need them.
func withMounts(lists ...[]corev1.VolumeMount) func(*corev1.Pod) {
	return func(p *corev1.Pod) {
		for i, list := range lists {
			if i >= len(p.Spec.Containers) {
				p.Spec.Containers = append(p.Spec.Containers, corev1.Container{Name: fmt.Sprintf("m%d", i), Image: p.Spec.Containers[0].Image})
			}
			p.Spec.Containers[i].VolumeMounts = list
		}
	}
}

func mnt(name, path string) []corev1.VolumeMount {
	return []corev1.VolumeMount{{Name: name, MountPath: path}}
}

func emptyDirSrc(medium corev1.StorageMedium) corev1.VolumeSource {
	return corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{Medium: medium}}
}

var (
	hostPathSrc  = corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/data"}}
	configMapSrc = corev1.VolumeSource{ConfigMap: &corev1.ConfigMapVolumeSource{LocalObjectReference: corev1.LocalObjectReference{Name: "cm"}}}
	pvcSrc       = corev1.VolumeSource{PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{ClaimName: "c"}}
	roPVCSrc     = corev1.VolumeSource{PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{ClaimName: "c", ReadOnly: true}}
)

// TestVMPodFitPolicyRefusesEachShape evaluates the vm pod fit policy with the
// apiserver's own compiler, evaluators and matcher against typed Pods. Each rule refuses its
// shape with its message, and admits the legal shape nearest to it.
func TestVMPodFitPolicyRefusesEachShape(t *testing.T) {
	policy := compileVMFitPolicy(t)

	ro := func(name, path string) []corev1.VolumeMount {
		return []corev1.VolumeMount{{Name: name, MountPath: path, ReadOnly: true}}
	}
	sub := func(name, path, subPath string) []corev1.VolumeMount {
		return []corev1.VolumeMount{{Name: name, MountPath: path, SubPath: subPath}}
	}
	gpuLimit := func(name string) func(*corev1.Pod) {
		return func(p *corev1.Pod) {
			p.Spec.Containers[0].Resources.Limits = corev1.ResourceList{corev1.ResourceName(name): resource.MustParse("1")}
		}
	}
	debugged := func(p *corev1.Pod) {
		p.Spec.EphemeralContainers = []corev1.EphemeralContainer{{EphemeralContainerCommon: corev1.EphemeralContainerCommon{Name: "dbg", Image: "busybox"}}}
	}

	const (
		r1Second  = "k3sm: this vm pod names images %s and %s, and the vm runtime starts every container from one image, so the second command would run against the first image's files. Use one image, or separate Pods."
		r2Host    = "k3sm: image %s names a host binary, and a vm pod runs in a Linux guest. Use a Linux image, or remove runtimeClassName: vm."
		r5Source  = "k3sm: volume %s is mounted, and its source is not one the vm RuntimeClass carries. See the vm RuntimeClass documentation for the supported sources."
		r8Sources = "k3sm: containers mount different sources at %s, and a vm pod holds one source at one path. Use one mount, or different paths."
		r10Text   = "k3sm: ephemeral containers are not supported on the vm RuntimeClass. Use kubectl exec."
		r11Text   = "k3sm: a vm pod cannot use the GPU. Remove the GPU limit, or remove runtimeClassName: vm."
	)

	tests := []struct {
		rule, name string
		pod        *corev1.Pod
		req        vmFitRequest
		want       string // the refusal message; empty means the shape is admitted
	}{
		{rule: "R1", name: "two main images", pod: vmFitPod(withImages("alpine", "nginx")), want: fmt.Sprintf(r1Second, "alpine", "nginx")},
		{rule: "R1", name: "an init image differs from the main image", pod: vmFitPod(withInit("busybox")), want: fmt.Sprintf(r1Second, "alpine", "busybox")},
		{rule: "R1", name: "neighbour: two containers on one image", pod: vmFitPod(withImages("alpine", "alpine"), withInit("alpine"))},

		{rule: "R2", name: "an absolute path", pod: vmFitPod(withImages("/bin/sleep")), want: fmt.Sprintf(r2Host, "/bin/sleep")},
		{rule: "R2", name: "native", pod: vmFitPod(withImages("native")), want: fmt.Sprintf(r2Host, "native")},
		{rule: "R2", name: "neighbour: a registry path holding a slash", pod: vmFitPod(withImages("registry.example/bin/sleep:1"))},
		{rule: "R2", name: "neighbour: an image named like the sentinel", pod: vmFitPod(withImages("native:1"))},

		{rule: "R3", name: "non-zero fsGroup", pod: vmFitPod(func(p *corev1.Pod) {
			g := int64(1000)
			p.Spec.SecurityContext = &corev1.PodSecurityContext{FSGroup: &g}
		}), want: "k3sm: fsGroup is not supported on the vm RuntimeClass. Remove fsGroup, or set it to 0."},
		{rule: "R3", name: "neighbour: fsGroup zero", pod: vmFitPod(func(p *corev1.Pod) {
			g := int64(0)
			p.Spec.SecurityContext = &corev1.PodSecurityContext{FSGroup: &g}
		})},
		{rule: "R3", name: "neighbour: a security context with no fsGroup", pod: vmFitPod(func(p *corev1.Pod) {
			p.Spec.SecurityContext = &corev1.PodSecurityContext{}
		})},

		{rule: "R4", name: "hostNetwork", pod: vmFitPod(func(p *corev1.Pod) { p.Spec.HostNetwork = true }),
			want: "k3sm: hostNetwork is not supported on the vm RuntimeClass: a guest has its own network stack."},
		{rule: "R4", name: "neighbour: no hostNetwork", pod: vmFitPod()},

		{rule: "R5", name: "a mounted hostPath", pod: vmFitPod(withVolume("h", hostPathSrc), withMounts(mnt("h", "/h"))), want: fmt.Sprintf(r5Source, "h")},
		{rule: "R5", name: "a mounted generic ephemeral volume", pod: vmFitPod(withVolume("e", corev1.VolumeSource{Ephemeral: &corev1.EphemeralVolumeSource{}}), withMounts(mnt("e", "/e"))), want: fmt.Sprintf(r5Source, "e")},
		{rule: "R5", name: "a mounted image volume", pod: vmFitPod(withVolume("i", corev1.VolumeSource{Image: &corev1.ImageVolumeSource{Reference: "x"}}), withMounts(mnt("i", "/i"))), want: fmt.Sprintf(r5Source, "i")},
		{rule: "R5", name: "mounted only by an init container", pod: vmFitPod(withVolume("h", hostPathSrc), withInit("alpine"), func(p *corev1.Pod) {
			p.Spec.InitContainers[0].VolumeMounts = mnt("h", "/h")
		}), want: fmt.Sprintf(r5Source, "h")},
		{rule: "R5", name: "neighbour: an unmounted hostPath", pod: vmFitPod(withVolume("h", hostPathSrc))},
		{rule: "R5", name: "neighbour: each carried source mounted", pod: vmFitPod(
			withVolume("cm", configMapSrc),
			withVolume("s", corev1.VolumeSource{Secret: &corev1.SecretVolumeSource{SecretName: "s"}}),
			withVolume("ed", emptyDirSrc("")),
			withVolume("d", corev1.VolumeSource{DownwardAPI: &corev1.DownwardAPIVolumeSource{}}),
			withVolume("pj", corev1.VolumeSource{Projected: &corev1.ProjectedVolumeSource{}}),
			withVolume("pv", pvcSrc),
			withMounts([]corev1.VolumeMount{{Name: "cm", MountPath: "/1"}, {Name: "s", MountPath: "/2"}, {Name: "ed", MountPath: "/3"}, {Name: "d", MountPath: "/4"}, {Name: "pj", MountPath: "/5"}, {Name: "pv", MountPath: "/6"}}),
		)},

		{rule: "R6", name: "HugePages medium", pod: vmFitPod(withVolume("hp", emptyDirSrc(corev1.StorageMediumHugePages))),
			want: "k3sm: volume hp asks for emptyDir medium HugePages, which the vm RuntimeClass does not support. Use the default medium or Memory."},
		{rule: "R6", name: "neighbour: Memory medium", pod: vmFitPod(withVolume("m", emptyDirSrc(corev1.StorageMediumMemory)))},
		{rule: "R6", name: "neighbour: default medium", pod: vmFitPod(withVolume("d", emptyDirSrc("")))},

		{rule: "R7", name: "Memory emptyDir with subPath", pod: vmFitPod(withVolume("m", emptyDirSrc(corev1.StorageMediumMemory)), withMounts(sub("m", "/m", "x"))),
			want: "k3sm: volume m is a Memory emptyDir mounted with subPath. That volume starts empty, so there is no subdirectory to mount. Remove subPath."},
		{rule: "R7", name: "neighbour: default emptyDir with subPath", pod: vmFitPod(withVolume("d", emptyDirSrc("")), withMounts(sub("d", "/d", "x")))},

		{rule: "R8", name: "different volumes at one path", pod: vmFitPod(withVolume("a", emptyDirSrc("")), withVolume("b", emptyDirSrc("")), withMounts(mnt("a", "/x"), mnt("b", "/x"))), want: fmt.Sprintf(r8Sources, "/x")},
		{rule: "R8", name: "different subPaths at one path", pod: vmFitPod(withVolume("a", emptyDirSrc("")), withMounts(sub("a", "/x", "1"), sub("a", "/x", "2"))), want: fmt.Sprintf(r8Sources, "/x")},
		{rule: "R8", name: "read-only differs on an emptyDir", pod: vmFitPod(withVolume("a", emptyDirSrc("")), withMounts(mnt("a", "/x"), ro("a", "/x"))), want: fmt.Sprintf(r8Sources, "/x")},
		{rule: "R8", name: "read-only differs on a PVC", pod: vmFitPod(withVolume("a", pvcSrc), withMounts(mnt("a", "/x"), ro("a", "/x"))), want: fmt.Sprintf(r8Sources, "/x")},
		{rule: "R8", name: "a conflict between non-adjacent containers", pod: vmFitPod(withVolume("a", emptyDirSrc("")), withVolume("b", emptyDirSrc("")), withMounts(mnt("a", "/x"), mnt("a", "/y"), mnt("b", "/x"))), want: fmt.Sprintf(r8Sources, "/x")},
		{rule: "R8", name: "neighbour: one mount repeated", pod: vmFitPod(withVolume("a", emptyDirSrc("")), withMounts(mnt("a", "/x"), mnt("a", "/x")))},
		{rule: "R8", name: "neighbour: read-only differs on a configMap, which collapses", pod: vmFitPod(withVolume("a", configMapSrc), withMounts(mnt("a", "/x"), ro("a", "/x")))},
		{rule: "R8", name: "neighbour: read-only differs on a read-only PVC, which collapses", pod: vmFitPod(withVolume("a", roPVCSrc), withMounts(mnt("a", "/x"), ro("a", "/x")))},
		{rule: "R8", name: "neighbour: different volumes at different paths", pod: vmFitPod(withVolume("a", emptyDirSrc("")), withVolume("b", emptyDirSrc("")), withMounts(mnt("a", "/x"), mnt("b", "/y")))},

		{rule: "R9", name: "one Memory emptyDir at two paths", pod: vmFitPod(withVolume("m", emptyDirSrc(corev1.StorageMediumMemory)), withMounts(mnt("m", "/a"), mnt("m", "/b"))),
			want: "k3sm: Memory emptyDir m is mounted at more than one path. Each path would be a separate volume, so the containers would not share it. Mount it at one path."},
		{rule: "R9", name: "neighbour: one Memory emptyDir at one path", pod: vmFitPod(withVolume("m", emptyDirSrc(corev1.StorageMediumMemory)), withMounts(mnt("m", "/a"), mnt("m", "/a")))},
		{rule: "R9", name: "neighbour: a default emptyDir at two paths", pod: vmFitPod(withVolume("d", emptyDirSrc("")), withMounts(mnt("d", "/a"), mnt("d", "/b")))},

		{rule: "R10", name: "kubectl debug", pod: vmFitPod(debugged), req: vmFitRequest{old: vmFitPod(), subResource: "ephemeralcontainers"}, want: r10Text},
		{rule: "R10", name: "neighbour: the subresource with no entry", pod: vmFitPod(), req: vmFitRequest{old: vmFitPod(), subResource: "ephemeralcontainers"}},

		{rule: "R11", name: "the mlx GPU limit", pod: vmFitPod(gpuLimit(mlxv1alpha1.ResourceGPU)), want: r11Text},
		{rule: "R11", name: "the runtime GPU limit", pod: vmFitPod(gpuLimit(runtimev1.ResourceGPU)), want: r11Text},
		{rule: "R11", name: "an init container's GPU limit", pod: vmFitPod(withInit("alpine"), func(p *corev1.Pod) {
			p.Spec.InitContainers[0].Resources.Limits = corev1.ResourceList{runtimev1.ResourceGPU: resource.MustParse("1")}
		}), want: r11Text},
		{rule: "R11", name: "neighbour: a memory limit", pod: vmFitPod(gpuLimit("memory"))},

		{rule: "R12", name: "subPathExpr", pod: vmFitPod(withVolume("d", emptyDirSrc("")), withMounts([]corev1.VolumeMount{{Name: "d", MountPath: "/d", SubPathExpr: "$(POD)"}})),
			want: "k3sm: volume d is mounted with subPathExpr, which the vm RuntimeClass does not expand, so the whole volume would appear at the path. Use subPath."},
		{rule: "R12", name: "neighbour: subPath", pod: vmFitPod(withVolume("d", emptyDirSrc("")), withMounts(sub("d", "/d", "x")))},
	}

	for _, tt := range tests {
		t.Run(tt.rule+"/"+tt.name, func(t *testing.T) {
			got := policy.review(t, tt.pod, tt.req, celconfig.RuntimeCELCostBudget)
			if !got.judged {
				t.Fatal("the match conditions left this request out, so nothing was judged")
			}
			if tt.want == "" {
				if len(got.refused) != 0 {
					t.Fatalf("refused the nearest legal shape: %v", got.refused)
				}
				return
			}
			if msg := got.refused[tt.rule]; msg != tt.want {
				t.Errorf("%s message:\n got %q\nwant %q", tt.rule, msg, tt.want)
			}
			if len(got.refused) != 1 {
				t.Errorf("want only %s to refuse this shape, got %v", tt.rule, got.refused)
			}
		})
	}

	t.Run("no runtimeClassName", func(t *testing.T) { testVMFitNoRuntimeClass(t, policy) })
	t.Run("requests", func(t *testing.T) { testVMFitRequests(t, policy) })
	t.Run("messages", testVMFitMessages)
	t.Run("provisioned object", testVMFitProvisionedObject)
	t.Run("worst-case cost", testVMFitWorstCaseCost)
}

// testVMFitNoRuntimeClass is the blast-radius proof: under failurePolicy Fail an
// erroring match condition would refuse every plain pod in the cluster.
func testVMFitNoRuntimeClass(t *testing.T, policy *vmFitCompiled) {
	plain := func(mutate ...func(*corev1.Pod)) *corev1.Pod {
		p := vmFitPod(mutate...)
		p.Spec.RuntimeClassName = nil
		return p
	}
	requests := map[string]vmFitRequest{
		"create":          {},
		"update":          {old: plain()},
		"image edit":      {old: plain(withImages("before"))},
		"ephemeral debug": {old: plain(), subResource: "ephemeralcontainers"},
	}
	for name, req := range requests {
		t.Run("match-condition evaluator/"+name, func(t *testing.T) {
			res := policy.matcher.Match(context.Background(), vmFitAttrs(t, plain(), req), nil, nil)
			if res.Error != nil {
				t.Fatalf("match condition error, which refuses the pod under Fail: %v", res.Error)
			}
			if res.Matches {
				t.Fatal("a pod with no runtimeClassName matched")
			}
			if got := res.FailedConditionName; got != vmPodFitScopeCondition {
				t.Errorf("left out by %q, want %q", got, vmPodFitScopeCondition)
			}
		})
	}
	t.Run("validation evaluator", func(t *testing.T) {
		unmatched := compileVMFit(t, VMPodFitVariables(), nil, vmFitValidations())
		got := unmatched.review(t, plain(), vmFitRequest{}, celconfig.RuntimeCELCostBudget)
		if !got.judged || len(got.refused) != 0 {
			t.Fatalf("validations on a plain pod: judged=%v refused=%v", got.judged, got.refused)
		}
	})
	t.Run("a plain pod in every refused shape is admitted", func(t *testing.T) {
		got := policy.review(t, plain(withImages("native", "/bin/sleep")), vmFitRequest{}, celconfig.RuntimeCELCostBudget)
		if got.judged {
			t.Fatalf("judged a pod outside the scope: %v", got.refused)
		}
	})
	t.Run("another runtime class is outside the scope", func(t *testing.T) {
		other := "container-vm"
		got := policy.review(t, plain(withImages("native"), func(p *corev1.Pod) { p.Spec.RuntimeClassName = &other }), vmFitRequest{}, celconfig.RuntimeCELCostBudget)
		if got.judged {
			t.Fatalf("judged a pod on another class: %v", got.refused)
		}
	})
	// The guards are load-bearing, which these two controls prove: without them the
	// same evaluator errors on the requests this policy sees most.
	t.Run("control: an unguarded runtimeClassName errors", func(t *testing.T) {
		bare := compileVMFit(t, VMPodFitVariables(), []admissionregistrationv1.MatchCondition{{Name: "bare", Expression: "object.spec.runtimeClassName == 'vm'"}}, vmFitValidations())
		if res := bare.matcher.Match(context.Background(), vmFitAttrs(t, plain(), vmFitRequest{}), nil, nil); res.Error == nil {
			t.Fatalf("the bare comparison did not error (matches=%v): the guard is not what admits a plain pod", res.Matches)
		}
	})
	t.Run("control: an unguarded subResource errors", func(t *testing.T) {
		bare := compileVMFit(t, VMPodFitVariables(), []admissionregistrationv1.MatchCondition{{Name: "bare", Expression: "request.subResource == 'ephemeralcontainers'"}}, vmFitValidations())
		if res := bare.matcher.Match(context.Background(), vmFitAttrs(t, vmFitPod(), vmFitRequest{old: vmFitPod()}), nil, nil); res.Error == nil {
			t.Fatalf("the bare comparison did not error (matches=%v): the guard is not what admits a metadata patch", res.Matches)
		}
	})
}

// testVMFitRequests covers each request arm of the match: which requests are judged,
// and that a validation gates on its own request.
func testVMFitRequests(t *testing.T, policy *vmFitCompiled) {
	fsGroup := func(p *corev1.Pod) {
		g := int64(1000)
		p.Spec.SecurityContext = &corev1.PodSecurityContext{FSGroup: &g}
	}
	memoryTwoPaths := []func(*corev1.Pod){withVolume("m", emptyDirSrc(corev1.StorageMediumMemory)), withMounts(mnt("m", "/a"), mnt("m", "/b"))}
	debugged := func(p *corev1.Pod) {
		p.Spec.EphemeralContainers = []corev1.EphemeralContainer{{EphemeralContainerCommon: corev1.EphemeralContainerCommon{Name: "dbg", Image: "busybox"}}}
	}
	storedBad := func(mutate ...func(*corev1.Pod)) *corev1.Pod {
		all := append([]func(*corev1.Pod){withImages("alpine", "nginx"), fsGroup}, memoryTwoPaths...)
		return vmFitPod(append(all, mutate...)...)
	}

	tests := []struct {
		name       string
		pod        *corev1.Pod
		req        vmFitRequest
		wantJudged bool
		wantRules  []string
	}{
		{name: "a metadata patch leaves a stored two-image pod alone", pod: storedBad(), req: vmFitRequest{old: storedBad()}},
		{name: "a metadata patch on a clean pod is not judged", pod: vmFitPod(), req: vmFitRequest{old: vmFitPod()}},
		{name: "kubectl set image keeping one image stays legal on a parked pod", pod: vmFitPod(withImages("fixed")), req: vmFitRequest{old: vmFitPod(withImages("typo"))}, wantJudged: true},
		{name: "an image edit to a second image is R1", pod: vmFitPod(withImages("alpine", "nginx")), req: vmFitRequest{old: vmFitPod(withImages("alpine", "alpine"))}, wantJudged: true, wantRules: []string{"R1"}},
		{name: "an init image edit to a second image is R1", pod: vmFitPod(withInit("busybox")), req: vmFitRequest{old: vmFitPod(withInit("alpine"))}, wantJudged: true, wantRules: []string{"R1"}},
		{name: "an image edit to a host binary is R2", pod: vmFitPod(withImages("native")), req: vmFitRequest{old: vmFitPod()}, wantJudged: true, wantRules: []string{"R2"}},
		{name: "an image edit judges only R1 and R2", pod: vmFitPod(withImages("fixed"), fsGroup, func(p *corev1.Pod) { p.Spec.HostNetwork = true }), req: vmFitRequest{old: vmFitPod(withImages("typo"), fsGroup, func(p *corev1.Pod) { p.Spec.HostNetwork = true })}, wantJudged: true},
		{name: "kubectl debug on a stored bad pod reads only R10", pod: storedBad(debugged), req: vmFitRequest{old: storedBad(), subResource: "ephemeralcontainers"}, wantJudged: true, wantRules: []string{"R10"}},
		{name: "a metadata patch on a pod holding an ephemeral container is not R10", pod: vmFitPod(debugged), req: vmFitRequest{old: vmFitPod(debugged)}},
		{name: "an image edit on a pod holding an ephemeral container is not R10", pod: vmFitPod(withImages("fixed"), debugged), req: vmFitRequest{old: vmFitPod(withImages("typo"), debugged)}, wantJudged: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := policy.review(t, tt.pod, tt.req, celconfig.RuntimeCELCostBudget)
			if got.judged != tt.wantJudged {
				t.Fatalf("judged = %v, want %v (refused: %v)", got.judged, tt.wantJudged, got.refused)
			}
			gotRules := make([]string, 0, len(got.refused))
			for id := range got.refused {
				gotRules = append(gotRules, id)
			}
			if len(gotRules) != len(tt.wantRules) || !slices.Equal(slices.Sorted(slices.Values(gotRules)), tt.wantRules) {
				t.Errorf("refused by %v, want %v", got.refused, tt.wantRules)
			}
		})
	}
}

// testVMFitMessages holds each message to what a 422 may say: it starts k3sm:, and
// names the user's own field, never a host path, a node or a mechanism. Rendered
// text quotes the user's image and path, so the path check reads the static text.
func testVMFitMessages(t *testing.T) {
	path := regexp.MustCompile(`(^|[\s'"(])/[A-Za-z0-9._-]`)
	banned := []string{"virtiofs", "idmapped", "guest init", "node", "kubelet", "runtimed", "launchd", "/var/", "/Users/"}
	rules := VMPodFitRules()
	if len(rules) != 12 {
		t.Fatalf("got %d rules, want 12", len(rules))
	}
	for i, r := range rules {
		if want := fmt.Sprintf("R%d", i+1); r.ID != want {
			t.Errorf("rule %d id = %q, want %q", i, r.ID, want)
		}
		v := r.Validation
		for _, text := range []string{v.Message, v.MessageExpression} {
			for _, word := range banned {
				if strings.Contains(text, word) {
					t.Errorf("%s holds %q: %s", r.ID, word, text)
				}
			}
		}
		if !strings.HasPrefix(v.Message, "k3sm:") {
			t.Errorf("%s static message does not start k3sm: %q", r.ID, v.Message)
		}
		if path.MatchString(v.Message) {
			t.Errorf("%s static message holds a path: %q", r.ID, v.Message)
		}
		if v.MessageExpression != "" && !strings.HasPrefix(v.MessageExpression, `"k3sm:`) {
			t.Errorf("%s message expression does not start k3sm: %q", r.ID, v.MessageExpression)
		}
		if v.Reason == nil || *v.Reason != metav1.StatusReasonInvalid {
			t.Errorf("%s reason = %v, want Invalid", r.ID, v.Reason)
		}
		// The apiserver's validation caps each expression at 5 KiB.
		for _, expr := range []string{v.Expression, v.MessageExpression} {
			if len(expr) > 5*1024 {
				t.Errorf("%s expression is %d bytes, over the 5 KiB cap", r.ID, len(expr))
			}
		}
	}
	for _, v := range VMPodFitVariables() {
		if len(v.Expression) > 5*1024 {
			t.Errorf("variable %s is %d bytes, over the 5 KiB cap", v.Name, len(v.Expression))
		}
	}
	t.Run("a message that cannot render falls back to the static text", func(t *testing.T) {
		policy := compileVMFitPolicy(t)
		got := policy.review(t, vmFitPod(withImages("alpine", "two\nlines")), vmFitRequest{}, celconfig.RuntimeCELCostBudget)
		if want := rules[0].Validation.Message; got.refused["R1"] != want {
			t.Errorf("R1 = %q, want the static %q", got.refused["R1"], want)
		}
	})
}

func testVMFitProvisionedObject(t *testing.T) {
	ctx := context.Background()
	cs := fake.NewClientset()
	if err := EnsureRejectUnrunnableVMPod(ctx, cs); err != nil {
		t.Fatalf("EnsureRejectUnrunnableVMPod: %v", err)
	}
	if err := EnsureRejectUnrunnableVMPod(ctx, cs); err != nil {
		t.Fatalf("second EnsureRejectUnrunnableVMPod: %v", err)
	}
	pol, err := cs.AdmissionregistrationV1().ValidatingAdmissionPolicies().Get(ctx, "k3sm-reject-unrunnable-vm-pod", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get policy: %v", err)
	}
	if pol.Labels[managedLabel] != "true" {
		t.Errorf("labels = %v", pol.Labels)
	}
	if pol.Spec.FailurePolicy == nil || *pol.Spec.FailurePolicy != admissionregistrationv1.Fail {
		t.Errorf("failurePolicy = %v, want Fail", pol.Spec.FailurePolicy)
	}
	if len(pol.Spec.Validations) != 12 {
		t.Errorf("validations = %d, want 12", len(pol.Spec.Validations))
	}
	type arm struct {
		op       admissionregistrationv1.OperationType
		resource string
	}
	var arms []arm
	for _, r := range pol.Spec.MatchConstraints.ResourceRules {
		if len(r.Operations) != 1 || len(r.Resources) != 1 {
			t.Fatalf("rule is not one operation on one resource: %+v", r)
		}
		arms = append(arms, arm{r.Operations[0], r.Resources[0]})
	}
	want := []arm{
		{admissionregistrationv1.Create, "pods"},
		{admissionregistrationv1.Update, "pods"},
		{admissionregistrationv1.Update, "pods/ephemeralcontainers"},
	}
	if !slices.Equal(arms, want) {
		t.Errorf("match arms = %v, want %v", arms, want)
	}
	if scope := pol.Spec.MatchConditions[0].Expression; scope != fmt.Sprintf("has(object.spec.runtimeClassName) && object.spec.runtimeClassName == '%s'", runtimev1.HandlerVM) {
		t.Errorf("scope condition = %q", scope)
	}
	binding, err := cs.AdmissionregistrationV1().ValidatingAdmissionPolicyBindings().Get(ctx, "k3sm-reject-unrunnable-vm-pod-binding", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get binding: %v", err)
	}
	if binding.Spec.PolicyName != pol.Name || !slices.Equal(binding.Spec.ValidationActions, []admissionregistrationv1.ValidationAction{admissionregistrationv1.Deny}) {
		t.Errorf("binding spec = %+v", binding.Spec)
	}
}

// vmFitWorstPod builds a pod of the given size. Names and paths are long, since a
// string comparison costs by length. Half the containers are init containers.
func vmFitWorstPod(shape string, containers, mountsEach, volumes int) *corev1.Pod {
	longName := func(i int) string { return fmt.Sprintf("volume-%056d", i) }
	longPath := func(a, b int) string { return fmt.Sprintf("/mnt/%040d/%040d/data", a, b) }
	pod := vmFitPod()
	pod.Spec.Containers = nil
	src := emptyDirSrc("")
	if shape != "distinct paths" {
		src = emptyDirSrc(corev1.StorageMediumMemory)
	}
	for v := range volumes {
		pod.Spec.Volumes = append(pod.Spec.Volumes, corev1.Volume{Name: longName(v), VolumeSource: src})
	}
	if shape == "distinct paths" {
		// R5's walk: a source no rule accepts, on a volume nothing mounts.
		for v := range volumes {
			pod.Spec.Volumes = append(pod.Spec.Volumes, corev1.Volume{Name: "unmounted-" + longName(v)[10:], VolumeSource: hostPathSrc})
		}
	}
	image := "registry.example/some/long/repository/path/image:v1.2.3-with-a-long-tag"
	for c := range containers {
		ctr := corev1.Container{Name: fmt.Sprintf("c%d", c), Image: image}
		for m := range mountsEach {
			var mount corev1.VolumeMount
			switch shape {
			case "distinct paths":
				mount = corev1.VolumeMount{Name: longName((c*mountsEach + m) % volumes), MountPath: longPath(c, m)}
			case "shared memory":
				mount = corev1.VolumeMount{Name: longName(m % volumes), MountPath: longPath(0, m)}
			case "every rule refuses":
				mount = corev1.VolumeMount{Name: longName((c + m) % volumes), MountPath: longPath(0, m), SubPath: "s", SubPathExpr: "$(POD)"}
			}
			ctr.VolumeMounts = append(ctr.VolumeMounts, mount)
		}
		if c%2 == 0 && c < containers-1 {
			pod.Spec.InitContainers = append(pod.Spec.InitContainers, ctr)
		} else {
			pod.Spec.Containers = append(pod.Spec.Containers, ctr)
		}
	}
	if shape == "every rule refuses" {
		g := int64(1000)
		pod.Spec.SecurityContext = &corev1.PodSecurityContext{FSGroup: &g}
		pod.Spec.HostNetwork = true
		pod.Spec.Containers[0].Image = "native"
		pod.Spec.Containers[0].Resources.Limits = corev1.ResourceList{runtimev1.ResourceGPU: resource.MustParse("1")}
		pod.Spec.Volumes = append(pod.Spec.Volumes,
			corev1.Volume{Name: "host", VolumeSource: hostPathSrc},
			corev1.Volume{Name: "huge", VolumeSource: emptyDirSrc(corev1.StorageMediumHugePages)})
		pod.Spec.Containers[0].VolumeMounts = append(pod.Spec.Containers[0].VolumeMounts, corev1.VolumeMount{Name: "host", MountPath: "/host"})
	}
	return pod
}

// vmFitCost returns what evaluating validations and then message expressions took
// from a fresh budget. The apiserver's validator evaluates every message expression on every
// request, whether or not its validation failed, and charges it to the same budget,
// so the message half counts on a legal pod too.
func vmFitCost(t *testing.T, c *vmFitCompiled, attrs *admission.VersionedAttributes) (validations, messages int64) {
	t.Helper()
	ctx := context.Background()
	req := plugincel.CreateAdmissionRequest(attrs.Attributes, metav1.GroupVersionResource(vmFitPodGVR), metav1.GroupVersionKind(vmFitPodGVK))
	const budget = int64(1) << 40
	results, left, err := c.validations.ForInput(ctx, attrs, req, plugincel.OptionalVariableBindings{}, nil, budget)
	if err != nil {
		t.Fatalf("validations: %v", err)
	}
	for _, r := range results {
		if r.Error != nil {
			t.Fatalf("validation evaluation error: %v", r.Error)
		}
	}
	validations = budget - left
	_, leftAfter, err := c.messages.ForInput(ctx, attrs, req, plugincel.OptionalVariableBindings{}, nil, budget)
	if err != nil {
		t.Fatalf("messages: %v", err)
	}
	return validations, budget - leftAfter
}

// testVMFitWorstCaseCost measures the policy on the largest pods it should meet, and
// holds each number under half its budget: a rule that burns the binding's budget
// takes the cheap rules with it, and Fail then refuses with a cost error in place
// of a k3sm reason. Run with -v to read the numbers.
func testVMFitWorstCaseCost(t *testing.T) {
	policy := compileVMFitPolicy(t)
	rules := VMPodFitRules()
	perRule := make([]*vmFitCompiled, len(rules))
	for i, r := range rules {
		perRule[i] = compileVMFit(t, VMPodFitVariables(), nil, []admissionregistrationv1.Validation{r.Validation})
	}
	sizes := []struct {
		name                         string
		containers, mountsEach, vols int
	}{
		{"30 containers, 60 mounts in all", 30, 2, 60},
		{"30 containers, 60 mounts each", 30, 60, 60},
		{"32 containers, 64 mounts each, 64 volumes", 32, 64, 64},
	}
	shapes := []string{"shared memory", "distinct paths", "every rule refuses"}
	for _, size := range sizes {
		for _, shape := range shapes {
			t.Run(size.name+"/"+shape, func(t *testing.T) {
				t.Parallel()
				pod := vmFitWorstPod(shape, size.containers, size.mountsEach, size.vols)
				attrs := vmFitAttrs(t, pod, vmFitRequest{})
				got := policy.review(t, pod, vmFitRequest{}, celconfig.RuntimeCELCostBudget/2)
				if !got.judged {
					t.Fatal("not judged")
				}
				switch shape {
				case "every rule refuses":
					for _, r := range rules {
						msg, refused := got.refused[r.ID]
						if !refused && r.ID != "R10" {
							t.Errorf("%s did not refuse", r.ID)
						}
						if refused && !strings.HasPrefix(msg, "k3sm:") {
							t.Errorf("%s message = %q", r.ID, msg)
						}
					}
				default:
					if len(got.refused) != 0 {
						t.Fatalf("a legal pod was refused: %v", got.refused)
					}
				}

				var report strings.Builder
				for i, r := range rules {
					validation, message := vmFitCost(t, perRule[i], attrs)
					fmt.Fprintf(&report, " %s=%d+%d", r.ID, validation, message)
					if validation > celconfig.PerCallLimit/2 || message > celconfig.PerCallLimit/2 {
						t.Errorf("%s costs %d+%d, over half the per-call limit %d", r.ID, validation, message, celconfig.PerCallLimit)
					}
				}
				validation, message := vmFitCost(t, policy, attrs)
				if total := validation + message; total > celconfig.RuntimeCELCostBudget/2 {
					t.Errorf("binding total %d is over half the budget %d", total, celconfig.RuntimeCELCostBudget)
				}
				encoded, err := json.Marshal(pod)
				if err != nil {
					t.Fatal(err)
				}
				t.Logf("cost: binding=%d+%d of %d; request %d bytes; rule=validation+message:%s",
					validation, message, celconfig.RuntimeCELCostBudget, len(encoded), report.String())
			})
		}
	}

	t.Run("match conditions on an image edit", func(t *testing.T) {
		pod := vmFitWorstPod("shared memory", 32, 64, 64)
		old := vmFitWorstPod("shared memory", 32, 64, 64)
		attrs := vmFitAttrs(t, pod, vmFitRequest{old: old})
		req := plugincel.CreateAdmissionRequest(attrs.Attributes, metav1.GroupVersionResource(vmFitPodGVR), metav1.GroupVersionKind(vmFitPodGVK))
		_, left, err := policy.match.ForInput(context.Background(), attrs, req, plugincel.OptionalVariableBindings{}, nil, celconfig.RuntimeCELCostBudgetMatchConditions)
		if err != nil {
			t.Fatalf("match conditions: %v", err)
		}
		used := int64(celconfig.RuntimeCELCostBudgetMatchConditions) - left
		if used > celconfig.RuntimeCELCostBudgetMatchConditions/2 {
			t.Errorf("match conditions cost %d, over half the budget %d", used, celconfig.RuntimeCELCostBudgetMatchConditions)
		}
		t.Logf("cost: match conditions=%d of %d", used, celconfig.RuntimeCELCostBudgetMatchConditions)
	})

	t.Run("the size at which evaluation first errors", func(t *testing.T) {
		t.Parallel()
		const requestLimit = celconfig.MaxRequestSizeBytes
		for mounts := 128; ; mounts += 64 {
			pod := vmFitWorstPod("shared memory", 32, mounts, mounts)
			encoded, err := json.Marshal(pod)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := policy.evaluate(t, pod, vmFitRequest{}, celconfig.RuntimeCELCostBudget); err != nil {
				t.Logf("first error: 32 containers, %d mounts each, %d request bytes (request limit %d): %.200v", mounts, len(encoded), requestLimit, err)
				return
			}
			if int64(len(encoded)) > 4*requestLimit {
				t.Logf("no error up to 32 containers, %d mounts each, %d request bytes (request limit %d)", mounts, len(encoded), requestLimit)
				return
			}
		}
	})
}

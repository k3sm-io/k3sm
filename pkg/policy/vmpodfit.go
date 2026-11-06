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

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	mlxv1alpha1 "k3sm.io/apis/mlx/v1alpha1"
	runtimev1 "k3sm.io/apis/runtime/v1"
)

const (
	// vmPodFitPolicyName / vmPodFitBindingName name the policy that refuses a vm
	// pod the provider cannot run. See EnsureRejectUnrunnableVMPod.
	vmPodFitPolicyName  = "k3sm-reject-unrunnable-vm-pod"
	vmPodFitBindingName = "k3sm-reject-unrunnable-vm-pod-binding"

	// vmPodFitScopeCondition and vmPodFitRequestCondition name the two match
	// conditions.
	vmPodFitScopeCondition   = "vm-runtime-class"
	vmPodFitRequestCondition = "create-debug-or-image-edit"

	// vmPodFitNativeImage is the sentinel image of a host-process container, which
	// a vm pod cannot run. The refuser's own constant is runtimed's
	// runtime.NativeImage; this package does not import runtimed.
	vmPodFitNativeImage = "native"
)

// VMPodFitRule is one rule of the vm pod fit policy: a stable id an audit can print,
// and the Validation the policy object carries.
type VMPodFitRule struct {
	// ID is "R1" to "R12". R10 judges the pods/ephemeralcontainers UPDATE; R1 and R2
	// judge Pod CREATE and an image edit; the others judge Pod CREATE.
	ID string
	// Validation is the rule as provisioned. Its expressions read the variables of
	// VMPodFitVariables and the request variable.
	Validation admissionregistrationv1.Validation
}

// VMPodFitMatchConditions returns the policy's match conditions.
//
// The first is the scope, and its has() is load-bearing. runtimeClassName is unset
// on almost every pod, selecting an unset field is an evaluation error, and under
// failurePolicy Fail an erroring condition refuses the request, so a bare comparison
// would refuse every plain pod in the cluster. Scoping is also the policy's blast
// radius: a broken rule can refuse vm pods, and no others.
//
// The second keeps metadata and controller patches out of evaluation. An image edit
// stays in, because a parked pod is rebuilt from its edited spec, so an edit to a
// second image would otherwise reach the runtime with no admission check.
func VMPodFitMatchConditions() []admissionregistrationv1.MatchCondition {
	return []admissionregistrationv1.MatchCondition{
		{
			Name:       vmPodFitScopeCondition,
			Expression: fmt.Sprintf("has(object.spec.runtimeClassName) && object.spec.runtimeClassName == '%s'", runtimev1.HandlerVM),
		},
		{
			Name:       vmPodFitRequestCondition,
			Expression: "variables.isCreate || variables.isEphemeralUpdate || variables.images != variables.oldImages",
		},
	}
}

// adjacentConflicts renders a variable that walks a sorted list once and yields
// result for each neighbouring pair where conflict holds. The rules that compare
// mounts use it because comparing every pair is quadratic: that form of the path rule
// passes the 1,000,000 per-call limit at a few hundred mounts, and a pod the provider
// could run would be refused with a cost error. Both conflict relations are an
// equality of fields, so if any two entries of a sorted run conflict then some
// neighbouring pair does.
func adjacentConflicts(sorted, conflict, result string) string {
	return fmt.Sprintf("%[1]s.size() < 2 ? [] : lists.range(%[1]s.size() - 1).filter(i, %[2]s).map(i, %[3]s)", sorted, conflict, result)
}

// VMPodFitVariables returns the variables the rules read, in dependency order. The
// apiserver evaluates a variable once per request and only when something reads it.
func VMPodFitVariables() []admissionregistrationv1.Variable {
	a, b := "variables.mountsByPath[i]", "variables.mountsByPath[i + 1]"
	subPath := func(m string) string { return fmt.Sprintf("(has(%[1]s.subPath) ? %[1]s.subPath : '')", m) }
	readOnly := func(m string) string { return fmt.Sprintf("(has(%[1]s.readOnly) && %[1]s.readOnly)", m) }
	pathConflict := fmt.Sprintf("%[1]s.mountPath == %[2]s.mountPath && (%[1]s.name != %[2]s.name || %[3]s != %[4]s || (%[5]s != %[6]s && %[1]s.name in variables.readOnlyMatters))",
		a, b, subPath(a), subPath(b), readOnly(a), readOnly(b))
	c, d := "variables.memoryMountsByName[i]", "variables.memoryMountsByName[i + 1]"
	memoryConflict := fmt.Sprintf("%[1]s.name == %[2]s.name && %[1]s.mountPath != %[2]s.mountPath", c, d)

	return []admissionregistrationv1.Variable{
		{Name: "isCreate", Expression: "request.operation == 'CREATE'"},
		// request.subResource is absent, not empty, on a request to the pod itself.
		{Name: "isEphemeralUpdate", Expression: "has(request.subResource) && request.subResource == 'ephemeralcontainers'"},
		{Name: "all", Expression: "object.spec.containers + (has(object.spec.initContainers) ? object.spec.initContainers : [])"},
		{Name: "images", Expression: "variables.all.map(c, has(c.image) ? c.image : '')"},
		{Name: "oldImages", Expression: "(oldObject.spec.containers + (has(oldObject.spec.initContainers) ? oldObject.spec.initContainers : [])).map(c, has(c.image) ? c.image : '')"},
		{Name: "mounts", Expression: "variables.all.map(c, has(c.volumeMounts) ? c.volumeMounts : []).flatten()"},
		{Name: "mountedNames", Expression: "variables.mounts.map(m, m.name)"},
		{Name: "volumes", Expression: "has(object.spec.volumes) ? object.spec.volumes : []"},
		{Name: "memoryVolumes", Expression: "variables.volumes.filter(v, has(v.emptyDir) && has(v.emptyDir.medium) && v.emptyDir.medium == 'Memory').map(v, v.name)"},
		{Name: "memoryMounts", Expression: "variables.memoryVolumes.size() == 0 ? [] : variables.mounts.filter(m, m.name in variables.memoryVolumes)"},
		{Name: "memoryMountsByName", Expression: "variables.memoryMounts.sortBy(m, m.name)"},
		{Name: "memoryPathConflicts", Expression: adjacentConflicts("variables.memoryMountsByName", memoryConflict, c+".name")},
		// A mount's read-only flag decides the guest mount only on these: a bind out
		// of a configMap, secret, downwardAPI or projected share is read-only
		// whatever the mount says, and so is any mount of a read-only claim.
		{Name: "readOnlyMatters", Expression: "variables.volumes.filter(v, has(v.emptyDir) || (has(v.persistentVolumeClaim) && !(has(v.persistentVolumeClaim.readOnly) && v.persistentVolumeClaim.readOnly))).map(v, v.name)"},
		{Name: "mountsByPath", Expression: "variables.mounts.sortBy(m, m.mountPath)"},
		{Name: "pathConflicts", Expression: adjacentConflicts("variables.mountsByPath", pathConflict, a+".mountPath")},
		{Name: "uncarriedMounted", Expression: "variables.volumes.filter(v, !has(v.configMap) && !has(v.secret) && !has(v.emptyDir) && !has(v.downwardAPI) && !has(v.projected) && !has(v.persistentVolumeClaim) && v.name in variables.mountedNames).map(v, v.name)"},
		{Name: "unsupportedMedia", Expression: "variables.volumes.filter(v, has(v.emptyDir) && has(v.emptyDir.medium) && v.emptyDir.medium != '' && v.emptyDir.medium != 'Memory')"},
		{Name: "memorySubPaths", Expression: "variables.memoryMounts.filter(m, has(m.subPath) && m.subPath != '').map(m, m.name)"},
		{Name: "subPathExprs", Expression: "variables.mounts.filter(m, has(m.subPathExpr) && m.subPathExpr != '').map(m, m.name)"},
	}
}

// onCreate gates a rule to Pod CREATE. An image edit and kubectl debug pass it, so a
// pod stored before this policy, or edited in place, never reads a rule its request
// did not touch.
func onCreate(rule string) string { return "!variables.isCreate || " + rule }

// VMPodFitRules returns the rules in order. Each carries a static message for when
// its message expression cannot render, for instance when the quoted image holds a
// line break. The apiserver evaluates every message expression on every judged
// request, so one that indexes an empty list simply errors and is ignored when its
// rule admits, and its cost counts on a legal pod too.
func VMPodFitRules() []VMPodFitRule {
	rule := func(id, expression, message, messageExpression string) VMPodFitRule {
		return VMPodFitRule{ID: id, Validation: admissionregistrationv1.Validation{
			Expression:        expression,
			Message:           message,
			MessageExpression: messageExpression,
			Reason:            reasonInvalid(),
		}}
	}
	hostBinary := fmt.Sprintf("i.startsWith('/') || i == '%s'", vmPodFitNativeImage)
	return []VMPodFitRule{
		rule("R1", "variables.isEphemeralUpdate || variables.images.all(i, i == variables.images[0])",
			"k3sm: this vm pod names more than one image, and the vm runtime starts every container from one image, so the second command would run against the first image's files. Use one image, or separate Pods.",
			`"k3sm: this vm pod names images " + variables.images[0] + " and " + variables.images.filter(i, i != variables.images[0])[0] + ", and the vm runtime starts every container from one image, so the second command would run against the first image's files. Use one image, or separate Pods."`),
		rule("R2", "variables.isEphemeralUpdate || !variables.images.exists(i, "+hostBinary+")",
			"k3sm: an image in this pod names a host binary, and a vm pod runs in a Linux guest. Use a Linux image, or remove runtimeClassName: vm.",
			`"k3sm: image " + variables.images.filter(i, `+hostBinary+`)[0] + " names a host binary, and a vm pod runs in a Linux guest. Use a Linux image, or remove runtimeClassName: vm."`),
		rule("R3", onCreate("!has(object.spec.securityContext) || !has(object.spec.securityContext.fsGroup) || object.spec.securityContext.fsGroup == 0"),
			"k3sm: fsGroup is not supported on the vm RuntimeClass. Remove fsGroup, or set it to 0.", ""),
		rule("R4", onCreate("!has(object.spec.hostNetwork) || !object.spec.hostNetwork"),
			"k3sm: hostNetwork is not supported on the vm RuntimeClass: a guest has its own network stack.", ""),
		rule("R5", onCreate("variables.uncarriedMounted.size() == 0"),
			"k3sm: a mounted volume's source is not one the vm RuntimeClass carries. See the vm RuntimeClass documentation for the supported sources.",
			`"k3sm: volume " + variables.uncarriedMounted[0] + " is mounted, and its source is not one the vm RuntimeClass carries. See the vm RuntimeClass documentation for the supported sources."`),
		rule("R6", onCreate("variables.unsupportedMedia.size() == 0"),
			"k3sm: an emptyDir volume asks for a medium the vm RuntimeClass does not support. Use the default medium or Memory.",
			`"k3sm: volume " + variables.unsupportedMedia[0].name + " asks for emptyDir medium " + variables.unsupportedMedia[0].emptyDir.medium + ", which the vm RuntimeClass does not support. Use the default medium or Memory."`),
		rule("R7", onCreate("variables.memorySubPaths.size() == 0"),
			"k3sm: a Memory emptyDir is mounted with subPath. That volume starts empty, so there is no subdirectory to mount. Remove subPath.",
			`"k3sm: volume " + variables.memorySubPaths[0] + " is a Memory emptyDir mounted with subPath. That volume starts empty, so there is no subdirectory to mount. Remove subPath."`),
		rule("R8", onCreate("variables.pathConflicts.size() == 0"),
			"k3sm: containers mount different sources at one path, and a vm pod holds one source at one path. Use one mount, or different paths.",
			`"k3sm: containers mount different sources at " + variables.pathConflicts[0] + ", and a vm pod holds one source at one path. Use one mount, or different paths."`),
		rule("R9", onCreate("variables.memoryPathConflicts.size() == 0"),
			"k3sm: a Memory emptyDir is mounted at more than one path. Each path would be a separate volume, so the containers would not share it. Mount it at one path.",
			`"k3sm: Memory emptyDir " + variables.memoryPathConflicts[0] + " is mounted at more than one path. Each path would be a separate volume, so the containers would not share it. Mount it at one path."`),
		rule("R10", "!variables.isEphemeralUpdate || !has(object.spec.ephemeralContainers) || object.spec.ephemeralContainers.size() == 0",
			"k3sm: ephemeral containers are not supported on the vm RuntimeClass. Use kubectl exec.", ""),
		rule("R11", onCreate(fmt.Sprintf("variables.all.all(c, !has(c.resources) || !has(c.resources.limits) || (!('%s' in c.resources.limits) && !('%s' in c.resources.limits)))", mlxv1alpha1.ResourceGPU, runtimev1.ResourceGPU)),
			"k3sm: a vm pod cannot use the GPU. Remove the GPU limit, or remove runtimeClassName: vm.", ""),
		rule("R12", onCreate("variables.subPathExprs.size() == 0"),
			"k3sm: a volume is mounted with subPathExpr, which the vm RuntimeClass does not expand, so the whole volume would appear at the path. Use subPath.",
			`"k3sm: volume " + variables.subPathExprs[0] + " is mounted with subPathExpr, which the vm RuntimeClass does not expand, so the whole volume would appear at the path. Use subPath."`),
	}
}

// EnsureRejectUnrunnableVMPod idempotently provisions the ValidatingAdmissionPolicy
// that refuses a pod on the vm RuntimeClass whose spec the provider cannot run, or
// would run wrong, with the reason for its own shape. A second image is such a shape
// and a second container is not: one guest runs every container of a pod. Safe to
// call on every server start (create-or-update; an unchanged spec is not rewritten).
//
// It is a fit check that tells an author a reason, not a security control, and the
// runtime's own refusals stay the authority: with no object present the apiserver
// admits everything. It covers only what the Pod spec shows, since CEL cannot read an
// image.
//
// It matches Pod CREATE, Pod UPDATE for an image edit, and the
// pods/ephemeralcontainers UPDATE `kubectl debug` issues. A rule on "pods" does not
// match a subresource, so a status patch never reaches it. Each validation gates on
// its own request, so `kubectl debug` on a stored pod reads the ephemeral-container
// reason and no other.
func EnsureRejectUnrunnableVMPod(ctx context.Context, cs kubernetes.Interface) error {
	rules := VMPodFitRules()
	validations := make([]admissionregistrationv1.Validation, len(rules))
	for i, r := range rules {
		validations[i] = r.Validation
	}
	podRule := func(op admissionregistrationv1.OperationType, resource string) admissionregistrationv1.NamedRuleWithOperations {
		return admissionregistrationv1.NamedRuleWithOperations{
			RuleWithOperations: admissionregistrationv1.RuleWithOperations{
				Operations: []admissionregistrationv1.OperationType{op},
				Rule: admissionregistrationv1.Rule{
					APIGroups:   []string{""},
					APIVersions: []string{"v1"},
					Resources:   []string{resource},
				},
			},
		}
	}
	failFail := admissionregistrationv1.Fail
	policy := &admissionregistrationv1.ValidatingAdmissionPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:   vmPodFitPolicyName,
			Labels: map[string]string{managedLabel: "true"},
		},
		Spec: admissionregistrationv1.ValidatingAdmissionPolicySpec{
			FailurePolicy: &failFail,
			MatchConstraints: &admissionregistrationv1.MatchResources{
				ResourceRules: []admissionregistrationv1.NamedRuleWithOperations{
					podRule(admissionregistrationv1.Create, "pods"),
					podRule(admissionregistrationv1.Update, "pods"),
					podRule(admissionregistrationv1.Update, "pods/ephemeralcontainers"),
				},
			},
			MatchConditions: VMPodFitMatchConditions(),
			Variables:       VMPodFitVariables(),
			Validations:     validations,
		},
	}
	if err := ensureValidatingAdmissionPolicy(ctx, cs, policy); err != nil {
		return fmt.Errorf("vm pod fit admission policy: %w", err)
	}

	binding := &admissionregistrationv1.ValidatingAdmissionPolicyBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:   vmPodFitBindingName,
			Labels: map[string]string{managedLabel: "true"},
		},
		Spec: admissionregistrationv1.ValidatingAdmissionPolicyBindingSpec{
			PolicyName:        vmPodFitPolicyName,
			ValidationActions: []admissionregistrationv1.ValidationAction{admissionregistrationv1.Deny},
		},
	}
	if err := ensureValidatingAdmissionPolicyBinding(ctx, cs, binding); err != nil {
		return fmt.Errorf("vm pod fit admission binding: %w", err)
	}
	return nil
}

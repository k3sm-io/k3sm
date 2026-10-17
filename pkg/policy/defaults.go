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
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	apiequality "k8s.io/apimachinery/pkg/api/equality"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// The apiserver fills defaults into every admission object it stores, so a
// stored spec is never DeepEqual to the sparse spec this package builds. The
// fields that differ, from the k8s.io/api admissionregistration/v1 type docs
// (the defaulting functions live in k8s.io/kubernetes, which this module does
// not import):
//
//   - spec.failurePolicy: Fail (validating and mutating policies);
//   - spec.reinvocationPolicy: Never (mutating policies);
//   - matchConstraints (policies) and matchResources (bindings): matchPolicy
//     Equivalent, an empty namespaceSelector and an empty objectSelector, and,
//     in every resource rule, scope "*". An absent matchResources on a binding
//     means "match all", the same as the defaulted empty one;
//   - paramRef.parameterNotFoundAction: Deny.
//
// Both sides of a comparison are defaulted the same way, so a field k3sm sets
// explicitly still compares as set, and a drifted one still differs.

func defaultMatchResources(m *admissionregistrationv1.MatchResources) *admissionregistrationv1.MatchResources {
	if m == nil {
		m = &admissionregistrationv1.MatchResources{}
	}
	if m.MatchPolicy == nil {
		p := admissionregistrationv1.Equivalent
		m.MatchPolicy = &p
	}
	if m.NamespaceSelector == nil {
		m.NamespaceSelector = &metav1.LabelSelector{}
	}
	if m.ObjectSelector == nil {
		m.ObjectSelector = &metav1.LabelSelector{}
	}
	for i := range m.ResourceRules {
		defaultRuleScope(&m.ResourceRules[i].Rule)
	}
	for i := range m.ExcludeResourceRules {
		defaultRuleScope(&m.ExcludeResourceRules[i].Rule)
	}
	return m
}

func defaultRuleScope(r *admissionregistrationv1.Rule) {
	if r.Scope == nil {
		s := admissionregistrationv1.AllScopes
		r.Scope = &s
	}
}

func defaultParamRef(p *admissionregistrationv1.ParamRef) {
	if p != nil && p.ParameterNotFoundAction == nil {
		a := admissionregistrationv1.DenyAction
		p.ParameterNotFoundAction = &a
	}
}

func defaultFailurePolicy(f **admissionregistrationv1.FailurePolicyType) {
	if *f == nil {
		p := admissionregistrationv1.Fail
		*f = &p
	}
}

// policySpecEqual compares two ValidatingAdmissionPolicy specs after the
// apiserver's defaults are applied to copies of both.
func policySpecEqual(a, b admissionregistrationv1.ValidatingAdmissionPolicySpec) bool {
	norm := func(s admissionregistrationv1.ValidatingAdmissionPolicySpec) admissionregistrationv1.ValidatingAdmissionPolicySpec {
		s = *s.DeepCopy()
		defaultFailurePolicy(&s.FailurePolicy)
		s.MatchConstraints = defaultMatchResources(s.MatchConstraints)
		return s
	}
	return apiequality.Semantic.DeepEqual(norm(a), norm(b))
}

// bindingSpecEqual is policySpecEqual for a ValidatingAdmissionPolicyBinding.
func bindingSpecEqual(a, b admissionregistrationv1.ValidatingAdmissionPolicyBindingSpec) bool {
	norm := func(s admissionregistrationv1.ValidatingAdmissionPolicyBindingSpec) admissionregistrationv1.ValidatingAdmissionPolicyBindingSpec {
		s = *s.DeepCopy()
		defaultParamRef(s.ParamRef)
		s.MatchResources = defaultMatchResources(s.MatchResources)
		return s
	}
	return apiequality.Semantic.DeepEqual(norm(a), norm(b))
}

// mutatingPolicySpecEqual is policySpecEqual for a MutatingAdmissionPolicy.
func mutatingPolicySpecEqual(a, b admissionregistrationv1.MutatingAdmissionPolicySpec) bool {
	norm := func(s admissionregistrationv1.MutatingAdmissionPolicySpec) admissionregistrationv1.MutatingAdmissionPolicySpec {
		s = *s.DeepCopy()
		defaultFailurePolicy(&s.FailurePolicy)
		if s.ReinvocationPolicy == "" {
			s.ReinvocationPolicy = admissionregistrationv1.NeverReinvocationPolicy
		}
		s.MatchConstraints = defaultMatchResources(s.MatchConstraints)
		return s
	}
	return apiequality.Semantic.DeepEqual(norm(a), norm(b))
}

// mutatingBindingSpecEqual is policySpecEqual for a MutatingAdmissionPolicyBinding.
func mutatingBindingSpecEqual(a, b admissionregistrationv1.MutatingAdmissionPolicyBindingSpec) bool {
	norm := func(s admissionregistrationv1.MutatingAdmissionPolicyBindingSpec) admissionregistrationv1.MutatingAdmissionPolicyBindingSpec {
		s = *s.DeepCopy()
		defaultParamRef(s.ParamRef)
		s.MatchResources = defaultMatchResources(s.MatchResources)
		return s
	}
	return apiequality.Semantic.DeepEqual(norm(a), norm(b))
}

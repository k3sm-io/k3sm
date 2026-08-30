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

package main

import (
	"context"
	"io"
	"log/slog"
	"slices"
	"strconv"
	"strings"
	"testing"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	runtimev1 "k3sm.io/apis/runtime/v1"
	"k3sm.io/k3sm/pkg/hostnet"
	"k3sm.io/k3sm/pkg/provider"
)

// wantClusterPolicies is the COMPLETE set of ValidatingAdmissionPolicy names
// bring-up must lay down, in EVERY posture. It is written out by name rather than
// derived from the code under test: a derived expectation would move with a
// regression instead of catching it.
//
// k3sm-reject-foreign-user is the load-bearing member (B153). It is the admission
// half of the documented no-per-pod-uid-isolation ceiling, and it was previously
// provisioned ONLY under the netd-helper backend — so a `--network none` or
// `--network direct` cluster had no such object and ADMITTED a pod requesting a
// foreign fsGroup/runAsUser, which is exactly what the first SIT T1 run observed.
//
// k3sm-warn-pod-hand-set-internet-egress is the B209 member: B91 landed the policy
// and its package-level tests, but bring-up never called the provisioner, so a live
// cluster carried six policies and this list is what makes that seventh one's
// absence a failing test rather than a `kubectl get vap` count nobody runs.
var wantClusterPolicies = []string{
	"k3sm-reject-foreign-user",
	"k3sm-reject-loadbalancer-reserved-port",
	"k3sm-require-os-darwin",
	"k3sm-warn-pod-hand-set-internet-egress",
	"k3sm-warn-pod-missing-provider-toleration",
	"k3sm-warn-service-externaltrafficpolicy-local",
	"k3sm-warn-service-udp",
}

// TestBringupProvisionsPolicies is the B153 regression gate: the set of admission
// policies bring-up provisions is INDEPENDENT of the host-network posture. The
// table is the real cross-product of the `--network` flag values and the two euid
// classes, resolved through the production resolver (hostnet.ResolveFor), so a row
// that cannot exist (`--network direct` unprivileged) is skipped by the resolver's
// own verdict rather than by the test's opinion.
func TestBringupProvisionsPolicies(t *testing.T) {
	const (
		rootEUID   = 0
		normalEUID = 501
	)
	tests := []struct {
		network string
		euid    int
	}{
		{"", normalEUID}, // auto, unprivileged -> helper (the shipped posture)
		{"", rootEUID},   // auto, root -> direct
		{"auto", normalEUID},
		{"auto", rootEUID},
		{"none", normalEUID}, // the SIT T0 posture
		{"none", rootEUID},
		{"direct", rootEUID}, // the SIT T1 posture
		{"helper", normalEUID},
		{"helper", rootEUID},
	}
	for _, tt := range tests {
		name := "network=" + tt.network + ",euid=" + strconv.Itoa(tt.euid)
		if tt.network == "" {
			name = "network=<unset>,euid=" + strconv.Itoa(tt.euid)
		}
		t.Run(name, func(t *testing.T) {
			mode, err := hostnet.ResolveFor(tt.network, tt.euid)
			if err != nil {
				t.Fatalf("hostnet.ResolveFor(%q, %d): %v", tt.network, tt.euid, err)
			}
			cs := fake.NewClientset()
			logger := slog.New(slog.NewTextHandler(io.Discard, nil))
			provisionClusterPolicies(context.Background(), cs, mode, tt.euid, logger)

			list, err := cs.AdmissionregistrationV1().ValidatingAdmissionPolicies().List(context.Background(), metav1.ListOptions{})
			if err != nil {
				t.Fatalf("list policies: %v", err)
			}
			var got []string
			for _, p := range list.Items {
				got = append(got, p.Name)
			}
			slices.Sort(got)
			if !slices.Equal(got, wantClusterPolicies) {
				t.Errorf("backend %s provisioned %v,\n                    want %v", mode.Backend, got, wantClusterPolicies)
			}
			// Named separately so the failure line says WHICH guard is missing —
			// this is the one whose absence is a security ceiling failing OPEN.
			if !slices.Contains(got, "k3sm-reject-foreign-user") {
				t.Errorf("backend %s did NOT provision k3sm-reject-foreign-user: the no-per-pod-uid-isolation ceiling fails OPEN in this posture (a pod requesting a foreign fsGroup/runAsUser is ADMITTED)", mode.Backend)
			}
			// Every policy needs its binding, or the object exists and enforces nothing.
			bindings, err := cs.AdmissionregistrationV1().ValidatingAdmissionPolicyBindings().List(context.Background(), metav1.ListOptions{})
			if err != nil {
				t.Fatalf("list bindings: %v", err)
			}
			bound := map[string]bool{}
			for _, b := range bindings.Items {
				bound[b.Spec.PolicyName] = true
			}
			for _, p := range wantClusterPolicies {
				if !bound[p] {
					t.Errorf("policy %s has no binding in backend %s — an unbound policy is evaluated by nothing", p, mode.Backend)
				}
			}
		})
	}
}

// TestBringupForeignUserPolicyPinsThePodExecutionUID pins the POLICY PARAMETER,
// not just the policy's presence: the CEL the foreign-user guard is provisioned
// with must embed the uid pods on this node actually execute as.
//
// Under a ROOT server os.Geteuid() is 0, and provisioning the guard with 0 would
// invert it — root becomes the only admitted identity, naming root as "the k3sm
// pod identity" in the very message that says otherwise. The expectation is
// therefore derived from provider.PodExecutionUID, the one authority for the
// question, and the root row asserts the non-inversion directly.
func TestBringupForeignUserPolicyPinsThePodExecutionUID(t *testing.T) {
	for _, tt := range []struct {
		name    string
		network string
		euid    int
	}{
		// 271 is deliberately NOT this test process's own euid: were the
		// provisioning to read os.Geteuid() instead of the euid it is handed,
		// these rows would embed the developer's uid and fail.
		{"unprivileged helper (the shipped posture)", "helper", 271},
		{"unprivileged none (SIT T0)", "none", 271},
		{"root direct (SIT T1)", "direct", 0},
	} {
		t.Run(tt.name, func(t *testing.T) {
			mode, err := hostnet.ResolveFor(tt.network, tt.euid)
			if err != nil {
				t.Fatalf("hostnet.ResolveFor: %v", err)
			}
			cs := fake.NewClientset()
			provisionClusterPolicies(context.Background(), cs, mode, tt.euid, slog.New(slog.NewTextHandler(io.Discard, nil)))

			pol, err := cs.AdmissionregistrationV1().ValidatingAdmissionPolicies().Get(context.Background(), "k3sm-reject-foreign-user", metav1.GetOptions{})
			if err != nil {
				t.Fatalf("get k3sm-reject-foreign-user: %v", err)
			}
			if len(pol.Spec.Validations) != 1 {
				t.Fatalf("validations = %d, want 1", len(pol.Spec.Validations))
			}
			expr := pol.Spec.Validations[0].Expression
			want := strconv.FormatInt(provider.PodExecutionUID(tt.euid), 10)
			if !strings.Contains(expr, "== "+want) {
				t.Errorf("provisioned CEL does not pin the pod-execution uid %s:\n%s", want, expr)
			}
			if tt.euid != 0 && strings.Contains(expr, "== 0)") {
				t.Errorf("provisioned CEL admits uid 0 in an unprivileged posture:\n%s", expr)
			}
		})
	}
}

// TestServerProvisionsTheEgressWarnVAP is the B209 gate: bring-up must CALL
// policy.EnsureEgressAnnotationWarn, not merely be able to.
//
// B91 landed the policy, its CEL, and its package-level tests — all green — while
// provisionClusterPolicies never invoked it, so a live cluster ran with six
// ValidatingAdmissionPolicies and hand-setting the internet-egress annotation
// warned nothing. That is the B195 class: a unit test over an exported constructor
// proves the object can be built, never that anything builds it. This test is
// therefore written at the ASSEMBLY seam (provisionClusterPolicies, the one
// production caller) and reds the moment the call site is dropped.
//
// It asserts the provisioned shape as well as the name, because a present-but-inert
// object is the same operator experience as an absent one: the binding must exist
// and act WARN (never Deny — the annotation is not a security boundary and its own
// doc comment says enforcement stops at the SandboxProfile), the policy must be
// FailurePolicy Ignore (an advisory must never take Pod CREATE down), it must match
// pods on CREATE only (matching UPDATE re-fires on every status patch), and its CEL
// must name the real annotation key from apis rather than a copy that can drift.
func TestServerProvisionsTheEgressWarnVAP(t *testing.T) {
	const (
		policyName  = "k3sm-warn-pod-hand-set-internet-egress"
		bindingName = "k3sm-warn-pod-hand-set-internet-egress-binding"
	)
	// The same posture cross-product the sibling gate walks: the advisory is
	// mode-independent, so every backend must lay it down.
	for _, tt := range []struct {
		network string
		euid    int
	}{
		{"", 501},
		{"auto", 501},
		{"none", 501},
		{"none", 0},
		{"direct", 0},
		{"helper", 501},
	} {
		name := "network=" + tt.network + ",euid=" + strconv.Itoa(tt.euid)
		if tt.network == "" {
			name = "network=<unset>,euid=" + strconv.Itoa(tt.euid)
		}
		t.Run(name, func(t *testing.T) {
			mode, err := hostnet.ResolveFor(tt.network, tt.euid)
			if err != nil {
				t.Fatalf("hostnet.ResolveFor(%q, %d): %v", tt.network, tt.euid, err)
			}
			cs := fake.NewClientset()
			provisionClusterPolicies(context.Background(), cs, mode, tt.euid,
				slog.New(slog.NewTextHandler(io.Discard, nil)))

			pol, err := cs.AdmissionregistrationV1().ValidatingAdmissionPolicies().
				Get(context.Background(), policyName, metav1.GetOptions{})
			if err != nil {
				t.Fatalf("bring-up did not provision %s (backend %s): %v — the hand-set %s annotation warns nothing on a live cluster",
					policyName, mode.Backend, err, runtimev1.AnnotationInternetEgress)
			}
			if pol.Spec.FailurePolicy == nil || *pol.Spec.FailurePolicy != admissionregistrationv1.Ignore {
				t.Errorf("%s FailurePolicy = %v, want Ignore — an advisory must never fail Pod CREATE closed", policyName, pol.Spec.FailurePolicy)
			}
			if len(pol.Spec.Validations) != 1 {
				t.Fatalf("%s validations = %d, want 1", policyName, len(pol.Spec.Validations))
			}
			if expr := pol.Spec.Validations[0].Expression; !strings.Contains(expr, runtimev1.AnnotationInternetEgress) {
				t.Errorf("%s CEL does not name %s:\n%s", policyName, runtimev1.AnnotationInternetEgress, expr)
			}
			rules := pol.Spec.MatchConstraints.ResourceRules
			if len(rules) != 1 {
				t.Fatalf("%s resource rules = %d, want 1", policyName, len(rules))
			}
			if got := rules[0].Resources; !slices.Equal(got, []string{"pods"}) {
				t.Errorf("%s matches %v, want [pods]", policyName, got)
			}
			if got := rules[0].Operations; !slices.Equal(got, []admissionregistrationv1.OperationType{admissionregistrationv1.Create}) {
				t.Errorf("%s operations = %v, want [CREATE] only — matching UPDATE re-fires on every status patch", policyName, got)
			}

			bind, err := cs.AdmissionregistrationV1().ValidatingAdmissionPolicyBindings().
				Get(context.Background(), bindingName, metav1.GetOptions{})
			if err != nil {
				t.Fatalf("bring-up did not provision %s (backend %s): %v — an unbound policy is evaluated by nothing", bindingName, mode.Backend, err)
			}
			if bind.Spec.PolicyName != policyName {
				t.Errorf("%s binds %q, want %q", bindingName, bind.Spec.PolicyName, policyName)
			}
			if got := bind.Spec.ValidationActions; !slices.Equal(got, []admissionregistrationv1.ValidationAction{admissionregistrationv1.Warn}) {
				t.Errorf("%s actions = %v, want [Warn] — the annotation is plumbing, never a boundary to deny on", bindingName, got)
			}
		})
	}
}

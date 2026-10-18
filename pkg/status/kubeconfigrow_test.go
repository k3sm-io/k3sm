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

package status

import (
	"context"
	"errors"
	"strings"
	"testing"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"k3sm.io/k3sm/pkg/dataroot"
)

// reviewSelf is a ReviewSelf seam that answers user, or err, and records the
// client it was handed.
func reviewSelf(user string, err error, got *Kube) func(context.Context, Kube) (string, error) {
	return func(_ context.Context, kube Kube) (string, error) {
		if got != nil {
			*got = kube
		}
		return user, err
	}
}

// TestKubeconfigRowReportsRefusedCredential pins the kubeconfig row's proof of
// the credential: a 401 to the SelfSubjectReview is the refused state with a
// remedy and an alert; a 403 authenticated and is not refused; a success adds
// the user name to Wide; any other error leaves the row as it was.
func TestKubeconfigRowReportsRefusedCredential(t *testing.T) {
	const source = `/Users/me/.kube/config context "k3sm"`
	unauthorized := apierrors.NewUnauthorized("Unauthorized")
	forbidden := apierrors.NewForbidden(schema.GroupResource{Group: "authentication.k8s.io", Resource: "selfsubjectreviews"}, "", errors.New("denied"))

	cases := []struct {
		name       string
		kube       Kube
		review     func(context.Context, Kube) (string, error)
		fromUser   bool
		role       dataroot.Role
		wantState  RowState
		wantSev    Severity
		wantDetail string
		wantRemedy string
		wantUser   string
		wantAlert  string // a substring of the alert's cause; empty means no alert
	}{
		{
			name: "401 on a server is refused", kube: fakeKube{}, review: reviewSelf("", unauthorized, nil), role: dataroot.RoleServer,
			wantState: StateRefused, wantSev: SeverityFail,
			wantDetail: "the apiserver refused the credential in " + source + " (401 Unauthorized)",
			wantRemedy: "sudo k3sm install   # merges this server's current admin credential into your kubeconfig",
			wantAlert:  "refused the credential in your kubeconfig",
		},
		{
			name: "401 on a worker's own kubeconfig is refused", kube: fakeKube{}, review: reviewSelf("", unauthorized, nil), fromUser: true, role: dataroot.RoleAgent,
			wantState: StateRefused, wantSev: SeverityFail,
			wantDetail: "the apiserver refused the credential in " + source + " (401 Unauthorized); " + UserKubeNote,
			wantRemedy: RefusedUserKubeconfigRemedy,
			wantAlert:  "refused the credential in your kubeconfig",
		},
		{
			name: "401 on a worker's node credential is refused", kube: fakeKube{}, review: reviewSelf("", unauthorized, nil), role: dataroot.RoleAgent,
			wantState: StateRefused, wantSev: SeverityFail,
			wantDetail: "the apiserver refused the credential in " + source + " (401 Unauthorized)",
			wantRemedy: Collector{}.joinRemedy(),
			wantAlert:  "refused this worker's node credential",
		},
		{
			name: "403 authenticated, so it is not refused", kube: fakeKube{}, review: reviewSelf("", forbidden, nil), role: dataroot.RoleServer,
			wantState: StateOK, wantSev: SeverityOK, wantDetail: source,
		},
		{
			name: "success names the user", kube: fakeKube{}, review: reviewSelf("admin", nil, nil), role: dataroot.RoleServer,
			wantState: StateOK, wantSev: SeverityOK, wantDetail: source, wantUser: "admin",
		},
		{
			name: "timeout leaves the row as it was", kube: fakeKube{}, review: reviewSelf("", context.DeadlineExceeded, nil), role: dataroot.RoleServer,
			wantState: StateOK, wantSev: SeverityOK, wantDetail: source,
		},
		{
			name: "unreachable leaves the row as it was", kube: fakeKube{}, review: reviewSelf("", errors.New("dial tcp 127.0.0.1:6444: connect: connection refused"), nil), role: dataroot.RoleServer,
			wantState: StateOK, wantSev: SeverityOK, wantDetail: source,
		},
		{
			name: "no client is missing and is not reviewed", review: func(context.Context, Kube) (string, error) {
				t.Error("ReviewSelf called without a client")
				return "", nil
			}, role: dataroot.RoleServer,
			wantState: StateMissing, wantSev: SeverityWarn, wantDetail: "no k3sm context",
			wantRemedy: "sudo k3sm install\nk3sm kubeconfig --write",
			wantAlert:  "No kubeconfig was found",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := Collector{Kube: tc.kube, KubeSource: source, ReviewSelf: tc.review, kubeFromUser: tc.fromUser}
			if tc.kube == nil {
				c.KubeErr = errors.New("no k3sm context")
			}
			r := c.kubeconfigRow(context.Background(), tc.role)
			if r.State != tc.wantState || r.Severity != tc.wantSev {
				t.Fatalf("state = %s/%s, want %s/%s (detail %q)", r.State, r.Severity, tc.wantState, tc.wantSev, r.Detail)
			}
			wantDetail := tc.wantDetail
			if tc.fromUser && tc.wantState == StateOK {
				wantDetail += " (" + UserKubeNote + ")"
			}
			if r.Detail != wantDetail {
				t.Errorf("detail = %q, want %q", r.Detail, wantDetail)
			}
			if r.Remedy != tc.wantRemedy {
				t.Errorf("remedy = %q, want %q", r.Remedy, tc.wantRemedy)
			}
			if got := r.Wide["user"]; got != tc.wantUser {
				t.Errorf("wide.user = %q, want %q", got, tc.wantUser)
			}
			var a *Alert
			if NeedsAlert(r) {
				a = alertFor(r, alertContext{now: goldenTime, role: tc.role})
			}
			switch {
			case tc.wantAlert == "" && a != nil:
				t.Errorf("alert = %+v, want none", a)
			case tc.wantAlert != "" && (a == nil || !strings.Contains(a.Cause, tc.wantAlert)):
				t.Errorf("alert = %+v, want a cause containing %q", a, tc.wantAlert)
			case tc.wantAlert != "" && len(a.Fix) == 0:
				t.Errorf("alert %q has no fix steps", a.Cause)
			}
			if a != nil && a.generic {
				t.Errorf("alert %q is the generic floor, not the kubeconfig row's own", a.Cause)
			}
		})
	}
}

// TestKubeconfigRowReviewsTheClientInUse pins that the review is made with the
// client the report reads the cluster with, not some other one.
func TestKubeconfigRowReviewsTheClientInUse(t *testing.T) {
	var got Kube
	kube := fakeKube{server: "https://192.0.2.10:6444"}
	Collector{Kube: kube, ReviewSelf: reviewSelf("admin", nil, &got)}.kubeconfigRow(context.Background(), dataroot.RoleServer)
	if fk, ok := got.(fakeKube); !ok || fk.server != kube.server {
		t.Fatalf("reviewed client = %#v, want %#v", got, kube)
	}
}

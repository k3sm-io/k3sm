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
	"net/http"
	"strings"
	"testing"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

// TestStatusReviewSelf pins the production review against a faked apiserver: a
// 401 comes back as the typed Unauthorized error the kubeconfig row keys on, a
// 403 as Forbidden (never Unauthorized), and a 201 as the user name.
func TestStatusReviewSelf(t *testing.T) {
	const path = "/apis/authentication.k8s.io/v1/selfsubjectreviews"
	cases := []struct {
		name         string
		code         int
		body         string
		wantUser     string
		unauthorized bool
		forbidden    bool
	}{
		{name: "401", code: http.StatusUnauthorized, body: `{"kind":"Status","apiVersion":"v1","status":"Failure","message":"Unauthorized","reason":"Unauthorized","code":401}`, unauthorized: true},
		{name: "403", code: http.StatusForbidden, body: `{"kind":"Status","apiVersion":"v1","status":"Failure","message":"forbidden","reason":"Forbidden","code":403}`, forbidden: true},
		{name: "201", code: http.StatusCreated, body: `{"kind":"SelfSubjectReview","apiVersion":"authentication.k8s.io/v1","status":{"userInfo":{"username":"admin"}}}`, wantUser: "admin"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// The apiserver is faked at the transport, so no socket is opened.
			rt := roundTripFunc(func(r *http.Request) (*http.Response, error) {
				if r.Method != http.MethodPost || r.URL.Path != path {
					t.Errorf("request %s %s, want POST %s", r.Method, r.URL.Path, path)
				}
				return &http.Response{
					StatusCode: tc.code,
					Header:     http.Header{"Content-Type": []string{"application/json"}},
					Body:       io.NopCloser(strings.NewReader(tc.body)),
					Request:    r,
				}, nil
			})
			client, err := kubernetes.NewForConfig(&rest.Config{Host: "https://apiserver.invalid:6444", Transport: rt})
			if err != nil {
				t.Fatal(err)
			}
			user, err := statusReviewSelf(context.Background(), restKube{client: client})
			if got := apierrors.IsUnauthorized(err); got != tc.unauthorized {
				t.Errorf("IsUnauthorized(%v) = %v, want %v", err, got, tc.unauthorized)
			}
			if got := apierrors.IsForbidden(err); got != tc.forbidden {
				t.Errorf("IsForbidden(%v) = %v, want %v", err, got, tc.forbidden)
			}
			if user != tc.wantUser {
				t.Errorf("user = %q, want %q", user, tc.wantUser)
			}
		})
	}
}

// TestStatusReviewSelfWithoutClient pins that a client this command did not
// build is reported as an error, which leaves the row as it was.
func TestStatusReviewSelfWithoutClient(t *testing.T) {
	if _, err := statusReviewSelf(context.Background(), restKube{}); err == nil || apierrors.IsUnauthorized(err) {
		t.Fatalf("err = %v, want a plain error", err)
	}
}

// roundTripFunc is an http.RoundTripper made of a function.
type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

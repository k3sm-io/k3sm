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
	"testing"
	"time"

	"k3sm.io/k3sm/pkg/certs"
)

// TestDeregisterEligibility pins the expiry rule an uninstall decides on.
//
// The rule is the certificate's RAW NotAfter, and the case that matters is the
// one where it DISAGREES with the credential store: a node whose certificate
// expires in an hour is `credentialExpired` to an agent START (inside
// credentialExpiryMargin, so the operator is told to supply a token), and that
// verdict has nothing to do with a deregistration, which needs the certificate
// to authenticate one request lasting a few seconds. Deciding this on the
// store's verdict would silently skip the deregistration for every node in its
// last day of validity and leave a peer entry behind on every other Mac.
func TestDeregisterEligibility(t *testing.T) {
	now := time.Date(2026, 9, 17, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		name       string
		notAfter   time.Time
		wantEligib bool
	}{
		{"a year of validity left", now.Add(365 * 24 * time.Hour), true},
		{"one hour from expiry, which the store already calls expired", now.Add(time.Hour), true},
		{"one second from expiry", now.Add(time.Second), true},
		{"expired one second ago", now.Add(-time.Second), false},
		{"expired a week ago", now.Add(-7 * 24 * time.Hour), false},
		{"expiring exactly now", now, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := deregisterEligible(tc.notAfter, now); got != tc.wantEligib {
				t.Errorf("deregisterEligible(%s, %s) = %v, want %v", tc.notAfter, now, got, tc.wantEligib)
			}
		})
	}
	// The disagreement stated as the property, not as an example: inside the
	// store's margin the credential is EXPIRED for a start and ELIGIBLE here.
	inMargin := now.Add(credentialExpiryMargin / 2)
	if !deregisterEligible(inMargin, now) {
		t.Errorf("a certificate %s from expiry must still deregister: the %s store margin decides which START failure to report, not whether a certificate can authenticate one request",
			credentialExpiryMargin/2, credentialExpiryMargin)
	}
}

// TestNodeNameFromClientCert proves the node a deregistration names comes from
// the CERTIFICATE, which is the only thing the server checks the request body
// against. A Mac renamed since it joined still deregisters the node it is.
func TestNodeNameFromClientCert(t *testing.T) {
	ca, err := certs.NewCA("k3sm-signing-ca")
	if err != nil {
		t.Fatalf("signing CA: %v", err)
	}
	certPEM, _, err := ca.IssueClient("system:node:k3sm-worker-1", []string{"system:nodes"}, time.Hour)
	if err != nil {
		t.Fatalf("issue client cert: %v", err)
	}
	got, err := nodeNameFromClientCert(certPEM)
	if err != nil {
		t.Fatalf("nodeNameFromClientCert: %v", err)
	}
	if got != "k3sm-worker-1" {
		t.Errorf("node name = %q, want k3sm-worker-1", got)
	}

	// An identity that is not a node cannot name one.
	otherPEM, _, err := ca.IssueClient(certs.APIServerKubeletClientCN, nil, time.Hour)
	if err != nil {
		t.Fatalf("issue non-node cert: %v", err)
	}
	if name, err := nodeNameFromClientCert(otherPEM); err == nil {
		t.Errorf("a non-node certificate yielded node name %q, want an error", name)
	}
	if _, err := nodeNameFromClientCert([]byte("not a certificate")); err == nil {
		t.Error("unparseable PEM yielded a node name, want an error")
	}
}

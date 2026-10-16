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

package certs

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"slices"
	"testing"
	"time"
)

// TestNetserveIdentity pins the netserve subject the issuer and the RBAC binding
// agree on: CN=k3sm:netserve:<node>, O=[k3sm:netservers] and nothing else, a
// client-auth leaf from the issuing CA with no SAN, and a reader that refuses any
// near miss.
func TestNetserveIdentity(t *testing.T) {
	ca, err := NewCA("k3sm-signing-ca")
	if err != nil {
		t.Fatalf("NewCA: %v", err)
	}
	certPEM, _, err := ca.IssueNetserveClient("worker-a", time.Hour)
	if err != nil {
		t.Fatalf("IssueNetserveClient: %v", err)
	}
	block, _ := pem.Decode(certPEM)
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if leaf.Subject.CommonName != "k3sm:netserve:worker-a" {
		t.Errorf("CN = %q, want k3sm:netserve:worker-a", leaf.Subject.CommonName)
	}
	if !slices.Equal(leaf.Subject.Organization, []string{"k3sm:netservers"}) {
		t.Errorf("O = %v, want [k3sm:netservers]", leaf.Subject.Organization)
	}
	if !slices.Equal(leaf.ExtKeyUsage, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}) {
		t.Errorf("EKU = %v, want client auth only", leaf.ExtKeyUsage)
	}
	if len(leaf.DNSNames)+len(leaf.IPAddresses) != 0 {
		t.Errorf("SANs = %v %v, want none", leaf.DNSNames, leaf.IPAddresses)
	}
	if err := leaf.CheckSignatureFrom(ca.Cert); err != nil {
		t.Errorf("not signed by the issuing CA: %v", err)
	}
	if node, ok := NetserveNodeName(leaf); !ok || node != "worker-a" {
		t.Errorf("NetserveNodeName = %q, %v; want worker-a, true", node, ok)
	}

	for name, subject := range map[string]pkix.Name{
		"a node identity":     {CommonName: "system:node:worker-a", Organization: []string{"system:nodes"}},
		"no group":            {CommonName: "k3sm:netserve:worker-a"},
		"an extra group":      {CommonName: "k3sm:netserve:worker-a", Organization: []string{"k3sm:netservers", "system:masters"}},
		"an empty node name":  {CommonName: "k3sm:netserve:", Organization: []string{"k3sm:netservers"}},
		"the group, wrong CN": {CommonName: "worker-a", Organization: []string{"k3sm:netservers"}},
	} {
		t.Run(name, func(t *testing.T) {
			if node, ok := NetserveNodeName(&x509.Certificate{Subject: subject}); ok {
				t.Errorf("NetserveNodeName accepted %+v as node %q", subject, node)
			}
		})
	}
	if _, ok := NetserveNodeName(nil); ok {
		t.Error("NetserveNodeName accepted nil")
	}
}

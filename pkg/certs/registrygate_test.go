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
	"encoding/pem"
	"slices"
	"testing"
	"time"
)

// TestRegistryGateIdentity pins the registry-gate subject the issuer and the
// RBAC binding agree on, spelled as literals so a renamed constant cannot move
// the identity an operator's kubectl reads back: CN=k3sm:registry-gate:<node>,
// O=[k3sm:registry-gates], a client-auth leaf from the issuing CA with no SAN.
func TestRegistryGateIdentity(t *testing.T) {
	ca, err := NewCA("k3sm-signing-ca")
	if err != nil {
		t.Fatalf("NewCA: %v", err)
	}
	certPEM, keyPEM, err := ca.IssueRegistryGateClient("node-a", time.Hour)
	if err != nil {
		t.Fatalf("IssueRegistryGateClient: %v", err)
	}
	if len(keyPEM) == 0 {
		t.Fatal("no key returned")
	}
	block, _ := pem.Decode(certPEM)
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if leaf.Subject.CommonName != "k3sm:registry-gate:node-a" {
		t.Errorf("CN = %q, want k3sm:registry-gate:node-a", leaf.Subject.CommonName)
	}
	if !slices.Equal(leaf.Subject.Organization, []string{"k3sm:registry-gates"}) {
		t.Errorf("O = %v, want [k3sm:registry-gates]", leaf.Subject.Organization)
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
	if got := RegistryGateSubject("node-a"); got.CommonName != leaf.Subject.CommonName {
		t.Errorf("RegistryGateSubject CN = %q, leaf CN = %q", got.CommonName, leaf.Subject.CommonName)
	}
}

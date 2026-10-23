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
	"crypto/x509/pkix"
	"time"
)

// The registry-gate identity: the client identity the push gate in front of a
// node's ingest registry authenticates to the apiserver as. The gate asks the
// apiserver three questions for every in-pod push (is this ServiceAccount token
// valid for the registry audience, does this namespace opt in, may this identity
// push this repository) and nothing else, so it runs under a dedicated user in a
// dedicated group bound to exactly those three grants (pkg/rbac's
// k3sm:registry-gate role), never under the server's retained admin client.
//
// It is the netserve shape: CN=k3sm:registry-gate:<node>, O=k3sm:registry-gates,
// minted in memory from the signing CA on every boot. The constants live here
// for the reason the netserve ones do: the issuer and the binder must agree on
// them.
const (
	// RegistryGateUserPrefix prefixes the node name in the certificate's
	// CommonName. It is deliberately NOT a system: name, so the Node authorizer
	// and NodeRestriction never treat it as a node.
	RegistryGateUserPrefix = "k3sm:registry-gate:"
	// RegistryGateGroup is the certificate's only Organization and the subject
	// of the k3sm:registry-gate ClusterRoleBinding.
	RegistryGateGroup = "k3sm:registry-gates"
)

// RegistryGateSubject is the authoritative subject of nodeName's registry-gate
// certificate: CN=k3sm:registry-gate:<nodeName>, O=k3sm:registry-gates and
// nothing else.
func RegistryGateSubject(nodeName string) pkix.Name {
	return pkix.Name{CommonName: RegistryGateUserPrefix + nodeName, Organization: []string{RegistryGateGroup}}
}

// IssueRegistryGateClient mints nodeName's registry-gate client keypair from
// this CA, which must be the SIGNING CA (the apiserver's --client-ca-file). Only
// a server runs the ingest registry, and a server holds the CA key, so the pair
// is minted in memory and never written to disk or fetched.
func (c *CA) IssueRegistryGateClient(nodeName string, validFor time.Duration) (certPEM, keyPEM []byte, err error) {
	s := RegistryGateSubject(nodeName)
	return c.IssueClient(s.CommonName, s.Organization, validFor)
}

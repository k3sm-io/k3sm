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
	"strings"
	"time"
)

// The netserve identity: the per-node client identity a node's datapath (the
// Service proxy, the cluster DNS resolver and the NetworkPolicy watcher)
// authenticates to the apiserver as. It is the k3s system:k3s-controller shape:
// a dedicated user per node in a dedicated group, bound by one ClusterRoleBinding
// to a read-only role (pkg/rbac), rather than the node identity, whose Node
// authorizer scope cannot see other nodes' pods and whose system:nodes grants were
// never meant to cover cluster-wide policy reads.
//
// The constants live here, in the PKI vocabulary, for the reason
// APIServerKubeletClientCN does: the issuer (pkg/bootstrap, the server's
// in-memory mint) and the binder (pkg/rbac) must agree on them, and a duplicated
// literal in an authorization subject is how that agreement rots.
const (
	// NetserveUserPrefix prefixes the node name in the certificate's CommonName:
	// CN=k3sm:netserve:<node>. It is deliberately NOT a system: name, so the Node
	// authorizer and NodeRestriction never treat it as a node.
	NetserveUserPrefix = "k3sm:netserve:"
	// NetserveGroup is the certificate's only Organization and the subject of
	// the k3sm:netserve ClusterRoleBinding.
	NetserveGroup = "k3sm:netservers"
)

// NetserveSubject is the authoritative subject of nodeName's netserve
// certificate: CN=k3sm:netserve:<nodeName>, O=k3sm:netservers and nothing else.
// An issuer sets it whatever subject a CSR asked for.
func NetserveSubject(nodeName string) pkix.Name {
	return pkix.Name{CommonName: NetserveUserPrefix + nodeName, Organization: []string{NetserveGroup}}
}

// NetserveNodeName returns the node a netserve certificate names, and whether
// cert is one at all: its CN must be k3sm:netserve:<non-empty name> and its
// Organization exactly [k3sm:netservers]. A certificate carrying any other group
// is refused, because a group beside this one would be authority the netserve
// role does not describe.
func NetserveNodeName(cert *x509.Certificate) (string, bool) {
	if cert == nil {
		return "", false
	}
	org := cert.Subject.Organization
	if len(org) != 1 || org[0] != NetserveGroup {
		return "", false
	}
	node, ok := strings.CutPrefix(cert.Subject.CommonName, NetserveUserPrefix)
	if !ok || node == "" {
		return "", false
	}
	return node, true
}

// IssueNetserveClient mints nodeName's netserve client keypair from this CA,
// which must be the SIGNING CA (the apiserver's --client-ca-file). It is the
// server's own mint: the control-plane process holds the CA key, so its datapath
// identity is minted in memory on every boot instead of fetched. A worker obtains
// the same identity by CSR (pkg/bootstrap), so its private key never leaves it.
func (c *CA) IssueNetserveClient(nodeName string, validFor time.Duration) (certPEM, keyPEM []byte, err error) {
	s := NetserveSubject(nodeName)
	return c.IssueClient(s.CommonName, s.Organization, validFor)
}

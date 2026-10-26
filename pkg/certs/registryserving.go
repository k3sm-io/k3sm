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
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"time"
)

// IssueRegistryServing mints the serving certificate the ingest registry's
// cluster-facing listeners present: a server-auth leaf for cn with dnsNames and
// ipAddrs as its SANs, returned as a ready tls.Certificate whose private key
// exists only in this process's memory.
//
// This CA must be the CLUSTER CA, the anchor the controller-manager republishes
// into every namespace as kube-root-ca.crt and every Pod already holds as its
// service-account ca.crt. That is the whole point: a Pod verifies the registry
// with a file it already has, so the certificate adds no trust root and asks
// the operator for nothing. Only a server runs the registry, and every server
// holds the cluster CA's key, so the pair is minted on each boot and re-minted
// before it expires; nothing is written to disk and nothing is fetched.
//
// The chain presented is the leaf alone, as the apiserver's is: a client that
// trusts the cluster CA needs nothing else, and one that does not must not be
// handed the anchor by the server it is trying to verify.
func (c *CA) IssueRegistryServing(cn string, dnsNames []string, ipAddrs []net.IP, validFor time.Duration) (tls.Certificate, error) {
	if c == nil || c.Cert == nil || c.Key == nil {
		return tls.Certificate{}, errors.New("mint the registry serving certificate: no usable cluster CA (the work dir's PKI must carry the cluster CA and its private key)")
	}
	if cn == "" || len(dnsNames) == 0 {
		return tls.Certificate{}, errors.New("mint the registry serving certificate: a common name and at least one DNS name are required")
	}
	certPEM, keyPEM, err := c.IssueServing(cn, dnsNames, ipAddrs, validFor)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("mint the registry serving certificate: %w", err)
	}
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("assemble the registry serving certificate: %w", err)
	}
	if pair.Leaf == nil {
		leaf, err := x509.ParseCertificate(pair.Certificate[0])
		if err != nil {
			return tls.Certificate{}, fmt.Errorf("parse the registry serving certificate: %w", err)
		}
		pair.Leaf = leaf
	}
	return pair, nil
}

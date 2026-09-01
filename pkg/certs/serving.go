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

// Package certs is k3sm's certificate authority and TLS material.
//
// M3 stands up a real PKI (ca.go): a CLUSTER CA (the serving anchor a K10 join
// token pins) and a SIGNING CA (issues the system:node client certs handed to
// joining nodes), with VerifyPinnedChain implementing CA-hash-pinned join WITHOUT
// insecure-skip-tls-verify. SelfSignedServing (below) is ONLY the dev/loopback,
// single-node and standalone-`k3sm node` path: a CA-less self-signed serving cert
// for the Virtual Kubelet node's :10250 endpoint in the posture where the apiserver
// names no --kubelet-certificate-authority. Every multi-node node serves a
// cluster-CA-issued pair instead (CA.IssueServing on the server, the join-delivered
// leaf on a worker).
package certs

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"time"
)

// SelfSignedServing returns a SELF-SIGNED TLS certificate for a server whose SANs
// include every host in dnsNames and every IP in ipAddrs. The SANs MUST include the
// node InternalIP: the apiserver is started with
// --kubelet-preferred-address-types=InternalIP, so it dials the node by IP and the
// cert has to verify against that address (the M0.3 logs/exec gap).
//
// SCOPE — this is the SINGLE-NODE, dev and standalone-`k3sm node` cert, and nothing
// else. It is correct exactly where the apiserver configures NO
// --kubelet-certificate-authority: with no CA named, the kubelet client trusts what
// the node presents, and a CA-issued leaf would buy nothing.
//
// On the MULTI-NODE (--mesh-ip) path it is NOT used, and using it there is a defect
// (B213): that apiserver runs --kubelet-certificate-authority=<cluster CA>, so a
// self-signed leaf is refused with "x509: certificate signed by unknown authority"
// and every kubectl logs/exec against the node fails while the node reports Ready.
// Both node roles therefore carry a CLUSTER-CA-issued pair instead — a worker from
// its join response (ApproveAndSignKubeletServing over its own CSR), the
// control-plane node from its own local mint (CA.IssueServing) — and both refuse to
// start rather than falling back here.
//
// ECDSA P-256 keeps it small and fast.
func SelfSignedServing(dnsNames []string, ipAddrs []net.IP) (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("generate key: %w", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("generate serial: %w", err)
	}
	now := time.Now()
	tmpl := x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "k3sm-kubelet"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.AddDate(1, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              dnsNames,
		IPAddresses:           ipAddrs,
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("create certificate: %w", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("marshal key: %w", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("assemble keypair: %w", err)
	}
	return pair, nil
}

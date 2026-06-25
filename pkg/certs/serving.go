// Package certs mints the self-signed TLS material k3sm components serve in M1
// (before the M3/M4 issued-cert PKI lands). Today that is the kubelet-serving
// certificate the Virtual Kubelet node presents on :10250.
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

// SelfSignedServing returns a TLS certificate for a server whose SANs include
// every host in dnsNames and every IP in ipAddrs. The kubelet-serving cert k3sm
// presents on :10250 uses it: the SANs MUST include the node InternalIP so the
// apiserver — started with --kubelet-preferred-address-types=InternalIP — can
// dial the node by IP and have the cert verify (closing the M0.3 logs/exec gap).
//
// The cert is self-signed (no CA) and short-lived; the apiserver's kubelet
// client trusts it because no --kubelet-certificate-authority is configured in
// M1. ECDSA P-256 keeps it small and fast.
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

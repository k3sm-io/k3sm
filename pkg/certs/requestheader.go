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
	"errors"
	"fmt"
	"path/filepath"
	"time"
)

// CAID names one CA of the hierarchy: a row of the CA table, a key of a report, the
// word an error uses for it. The ids are stable; they appear in logs and errors.
type CAID string

// The CAs of the hierarchy.
const (
	CACluster       CAID = "cluster"
	CASigning       CAID = "signing"
	CAEtcdServer    CAID = "etcd-server"
	CAEtcdPeer      CAID = "etcd-peer"
	CARequestHeader CAID = "request-header"
)

// Role says whether this server may mint a CA it does not hold.
//
// RoleMintAuthority is a server started with --cluster-init, or any server outside
// HA (single-node, `k3sm dev`, a single-server mesh): an absent CA is minted.
// RoleJoined is any server started with --server-join: an absent CA is
// ErrCANotImported, because a CA minted there would be a second, divergent root.
// The zero value is neither, so a caller always chooses.
type Role int

const (
	// RoleMintAuthority mints an absent CA.
	RoleMintAuthority Role = iota + 1
	// RoleJoined never mints; every CA must have been imported.
	RoleJoined
)

// String returns the role as `k3sm status` and the errors spell it.
func (r Role) String() string {
	switch r {
	case RoleMintAuthority:
		return "mint-authority"
	case RoleJoined:
		return "joined"
	}
	return fmt.Sprintf("Role(%d)", int(r))
}

// Posture says which CAs a server's datastore needs. PostureKine is every server
// whose datastore is kine; PostureEtcd is the embedded-etcd HA posture, which adds
// the etcd server and peer CAs. The zero value is neither.
type Posture int

const (
	// PostureKine needs the cluster, signing and request-header CAs.
	PostureKine Posture = iota + 1
	// PostureEtcd needs every CA, the etcd pair included.
	PostureEtcd
)

// ErrCANotImported reports that a joined server lacks a CA that only the bootstrap
// bundle may provide. Nothing is written: a joined server never mints. Compare with
// errors.Is.
var ErrCANotImported = errors.New("certs: a CA this joined server needs was never imported from the bootstrap bundle")

// ProxyClientCN is the CommonName of the aggregator's front-proxy client leaf (k3s's
// value) and the single value of the apiserver's --requestheader-allowed-names. One
// literal, shared by the minter and the flag.
const ProxyClientCN = "system:auth-proxy"

// On-disk names of the request-header CA, under the PKI dir.
const (
	requestHeaderCACert = "request-header-ca.crt"
	requestHeaderCAKey  = "request-header-ca.key"
	requestHeaderCACN   = "k3sm-request-header-ca"
)

// RequestHeaderCACertPath is the request-header CA certificate, the apiserver's
// --requestheader-client-ca-file.
func RequestHeaderCACertPath(workDir string) string {
	return filepath.Join(PKIDir(workDir), requestHeaderCACert)
}

// RequestHeaderCAKeyPath is the request-header CA PRIVATE KEY (0600). Exported to be
// named (stat'ed, reported), never opened outside this package.
func RequestHeaderCAKeyPath(workDir string) string {
	return filepath.Join(PKIDir(workDir), requestHeaderCAKey)
}

// LoadRequestHeaderPin is the request-header CA's counterpart of LoadCAPins, with the
// same read-only contract: it reads only the certificate and returns its PinHash, it
// creates nothing (an absent CA is ErrNoHierarchy), and it never opens the private
// key, which is lstat'ed only to refuse a half-present pair (ErrIncompleteHierarchy).
// `k3sm certificate rotate` and `k3sm status` read the pin with it.
func LoadRequestHeaderPin(workDir string) (string, error) {
	pin, err := caPin(RequestHeaderCACertPath(workDir), RequestHeaderCAKeyPath(workDir))
	if err != nil {
		return "", fmt.Errorf("request-header CA: %w", err)
	}
	return pin, nil
}

// IssueProxyClient mints the aggregator's front-proxy client leaf from the
// request-header CA: CN ProxyClientCN, no Organization, clientAuth only. It is the
// only issuance the request-header CA makes: the CA is held in an unexported field,
// so no caller can issue any other leaf from it. The leaf carries no groups and is
// no identity at kube-apiserver itself (its issuer is not --client-ca-file); what it
// grants is the right to assert a user in the request headers to a backend that
// trusts the request-header CA, which is why its key is 0600 beside the CA keys.
func (h *Hierarchy) IssueProxyClient(validFor time.Duration) (certPEM, keyPEM []byte, err error) {
	if h == nil || h.requestHeader == nil {
		return nil, nil, errors.New("certs: issue proxy client: the hierarchy holds no request-header CA")
	}
	return h.requestHeader.IssueClient(ProxyClientCN, nil, validFor)
}

// Missing returns the ids of the CAs posture needs that h does not hold, in table
// order. A nil h holds none. An invalid posture is treated as PostureEtcd, the
// stricter one.
func (h *Hierarchy) Missing(posture Posture) []CAID {
	var out []CAID
	for _, spec := range caSpecs {
		if spec.class != classAlways && posture == PostureKine {
			continue
		}
		if h == nil || spec.ca(h) == nil {
			out = append(out, spec.id)
		}
	}
	return out
}

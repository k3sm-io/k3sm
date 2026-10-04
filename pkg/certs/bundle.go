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
	"encoding/json"
	"fmt"
)

// bundleSchemaVersion stamps the serialized CA hierarchy so a field change is
// detectable rather than silently mis-parsed. Version 2 added the etcd server and peer
// CA pairs; Unmarshal accepts exactly this version.
const bundleSchemaVersion = 2

// bundleSchemaPreEtcd is the schema a server that predates etcd HA emits (cluster +
// signing CAs only). It is refused with a message naming the cause, since the only
// way to receive one is a mixed-release HA control plane.
const bundleSchemaPreEtcd = 1

// marshalledHierarchy is the on-the-wire shape of Marshal: the eight PEMs (four CA
// certificates and their private keys) the HA server-join bundle reconstructs.
// encoding/json base64-encodes the []byte fields.
type marshalledHierarchy struct {
	SchemaVersion       int    `json:"schemaVersion"`
	ClusterCACertPEM    []byte `json:"clusterCACertPEM"`
	ClusterCAKeyPEM     []byte `json:"clusterCAKeyPEM"`
	SigningCACertPEM    []byte `json:"signingCACertPEM"`
	SigningCAKeyPEM     []byte `json:"signingCAKeyPEM"`
	EtcdServerCACertPEM []byte `json:"etcdServerCACertPEM"`
	EtcdServerCAKeyPEM  []byte `json:"etcdServerCAKeyPEM"`
	EtcdPeerCACertPEM   []byte `json:"etcdPeerCACertPEM"`
	EtcdPeerCAKeyPEM    []byte `json:"etcdPeerCAKeyPEM"`
}

// Marshal serializes the four-CA hierarchy — the cluster, signing, etcd server and
// etcd peer CA certificate and PRIVATE-KEY PEMs — into opaque, self-describing bytes.
// All four CAs are required: the bundle exists only for an HA control plane, and HA
// is the etcd posture. This is the plaintext the HA server-join bootstrap bundle
// AES-256-GCM-seals (k3sm.io/k3sm/pkg/bootstrap.SealBundle) so a joining control-plane
// server reconstructs the IDENTICAL CAs (DESIGN §5c). The seal lives in pkg/bootstrap,
// not here, so certs keeps no crypto-secret dependency and the bootstrap→certs import
// edge does not cycle. The bytes carry private keys and must only ever leave a host
// SEALED.
func (h *Hierarchy) Marshal() ([]byte, error) {
	if h == nil || h.Cluster == nil || h.Signing == nil || h.EtcdServer == nil || h.EtcdPeer == nil {
		return nil, fmt.Errorf("certs: marshal hierarchy: cluster, signing, etcd server and etcd peer CAs are required")
	}
	return json.Marshal(marshalledHierarchy{
		SchemaVersion:       bundleSchemaVersion,
		ClusterCACertPEM:    h.Cluster.CertPEM,
		ClusterCAKeyPEM:     h.Cluster.KeyPEM,
		SigningCACertPEM:    h.Signing.CertPEM,
		SigningCAKeyPEM:     h.Signing.KeyPEM,
		EtcdServerCACertPEM: h.EtcdServer.CertPEM,
		EtcdServerCAKeyPEM:  h.EtcdServer.KeyPEM,
		EtcdPeerCACertPEM:   h.EtcdPeer.CertPEM,
		EtcdPeerCAKeyPEM:    h.EtcdPeer.KeyPEM,
	})
}

// Unmarshal reconstructs the hierarchy from Marshal's bytes, parsing the eight PEMs
// back into four loaded CAs (identical pins to the source). It populates the receiver
// only on success. A schema-1 bundle (from a server that predates etcd HA) and any
// other version are refused, as is a v2 bundle missing either etcd pair. The caller
// is the HA server-join path, AFTER it has decrypted + authenticated the bundle (a GCM
// tag failure means these bytes are never reached) and BEFORE
// ReconcileImportedHierarchy, so a refusal here writes nothing.
func (h *Hierarchy) Unmarshal(data []byte) error {
	var m marshalledHierarchy
	if err := json.Unmarshal(data, &m); err != nil {
		return fmt.Errorf("certs: unmarshal hierarchy: %w", err)
	}
	switch m.SchemaVersion {
	case bundleSchemaVersion:
	case bundleSchemaPreEtcd:
		return fmt.Errorf("certs: unmarshal hierarchy: unsupported schema version %d: this server predates etcd HA; every HA server must run the same release", m.SchemaVersion)
	default:
		return fmt.Errorf("certs: unmarshal hierarchy: unsupported schema version %d (want %d)", m.SchemaVersion, bundleSchemaVersion)
	}
	cluster, err := LoadCA(m.ClusterCACertPEM, m.ClusterCAKeyPEM)
	if err != nil {
		return fmt.Errorf("certs: unmarshal hierarchy: cluster CA: %w", err)
	}
	signing, err := LoadCA(m.SigningCACertPEM, m.SigningCAKeyPEM)
	if err != nil {
		return fmt.Errorf("certs: unmarshal hierarchy: signing CA: %w", err)
	}
	etcdServer, err := LoadCA(m.EtcdServerCACertPEM, m.EtcdServerCAKeyPEM)
	if err != nil {
		return fmt.Errorf("certs: unmarshal hierarchy: etcd server CA: %w", err)
	}
	etcdPeer, err := LoadCA(m.EtcdPeerCACertPEM, m.EtcdPeerCAKeyPEM)
	if err != nil {
		return fmt.Errorf("certs: unmarshal hierarchy: etcd peer CA: %w", err)
	}
	h.Cluster = cluster
	h.Signing = signing
	h.EtcdServer = etcdServer
	h.EtcdPeer = etcdPeer
	return nil
}

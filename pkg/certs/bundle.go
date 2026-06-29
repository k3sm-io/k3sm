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

// bundleSchemaVersion stamps the serialized two-CA hierarchy so a future field change
// is detectable rather than silently mis-parsed.
const bundleSchemaVersion = 1

// marshalledHierarchy is the on-the-wire shape of Marshal: the four CA PEMs the HA
// server-join bundle reconstructs. encoding/json base64-encodes the []byte fields.
type marshalledHierarchy struct {
	SchemaVersion    int    `json:"schemaVersion"`
	ClusterCACertPEM []byte `json:"clusterCACertPEM"`
	ClusterCAKeyPEM  []byte `json:"clusterCAKeyPEM"`
	SigningCACertPEM []byte `json:"signingCACertPEM"`
	SigningCAKeyPEM  []byte `json:"signingCAKeyPEM"`
}

// Marshal serializes the two-CA hierarchy — the cluster + signing CA certificate and
// PRIVATE-KEY PEMs — into opaque, self-describing bytes. This is the plaintext the HA
// server-join bootstrap bundle AES-256-GCM-seals (k3sm.io/k3sm/pkg/bootstrap.SealBundle)
// so a joining control-plane server reconstructs the IDENTICAL cluster + signing CAs
// (DESIGN §5c). The seal lives in pkg/bootstrap, not here, so certs keeps no
// crypto-secret dependency and the bootstrap→certs import edge does not cycle. The
// bytes carry private keys and must only ever leave a host SEALED.
func (h *Hierarchy) Marshal() ([]byte, error) {
	if h == nil || h.Cluster == nil || h.Signing == nil {
		return nil, fmt.Errorf("certs: marshal hierarchy: cluster and signing CA are required")
	}
	return json.Marshal(marshalledHierarchy{
		SchemaVersion:    bundleSchemaVersion,
		ClusterCACertPEM: h.Cluster.CertPEM,
		ClusterCAKeyPEM:  h.Cluster.KeyPEM,
		SigningCACertPEM: h.Signing.CertPEM,
		SigningCAKeyPEM:  h.Signing.KeyPEM,
	})
}

// Unmarshal reconstructs the hierarchy from Marshal's bytes, parsing the four PEMs back
// into loaded CAs (identical pins to the source). It populates the receiver. The caller
// is the HA server-join path, AFTER it has decrypted + authenticated the bundle
// (a GCM tag failure means these bytes are never reached).
func (h *Hierarchy) Unmarshal(data []byte) error {
	var m marshalledHierarchy
	if err := json.Unmarshal(data, &m); err != nil {
		return fmt.Errorf("certs: unmarshal hierarchy: %w", err)
	}
	if m.SchemaVersion != bundleSchemaVersion {
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
	h.Cluster = cluster
	h.Signing = signing
	return nil
}

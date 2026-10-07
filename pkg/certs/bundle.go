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
	"bytes"
	"encoding/json"
	"fmt"
	"strconv"
)

// bundleSchemaVersion stamps the serialized CA hierarchy so a field change is
// detectable rather than silently mis-parsed. Version 2 added the etcd server and peer
// CA pairs; Unmarshal accepts exactly this version. The CAs a version carries are the
// rows of caSpecs whose sinceSchema is at most that version.
const bundleSchemaVersion = 2

// bundleSchemaPreEtcd is the schema a server that predates etcd HA emits (cluster +
// signing CAs only). It is refused with a message naming the cause, since the only
// way to receive one is a mixed-release HA control plane.
const bundleSchemaPreEtcd = 1

// bundleRows returns the CA rows a bundle of schema version carries, in key order.
func bundleRows(version int) []caSpec {
	var rows []caSpec
	for _, spec := range caSpecs {
		if spec.sinceSchema <= version {
			rows = append(rows, spec)
		}
	}
	return rows
}

// Marshal serializes the four-CA hierarchy — the cluster, signing, etcd server and
// etcd peer CA certificate and PRIVATE-KEY PEMs — into opaque, self-describing bytes:
// a JSON object of schemaVersion followed by each CA's certificate and key, in the CA
// table's order (encoding/json base64-encodes the PEMs).
// All four CAs are required: the bundle exists only for an HA control plane, and HA
// is the etcd posture. This is the plaintext the HA server-join bootstrap bundle
// AES-256-GCM-seals (k3sm.io/k3sm/pkg/bootstrap.SealBundle) so a joining control-plane
// server reconstructs the IDENTICAL CAs (DESIGN §5c). The seal lives in pkg/bootstrap,
// not here, so certs keeps no crypto-secret dependency and the bootstrap→certs import
// edge does not cycle. The bytes carry private keys and must only ever leave a host
// SEALED.
func (h *Hierarchy) Marshal() ([]byte, error) {
	if !hierarchyComplete(h) {
		return nil, fmt.Errorf("certs: marshal hierarchy: cluster, signing, etcd server and etcd peer CAs are required")
	}
	var b bytes.Buffer
	b.WriteString(`{"schemaVersion":`)
	b.WriteString(strconv.Itoa(bundleSchemaVersion))
	for _, spec := range bundleRows(bundleSchemaVersion) {
		ca := spec.ca(h)
		for _, kv := range []struct {
			key string
			pem []byte
		}{{spec.certKey, ca.CertPEM}, {spec.keyKey, ca.KeyPEM}} {
			val, err := json.Marshal(kv.pem)
			if err != nil {
				return nil, fmt.Errorf("certs: marshal hierarchy: %s CA: %w", spec.label, err)
			}
			b.WriteString(`,"` + kv.key + `":`)
			b.Write(val)
		}
	}
	b.WriteByte('}')
	return b.Bytes(), nil
}

// Unmarshal reconstructs the hierarchy from Marshal's bytes, parsing the eight PEMs
// back into four loaded CAs (identical pins to the source). It populates the receiver
// only on success. A schema-1 bundle (from a server that predates etcd HA) and any
// other version are refused, as is a v2 bundle missing either etcd pair. The caller
// is the HA server-join path, AFTER it has decrypted + authenticated the bundle (a GCM
// tag failure means these bytes are never reached) and BEFORE
// ReconcileImportedHierarchy, so a refusal here writes nothing.
func (h *Hierarchy) Unmarshal(data []byte) error {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return fmt.Errorf("certs: unmarshal hierarchy: %w", err)
	}
	var version int
	if v, ok := raw["schemaVersion"]; ok {
		if err := json.Unmarshal(v, &version); err != nil {
			return fmt.Errorf("certs: unmarshal hierarchy: schemaVersion: %w", err)
		}
	}
	switch version {
	case bundleSchemaVersion:
	case bundleSchemaPreEtcd:
		return fmt.Errorf("certs: unmarshal hierarchy: unsupported schema version %d: this server predates etcd HA; every HA server must run the same release", version)
	default:
		return fmt.Errorf("certs: unmarshal hierarchy: unsupported schema version %d (want %d)", version, bundleSchemaVersion)
	}
	var out Hierarchy
	for _, spec := range bundleRows(version) {
		var certPEM, keyPEM []byte
		for _, kv := range []struct {
			key string
			dst *[]byte
		}{{spec.certKey, &certPEM}, {spec.keyKey, &keyPEM}} {
			if v, ok := raw[kv.key]; ok {
				if err := json.Unmarshal(v, kv.dst); err != nil {
					return fmt.Errorf("certs: unmarshal hierarchy: %s: %w", kv.key, err)
				}
			}
		}
		ca, err := LoadCA(certPEM, keyPEM)
		if err != nil {
			return fmt.Errorf("certs: unmarshal hierarchy: %s CA: %w", spec.label, err)
		}
		spec.set(&out, ca)
	}
	*h = out
	return nil
}

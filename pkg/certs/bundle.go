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
	"sort"
	"strconv"
)

// bundleSchemaVersion stamps the serialized CA hierarchy so a field change is
// detectable rather than silently mis-parsed. Version 2 added the etcd server and peer
// CA pairs; version 3 added the request-header CA. The CAs a version carries are the
// rows of caSpecs whose sinceSchema is at most that version, so a v3 plaintext is a v2
// plaintext with two more keys. Marshal writes this version; Unmarshal decodes it and
// bundleSchemaPreRequestHeader (TestBundleSchemaVersionSingleSourced pins the number
// and the CAs together).
const bundleSchemaVersion = 3

// bundleSchemaPreRequestHeader is the schema a server one release older emits: every
// CA but the request-header one. It decodes, and Hierarchy.Missing then names the
// request-header CA, which the server-join turns into a wait for that server to be
// upgraded (never a local mint).
const bundleSchemaPreRequestHeader = 2

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

// Marshal serializes the five-CA hierarchy — the cluster, signing, etcd server, etcd
// peer and request-header CA certificate and PRIVATE-KEY PEMs — into opaque,
// self-describing bytes: a JSON object of schemaVersion followed by each CA's
// certificate and key, in the CA table's order (encoding/json base64-encodes the
// PEMs). Every CA is required (Hierarchy.Missing(PostureEtcd) must be empty): the
// bundle exists only for an HA control plane, HA is the etcd posture, and a bundle
// without the request-header CA would leave a joiner to mint its own. This is the plaintext the HA server-join bootstrap bundle
// AES-256-GCM-seals (k3sm.io/k3sm/pkg/bootstrap.SealBundle) so a joining control-plane
// server reconstructs the IDENTICAL CAs (DESIGN §5c). The seal lives in pkg/bootstrap,
// not here, so certs keeps no crypto-secret dependency and the bootstrap→certs import
// edge does not cycle. The bytes carry private keys and must only ever leave a host
// SEALED.
func (h *Hierarchy) Marshal() ([]byte, error) {
	if missing := h.Missing(PostureEtcd); len(missing) > 0 {
		return nil, fmt.Errorf("certs: marshal hierarchy: the %s CA is required", joinIDs(missing))
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

// Unmarshal reconstructs the hierarchy from Marshal's bytes, parsing the PEMs back into
// loaded CAs (identical pins to the source). It decodes schema 3 (five CAs) and schema
// 2 (the four before the request-header CA; the caller decides what a bundle without
// it means, through Hierarchy.Missing). It populates the receiver only on success. A
// schema-1 bundle (from a server that predates etcd HA) and any other version are
// refused, as is a bundle missing a CA its version carries or carrying a key its
// version does not. The caller
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
	switch {
	case version == bundleSchemaPreEtcd:
		return fmt.Errorf("certs: unmarshal hierarchy: unsupported schema version %d: this server predates etcd HA; every HA server must run the same release", version)
	case version < bundleSchemaPreRequestHeader || version > bundleSchemaVersion:
		return fmt.Errorf("certs: unmarshal hierarchy: unsupported schema version %d (want %d)", version, bundleSchemaVersion)
	}
	rows := bundleRows(version)
	known := map[string]bool{"schemaVersion": true}
	for _, spec := range rows {
		known[spec.certKey], known[spec.keyKey] = true, true
	}
	keys := make([]string, 0, len(raw))
	for k := range raw {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if !known[k] {
			return fmt.Errorf("certs: unmarshal hierarchy: schema %d carries no field %q", version, k)
		}
	}
	var out Hierarchy
	for _, spec := range rows {
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

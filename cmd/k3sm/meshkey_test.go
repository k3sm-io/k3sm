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

package main

import (
	"os"
	"path/filepath"
	"testing"

	"k3sm.io/k3sm/pkg/bootstrap"
)

// TestAgentMeshKeyIsMintedOnceAndReused is M14.2 defect-B's unit tier, and the
// worker-side mirror of TestServerMeshKeyIsMintedOnceAndReused.
//
// The property is PERSISTENCE, not secrecy. bootstrap.Join minted a fresh
// wireguard key on every call and the agent had nothing on disk, so each `k3sm
// agent` start enrolled a NEW public key: four restarts in one lab session were
// four MeshPeer key rotations, each stranding every peer's programmed key until it
// re-reconciled. 0600 is asserted alongside it because the file is a private key
// sitting in a work dir.
func TestAgentMeshKeyIsMintedOnceAndReused(t *testing.T) {
	dir := t.TempDir()

	priv, pub, err := loadOrCreateMeshKey(dir, meshKeyRef)
	if err != nil {
		t.Fatalf("first loadOrCreateMeshKey: %v", err)
	}
	if priv == "" || pub == "" {
		t.Fatal("loadOrCreateMeshKey returned an empty key pair")
	}
	if priv == pub {
		t.Fatal("the private and public keys are identical")
	}

	path := filepath.Join(dir, meshKeyRef)
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("the key was not persisted at %s: %v", path, err)
	}
	if mode := fi.Mode().Perm(); mode != 0o600 {
		t.Errorf("persisted key mode = %04o, want 0600", mode)
	}
	if b, err := os.ReadFile(path); err != nil || string(b) != priv {
		t.Errorf("persisted key %q != returned private key %q (err %v)", string(b), priv, err)
	}

	// The restart: the SAME private key, and a public key re-derived from it rather
	// than re-minted.
	priv2, pub2, err := loadOrCreateMeshKey(dir, meshKeyRef)
	if err != nil {
		t.Fatalf("second loadOrCreateMeshKey: %v", err)
	}
	if priv2 != priv {
		t.Errorf("restart minted a NEW private key (%q != %q); this node's MeshPeer would rotate its public key on every launchctl kickstart", priv2, priv)
	}
	if pub2 != pub {
		t.Errorf("restart derived a different public key (%q != %q)", pub2, pub)
	}
	derived, err := bootstrap.WireguardPublicKey(priv)
	if err != nil {
		t.Fatalf("WireguardPublicKey: %v", err)
	}
	if derived != pub {
		t.Errorf("the advertised public key %q is not the derivation of the stored private key (%q)", pub, derived)
	}
}

// TestAgentAndServerMeshKeysDoNotCollide: a server and a joined worker on ONE Mac
// (the single-host acceptance posture) each persist a key, and both provision into
// install.MeshKeyDir under the same bare ref they use in their work dir. Sharing a
// ref would have each overwrite the other's identity.
func TestAgentAndServerMeshKeysDoNotCollide(t *testing.T) {
	if meshKeyRef == serverMeshKeyRef {
		t.Fatalf("the agent and server mesh key refs are both %q", meshKeyRef)
	}
	if meshKeyRef != filepath.Base(meshKeyRef) {
		t.Errorf("meshKeyRef %q must be a bare file name — the netd MeshKeyResolver rejects anything else", meshKeyRef)
	}

	dir := t.TempDir()
	agentPriv, _, err := loadOrCreateMeshKey(dir, meshKeyRef)
	if err != nil {
		t.Fatalf("agent key: %v", err)
	}
	serverPriv, _, err := loadOrCreateServerMeshKey(dir)
	if err != nil {
		t.Fatalf("server key: %v", err)
	}
	if agentPriv == serverPriv {
		t.Fatal("the agent and server minted the same key in one directory — one ref overwrote the other")
	}
	reloaded, _, err := loadOrCreateMeshKey(dir, meshKeyRef)
	if err != nil {
		t.Fatalf("agent key reload: %v", err)
	}
	if reloaded != agentPriv {
		t.Error("minting the server key clobbered the agent's persisted key")
	}
}

// TestAgentMeshKeyRejectsAnUnusableKeyFile: a truncated or corrupt key file must
// fail loudly. Silently re-minting over it would rotate the node's identity for
// exactly the reason this persistence exists to prevent, and would destroy the
// evidence of whatever corrupted it.
func TestAgentMeshKeyRejectsAnUnusableKeyFile(t *testing.T) {
	for _, tc := range []struct {
		name    string
		content string
	}{
		{"empty", ""},
		{"not base64", "!!!not-base64!!!"},
		{"wrong length", "c2hvcnQ="},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, meshKeyRef), []byte(tc.content), 0o600); err != nil {
				t.Fatalf("seed key file: %v", err)
			}
			if _, _, err := loadOrCreateMeshKey(dir, meshKeyRef); err == nil {
				t.Fatal("loadOrCreateMeshKey accepted an unusable key file")
			}
		})
	}
}

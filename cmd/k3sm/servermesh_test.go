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
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"k3sm.io/k3sm/pkg/bootstrap"
	"k3sm.io/k3sm/pkg/hostnet"
)

// TestServerMeshKeyIsMintedOnceAndReused is M14.2 d2's unit tier.
//
// The property is PERSISTENCE, not secrecy: the public key derived from this file
// is what every peer programs into its wireguard device, so a key re-minted on
// each boot rotates the node's identity on every `launchctl kickstart` and
// blackholes the mesh until each peer re-reconciles. 0600 is asserted alongside it
// because the file is a private key sitting in a work dir.
func TestServerMeshKeyIsMintedOnceAndReused(t *testing.T) {
	dir := t.TempDir()

	priv, pub, err := loadOrCreateServerMeshKey(dir)
	if err != nil {
		t.Fatalf("first loadOrCreateServerMeshKey: %v", err)
	}
	if priv == "" || pub == "" {
		t.Fatal("loadOrCreateServerMeshKey returned an empty key pair")
	}
	if priv == pub {
		t.Fatal("the private and public keys are identical")
	}

	path := filepath.Join(dir, serverMeshKeyRef)
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

	// The reload: same private key, and a public key re-DERIVED from it rather
	// than re-minted.
	priv2, pub2, err := loadOrCreateServerMeshKey(dir)
	if err != nil {
		t.Fatalf("second loadOrCreateServerMeshKey: %v", err)
	}
	if priv2 != priv {
		t.Errorf("reload minted a NEW private key (%q != %q); every peer's programmed public key would be stale", priv2, priv)
	}
	if pub2 != pub {
		t.Errorf("reload derived a different public key (%q != %q)", pub2, pub)
	}
	derived, err := bootstrap.WireguardPublicKey(priv)
	if err != nil {
		t.Fatalf("WireguardPublicKey: %v", err)
	}
	if derived != pub {
		t.Errorf("the returned public key %q is not the derivation of the stored private key (%q)", pub, derived)
	}
}

// TestServerMeshKeyRefusesAnUnusableFile: a corrupt or truncated key must be a
// named error, never a silent re-mint — a re-mint here IS the identity rotation
// persistence exists to prevent, and it would look like success.
func TestServerMeshKeyRefusesAnUnusableFile(t *testing.T) {
	cases := map[string]string{
		"not base64":   "!!!! not base64 !!!!",
		"wrong length": "dG9vLXNob3J0",
		"empty":        "",
	}
	for name, content := range cases {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, serverMeshKeyRef), []byte(content), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, _, err := loadOrCreateServerMeshKey(dir); err == nil {
				t.Fatal("loadOrCreateServerMeshKey accepted an unusable key file")
			}
		})
	}
}

// TestServerMeshKeyRefIsNotTheAgentRef: a server and a joined worker on ONE Mac
// (the single-host acceptance posture) both provision into install.MeshKeyDir, so
// a shared ref would have each overwrite the other's identity.
func TestServerMeshKeyRefIsNotTheAgentRef(t *testing.T) {
	if serverMeshKeyRef == meshKeyRef {
		t.Fatalf("the server and agent mesh key refs are both %q; on a single-host cluster they overwrite each other", serverMeshKeyRef)
	}
	if serverMeshKeyRef != filepath.Base(serverMeshKeyRef) || strings.ContainsRune(serverMeshKeyRef, '/') {
		t.Errorf("serverMeshKeyRef %q must be a bare file name — the netd MeshKeyResolver rejects anything else", serverMeshKeyRef)
	}
}

// TestServerMeshEndpointPrefersAnUnderlayAddress pins d3's endpoint rule: a
// joining worker has no mesh yet, so the endpoint it dials for the wireguard
// handshake has to be an address the host answers on TODAY. It falls back to the
// configured node IP only when the host offers no globally-unicast address of its
// own (a single-host cluster), never to nothing.
func TestServerMeshEndpointPrefersAnUnderlayAddress(t *testing.T) {
	orig := hostInterfaceIPs
	t.Cleanup(func() { hostInterfaceIPs = orig })

	hostInterfaceIPs = func() []net.IP { return []net.IP{net.ParseIP("192.0.2.55")} }
	if got, want := serverMeshEndpoint("100.64.0.1", 51820), "192.0.2.55:51820"; got != want {
		t.Errorf("serverMeshEndpoint = %q, want the host's own underlay address %q", got, want)
	}

	hostInterfaceIPs = func() []net.IP { return nil }
	if got, want := serverMeshEndpoint("127.0.0.1", 51820), "127.0.0.1:51820"; got != want {
		t.Errorf("serverMeshEndpoint fallback = %q, want %q", got, want)
	}
	if host, port, err := net.SplitHostPort(serverMeshEndpoint("100.64.0.1", serverMeshListenPort)); err != nil || host == "" || port == "" {
		t.Errorf("serverMeshEndpoint produced an unparsable host:port (%v)", err)
	}
}

// TestBringUpMeshRefusesAMeshIPTheCIDRDoesNotDerive: the enroll's assigned /32 and
// the device's own derivation must agree, because the proxy sources backend dials
// from the FORMER while wireguard aliases the LATTER. A mismatch means this node's
// routing locality and its mesh identity have diverged, and half-configuring it
// would surface as backend dials from an address nothing answers on.
//
// The check runs BEFORE the device is started, so this test performs no privileged
// operation.
func TestBringUpMeshRefusesAMeshIPTheCIDRDoesNotDerive(t *testing.T) {
	priv, _, err := bootstrap.GenerateWireguardKey()
	if err != nil {
		t.Fatalf("GenerateWireguardKey: %v", err)
	}
	err = bringUpMesh(context.Background(), meshBringUp{
		podCIDR:       "100.64.0.0/24",
		meshIP:        "100.64.7.1", // NOT the .1 of the pod /24
		privateKeyB64: priv,
		keyRef:        serverMeshKeyRef,
		listenPort:    serverMeshListenPort,
		kubeconfig:    filepath.Join(t.TempDir(), "absent.kubeconfig"),
	}, hostnet.Mode{Backend: hostnet.BackendDirect}, quietLogger())
	if err == nil {
		t.Fatal("bringUpMesh accepted a mesh-egress IP the pod CIDR does not derive")
	}
	if !strings.Contains(err.Error(), "100.64.7.1") {
		t.Errorf("bringUpMesh error %q does not name the disagreeing address", err)
	}
}

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
	"fmt"
	"os"
	"path/filepath"

	"k3sm.io/k3sm/pkg/bootstrap"
)

// loadOrCreateMeshKey returns this node's persisted wireguard identity (base64
// private + derived public key), minting and persisting a fresh private key 0600
// at dir/ref on first run.
//
// Persistence is the whole point. The public key is what the node's MeshPeer
// advertises and what every peer programs into its wireguard device; a key
// re-minted on each boot rotates that identity on every `launchctl kickstart` and
// silently blackholes the mesh until each peer re-reconciles. The PUBLIC key is
// derived from the stored private key rather than stored beside it, so the two can
// never disagree.
//
// ref is the BARE file name — the same token the netd MeshKeyResolver resolves
// inside the root-only key dir in helper mode, so a node names its identity once
// and both the unprivileged work-dir copy and the privileged provisioned copy
// agree. Both node roles call this: the control-plane node via
// loadOrCreateServerMeshKey, and a joined worker with meshKeyRef.
//
// An unreadable or unusable key file is an ERROR, never a re-mint: falling back to
// a fresh key would rotate the identity for exactly the reason this function
// exists to prevent, and would overwrite whatever evidence corrupted it.
func loadOrCreateMeshKey(dir, ref string) (privB64, pubB64 string, err error) {
	path := filepath.Join(dir, ref)
	if b, err := os.ReadFile(path); err == nil {
		priv := string(b)
		pub, err := bootstrap.WireguardPublicKey(priv)
		if err != nil {
			return "", "", fmt.Errorf("read persisted mesh key %s: %w", path, err)
		}
		return priv, pub, nil
	} else if !os.IsNotExist(err) {
		return "", "", fmt.Errorf("read mesh key %s: %w", path, err)
	}
	priv, pub, err := bootstrap.GenerateWireguardKey()
	if err != nil {
		return "", "", fmt.Errorf("mint mesh key: %w", err)
	}
	if err := os.WriteFile(path, []byte(priv), 0o600); err != nil {
		return "", "", fmt.Errorf("persist mesh key: %w", err)
	}
	return priv, pub, nil
}

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
	"errors"
	"flag"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"k8s.io/client-go/kubernetes/fake"

	"k3sm.io/k3sm/pkg/keystore"
	keydeliver "k3sm.io/k3sm/pkg/keystore/deliver"
)

// TestKeysDeliveryServerFlag: `k3sm server --allow-plaintext-secrets-delivery`
// is registered, off by default, and sets the option the reconciler is built
// from (G18).
func TestKeysDeliveryServerFlag(t *testing.T) {
	for _, tc := range []struct {
		args []string
		want bool
	}{
		{nil, false},
		{[]string{"--" + keydeliver.AllowPlaintextFlag}, true},
	} {
		fs := flag.NewFlagSet("server", flag.ContinueOnError)
		fs.SetOutput(io.Discard)
		var opts serverOptions
		_ = registerServerFlags(fs, &opts)
		if err := fs.Parse(tc.args); err != nil {
			t.Fatalf("parse %v: %v", tc.args, err)
		}
		if opts.allowPlaintextSecretsDelivery != tc.want {
			t.Errorf("args %v: allowPlaintextSecretsDelivery = %v, want %v", tc.args, opts.allowPlaintextSecretsDelivery, tc.want)
		}
	}
}

// TestKeysDeliveryServerConfig: the server builds the reconciler over the
// declaration in the data root, with the encryption verdict and the override
// it was given, opening the store as itself or, run as root, as the service
// user (G18).
func TestKeysDeliveryServerConfig(t *testing.T) {
	cs := fake.NewClientset()
	ids := func(euid int, service error) keystoreDeliveryIDs {
		return keystoreDeliveryIDs{
			euid:    func() int { return euid },
			egid:    func() int { return 20 },
			service: func() (uint32, uint32, error) { return 777, 778, service },
		}
	}
	cfg, err := keystoreDeliveryConfig("/var/lib/k3sm/server", false, true, cs, ids(501, nil), nil)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Path != "/var/lib/k3sm/keystore-delivery.json" {
		t.Errorf("path %q, want the data root's keystore-delivery.json", cfg.Path)
	}
	if cfg.StatePath != "/var/lib/k3sm/server/keystore-delivery-state.json" || cfg.StateOwner != 501 {
		t.Errorf("state file %q owner %d, want the work dir's keystore-delivery-state.json owned by the server's euid 501", cfg.StatePath, cfg.StateOwner)
	}
	if cfg.EncryptionOn || !cfg.AllowPlaintext {
		t.Errorf("EncryptionOn %v AllowPlaintext %v, want false and true as given", cfg.EncryptionOn, cfg.AllowPlaintext)
	}
	if root, err := keystoreDeliveryConfig("/var/lib/k3sm/server", true, false, cs, ids(0, nil), nil); err != nil ||
		root.StateOwner != 0 || len(root.StateDirOwners) != 1 || root.StateDirOwners[0] != 777 {
		t.Errorf("a root server: state owner %d, directory owners %v (%v), want root and the service user 777", root.StateOwner, root.StateDirOwners, err)
	}
	if _, err := keystoreDeliveryConfig("/var/lib/k3sm/server", true, false, cs, ids(0, errors.New("no _k3sm")), nil); err == nil {
		t.Error("a root server with no service user built a reconciler")
	}
	if _, err := keystoreDeliveryConfig("relative", true, false, cs, ids(501, nil), nil); err == nil {
		t.Error("a relative work dir built a reconciler")
	}
}

// TestKeysDeliveryServerGate: the server's plan refuses delivery when this
// start passes the apiserver no encryption provider configuration, and
// allows it when it passes one or the override is set, through the same
// mapping startKeystoreDelivery uses (G18).
func TestKeysDeliveryServerGate(t *testing.T) {
	ids := keystoreDeliveryIDs{
		euid:    func() int { return 501 },
		egid:    func() int { return 20 },
		service: func() (uint32, uint32, error) { return 0, 0, errors.New("unused") },
	}
	for _, tc := range []struct {
		name     string
		epc      string
		override bool
		want     bool
	}{
		{"encryption off", "", false, false},
		{"encryption on", "/var/lib/k3sm/server/cred/encryption-config.json", false, true},
		{"override", "", true, true},
	} {
		var plan serverPlan
		plan.opts.workDir = "/var/lib/k3sm/server"
		plan.opts.allowPlaintextSecretsDelivery = tc.override
		plan.cfg.EncryptionProviderConfig = tc.epc
		on, allow := keystoreDeliveryGate(plan)
		cfg, err := keystoreDeliveryConfig(plan.opts.workDir, on, allow, fake.NewClientset(), ids, nil)
		if err != nil {
			t.Fatal(err)
		}
		if got := cfg.Delivers(); got != tc.want {
			t.Errorf("%s: delivers %v, want %v", tc.name, got, tc.want)
		}
	}
}

// TestKeysEnvDefaultsBindRoot: the production keys environment judges the
// declaration with the root check and hands a new one to root, by behaviour:
// a file the test user owns is refused, and the chown either makes the file
// root's (run as root) or fails (G19).
func TestKeysEnvDefaultsBindRoot(t *testing.T) {
	env := defaultKeysEnv(io.Discard, io.Discard)
	path := filepath.Join(t.TempDir(), "f")
	if err := os.WriteFile(path, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if os.Geteuid() == 0 {
		if err := os.Chown(path, 1, 1); err != nil {
			t.Fatal(err)
		}
	}
	fi, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := env.deliveryCheck(fi); err == nil || !strings.Contains(err.Error(), "not root") {
		t.Fatalf("the default check accepted a file root does not own: %v", err)
	}
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }() // nothing written
	cerr := env.deliveryChown(f)
	fi, err = os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatal("no stat_t")
	}
	if cerr == nil && st.Uid != 0 {
		t.Fatalf("the default chown succeeded and left the file uid %d, not root's", st.Uid)
	}
}

// One lock per tree: the store the delivery reconciler opens and the one
// the user socket's wiring builds over the same work dir hold the same
// keystore.TreeState, checked by pointer equality of Tree(). That state is
// the in-process lock and the usage figures, so sharing it is what puts a
// revocation the reconciler writes behind the socket's writer preference
// and a write by either into the other's figures; this test checks the
// sharing only, not the queueing or the figures.
func TestKeystoreSocketAndDeliveryShareTree(t *testing.T) {
	f := newWiringFixture(t)
	var socketStore *keystore.FileStore
	f.deps.opened = func(s *keystore.FileStore) { socketStore = s }
	_, closeAll, err := keystoreSocketConfig(f.deps)
	if err != nil {
		t.Fatal(err)
	}
	defer closeAll()
	ids := keystoreDeliveryIDs{euid: func() int { return 501 }, egid: func() int { return 20 }, service: func() (uint32, uint32, error) { return 777, 778, nil }}
	cfg, err := keystoreDeliveryConfig(f.deps.workDir, true, false, fake.NewClientset(), ids, nil)
	if err != nil {
		t.Fatal(err)
	}
	delivery, ok := cfg.Store.(*keystore.FileStore)
	if !ok || socketStore == nil {
		t.Fatalf("the stores: delivery %T, socket %v", cfg.Store, socketStore)
	}
	if delivery.Tree() == nil || delivery.Tree() != socketStore.Tree() {
		t.Fatal("the delivery reconciler's store and the socket's store hold different in-process lock and usage state over one tree")
	}
}

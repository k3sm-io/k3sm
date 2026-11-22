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
	"testing"

	"k8s.io/client-go/kubernetes/fake"

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
	if cfg.EncryptionOn || !cfg.AllowPlaintext {
		t.Errorf("EncryptionOn %v AllowPlaintext %v, want false and true as given", cfg.EncryptionOn, cfg.AllowPlaintext)
	}
	if _, err := keystoreDeliveryConfig("/var/lib/k3sm/server", true, false, cs, ids(0, errors.New("no _k3sm")), nil); err == nil {
		t.Error("a root server with no service user built a reconciler")
	}
	if _, err := keystoreDeliveryConfig("relative", true, false, cs, ids(501, nil), nil); err == nil {
		t.Error("a relative work dir built a reconciler")
	}
}

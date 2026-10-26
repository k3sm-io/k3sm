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
	"slices"
	"testing"

	"k8s.io/client-go/rest"

	"k3sm.io/k3sm/pkg/certs"
	"k3sm.io/k3sm/pkg/nodecred"
)

// TestServerRegistryGateIsItsOwnIdentity pins the push gate's apiserver
// identity: from an admin config carrying a bearer token, impersonation and a
// client pair, the result carries ONLY a CN=k3sm:registry-gate:<node>,
// O=k3sm:registry-gates client cert from the signing CA, keeps the apiserver
// address and its trust, and fails closed rather than falling back to admin.
func TestServerRegistryGateIsItsOwnIdentity(t *testing.T) {
	wd := t.TempDir()
	h, err := certs.EnsureHierarchy(wd, certs.RoleMintAuthority, certs.PostureKine)
	if err != nil {
		t.Fatalf("EnsureHierarchy: %v", err)
	}
	admin := func() *rest.Config {
		return &rest.Config{
			Host:        "https://127.0.0.1:6444",
			BearerToken: "admin-static-token",
			Impersonate: rest.ImpersonationConfig{UserName: "system:admin", Groups: []string{"system:masters"}},
			TLSClientConfig: rest.TLSClientConfig{
				ServerName: "kubernetes",
				CAData:     h.Cluster.CertPEM,
				CertData:   []byte("admin-cert"),
				KeyData:    []byte("admin-key"),
			},
		}
	}
	const node = "k3sm-server-node"
	cfg, err := serverRegistryGateRESTConfig(admin(), h, node)
	if err != nil {
		t.Fatalf("serverRegistryGateRESTConfig: %v", err)
	}
	if cfg.BearerToken != "" || cfg.Impersonate.UserName != "" || len(cfg.Impersonate.Groups) != 0 {
		t.Errorf("an admin credential survived: bearer %q, impersonate %+v", cfg.BearerToken, cfg.Impersonate)
	}
	if cfg.Host != "https://127.0.0.1:6444" || cfg.ServerName != "kubernetes" || string(cfg.CAData) != string(h.Cluster.CertPEM) {
		t.Errorf("server half not kept: host=%q serverName=%q", cfg.Host, cfg.ServerName)
	}
	leaf, err := nodecred.DecodeCertPEM(cfg.CertData)
	if err != nil {
		t.Fatalf("decode leaf: %v", err)
	}
	if leaf.Subject.CommonName != "k3sm:registry-gate:"+node || !slices.Equal(leaf.Subject.Organization, []string{"k3sm:registry-gates"}) {
		t.Errorf("subject = CN %q O %v, want CN k3sm:registry-gate:%s O [k3sm:registry-gates]", leaf.Subject.CommonName, leaf.Subject.Organization, node)
	}
	if err := leaf.CheckSignatureFrom(h.Signing.Cert); err != nil {
		t.Errorf("the gate leaf is not signed by the signing CA: %v", err)
	}
	for name, tc := range map[string]struct {
		admin *rest.Config
		h     *certs.Hierarchy
		node  string
	}{
		"nil hierarchy":    {admin(), nil, node},
		"no signing CA":    {admin(), &certs.Hierarchy{Cluster: h.Cluster}, node},
		"nil admin config": {nil, h, node},
		"empty node name":  {admin(), h, ""},
	} {
		t.Run(name, func(t *testing.T) {
			if got, err := serverRegistryGateRESTConfig(tc.admin, tc.h, tc.node); err == nil || got != nil {
				t.Fatalf("want an error and no config, got %v / %v", got, err)
			}
		})
	}
}

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
	"testing"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"

	"k3sm.io/k3sm/pkg/registrysvc"
)

// stageLocalCredential writes a registry push credential for addr into a fresh
// work dir and returns both.
func stageLocalCredential(t *testing.T, addr string) (workDir string, cred registrysvc.Credential) {
	t.Helper()
	workDir = t.TempDir()
	if err := os.MkdirAll(registrysvc.StateDir(workDir), 0o700); err != nil {
		t.Fatalf("create the registry state dir: %v", err)
	}
	cred = registrysvc.Credential{Address: addr, Username: "k3sm", Password: "per-boot-secret"}
	if err := registrysvc.WriteCredential(workDir, cred); err != nil {
		t.Fatalf("WriteCredential: %v", err)
	}
	return workDir, cred
}

// TestLocalRegistryAuthTargeting pins WHICH push targets the node's own registry
// credential is presented to. This is the containment of the secret: a match
// authenticates a push to this node's loopback registry, and everything else must
// leave the password on disk — most of all a public registry, which would receive
// it in an Authorization header.
func TestLocalRegistryAuthTargeting(t *testing.T) {
	workDir, cred := stageLocalCredential(t, "127.0.0.1:6450")

	cases := []struct {
		name   string
		target string
		want   bool
	}{
		{"the node's own registry by name", "localhost:6450/probe:t", true},
		{"the node's own registry by address", "127.0.0.1:6450/probe:t", true},
		{"a different loopback port", "localhost:6451/probe:t", false},
		{"a public registry", "ghcr.io/k3sm-io/probe:t", false},
		{"an implicit docker hub reference", "alpine:3", false},
		{"a LAN registry", "192.168.1.5:6450/probe:t", false},
		{"a hostname that merely embeds the address", "127.0.0.1.example.com:6450/probe:t", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ref, err := name.ParseReference(tc.target)
			if err != nil {
				t.Fatalf("parse %q: %v", tc.target, err)
			}
			got := localRegistryAuth(ref, workDir)
			if (got != nil) != tc.want {
				t.Fatalf("localRegistryAuth(%q) present = %v, want %v", tc.target, got != nil, tc.want)
			}
			if !tc.want {
				return
			}
			cfg, err := got.Authorization()
			if err != nil {
				t.Fatalf("Authorization: %v", err)
			}
			if cfg.Username != cred.Username || cfg.Password != cred.Password {
				t.Errorf("presented %q/%q, want the staged credential", cfg.Username, cfg.Password)
			}
		})
	}
}

// TestLocalRegistryAuthDegradesQuietly pins that every way of NOT having a local
// credential falls through instead of failing. The credential is an optional
// convenience for exactly one target, so a host whose registry is off must still
// be able to push to every other registry in the world.
func TestLocalRegistryAuthDegradesQuietly(t *testing.T) {
	ref, err := name.ParseReference("localhost:6450/probe:t")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	t.Run("no work dir", func(t *testing.T) {
		if got := localRegistryAuth(ref, ""); got != nil {
			t.Error("an empty work dir produced a credential")
		}
	})
	t.Run("registry disabled (no credential file)", func(t *testing.T) {
		if got := localRegistryAuth(ref, t.TempDir()); got != nil {
			t.Error("a work dir with no credential file produced one")
		}
	})
	t.Run("malformed credential", func(t *testing.T) {
		work := t.TempDir()
		if err := os.MkdirAll(registrysvc.StateDir(work), 0o700); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		if err := os.WriteFile(registrysvc.CredentialPath(work), []byte("{"), 0o600); err != nil {
			t.Fatalf("write: %v", err)
		}
		if got := localRegistryAuth(ref, work); got != nil {
			t.Error("a malformed credential file produced a credential")
		}
	})
}

// TestRegistryAuthChainOrder pins the precedence among the three sources. Both
// ends matter: an explicit K3SM_REGISTRY_TOKEN must win because the operator set
// it deliberately, and the local credential must come BEFORE the docker chain
// because that chain never reports "no match" — it returns Anonymous — so the
// push would arrive unauthenticated with a usable credential sitting on disk.
func TestRegistryAuthChainOrder(t *testing.T) {
	workDir, cred := stageLocalCredential(t, "127.0.0.1:6450")
	local, err := name.ParseReference("localhost:6450/probe:t")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	t.Run("the env token wins over the local credential", func(t *testing.T) {
		t.Setenv(registryTokenEnv, "an-explicit-token")
		auth, err := registryAuth(local, workDir)
		if err != nil {
			t.Fatalf("registryAuth: %v", err)
		}
		cfg, err := auth.Authorization()
		if err != nil {
			t.Fatalf("Authorization: %v", err)
		}
		if cfg.RegistryToken != "an-explicit-token" {
			t.Errorf("RegistryToken = %q, want the env token", cfg.RegistryToken)
		}
		if cfg.Password == cred.Password {
			t.Error("the local credential shadowed an explicitly set token")
		}
	})

	t.Run("the local credential beats the docker chain for a local target", func(t *testing.T) {
		t.Setenv(registryTokenEnv, "")
		auth, err := registryAuth(local, workDir)
		if err != nil {
			t.Fatalf("registryAuth: %v", err)
		}
		cfg, err := auth.Authorization()
		if err != nil {
			t.Fatalf("Authorization: %v", err)
		}
		if cfg.Password != cred.Password {
			t.Errorf("resolved %+v, want the local registry credential — an anonymous push would be refused 401", cfg)
		}
	})

	t.Run("a public target still goes to the docker chain", func(t *testing.T) {
		t.Setenv(registryTokenEnv, "")
		// HOME is redirected so the resolution cannot read the developer's real
		// docker config; the assertion is only that the local secret is absent.
		t.Setenv("HOME", t.TempDir())
		t.Setenv("DOCKER_CONFIG", t.TempDir())
		public, err := name.ParseReference("ghcr.io/k3sm-io/probe:t")
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		auth, err := registryAuth(public, workDir)
		if err != nil {
			t.Fatalf("registryAuth: %v", err)
		}
		cfg, err := auth.Authorization()
		if err != nil {
			t.Fatalf("Authorization: %v", err)
		}
		if cfg.Password == cred.Password || cfg.Username == cred.Username {
			t.Fatalf("the node's registry credential was offered to a public registry: %+v", cfg)
		}
		if *cfg != (authn.AuthConfig{}) {
			t.Errorf("resolved %+v for a public registry with no docker config, want the anonymous config", cfg)
		}
	})
}

// TestImageWorkDirFlag pins that push has a way to be pointed at the control
// plane that minted the credential — the case where the server runs as another
// user, or where a `k3sm dev` instance keeps its state somewhere else entirely.
func TestImageWorkDirFlag(t *testing.T) {
	o, err := parseImageArgs([]string{"push", "/layout", "localhost:6450/probe:t", "--work-dir", "/tmp/other"}, os.Stderr)
	if err != nil {
		t.Fatalf("parseImageArgs: %v", err)
	}
	if o.workDir != "/tmp/other" {
		t.Errorf("workDir = %q, want the flag value", o.workDir)
	}
	if o.layoutDir != "/layout" || o.target != "localhost:6450/probe:t" {
		t.Errorf("positional args = (%q,%q), want the layout and the reference", o.layoutDir, o.target)
	}
}

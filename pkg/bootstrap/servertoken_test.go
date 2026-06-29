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

package bootstrap_test

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"k3sm.io/k3sm/pkg/bootstrap"
)

// TestServerTokenDistinctFromWorker proves the server-class identity is DISTINCT from
// the worker one: the server token's user marker, identity, and group differ from the
// worker's, and ParseServerToken rejects a worker token (so the CA-bundle endpoint can
// never accept a worker credential).
func TestServerTokenDistinctFromWorker(t *testing.T) {
	caHash := "deadbeef"
	serverTok := bootstrap.FormatServerToken(caHash, "s3cr3t")
	st, err := bootstrap.ParseServerToken(serverTok)
	if err != nil {
		t.Fatalf("parse server token: %v", err)
	}
	if st.User != bootstrap.ServerTokenUser {
		t.Errorf("server token user = %q, want %q", st.User, bootstrap.ServerTokenUser)
	}
	if st.CAHash != caHash || st.Secret != "s3cr3t" {
		t.Errorf("server token = %+v, want caHash=%q secret=s3cr3t", st, caHash)
	}

	// The server identity/group must differ from the worker identity/group.
	if bootstrap.ServerBootstrapUser == bootstrap.BootstrapUser {
		t.Error("server-class user must differ from the worker BootstrapUser")
	}
	if bootstrap.ServerBootstrapGroup == bootstrap.BootstrapGroup {
		t.Error("server-class group must differ from the worker BootstrapGroup")
	}
	if strings.Contains(bootstrap.ServerBootstrapGroup, "system:masters") {
		t.Errorf("server-class group %q must not grant system:masters", bootstrap.ServerBootstrapGroup)
	}

	// A WORKER token (user boot-...) is NOT a server token.
	workerTok := bootstrap.FormatToken(caHash, "boot-abc123", "wsecret")
	if _, err := bootstrap.ParseServerToken(workerTok); !errors.Is(err, bootstrap.ErrNotServerToken) {
		t.Errorf("ParseServerToken(worker) err = %v, want ErrNotServerToken", err)
	}

	// The StaticServerSecret authorizer: right secret allowed, wrong secret rejected,
	// worker token rejected (constant-time compare, server-class only).
	auth := bootstrap.NewStaticServerSecret("s3cr3t")
	if err := auth.AuthorizeServerToken(serverTok); err != nil {
		t.Errorf("authorize correct server token: %v", err)
	}
	if err := auth.AuthorizeServerToken(bootstrap.FormatServerToken(caHash, "wrong")); !errors.Is(err, bootstrap.ErrServerTokenMismatch) {
		t.Errorf("wrong-secret err = %v, want ErrServerTokenMismatch", err)
	}
	if err := auth.AuthorizeServerToken(workerTok); !errors.Is(err, bootstrap.ErrNotServerToken) {
		t.Errorf("worker-token authorize err = %v, want ErrNotServerToken", err)
	}
}

// TestLoadOrCreateServerSecret proves the secret is machine-generated (≥128-bit),
// persisted 0600, and stable across calls (so the seal key + endpoint credential do not
// rotate on every restart). SaveServerSecret records an operator-provided secret (the
// joining-server path).
func TestLoadOrCreateServerSecret(t *testing.T) {
	path := filepath.Join(t.TempDir(), "server-token")

	s1, err := bootstrap.LoadOrCreateServerSecret(path)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if len(s1) < 32 { // hex of ≥16 bytes (128-bit); we mint 32 bytes = 64 hex chars
		t.Errorf("server secret %q too short (want a high-entropy ≥128-bit secret)", s1)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("server secret mode = %o, want 0600", info.Mode().Perm())
	}

	// Stable across calls (not regenerated).
	s2, err := bootstrap.LoadOrCreateServerSecret(path)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if s1 != s2 {
		t.Error("LoadOrCreateServerSecret must be stable across calls (not rotate the secret)")
	}

	// Two fresh secrets differ (machine-generated, not a fixed default).
	other, err := bootstrap.LoadOrCreateServerSecret(filepath.Join(t.TempDir(), "server-token"))
	if err != nil {
		t.Fatalf("create other: %v", err)
	}
	if other == s1 {
		t.Error("two independently-minted server secrets must differ")
	}

	// SaveServerSecret records an operator-provided secret (the joining-server path).
	saved := filepath.Join(t.TempDir(), "server-token")
	if err := bootstrap.SaveServerSecret(saved, "provided-secret"); err != nil {
		t.Fatalf("save: %v", err)
	}
	got, err := bootstrap.LoadOrCreateServerSecret(saved)
	if err != nil {
		t.Fatalf("reload saved: %v", err)
	}
	if got != "provided-secret" {
		t.Errorf("saved secret = %q, want provided-secret", got)
	}
}

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
	if err := auth.AuthorizeServerToken(t.Context(), serverTok); err != nil {
		t.Errorf("authorize correct server token: %v", err)
	}
	if err := auth.AuthorizeServerToken(t.Context(), bootstrap.FormatServerToken(caHash, "wrong")); !errors.Is(err, bootstrap.ErrServerTokenMismatch) {
		t.Errorf("wrong-secret err = %v, want ErrServerTokenMismatch", err)
	}
	if err := auth.AuthorizeServerToken(t.Context(), workerTok); !errors.Is(err, bootstrap.ErrNotServerToken) {
		t.Errorf("worker-token authorize err = %v, want ErrNotServerToken", err)
	}
}

// TestLoadOrCreateServerSecret proves the secret is machine-generated (≥128-bit),
// persisted 0600, and stable across calls (so the seal key + endpoint credential do not
// rotate on every restart). EnsureServerSecret records an operator-provided secret (the
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

	// EnsureServerSecret records an operator-provided secret (the joining-server path).
	saved := filepath.Join(t.TempDir(), "server-token")
	if err := bootstrap.EnsureServerSecret(saved, "provided-secret"); err != nil {
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

// TestEnsureServerSecret pins the B435 secret record: written once (0600, bare), a
// re-run with the same secret is a no-op even across whitespace, and a different
// secret is ErrServerSecretMismatch with the recorded one untouched and neither
// secret in the error.
func TestEnsureServerSecret(t *testing.T) {
	const secret = "joined-secret-0123456789abcdef"
	cases := []struct {
		name     string
		existing *string // nil: no file
		secret   string
		wantErr  error // nil: success; errAny: any error
		wantFile string
	}{
		{name: "absent: written bare", secret: secret, wantFile: secret},
		{name: "equal: no-op", existing: ptr(secret), secret: secret, wantFile: secret},
		{name: "equal across whitespace", existing: ptr("  " + secret + "\n"), secret: secret, wantFile: "  " + secret + "\n"},
		{name: "different: mismatch, untouched", existing: ptr("other-secret-ffff"), secret: secret, wantErr: bootstrap.ErrServerSecretMismatch, wantFile: "other-secret-ffff"},
		{name: "empty recorded secret: mismatch", existing: ptr("\n"), secret: secret, wantErr: bootstrap.ErrServerSecretMismatch, wantFile: "\n"},
		{name: "empty secret refused", secret: "", wantErr: errAny},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "server-token")
			if tc.existing != nil {
				if err := os.WriteFile(path, []byte(*tc.existing), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			err := bootstrap.EnsureServerSecret(path, tc.secret)
			switch {
			case tc.wantErr == nil && err != nil:
				t.Fatalf("EnsureServerSecret: %v", err)
			case tc.wantErr == errAny && err == nil:
				t.Fatal("EnsureServerSecret must fail")
			case tc.wantErr != nil && tc.wantErr != errAny && !errors.Is(err, tc.wantErr):
				t.Fatalf("err = %v, want %v", err, tc.wantErr)
			}
			if err != nil && tc.secret != "" && strings.Contains(err.Error(), tc.secret) {
				t.Errorf("error %q leaks the secret", err)
			}
			if err != nil && tc.existing != nil && strings.TrimSpace(*tc.existing) != "" && strings.Contains(err.Error(), strings.TrimSpace(*tc.existing)) {
				t.Errorf("error %q leaks the recorded secret", err)
			}
			if tc.wantFile == "" {
				if _, statErr := os.Stat(path); !os.IsNotExist(statErr) {
					t.Errorf("a refused secret must write nothing (stat err %v)", statErr)
				}
				return
			}
			got, rerr := os.ReadFile(path)
			if rerr != nil || string(got) != tc.wantFile {
				t.Errorf("file = %q (err %v), want %q", got, rerr, tc.wantFile)
			}
			info, serr := os.Stat(path)
			if serr != nil || info.Mode().Perm() != 0o600 {
				t.Errorf("secret mode: err %v, want 0600", serr)
			}
			entries, _ := os.ReadDir(filepath.Dir(path))
			if len(entries) != 1 {
				t.Errorf("dir holds %d entries, want only the secret (no temp file left)", len(entries))
			}
		})
	}

	t.Run("mismatch names the path and the remedy", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "server-token")
		if err := os.WriteFile(path, []byte("other-secret-ffff"), 0o600); err != nil {
			t.Fatal(err)
		}
		err := bootstrap.EnsureServerSecret(path, secret)
		for _, want := range []string{path, "remove it only after confirming the token is the one this cluster's servers share"} {
			if err == nil || !strings.Contains(err.Error(), want) {
				t.Errorf("error %v must contain %q", err, want)
			}
		}
	})

	t.Run("symlinked secret: refused, naming the path", func(t *testing.T) {
		dir := t.TempDir()
		target := filepath.Join(dir, "elsewhere")
		if err := os.WriteFile(target, []byte(secret), 0o600); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(dir, "server-token")
		if err := os.Symlink(target, path); err != nil {
			t.Fatal(err)
		}
		err := bootstrap.EnsureServerSecret(path, secret)
		if err == nil || !strings.Contains(err.Error(), path) || !strings.Contains(err.Error(), "not a regular file") {
			t.Fatalf("err = %v, want a not-a-regular-file error naming %s", err, path)
		}
	})

	t.Run("orphan temp reaped before the write", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "server-token")
		orphan := filepath.Join(dir, ".server-token.tmp-424242")
		if err := os.WriteFile(orphan, []byte("stale-secret"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := bootstrap.EnsureServerSecret(path, secret); err != nil {
			t.Fatalf("EnsureServerSecret: %v", err)
		}
		if _, err := os.Lstat(orphan); !os.IsNotExist(err) {
			t.Errorf("orphan temp survived (stat err %v)", err)
		}
		if got, _ := os.ReadFile(path); string(got) != secret {
			t.Error("the secret was not recorded")
		}
	})

	t.Run("missing directory: error, nothing written", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "absent", "server-token")
		if err := bootstrap.EnsureServerSecret(path, secret); err == nil {
			t.Fatal("EnsureServerSecret into a missing directory must fail")
		}
	})
}

// errAny marks a case that expects some error, of no particular identity.
var errAny = errors.New("any error")

func ptr(s string) *string { return &s }

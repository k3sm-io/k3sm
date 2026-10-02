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
	"bytes"
	"context"
	"encoding/base64"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"k3sm.io/k3sm/pkg/executor"
)

// statusTestKey is placeholder key material: 32 bytes of 0x07, never a real key.
var statusTestKey = bytes.Repeat([]byte{0x07}, executor.EncryptionKeySize)

func writeEncryptionFile(t *testing.T, path string, b []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
}

func writeEncryptionPair(t *testing.T, wd string, withFingerprint bool) {
	t.Helper()
	cfg, err := executor.RenderEncryptionConfig(statusTestKey)
	if err != nil {
		t.Fatal(err)
	}
	writeEncryptionFile(t, executor.EncryptionConfigPath(wd), cfg)
	if withFingerprint {
		writeEncryptionFile(t, executor.EncryptionFingerprintPath(wd), []byte(executor.EncryptionKeyFingerprint(statusTestKey)+"\n"))
	}
}

// TestSecretsEncryptStatus asserts the status verb reports the start verdict,
// exits non-zero on a state that would refuse a start, and never prints the key.
func TestSecretsEncryptStatus(t *testing.T) {
	cases := []struct {
		name     string
		setup    func(t *testing.T, wd string)
		args     []string
		wantCode int
		want     []string
	}{
		{
			name:     "disabled",
			wantCode: 0,
			want:     []string{"secrets encryption: disabled", "provider:           none", "mode:               absent"},
		},
		{
			name:     "enabled",
			setup:    func(t *testing.T, wd string) { writeEncryptionPair(t, wd, true) },
			wantCode: 0,
			want:     []string{"secrets encryption: enabled", "provider:           secretbox", "mode:               0600"},
		},
		{
			name:     "inconsistent: configuration without fingerprint",
			setup:    func(t *testing.T, wd string) { writeEncryptionPair(t, wd, false) },
			wantCode: 1,
			want:     []string{"secrets encryption: refused (", "fingerprint"},
		},
		{
			name: "inconsistent: fingerprint without key",
			setup: func(t *testing.T, wd string) {
				writeEncryptionFile(t, executor.EncryptionFingerprintPath(wd), []byte(executor.EncryptionKeyFingerprint(statusTestKey)+"\n"))
			},
			wantCode: 1,
			want:     []string{"secrets encryption: refused (", "key file is missing"},
		},
		{
			name:     "enabled beside a server join is refused",
			setup:    func(t *testing.T, wd string) { writeEncryptionPair(t, wd, true) },
			args:     []string{"--server-join"},
			wantCode: 1,
			want:     []string{"secrets encryption: refused ("},
		},
	}
	encodedKey := base64.StdEncoding.EncodeToString(statusTestKey)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("K3SM_DATASTORE_ENDPOINT", "")
			wd := filepath.Join(t.TempDir(), "server")
			if tc.setup != nil {
				tc.setup(t, wd)
			}
			var out, errOut bytes.Buffer
			args := append([]string{"status", "--work-dir", wd}, tc.args...)
			code := runSecretsEncrypt(args, &out, &errOut)
			if code != tc.wantCode {
				t.Fatalf("exit = %d, want %d\nstdout:\n%s\nstderr:\n%s", code, tc.wantCode, out.String(), errOut.String())
			}
			for _, w := range tc.want {
				if !strings.Contains(out.String(), w) {
					t.Errorf("output lacks %q:\n%s", w, out.String())
				}
			}
			if !strings.Contains(out.String(), executor.EncryptionConfigPath(wd)) {
				t.Errorf("output does not name the configuration path:\n%s", out.String())
			}
			if all := out.String() + errOut.String(); strings.Contains(all, encodedKey) {
				t.Fatalf("the status output carries the key:\n%s", all)
			}
		})
	}
}

// TestParkWhileEncryptionRefusedEndsOnRepair asserts the start refusal stays
// resident while the pair is inconsistent and exits once it is repaired.
func TestParkWhileEncryptionRefusedEndsOnRepair(t *testing.T) {
	wd := filepath.Join(t.TempDir(), "server")
	writeEncryptionPair(t, wd, false)
	logger := slog.New(slog.DiscardHandler)
	done := make(chan error, 1)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	go func() { done <- parkWhileEncryptionRefused(ctx, wd, false, 10*time.Millisecond, logger) }()
	select {
	case err := <-done:
		t.Fatalf("the park ended while the pair was still inconsistent: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	writeEncryptionFile(t, executor.EncryptionFingerprintPath(wd), []byte(executor.EncryptionKeyFingerprint(statusTestKey)+"\n"))
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("park returned %v, want nil", err)
		}
		if ctx.Err() != nil {
			t.Fatal("the park ended on the timeout, not on the repair")
		}
	case <-ctx.Done():
		t.Fatal("the park did not end after the pair was repaired")
	}
}

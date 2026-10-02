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

package install

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"k3sm.io/k3sm/pkg/executor"
)

// placeholderEntropy is the only key material these tests mint from: zeros.
func placeholderEntropy() *bytes.Reader {
	return bytes.NewReader(make([]byte, executor.EncryptionKeySize))
}

// mutatingCallPrefixes are the fake's recorded calls that change the machine:
// a write, a copy, an ownership or mode change, a removal, or a launchd verb.
// The install lock is not among them; it is taken before every preflight that
// needs the data root and holds no state.
var mutatingCallPrefixes = []string{
	"AdHocSign", "AdoptTree", "Bootout", "Bootstrap", "Chown", "CloneToOwned",
	"CopyToRootOwned", "CopyTree", "Enable", "Ensure", "FlushLo", "FlushMeshPFAnchor",
	"Kickstart", "ReapOrphans", "Remove", "Rename", "Signal", "SwapInstallRoot", "Write",
}

func mutatingCalls(calls []string) []string {
	var out []string
	for _, c := range calls {
		for _, p := range mutatingCallPrefixes {
			if strings.HasPrefix(c, p) {
				out = append(out, c)
				break
			}
		}
	}
	return out
}

// TestInstallSecretsEncryption covers the install half of opt-in secrets
// encryption: the pair is staged service-user-owned 0600 in a 0700 directory
// before any daemon starts, and every refusal comes before the install has
// changed anything.
func TestInstallSecretsEncryption(t *testing.T) {
	cases := []struct {
		name    string
		args    []string
		stateDB bool
		wantErr error
	}{
		{name: "fresh install stages the pair"},
		{name: "an existing datastore refuses", stateDB: true, wantErr: executor.ErrEncryptionExistingDatastore},
		{name: "a carried datastore endpoint refuses", args: []string{"--datastore-endpoint", thePasswordlessDSN}, wantErr: executor.ErrEncryptionHA},
		{name: "a carried server join refuses", args: []string{"--server-join", "--datastore-endpoint-file", "/x"}, wantErr: executor.ErrEncryptionHA},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := &fakeSystem{}
			cfg := testConfig(t)
			cfg.SecretsEncryption = true
			cfg.KeyEntropy = placeholderEntropy()
			dc := cfg.withDefaults()
			wd := dc.serverWorkDir()
			if tc.args != nil {
				configureServerArgs(f, cfg, tc.args...)
				if v := flagValue(tc.args, datastoreEndpointFileFlag); v != "" {
					f.putFile(v, []byte(thePasswordlessDSN))
				}
			}
			if tc.stateDB {
				if err := os.MkdirAll(filepath.Join(wd, "db"), 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(executor.StateDBPath(wd), []byte("db"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			err := Install(context.Background(), f, cfg)
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("Install err = %v, want %v", err, tc.wantErr)
				}
				if m := mutatingCalls(f.calls); len(m) > 0 {
					t.Fatalf("the refusal came after the install changed the machine: %v", m)
				}
				return
			}
			if err != nil {
				t.Fatalf("Install: %v", err)
			}
			cfgCall := "WriteServiceUserFile:" + executor.EncryptionConfigPath(wd) + ":0600:0700:271"
			fpCall := "WriteServiceUserFile:" + executor.EncryptionFingerprintPath(wd) + ":0600:0700:271"
			ci, fi := idx(f.calls, cfgCall), idx(f.calls, fpCall)
			if ci < 0 || fi < 0 {
				t.Fatalf("the pair was not staged as %q and %q; calls: %v", cfgCall, fpCall, f.calls)
			}
			if ci > fi {
				t.Error("the fingerprint was written before the configuration it vouches for")
			}
			for _, c := range f.calls {
				if strings.HasPrefix(c, "Bootstrap:") || strings.HasPrefix(c, "Kickstart:") {
					if idx(f.calls, c) < fi {
						t.Errorf("%s ran before the pair was staged", c)
					}
					break
				}
			}
			key, err := executor.EncryptionConfigKey(f.files[executor.EncryptionConfigPath(wd)])
			if err != nil {
				t.Fatalf("the staged configuration does not parse: %v", err)
			}
			if got := strings.TrimSpace(string(f.files[executor.EncryptionFingerprintPath(wd)])); got != executor.EncryptionKeyFingerprint(key) {
				t.Errorf("staged fingerprint %q does not match the staged key", got)
			}
			// Enablement lives in the data root only, never in the argument record.
			if rec, ok := f.serverArgs[dc.ServerArgsRecord]; ok {
				for _, a := range rec.Args {
					if strings.Contains(a, "encryption") {
						t.Errorf("the server-arguments record carries %q", a)
					}
				}
			}
		})
	}
}

// TestReinstallLeavesSecretsEncryptionPairAlone asserts a reinstall, with or
// without the option, never rewrites a pair that is already there.
func TestReinstallLeavesSecretsEncryptionPairAlone(t *testing.T) {
	for _, again := range []bool{false, true} {
		name := "without the option"
		if again {
			name = "with the option and no datastore"
		}
		t.Run(name, func(t *testing.T) {
			f := &fakeSystem{}
			cfg := testConfig(t)
			cfg.SecretsEncryption = true
			cfg.KeyEntropy = placeholderEntropy()
			if err := Install(context.Background(), f, cfg); err != nil {
				t.Fatalf("first Install: %v", err)
			}
			wd := cfg.withDefaults().serverWorkDir()
			paths := []string{executor.EncryptionConfigPath(wd), executor.EncryptionFingerprintPath(wd)}
			before := map[string][]byte{}
			for _, p := range paths {
				before[p] = bytes.Clone(f.files[p])
			}
			f.calls = nil
			cfg.SecretsEncryption = again
			cfg.KeyEntropy = bytes.NewReader(bytes.Repeat([]byte{0x01}, executor.EncryptionKeySize))
			if err := Install(context.Background(), f, cfg); err != nil {
				t.Fatalf("reinstall: %v", err)
			}
			for _, p := range paths {
				if !bytes.Equal(f.files[p], before[p]) {
					t.Errorf("%s changed across the reinstall", p)
				}
				for _, c := range f.calls {
					if strings.HasPrefix(c, "WriteServiceUserFile:"+p+":") {
						t.Errorf("the reinstall wrote %s", p)
					}
				}
			}
		})
	}
}

// TestInstallWithoutSecretsEncryptionNeverTouchesCred asserts the default
// install neither reads nor writes the credential directory.
func TestInstallWithoutSecretsEncryptionNeverTouchesCred(t *testing.T) {
	f := &fakeSystem{}
	cfg := testConfig(t)
	if err := Install(context.Background(), f, cfg); err != nil {
		t.Fatalf("Install: %v", err)
	}
	cred := executor.CredDir(cfg.withDefaults().serverWorkDir())
	for _, c := range f.calls {
		if strings.Contains(c, cred) {
			t.Errorf("the default install touched the credential directory: %s", c)
		}
	}
}

// TestPreflightSecretsEncryptionRefusesAgent asserts the worker refusal.
func TestPreflightSecretsEncryptionRefusesAgent(t *testing.T) {
	f := &fakeSystem{}
	cfg := testConfig(t)
	cfg.Role = RoleAgent
	cfg.SecretsEncryption = true
	if _, err := preflightSecretsEncryption(f, cfg.withDefaults(), nil); !errors.Is(err, executor.ErrEncryptionAgent) {
		t.Fatalf("err = %v, want ErrEncryptionAgent", err)
	}
	if m := mutatingCalls(f.calls); len(m) > 0 {
		t.Fatalf("the refusal changed the machine: %v", m)
	}
}

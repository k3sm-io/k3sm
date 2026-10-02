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

package executor

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"sigs.k8s.io/yaml"
)

// zeroKey is the placeholder key material every test mints from: 32 zero
// bytes, never a real key.
var zeroKey = make([]byte, EncryptionKeySize)

// sequentialReader yields 0,1,2,... so a second mint is a different, still
// obviously fake, key.
type sequentialReader struct{ next byte }

func (r *sequentialReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = r.next
		r.next++
	}
	return len(p), nil
}

// treeSnapshot maps every path under root to its content ("<dir>" for a
// directory), so a test can assert a refusal wrote nothing.
func treeSnapshot(t *testing.T, root string) map[string]string {
	t.Helper()
	out := map[string]string{}
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, p)
		if d.IsDir() {
			out[rel] = "<dir>"
			return nil
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		out[rel] = string(b)
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", root, err)
	}
	return out
}

func diffTrees(before, after map[string]string) []string {
	var d []string
	for k, v := range after {
		if bv, ok := before[k]; !ok || bv != v {
			d = append(d, k)
		}
	}
	for k := range before {
		if _, ok := after[k]; !ok {
			d = append(d, "-"+k)
		}
	}
	sort.Strings(d)
	return d
}

func writeFile(t *testing.T, path string, b []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
}

// writePair lays down a configuration and a fingerprint. fpKey is the key the
// fingerprint records, so a mismatch is fpKey != key.
func writePair(t *testing.T, wd string, key, fpKey []byte) {
	t.Helper()
	cfg, err := RenderEncryptionConfig(key)
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, EncryptionConfigPath(wd), cfg)
	writeFile(t, EncryptionFingerprintPath(wd), []byte(EncryptionKeyFingerprint(fpKey)+"\n"))
}

// TestEncryptionEnableRefusesNonEmptyStateDB is the gate for opt-in secrets
// encryption: it may be enabled only at a fresh install of a single server,
// and a start accepts only the pair the installer wrote. Every refusal is a
// distinct sentinel and writes nothing.
func TestEncryptionEnableRefusesNonEmptyStateDB(t *testing.T) {
	otherKey := bytes.Repeat([]byte{0x01}, EncryptionKeySize)

	installCases := []struct {
		name    string
		setup   func(t *testing.T, wd string)
		req     EncryptionInstallRequest
		want    EncryptionInstallAction
		wantErr error
	}{
		{name: "fresh install is enabled", req: EncryptionInstallRequest{Requested: true}, want: EncryptionMint},
		{name: "not requested touches nothing", req: EncryptionInstallRequest{}, want: EncryptionLeave},
		{
			name:    "existing state.db is refused",
			setup:   func(t *testing.T, wd string) { writeFile(t, StateDBPath(wd), []byte("db")) },
			req:     EncryptionInstallRequest{Requested: true},
			wantErr: ErrEncryptionExistingDatastore,
		},
		{
			name:    "WAL residue is refused",
			setup:   func(t *testing.T, wd string) { writeFile(t, StateDBPath(wd)+"-wal", []byte("wal")) },
			req:     EncryptionInstallRequest{Requested: true},
			wantErr: ErrEncryptionExistingDatastore,
		},
		{
			name:    "shared-memory residue is refused",
			setup:   func(t *testing.T, wd string) { writeFile(t, StateDBPath(wd)+"-shm", []byte("shm")) },
			req:     EncryptionInstallRequest{Requested: true},
			wantErr: ErrEncryptionExistingDatastore,
		},
		{
			name:    "kine pin stamp is refused",
			setup:   func(t *testing.T, wd string) { writeFile(t, kinePinStampPath(wd), []byte(DefaultKineVersion)) },
			req:     EncryptionInstallRequest{Requested: true},
			wantErr: ErrEncryptionExistingDatastore,
		},
		{
			name:    "a leftover external-datastore credential is refused",
			setup:   func(t *testing.T, wd string) { writeFile(t, pgPassPath(wd), []byte("placeholder")) },
			req:     EncryptionInstallRequest{Requested: true},
			wantErr: ErrEncryptionExistingDatastore,
		},
		{
			name: "existing pair beside a datastore is refused",
			setup: func(t *testing.T, wd string) {
				writePair(t, wd, zeroKey, zeroKey)
				writeFile(t, StateDBPath(wd), []byte("db"))
			},
			req:     EncryptionInstallRequest{Requested: true},
			wantErr: ErrEncryptionExistingDatastore,
		},
		{name: "server join is refused", req: EncryptionInstallRequest{Requested: true, HA: true}, wantErr: ErrEncryptionHA},
		{name: "agent is refused", req: EncryptionInstallRequest{Requested: true, Agent: true}, wantErr: ErrEncryptionAgent},
		{
			name:  "existing pair and no datastore is kept",
			setup: func(t *testing.T, wd string) { writePair(t, wd, zeroKey, zeroKey) },
			req:   EncryptionInstallRequest{Requested: true},
			want:  EncryptionKeep,
		},
		{
			name:    "a lone configuration is refused, never re-minted",
			setup:   func(t *testing.T, wd string) { writeFile(t, EncryptionConfigPath(wd), mustRender(t, zeroKey)) },
			req:     EncryptionInstallRequest{Requested: true},
			wantErr: ErrEncryptionConfigWithoutFingerprint,
		},
	}
	for _, tc := range installCases {
		t.Run("install/"+tc.name, func(t *testing.T) {
			wd := filepath.Join(t.TempDir(), "server")
			if err := os.MkdirAll(wd, 0o700); err != nil {
				t.Fatal(err)
			}
			if tc.setup != nil {
				tc.setup(t, wd)
			}
			before := treeSnapshot(t, wd)
			action, err := PlanEncryptionAtInstall(OSEncryptionStore{}, wd, tc.req)
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("Plan err = %v, want %v", err, tc.wantErr)
				}
				if d := diffTrees(before, treeSnapshot(t, wd)); len(d) > 0 {
					t.Fatalf("a refusal wrote: %v", d)
				}
				return
			}
			if err != nil {
				t.Fatalf("Plan: %v", err)
			}
			if action != tc.want {
				t.Fatalf("action = %v, want %v", action, tc.want)
			}
			if err := ApplyEncryptionAtInstall(OSEncryptionStore{}, wd, action, bytes.NewReader(zeroKey)); err != nil {
				t.Fatalf("Apply: %v", err)
			}
			after := treeSnapshot(t, wd)
			if action != EncryptionMint {
				if d := diffTrees(before, after); len(d) > 0 {
					t.Fatalf("action %v wrote: %v", action, d)
				}
				return
			}
			key, err := EncryptionConfigKey([]byte(after[filepath.Join(credSubdir, encryptionConfigName)]))
			if err != nil {
				t.Fatalf("the written configuration does not parse: %v", err)
			}
			if !bytes.Equal(key, zeroKey) {
				t.Fatal("the written key is not the one minted from the injected reader")
			}
			fp := strings.TrimSpace(after[filepath.Join(credSubdir, encryptionFingerprintName)])
			if fp != EncryptionKeyFingerprint(zeroKey) {
				t.Fatalf("fingerprint = %q, want the key's", fp)
			}
			for _, p := range []string{EncryptionConfigPath(wd), EncryptionFingerprintPath(wd)} {
				fi, err := os.Stat(p)
				if err != nil {
					t.Fatal(err)
				}
				if fi.Mode().Perm() != 0o600 {
					t.Errorf("%s mode = %#o, want 0600", p, fi.Mode().Perm())
				}
			}
			if fi, err := os.Stat(CredDir(wd)); err != nil || fi.Mode().Perm() != 0o700 {
				t.Errorf("cred dir mode = %v (err %v), want 0700", fi.Mode().Perm(), err)
			}
			// The pair the install wrote is the pair the next start accepts.
			path, err := EncryptionAtStart(OSEncryptionStore{}, wd, false)
			if err != nil || path != EncryptionConfigPath(wd) {
				t.Fatalf("start after install = %q, %v; want enabled", path, err)
			}
		})
	}

	startCases := []struct {
		name    string
		setup   func(t *testing.T, wd string)
		ha      bool
		enabled bool
		wantErr error
	}{
		{name: "neither file is off"},
		{
			name: "config beside an existing db and no fingerprint is refused",
			setup: func(t *testing.T, wd string) {
				writeFile(t, StateDBPath(wd), []byte("db"))
				writeFile(t, EncryptionConfigPath(wd), mustRender(t, zeroKey))
			},
			wantErr: ErrEncryptionConfigWithoutFingerprint,
		},
		{
			name: "fingerprint only is refused",
			setup: func(t *testing.T, wd string) {
				writeFile(t, EncryptionFingerprintPath(wd), []byte(EncryptionKeyFingerprint(zeroKey)+"\n"))
			},
			wantErr: ErrEncryptionKeyMissing,
		},
		{
			name:    "mismatch is refused",
			setup:   func(t *testing.T, wd string) { writePair(t, wd, zeroKey, otherKey) },
			wantErr: ErrEncryptionFingerprintMismatch,
		},
		{
			name: "an identity provider is refused",
			setup: func(t *testing.T, wd string) {
				writePair(t, wd, zeroKey, zeroKey)
				cfg := "kind: EncryptionConfiguration\napiVersion: apiserver.config.k8s.io/v1\nresources:\n- resources: [secrets]\n  providers:\n  - identity: {}\n  - secretbox:\n      keys:\n      - name: key1\n        secret: " +
					base64.StdEncoding.EncodeToString(zeroKey) + "\n"
				writeFile(t, EncryptionConfigPath(wd), []byte(cfg))
			},
			wantErr: ErrEncryptionConfigInvalid,
		},
		{
			name:    "both matching under a server join is refused",
			setup:   func(t *testing.T, wd string) { writePair(t, wd, zeroKey, zeroKey) },
			ha:      true,
			wantErr: ErrEncryptionHA,
		},
		{
			name:    "both matching is enabled",
			setup:   func(t *testing.T, wd string) { writePair(t, wd, zeroKey, zeroKey) },
			enabled: true,
		},
	}
	for _, tc := range startCases {
		t.Run("start/"+tc.name, func(t *testing.T) {
			wd := filepath.Join(t.TempDir(), "server")
			if err := os.MkdirAll(wd, 0o700); err != nil {
				t.Fatal(err)
			}
			if tc.setup != nil {
				tc.setup(t, wd)
			}
			before := treeSnapshot(t, wd)
			path, err := EncryptionAtStart(OSEncryptionStore{}, wd, tc.ha)
			if d := diffTrees(before, treeSnapshot(t, wd)); len(d) > 0 {
				t.Fatalf("the start verdict wrote: %v", d)
			}
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("err = %v, want %v", err, tc.wantErr)
				}
				if path != "" {
					t.Fatalf("a refusal returned a config path %q", path)
				}
				return
			}
			if err != nil {
				t.Fatalf("EncryptionAtStart: %v", err)
			}
			if got := path != ""; got != tc.enabled {
				t.Fatalf("enabled = %v (path %q), want %v", got, path, tc.enabled)
			}
		})
	}
}

// TestEncryptionInstallKeepsExistingPair asserts a second install with the
// option over a pair and no datastore leaves the key byte-identical.
func TestEncryptionInstallKeepsExistingPair(t *testing.T) {
	wd := filepath.Join(t.TempDir(), "server")
	req := EncryptionInstallRequest{Requested: true}
	a, err := PlanEncryptionAtInstall(OSEncryptionStore{}, wd, req)
	if err != nil || a != EncryptionMint {
		t.Fatalf("first plan = %v, %v", a, err)
	}
	if err := ApplyEncryptionAtInstall(OSEncryptionStore{}, wd, a, &sequentialReader{}); err != nil {
		t.Fatal(err)
	}
	before := treeSnapshot(t, wd)
	a, err = PlanEncryptionAtInstall(OSEncryptionStore{}, wd, req)
	if err != nil || a != EncryptionKeep {
		t.Fatalf("second plan = %v, %v; want keep", a, err)
	}
	if err := ApplyEncryptionAtInstall(OSEncryptionStore{}, wd, a, &sequentialReader{next: 100}); err != nil {
		t.Fatal(err)
	}
	if d := diffTrees(before, treeSnapshot(t, wd)); len(d) > 0 {
		t.Fatalf("keep re-minted: %v", d)
	}
}

// TestAPIServerArgsCarryEncryptionProviderConfigWhenPresent asserts the flag is
// rendered exactly when the Config names a path, with that path as its value.
func TestAPIServerArgsCarryEncryptionProviderConfigWhenPresent(t *testing.T) {
	const wd = "/var/lib/k3sm/server"
	cases := []struct {
		name string
		path string
	}{
		{name: "present", path: EncryptionConfigPath(wd)},
		{name: "absent"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			args := apiServerArgs(Config{WorkDir: wd, KinePort: 2379, APIServerPort: 6444, NodeIP: "127.0.0.1", EncryptionProviderConfig: tc.path})
			n := 0
			for _, a := range args {
				if strings.HasPrefix(a, "--encryption-provider-config") {
					n++
				}
			}
			if tc.path == "" {
				if n != 0 {
					t.Fatalf("--encryption-provider-config rendered without a path: %v", args)
				}
				return
			}
			if n != 1 {
				t.Fatalf("--encryption-provider-config appears %d times, want 1: %v", n, args)
			}
			if got := flagValue(args, "--encryption-provider-config"); got != tc.path {
				t.Fatalf("--encryption-provider-config = %q, want %q", got, tc.path)
			}
		})
	}
}

// TestEncryptionConfigHasNoIdentityProvider asserts the rendered configuration
// is one secretbox provider over secrets, with a 32-byte key and no identity
// provider (which would let the apiserver keep reading plaintext Secrets).
func TestEncryptionConfigHasNoIdentityProvider(t *testing.T) {
	out, err := RenderEncryptionConfig(zeroKey)
	if err != nil {
		t.Fatal(err)
	}
	var cfg struct {
		Kind       string `json:"kind"`
		APIVersion string `json:"apiVersion"`
		Resources  []struct {
			Resources []string                     `json:"resources"`
			Providers []map[string]json.RawMessage `json:"providers"`
		} `json:"resources"`
	}
	if err := yaml.Unmarshal(out, &cfg); err != nil {
		t.Fatalf("unmarshal: %v\n%s", err, out)
	}
	if cfg.Kind != "EncryptionConfiguration" || cfg.APIVersion != "apiserver.config.k8s.io/v1" {
		t.Errorf("kind/apiVersion = %q/%q", cfg.Kind, cfg.APIVersion)
	}
	if len(cfg.Resources) != 1 || len(cfg.Resources[0].Resources) != 1 || cfg.Resources[0].Resources[0] != "secrets" {
		t.Fatalf("resources = %+v, want exactly [secrets]", cfg.Resources)
	}
	providers := cfg.Resources[0].Providers
	if len(providers) != 1 {
		t.Fatalf("providers = %d, want 1", len(providers))
	}
	for name := range providers[0] {
		if name != "secretbox" {
			t.Errorf("provider %q present, want only secretbox", name)
		}
	}
	if _, ok := providers[0]["identity"]; ok {
		t.Error("an identity provider is present")
	}
	var sb struct {
		Keys []struct {
			Name   string `json:"name"`
			Secret string `json:"secret"`
		} `json:"keys"`
	}
	if err := yaml.Unmarshal(providers[0]["secretbox"], &sb); err != nil {
		t.Fatal(err)
	}
	if len(sb.Keys) != 1 {
		t.Fatalf("keys = %d, want 1", len(sb.Keys))
	}
	key, err := base64.StdEncoding.DecodeString(sb.Keys[0].Secret)
	if err != nil || len(key) != 32 {
		t.Fatalf("key decodes to %d bytes (err %v), want 32", len(key), err)
	}
}

// TestValidateRefusesEncryptionWithHA asserts the executor will not start an
// HA server with encryption configured.
func TestValidateRefusesEncryptionWithHA(t *testing.T) {
	cases := []struct {
		name string
		cfg  Config
		want error
	}{
		{name: "single server", cfg: Config{EncryptionProviderConfig: "/x"}},
		{name: "datastore endpoint", cfg: Config{EncryptionProviderConfig: "/x", DatastoreEndpoint: "postgres://h/db"}, want: ErrEncryptionHA},
		{name: "server join", cfg: Config{EncryptionProviderConfig: "/x", ServerJoin: true, DatastoreEndpoint: "postgres://h/db"}, want: ErrEncryptionHA},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.cfg.Validate(); !errors.Is(err, tc.want) && !(tc.want == nil && err == nil) {
				t.Fatalf("Validate = %v, want %v", err, tc.want)
			}
		})
	}
}

func mustRender(t *testing.T, key []byte) []byte {
	t.Helper()
	b, err := RenderEncryptionConfig(key)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

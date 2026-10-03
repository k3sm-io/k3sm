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
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	"k3sm.io/k3sm/pkg/executor"
)

// TestInstallRefusesCarriedDatastoreEndpoint pins the upgrade refusal that replaces
// the external-datastore HA posture: an install whose carried server arguments name
// --datastore-endpoint or --datastore-endpoint-file, in any spelling and from either
// carried source, is refused before it writes anything, and the refusal names the
// embedded-etcd replacement. Rendering the plist anyway would hand launchd a daemon
// that exits on an unknown flag at every respawn.
func TestInstallRefusesCarriedDatastoreEndpoint(t *testing.T) {
	spellings := [][]string{
		{"--datastore-endpoint", "scheme://u:s3cret@h/db"},
		{"--datastore-endpoint=scheme://h/db"},
		{"-datastore-endpoint", "scheme://h/db"},
		{"--datastore-endpoint-file", "/var/lib/k3sm/server/datastore-endpoint"},
		{"--datastore-endpoint-file=/x"},
		{"-datastore-endpoint-file=/x"},
		{"--mesh-ip", "198.51.100.10", "--datastore-endpoint"},
	}
	for _, args := range spellings {
		for _, source := range []string{"plist", "record"} {
			t.Run(source+" "+strings.Join(args, " "), func(t *testing.T) {
				f := &fakeSystem{}
				cfg := testConfig(t)
				if source == "plist" {
					configureServerArgs(f, cfg, args...)
				} else {
					putServerArgsRecord(t, f, cfg.withDefaults().ServerArgsRecord, args...)
				}
				err := Install(context.Background(), f, cfg)
				if !errors.Is(err, ErrRetiredDatastoreFlag) {
					t.Fatalf("Install = %v, want ErrRetiredDatastoreFlag", err)
				}
				for _, want := range []string{"--cluster-init", "--server-join", "no conversion"} {
					if !strings.Contains(err.Error(), want) {
						t.Errorf("the refusal does not name %q: %v", want, err)
					}
				}
				if strings.Contains(err.Error(), "s3cret") {
					t.Errorf("the refusal echoed a carried credential: %v", err)
				}
				if m := mutatingCalls(f.calls); len(m) > 0 {
					t.Errorf("the refusal came after the install changed the machine: %v", m)
				}
			})
		}
	}
}

// TestSecretsEncryptionRefusedWithClusterInit pins the install half of the
// single-server-only encryption rule in the etcd posture: a carried --cluster-init or
// --server-join, in any spelling, is HA and refuses --secrets-encryption before any
// write; an explicit =false is not HA; and the HA role flags are carried to the
// daemon verbatim beside --node-ip when encryption is not requested.
func TestSecretsEncryptionRefusedWithClusterInit(t *testing.T) {
	for _, tc := range []struct {
		args []string
		ha   bool
	}{
		{[]string{"--cluster-init"}, true},
		{[]string{"-cluster-init"}, true},
		{[]string{"--cluster-init=true"}, true},
		{[]string{"--server-join"}, true},
		{[]string{"--server-join=true", "--server", "192.0.2.10"}, true},
		{[]string{"--cluster-init=false"}, false},
		{[]string{"--node-ip", "192.0.2.10"}, false},
		{nil, false},
	} {
		if got := carriesEtcdPosture(tc.args); got != tc.ha {
			t.Errorf("carriesEtcdPosture(%q) = %v, want %v", tc.args, got, tc.ha)
		}
	}

	t.Run("install refuses before writing", func(t *testing.T) {
		f := &fakeSystem{}
		cfg := testConfig(t)
		cfg.SecretsEncryption = true
		cfg.KeyEntropy = placeholderEntropy()
		configureServerArgs(f, cfg, "--cluster-init", "--node-ip", "192.0.2.10")
		err := Install(context.Background(), f, cfg)
		if !errors.Is(err, executor.ErrEncryptionHA) {
			t.Fatalf("Install = %v, want ErrEncryptionHA", err)
		}
		if m := mutatingCalls(f.calls); len(m) > 0 {
			t.Errorf("the refusal came after the install changed the machine: %v", m)
		}
	})

	t.Run("the role flags reach the daemon verbatim", func(t *testing.T) {
		f := &fakeSystem{}
		cfg := testConfig(t)
		want := []string{"--cluster-init", "--node-ip", "192.0.2.10", "--mesh-ip", "198.51.100.10"}
		configureServerArgs(f, cfg, want...)
		if err := Install(context.Background(), f, cfg); err != nil {
			t.Fatalf("Install: %v", err)
		}
		if got := serverArgsOf(t, f, cfg); !slices.Equal(got, want) {
			t.Errorf("rendered server args = %v, want %v", got, want)
		}
	})
}

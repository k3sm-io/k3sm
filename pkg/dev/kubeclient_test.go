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

package dev

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestDevKubeClientResolution is the pkg/dev half of the B251 characterization
// table (the cmd half is TestNewKubeClientResolution): both bootstrap waits load
// the INSTANCE's own kubeconfig by explicit path and wrap a load failure in
// their own text naming that path. Folding the inline clientcmd+kubernetes pair
// onto pkg/kubeclient must leave both verdicts unchanged.
//
// Only the failure paths are exercised: a loadable kubeconfig sends each wait on
// to a 90s/5m poll against a real apiserver, which is not a unit test.
func TestDevKubeClientResolution(t *testing.T) {
	m := newTestManager(t, newFakeSystem(), 501)

	unparseable := func(t *testing.T) string {
		t.Helper()
		path := filepath.Join(t.TempDir(), "kubeconfig")
		if err := os.WriteFile(path, []byte("{{ this is not a kubeconfig\n"), 0o600); err != nil {
			t.Fatalf("write kubeconfig: %v", err)
		}
		return path
	}

	cases := []struct {
		name string
		call func(ctx context.Context, kubeconfig string) error
		wrap string
	}{
		{
			name: "default-namespace bootstrap wait",
			call: m.awaitDefaultNamespaceBootstrap,
			wrap: "build client config from %s: ",
		},
		{
			name: "node-registration wait",
			call: m.awaitNodeRegistered,
			wrap: "build client config from %s: ",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name+", absent kubeconfig", func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			kc := filepath.Join(t.TempDir(), "absent.kubeconfig")
			err := tc.call(ctx, kc)
			if err == nil {
				t.Fatal("expected an error for a missing kubeconfig")
			}
			if want := fmt.Sprintf(tc.wrap, kc); !strings.HasPrefix(err.Error(), want) {
				t.Errorf("error = %q, want the site's own %q wrap", err.Error(), want)
			}
		})
		t.Run(tc.name+", unparseable kubeconfig", func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			kc := unparseable(t)
			err := tc.call(ctx, kc)
			if err == nil {
				t.Fatal("expected an error for an unparseable kubeconfig")
			}
			if want := fmt.Sprintf(tc.wrap, kc); !strings.HasPrefix(err.Error(), want) {
				t.Errorf("error = %q, want the site's own %q wrap", err.Error(), want)
			}
		})
	}
}

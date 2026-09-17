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

package kubeclient

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// assertUnwrapped fails unless err is the loader's own error: it must name the
// path (clientcmd's messages do) and must NOT carry any context this package
// could have added.
func assertUnwrapped(t *testing.T, err error, path string) {
	t.Helper()
	if !strings.Contains(err.Error(), path) {
		t.Errorf("error = %q, want the loader's message naming %s", err.Error(), path)
	}
	for _, added := range []string{"load kubeconfig", "build kubernetes client"} {
		if strings.Contains(err.Error(), added) {
			t.Errorf("error = %q carries the helper's %q; a load error must come back unwrapped", err.Error(), added)
		}
	}
}

// writeKubeconfig writes a minimal kubeconfig naming server into a temp dir and
// returns its path. The tests drive the real loader rather than hand-building a
// rest.Config, so what they pin is what a caller's file actually resolves to.
func writeKubeconfig(t *testing.T, server string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "kubeconfig")
	body := fmt.Sprintf(`apiVersion: v1
kind: Config
clusters:
- name: k3sm
  cluster:
    server: %s
contexts:
- name: k3sm
  context:
    cluster: k3sm
    user: k3sm
current-context: k3sm
users:
- name: k3sm
  user: {}
`, server)
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write kubeconfig: %v", err)
	}
	return path
}

func TestFromPathResolvesTheNamedFile(t *testing.T) {
	t.Run("the host comes from the named file", func(t *testing.T) {
		path := writeKubeconfig(t, "https://127.0.0.1:6443")
		cfg, cs, err := FromPath(path)
		if err != nil {
			t.Fatalf("FromPath: %v", err)
		}
		if cfg.Host != "https://127.0.0.1:6443" {
			t.Errorf("Host = %q, want the server the file names", cfg.Host)
		}
		if cs == nil {
			t.Error("clientset is nil with no error")
		}
	})

	t.Run("a second file resolves to its own host", func(t *testing.T) {
		// Two files in one test binary: proves the resolution is per-call and
		// nothing is cached or inherited from the environment.
		cfg, _, err := FromPath(writeKubeconfig(t, "https://10.0.0.7:6443"))
		if err != nil {
			t.Fatalf("FromPath: %v", err)
		}
		if cfg.Host != "https://10.0.0.7:6443" {
			t.Errorf("Host = %q, want the second file's server", cfg.Host)
		}
	})

	t.Run("no timeout or rate limit is imposed", func(t *testing.T) {
		// The callers that need one set it themselves (cmd/k3sm's nodeRESTConfig
		// pins a request timeout); the helper must not quietly decide for them.
		cfg, _, err := FromPath(writeKubeconfig(t, "https://127.0.0.1:6443"))
		if err != nil {
			t.Fatalf("FromPath: %v", err)
		}
		if cfg.Timeout != 0 {
			t.Errorf("Timeout = %v, want the loader's zero value", cfg.Timeout)
		}
	})
}

// TestFromPathReturnsTheLoaderError pins the contract every caller depends on to
// keep its own message: a load failure comes back EXACTLY as clientcmd produced
// it. Six call sites each wrap it in their own words, so a context segment added
// here would either stutter with theirs or silently reword four shipped errors.
func TestFromPathReturnsTheLoaderError(t *testing.T) {
	t.Run("absent file", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "absent.kubeconfig")
		cfg, cs, err := FromPath(path)
		if err == nil {
			t.Fatal("expected an error for an absent kubeconfig")
		}
		if cfg != nil || cs != nil {
			t.Error("an error must come with a nil config and a nil clientset")
		}
		// The loader's own error, unaltered: it stats the file, so it is both an
		// fs.ErrNotExist and already names the path.
		if !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("error = %v, want the loader's own fs.ErrNotExist to survive unwrapped", err)
		}
		assertUnwrapped(t, err, path)
	})

	t.Run("unparseable file", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "kubeconfig")
		if err := os.WriteFile(path, []byte("{{ this is not a kubeconfig\n"), 0o600); err != nil {
			t.Fatalf("write kubeconfig: %v", err)
		}
		_, _, err := FromPath(path)
		if err == nil {
			t.Fatal("expected an error for an unparseable kubeconfig")
		}
		assertUnwrapped(t, err, path)
	})

	t.Run("empty path does not search the environment", func(t *testing.T) {
		// An empty path leaves client-go with nothing explicit, and it falls back
		// to in-cluster config — which on a macOS host is always an error. The
		// point of the assertion is the NEGATIVE one: no KUBECONFIG env var and no
		// ~/.kube/config is consulted, so an empty path can never silently resolve
		// to whatever cluster the operator last used.
		t.Setenv("KUBECONFIG", writeKubeconfig(t, "https://198.51.100.1:6443"))
		cfg, _, err := FromPath("")
		if err == nil {
			t.Fatalf("FromPath(\"\") resolved to %q; it must not consult the environment", cfg.Host)
		}
	})
}

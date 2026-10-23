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
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"k3sm.io/k3sm/pkg/executor"
)

// writeContextKubeconfig writes a kubeconfig at path holding two contexts: the
// named one, pointing at server, and an "other" context that is current. A
// builder that resolves to it must therefore PIN the named context; reading the
// current context would land on the wrong cluster.
func writeContextKubeconfig(t *testing.T, path, contextName, server string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	body := fmt.Sprintf(`apiVersion: v1
kind: Config
clusters:
- name: %[1]s
  cluster:
    server: %[2]s
- name: other
  cluster:
    server: https://192.0.2.99:6443
contexts:
- name: %[1]s
  context:
    cluster: %[1]s
    user: %[1]s
- name: other
  context:
    cluster: other
    user: other
current-context: other
users:
- name: %[1]s
  user: {}
- name: other
  user: {}
`, contextName, server)
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write kubeconfig: %v", err)
	}
}

// unreadableWorkDir returns a work dir holding an admin kubeconfig inside a
// mode-0000 directory, so a non-root stat of the kubeconfig fails with EACCES —
// the ordinary user's view of the service user's mode-0700 work dir.
func unreadableWorkDir(t *testing.T) string {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Skip("root reads a mode-0000 directory; the unreadable work dir cannot be staged")
	}
	workDir := filepath.Join(t.TempDir(), "server")
	writeKubeconfigAt(t, executor.KubeconfigPath(workDir), "https://127.0.0.1:6443")
	if err := os.Chmod(workDir, 0); err != nil {
		t.Fatalf("chmod work dir: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(workDir, 0o700) })
	return workDir
}

// TestBuilderUsesTheUserKubeconfigWhenTheWorkDirIsUnreadable is the gate for this behaviour.
// The builder verbs (up|down|delete|status, and `k3sm build prune`, which goes
// through the same newBuilderManager) resolve their kubeconfig the way
// `k3sm kubectl` does: the work dir's admin kubeconfig when it is readable, the
// user's own kubeconfig pinned to the installed context when it is not, and an
// explicit --work-dir verbatim with no fallback.
func TestBuilderUsesTheUserKubeconfigWhenTheWorkDirIsUnreadable(t *testing.T) {
	const (
		adminServer = "https://127.0.0.1:6443"
		userServer  = "https://127.0.0.1:16443"
	)
	contextName := installedKubeconfigName()

	readableWorkDir := func(t *testing.T) string {
		workDir := filepath.Join(t.TempDir(), "server")
		writeKubeconfigAt(t, executor.KubeconfigPath(workDir), adminServer)
		return workDir
	}

	tests := []struct {
		name string
		// opts builds the parsed options; it runs after HOME is staged.
		opts func(t *testing.T) builderOptions
		// userKubeconfig writes the user's ~/.kube/config when true.
		userKubeconfig bool
		// wantHost is the apiserver the resolved client dials ("" on error).
		wantHost string
		// wantErr are substrings the error must carry; nil means success.
		wantErr []string
	}{
		{
			name: "readable work dir uses its admin kubeconfig",
			opts: func(t *testing.T) builderOptions {
				return builderOptions{workDir: readableWorkDir(t)}
			},
			userKubeconfig: true,
			wantHost:       adminServer,
		},
		{
			name: "unreadable work dir falls back to the user kubeconfig",
			opts: func(t *testing.T) builderOptions {
				return builderOptions{workDir: unreadableWorkDir(t)}
			},
			userKubeconfig: true,
			wantHost:       userServer,
		},
		{
			name: "unreadable work dir and no user kubeconfig names both paths and both fixes",
			opts: func(t *testing.T) builderOptions {
				return builderOptions{workDir: unreadableWorkDir(t)}
			},
			wantErr: []string{"run with sudo", "sudo k3sm kubeconfig --write", filepath.Join(".kube", "config"), filepath.Base(executor.KubeconfigPath("x"))},
		},
		{
			name: "explicit --work-dir is used verbatim with no fallback",
			opts: func(t *testing.T) builderOptions {
				o, err := parseBuilderArgs("up", []string{"--work-dir", t.TempDir()})
				if err != nil {
					t.Fatalf("parseBuilderArgs: %v", err)
				}
				return o
			},
			userKubeconfig: true,
			wantErr:        []string{"run `k3sm server` first"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			home := t.TempDir()
			t.Setenv("HOME", home)
			t.Setenv("KUBECONFIG", "")
			t.Setenv("K3SM_WORK_DIR", "")
			if tt.userKubeconfig {
				writeContextKubeconfig(t, filepath.Join(home, ".kube", "config"), contextName, userServer)
			}
			opts := tt.opts(t)

			mgr, mgrErr := newBuilderManager(opts)
			restCfg, _, err := builderClients(builderKubeInputs(opts))
			if (mgrErr == nil) != (err == nil) {
				t.Fatalf("newBuilderManager err = %v, builderClients err = %v; they must agree", mgrErr, err)
			}
			if tt.wantErr == nil {
				if err != nil {
					t.Fatalf("builderClients: %v", err)
				}
				if mgr == nil {
					t.Fatal("newBuilderManager returned a nil manager and no error")
				}
				if restCfg.Host != tt.wantHost {
					t.Errorf("resolved host = %q, want %q", restCfg.Host, tt.wantHost)
				}
				return
			}
			if err == nil {
				t.Fatalf("builderClients succeeded (host %q), want an error", restCfg.Host)
			}
			for _, want := range tt.wantErr {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("error %q does not contain %q", err.Error(), want)
				}
			}
		})
	}
}

// TestBuilderWorkDirExplicitness pins which spellings name the work dir: the
// --work-dir flag and K3SM_WORK_DIR do; the posture default does not.
func TestBuilderWorkDirExplicitness(t *testing.T) {
	t.Setenv("K3SM_WORK_DIR", "")
	if dir, explicit := builderWorkDir("/x/server"); dir != "/x/server" || !explicit {
		t.Errorf("flag: got (%q, %v), want (/x/server, true)", dir, explicit)
	}
	if _, explicit := builderWorkDir(""); explicit {
		t.Error("posture default reported as explicit")
	}
	t.Setenv("K3SM_WORK_DIR", "/y/server")
	if dir, explicit := builderWorkDir(""); dir != "/y/server" || !explicit {
		t.Errorf("K3SM_WORK_DIR: got (%q, %v), want (/y/server, true)", dir, explicit)
	}
}

// TestBuilderAndKubectlResolveAlike holds the builder to `k3sm kubectl`: on
// every input where kubectl resolves a kubeconfig, the builder resolves the same
// one. TestResolveKubectlConfig, unchanged by this change, pins kubectl's own answers.
func TestBuilderAndKubectlResolveAlike(t *testing.T) {
	const (
		serviceWorkDir = "/var/lib/k3sm/server"
		userHome       = "/Users/alice"
	)
	serviceKubeconfig := executor.KubeconfigPath(serviceWorkDir)
	userKubeconfig := filepath.Join(userHome, ".kube", "config")
	envKubeconfig := "/Users/alice/work/kubeconfig.yaml"

	for _, in := range []kubectlInputs{
		{workDir: serviceWorkDir, home: "/var/lib/k3sm", contextName: "k3sm", exists: setOf(serviceKubeconfig)},
		{workDir: serviceWorkDir, home: userHome, contextName: "k3sm", exists: setOf(userKubeconfig)},
		{workDir: serviceWorkDir, kubeconfigEnv: envKubeconfig, contextName: "lab", exists: setOf(envKubeconfig)},
		{workDirOverride: serviceWorkDir, workDir: serviceWorkDir, home: userHome, contextName: "k3sm", exists: setOf(serviceKubeconfig, userKubeconfig)},
	} {
		want, err := resolveKubectlConfig(in)
		if err != nil {
			t.Fatalf("resolveKubectlConfig(%+v): %v", in, err)
		}
		got, err := builderKubeconfig(in)
		if err != nil {
			t.Fatalf("builderKubeconfig(%+v): %v", in, err)
		}
		if got != want {
			t.Errorf("builderKubeconfig = %+v, kubectl resolves %+v", got, want)
		}
	}
}

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
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/rest"

	"k3sm.io/k3sm/pkg/builder"
	"k3sm.io/k3sm/pkg/executor"
)

// fakeBuildxClients replaces the session's client seam for one test. The fake
// resolves the kubeconfig exactly as builderClients does (builderKubeconfig over
// the session's inputs), records the choice, and returns an empty fake
// clientset, so the builder's Service lookup reports builder.ErrAbsent without
// any socket. calls counts how often the session reached the seam.
func fakeBuildxClients(t *testing.T) (chosen *kubectlConfig, calls *int) {
	t.Helper()
	chosen, calls = &kubectlConfig{}, new(int)
	prev := buildxClients
	buildxClients = func(in kubectlInputs) (*rest.Config, kubernetes.Interface, error) {
		*calls++
		cfg, err := builderKubeconfig(in)
		if err != nil {
			return nil, nil, err
		}
		*chosen = cfg
		return &rest.Config{}, fake.NewClientset(), nil
	}
	t.Cleanup(func() { buildxClients = prev })
	return chosen, calls
}

// TestBuildxSessionUnprivilegedOnRootInstall is the gate for the buildx session
// behind `k3sm build` (a RUN Dockerfile, a Linux --platform) and
// `k3sm builder buildx`. It chooses its kubeconfig the way the builder verbs do:
// an ordinary account on a root install, whose posture work dir holds no
// readable admin kubeconfig, runs on its own kubeconfig pinned to the installed
// context and stages buildx under <home>/.k3sm; a readable work dir (root, the
// service user) or one named by K3SM_WORK_DIR keeps its admin kubeconfig and
// stages in the work dir, as before.
func TestBuildxSessionUnprivilegedOnRootInstall(t *testing.T) {
	contextName := installedKubeconfigName()

	tests := []struct {
		name string
		// explicitWorkDir sets K3SM_WORK_DIR to a temp work dir when true.
		explicitWorkDir bool
		// adminKubeconfig writes the work dir's admin kubeconfig when true.
		adminKubeconfig bool
		// userKubeconfig writes the account's ~/.kube/config when true.
		userKubeconfig bool
		// wantDial is "admin" or "user": the kubeconfig the session must build
		// its clients from ("" when the session must fail first).
		wantDial string
		// wantStateUnderHome stages buildx under <home>/.k3sm, else the work dir.
		wantStateUnderHome bool
		// wantErr are substrings the error must carry when wantDial is "".
		wantErr []string
	}{
		{
			name:               "ordinary account on a root install uses its own kubeconfig and home",
			userKubeconfig:     true,
			wantDial:           "user",
			wantStateUnderHome: true,
		},
		{
			name:    "ordinary account with no kubeconfig names sudo and kubeconfig --write",
			wantErr: []string{"run with sudo", "sudo k3sm kubeconfig --write"},
		},
		{
			name:            "readable work dir keeps its admin kubeconfig and stages there",
			adminKubeconfig: true,
			userKubeconfig:  true,
			wantDial:        "admin",
		},
		{
			name:            "K3SM_WORK_DIR keeps its admin kubeconfig and stages there",
			explicitWorkDir: true,
			adminKubeconfig: true,
			userKubeconfig:  true,
			wantDial:        "admin",
		},
		{
			name:            "K3SM_WORK_DIR without a kubeconfig is pinned with no fallback",
			explicitWorkDir: true,
			userKubeconfig:  true,
			wantErr:         []string{"run `k3sm server` first"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if !tt.explicitWorkDir && os.Geteuid() == 0 {
				t.Skip("as root the posture work dir is the system one; the ordinary-account cases need a non-root euid")
			}
			home := t.TempDir()
			t.Setenv("HOME", home)
			t.Setenv("KUBECONFIG", "")
			workDir := filepath.Join(home, "server")
			if tt.explicitWorkDir {
				workDir = filepath.Join(t.TempDir(), "server")
				t.Setenv("K3SM_WORK_DIR", workDir)
			} else {
				t.Setenv("K3SM_WORK_DIR", "")
			}
			chosen, calls := fakeBuildxClients(t)
			if tt.adminKubeconfig {
				writeKubeconfigAt(t, executor.KubeconfigPath(workDir), "https://127.0.0.1:6443")
			}
			if tt.userKubeconfig {
				writeContextKubeconfig(t, filepath.Join(home, ".kube", "config"), contextName, "https://127.0.0.1:16443")
			}

			opts := buildxSessionOptions()
			if opts.workDir != workDir {
				t.Fatalf("session work dir = %q, want %q", opts.workDir, workDir)
			}
			if opts.workDirExplicit != tt.explicitWorkDir {
				t.Fatalf("session workDirExplicit = %v, want %v", opts.workDirExplicit, tt.explicitWorkDir)
			}

			// bootstrap=false: the empty fake clientset has no engine, so a session
			// that reached it stops at ErrAbsent, before any buildx download.
			_, err := newBuildxSession(context.Background(), opts, false, io.Discard)
			if tt.wantDial == "" {
				if err == nil {
					t.Fatal("newBuildxSession succeeded, want an error")
				}
				for _, want := range tt.wantErr {
					if !strings.Contains(err.Error(), want) {
						t.Errorf("error %q does not contain %q", err.Error(), want)
					}
				}
				if *calls != 0 {
					t.Errorf("a failed kubeconfig choice still built clients (%d calls)", *calls)
				}
				return
			}
			if !errors.Is(err, builder.ErrAbsent) {
				t.Fatalf("newBuildxSession err = %v, want builder.ErrAbsent from the fake clientset", err)
			}
			if *calls != 1 {
				t.Fatalf("session built clients %d times, want 1", *calls)
			}
			switch tt.wantDial {
			case "admin":
				if want := executor.KubeconfigPath(workDir); chosen.kubeconfig != want || chosen.context != "" {
					t.Errorf("session chose %+v, want the admin kubeconfig %s", *chosen, want)
				}
			case "user":
				if chosen.kubeconfig != "" || chosen.context != contextName {
					t.Errorf("session chose %+v, want the user kubeconfig at context %q", *chosen, contextName)
				}
			}

			in := builderKubeInputs(opts)
			cfg, err := builderKubeconfig(in)
			if err != nil {
				t.Fatalf("builderKubeconfig: %v", err)
			}
			stateDir, err := buildxStateDir(opts, in, cfg)
			if err != nil {
				t.Fatalf("buildxStateDir: %v", err)
			}
			want := workDir
			if tt.wantStateUnderHome {
				want = filepath.Join(home, ".k3sm")
			}
			if stateDir != want {
				t.Errorf("buildx state dir = %q, want %q", stateDir, want)
			}
		})
	}
}

// TestBuildxStateDirNeedsAHome pins the legible refusal when the account's own
// kubeconfig is in use but there is no home to stage buildx under.
func TestBuildxStateDirNeedsAHome(t *testing.T) {
	_, err := buildxStateDir(builderOptions{workDir: "/var/lib/k3sm/server"}, kubectlInputs{}, kubectlConfig{context: "k3sm"})
	if err == nil || !strings.Contains(err.Error(), "sudo") {
		t.Fatalf("buildxStateDir with no home = %v, want an error naming sudo", err)
	}
}

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
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"k3sm.io/k3sm/pkg/builder"
	"k3sm.io/k3sm/pkg/executor"
)

// fakeAPIServer is an apiserver that knows no objects: every request is a 404,
// so the builder's Service lookup reports builder.ErrAbsent. hits counts the
// requests, which is how a case proves WHICH kubeconfig the session dialled.
func fakeAPIServer(t *testing.T) (string, *atomic.Int32) {
	t.Helper()
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		http.NotFound(w, r)
	}))
	t.Cleanup(srv.Close)
	return srv.URL, &hits
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
		// wantDial is "admin" or "user": the kubeconfig the session must reach
		// the cluster through ("" when the session must fail first).
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
			adminURL, adminHits := fakeAPIServer(t)
			userURL, userHits := fakeAPIServer(t)
			if tt.adminKubeconfig {
				writeKubeconfigAt(t, executor.KubeconfigPath(workDir), adminURL)
			}
			if tt.userKubeconfig {
				writeContextKubeconfig(t, filepath.Join(home, ".kube", "config"), contextName, userURL)
			}

			opts := buildxSessionOptions()
			if opts.workDir != workDir {
				t.Fatalf("session work dir = %q, want %q", opts.workDir, workDir)
			}
			if opts.workDirExplicit != tt.explicitWorkDir {
				t.Fatalf("session workDirExplicit = %v, want %v", opts.workDirExplicit, tt.explicitWorkDir)
			}

			// bootstrap=false: the empty fake cluster has no engine, so a session
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
				if adminHits.Load()+userHits.Load() != 0 {
					t.Errorf("a failed kubeconfig choice still dialled a cluster")
				}
				return
			}
			if !errors.Is(err, builder.ErrAbsent) {
				t.Fatalf("newBuildxSession err = %v, want builder.ErrAbsent from the fake cluster", err)
			}
			dialled := map[string]int32{"admin": adminHits.Load(), "user": userHits.Load()}
			for who, n := range dialled {
				if (who == tt.wantDial) != (n > 0) {
					t.Errorf("%s kubeconfig dialled %d times; want the session to dial only %s", who, n, tt.wantDial)
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

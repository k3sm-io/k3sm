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
	"errors"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"k3sm.io/k3sm/pkg/executor"
)

// setOf turns a path list into a membership test for the injected exists seam,
// so no case touches the real filesystem.
func setOf(paths ...string) func(string) bool {
	set := make(map[string]bool, len(paths))
	for _, p := range paths {
		set[p] = true
	}
	return func(p string) bool { return set[p] }
}

func TestResolveKubectlConfig(t *testing.T) {
	const (
		serviceWorkDir = "/var/lib/k3sm/server"
		userHome       = "/Users/alice"
		altWorkDir     = "/tmp/k3sm-alt/server"
	)
	var (
		serviceKubeconfig = executor.KubeconfigPath(serviceWorkDir)
		altKubeconfig     = executor.KubeconfigPath(altWorkDir)
		userKubeconfig    = filepath.Join(userHome, ".kube", "config")
		envKubeconfig     = "/Users/alice/work/kubeconfig.yaml"
	)

	tests := []struct {
		name    string
		in      kubectlInputs
		want    kubectlConfig
		wantErr string // substring; "" means success
	}{
		{
			name: "K3SM_WORK_DIR pins that work dir's kubeconfig",
			in: kubectlInputs{
				workDirOverride: altWorkDir,
				workDir:         altWorkDir,
				home:            userHome,
				contextName:     "k3sm",
				exists:          setOf(altKubeconfig, userKubeconfig),
			},
			want: kubectlConfig{kubeconfig: altKubeconfig},
		},
		{
			name: "K3SM_WORK_DIR with no kubeconfig errors instead of falling back",
			in: kubectlInputs{
				workDirOverride: altWorkDir,
				workDir:         altWorkDir,
				home:            userHome,
				contextName:     "k3sm",
				exists:          setOf(userKubeconfig),
			},
			wantErr: "run `k3sm server` first",
		},
		{
			name: "root or the service user gets the work-dir kubeconfig",
			in: kubectlInputs{
				workDir:     serviceWorkDir,
				home:        "/var/lib/k3sm",
				contextName: "k3sm",
				exists:      setOf(serviceKubeconfig),
			},
			want: kubectlConfig{kubeconfig: serviceKubeconfig},
		},
		{
			name: "unprivileged user falls back to the installed k3sm context",
			in: kubectlInputs{
				workDir:     filepath.Join(userHome, "server"),
				home:        userHome,
				contextName: "k3sm",
				exists:      setOf(userKubeconfig),
			},
			want: kubectlConfig{context: "k3sm"},
		},
		{
			name: "unprivileged user with KUBECONFIG set falls back too",
			in: kubectlInputs{
				workDir:       filepath.Join(userHome, "server"),
				kubeconfigEnv: envKubeconfig + ":" + userKubeconfig,
				home:          "",
				contextName:   "k3sm",
				exists:        setOf(envKubeconfig),
			},
			want: kubectlConfig{context: "k3sm"},
		},
		{
			name: "no kubeconfig anywhere names the install fix",
			in: kubectlInputs{
				workDir:     filepath.Join(userHome, "server"),
				home:        userHome,
				contextName: "k3sm",
				exists:      setOf(),
			},
			wantErr: "run `sudo k3sm install`",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := resolveKubectlConfig(tt.in)
			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("resolveKubectlConfig = %+v, want error containing %q", got, tt.wantErr)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("error = %q, want it to contain %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("resolveKubectlConfig: %v", err)
			}
			if got != tt.want {
				t.Errorf("resolveKubectlConfig = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestKubectlConfigArgv(t *testing.T) {
	args := []string{"get", "nodes"}
	if got := (kubectlConfig{kubeconfig: "/x"}).argv(args); !reflect.DeepEqual(got, args) {
		t.Errorf("argv with no context = %v, want %v", got, args)
	}
	got := (kubectlConfig{context: "k3sm"}).argv([]string{"get", "nodes", "--context=other"})
	want := []string{"--context=k3sm", "get", "nodes", "--context=other"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("argv = %v, want %v", got, want)
	}
	// The pinned context must come FIRST: kubectl honors the LAST occurrence, so
	// this ordering is what lets a user's own --context still win.
	if got[0] != "--context=k3sm" || got[len(got)-1] != "--context=other" {
		t.Errorf("argv ordering = %v, want the pinned context first and the caller's last", got)
	}
}

func TestResolveKubectlIn(t *testing.T) {
	const (
		workDir    = "/Users/alice/server"
		installDir = "/Library/k3sm"
		onPath     = "/opt/homebrew/bin/kubectl"
	)
	var (
		bundled = executor.KubectlPath(workDir)
		payload = installedKubectl(installDir)
	)
	found := func(string) (string, error) { return onPath, nil }
	missing := func(string) (string, error) { return "", errors.New("not found") }

	tests := []struct {
		name     string
		exists   func(string) bool
		lookPath func(string) (string, error)
		want     string
		wantErr  bool
	}{
		{name: "work-dir bundled kubectl wins", exists: setOf(bundled, payload), lookPath: found, want: bundled},
		{name: "installed payload kubectl when the work dir has none", exists: setOf(payload), lookPath: found, want: payload},
		{name: "PATH kubectl last", exists: setOf(), lookPath: found, want: onPath},
		{name: "nothing anywhere errors", exists: setOf(), lookPath: missing, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := resolveKubectlIn(workDir, installDir, tt.exists, tt.lookPath)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("resolveKubectlIn = %q, want an error", got)
				}
				for _, want := range []string{bundled, payload} {
					if !strings.Contains(err.Error(), want) {
						t.Errorf("error = %q, want it to name %q", err, want)
					}
				}
				return
			}
			if err != nil {
				t.Fatalf("resolveKubectlIn: %v", err)
			}
			if got != tt.want {
				t.Errorf("resolveKubectlIn = %q, want %q", got, tt.want)
			}
		})
	}
}

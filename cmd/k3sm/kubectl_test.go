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
	"os"
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

// TestKubectlExecsInPlace drives `k3sm kubectl` end to end through the exec
// seam: the wrapper must hand its process image to the resolved kubectl, with
// argv[0] the binary, the caller's arguments after it and the resolved
// KUBECONFIG in the environment, rather than fork a child and wait on it. The
// staged kubectl is a script that leaves a marker when run, so a child spawned
// past the seam is caught.
func TestKubectlExecsInPlace(t *testing.T) {
	workDir := t.TempDir()
	kubeconfig := executor.KubeconfigPath(workDir)
	bin := executor.KubectlPath(workDir)
	marker := filepath.Join(t.TempDir(), "child-ran")
	for path, body := range map[string]string{
		kubeconfig: "apiVersion: v1\nkind: Config\n",
		bin:        "#!/bin/sh\ntouch '" + marker + "'\n",
	} {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("K3SM_WORK_DIR", workDir)
	t.Setenv("KUBECONFIG", "/elsewhere")

	var (
		calls   int
		gotBin  string
		gotArgv []string
		gotEnv  []string
	)
	prev := kubectlExec
	kubectlExec = func(bin string, argv, env []string) error {
		calls++
		gotBin, gotArgv, gotEnv = bin, argv, env
		return nil
	}
	t.Cleanup(func() { kubectlExec = prev })

	if err := runKubectl([]string{"get", "pods", "-A"}); err != nil {
		t.Fatalf("runKubectl: %v", err)
	}
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("kubectl ran as a child process; want the wrapper to exec it in place")
	}
	if calls != 1 {
		t.Fatalf("exec called %d times, want 1", calls)
	}
	if gotBin != bin {
		t.Errorf("exec binary = %q, want %q", gotBin, bin)
	}
	if want := []string{bin, "get", "pods", "-A"}; !reflect.DeepEqual(gotArgv, want) {
		t.Errorf("exec argv = %q, want %q", gotArgv, want)
	}
	var kubeconfigs []string
	for _, kv := range gotEnv {
		if strings.HasPrefix(kv, "KUBECONFIG=") {
			kubeconfigs = append(kubeconfigs, kv)
		}
	}
	if want := []string{"KUBECONFIG=" + kubeconfig}; !reflect.DeepEqual(kubeconfigs, want) {
		t.Errorf("exec env KUBECONFIG entries = %q, want exactly %q", kubeconfigs, want)
	}
}

// TestKubectlExecFailure returns the exec error wrapped, so a kubectl that
// cannot be started is reported rather than swallowed.
func TestKubectlExecFailure(t *testing.T) {
	workDir := t.TempDir()
	for _, path := range []string{executor.KubeconfigPath(workDir), executor.KubectlPath(workDir)} {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, nil, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("K3SM_WORK_DIR", workDir)
	prev := kubectlExec
	kubectlExec = func(string, []string, []string) error { return os.ErrPermission }
	t.Cleanup(func() { kubectlExec = prev })

	err := runKubectl(nil)
	if !errors.Is(err, os.ErrPermission) || !strings.Contains(err.Error(), "exec kubectl") {
		t.Fatalf("runKubectl error = %v, want a wrapped exec failure", err)
	}
}

func TestEnvWithKubeconfig(t *testing.T) {
	tests := []struct {
		name string
		env  []string
		path string
		want []string
	}{
		{
			name: "no ambient entry gains the resolved one",
			env:  []string{"HOME=/Users/alice", "PATH=/usr/bin"},
			path: "/var/lib/k3sm/server/kubeconfig",
			want: []string{"HOME=/Users/alice", "PATH=/usr/bin", "KUBECONFIG=/var/lib/k3sm/server/kubeconfig"},
		},
		{
			name: "one ambient entry is replaced",
			env:  []string{"KUBECONFIG=/elsewhere", "HOME=/Users/alice"},
			path: "/var/lib/k3sm/server/kubeconfig",
			want: []string{"HOME=/Users/alice", "KUBECONFIG=/var/lib/k3sm/server/kubeconfig"},
		},
		{
			name: "two ambient entries are both dropped",
			env:  []string{"KUBECONFIG=/a", "HOME=/Users/alice", "KUBECONFIG=/b"},
			path: "/var/lib/k3sm/server/kubeconfig",
			want: []string{"HOME=/Users/alice", "KUBECONFIG=/var/lib/k3sm/server/kubeconfig"},
		},
		{
			name: "empty resolved path keeps the ambient entry",
			env:  []string{"KUBECONFIG=/elsewhere", "HOME=/Users/alice"},
			path: "",
			want: []string{"KUBECONFIG=/elsewhere", "HOME=/Users/alice"},
		},
		{
			name: "a lookalike key is kept",
			env:  []string{"KUBECONFIG_EXTRA=/x"},
			path: "/k",
			want: []string{"KUBECONFIG_EXTRA=/x", "KUBECONFIG=/k"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := envWithKubeconfig(tt.env, tt.path); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("envWithKubeconfig = %q, want %q", got, tt.want)
			}
		})
	}
}

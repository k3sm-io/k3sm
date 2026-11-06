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
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"k3sm.io/k3sm/pkg/executor"
)

// TestKubectlAsRootRefusesConfigWrites covers every kubectl config verb that edits
// a kubeconfig, wherever the flags sit, before kubectl or any named file is touched.
func TestKubectlAsRootRefusesConfigWrites(t *testing.T) {
	setupRootKubectl(t)
	absent := filepath.Join(t.TempDir(), "absent.yaml")
	named := writeNamedKubeconfig(t, kubeconfigWithUser("{token: t}"))
	tests := []struct {
		name string
		args []string
		verb string
	}{
		{"set", []string{"config", "set", "users.u.token", "x"}, "set"},
		{"set-cluster", []string{"config", "set-cluster", "c"}, "set-cluster"},
		{"set-context", []string{"config", "set-context", "c", "--cluster=c"}, "set-context"},
		{"set-credentials", []string{"config", "set-credentials", "u"}, "set-credentials"},
		{"unset", []string{"config", "unset", "users.u"}, "unset"},
		{"use-context", []string{"config", "use-context", "c"}, "use-context"},
		{"use", []string{"config", "use", "c"}, "use"},
		{"delete-cluster", []string{"config", "delete-cluster", "c"}, "delete-cluster"},
		{"delete-context", []string{"config", "delete-context", "c"}, "delete-context"},
		{"delete-user", []string{"config", "delete-user", "u"}, "delete-user"},
		{"rename-context", []string{"config", "rename-context", "a", "b"}, "rename-context"},
		{"a flag and value first", []string{"--context", "c", "config", "use-context", "c"}, "use-context"},
		{"a flag with = first", []string{"--context=c", "config", "use-context", "c"}, "use-context"},
		{"a boolean flag first", []string{"--warnings-as-errors", "config", "use-context", "c"}, "use-context"},
		{"a flag between", []string{"config", "--context", "c", "use-context", "c"}, "use-context"},
		{"a checked file named", []string{"--kubeconfig", named, "config", "set-context", "c"}, "set-context"},
		{"a file named after the verb", []string{"config", "use-context", "c", "--kubeconfig=" + named}, "use-context"},
		{"a file that is not there", []string{"--kubeconfig", absent, "config", "use-context", "c"}, "use-context"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			run, err := recordKubectl(t, tc.args...)
			if run.calls != 0 {
				t.Errorf("kubectl was exec'd with %q", run.argv)
			}
			if err == nil {
				t.Fatal("runKubectl = nil, want a refusal")
			}
			for _, want := range []string{"kubectl config " + tc.verb, "changes nothing", "`k3sm kubectl config " + tc.verb, "without sudo"} {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("error = %q, want it to say %q", err, want)
				}
			}
			if strings.Contains(err.Error(), "/dev/fd") {
				t.Errorf("error = %q names the handoff", err)
			}
		})
	}
}

// TestKubectlAsRootKeepsConfigReads pins everything that only reads, and each
// reaches kubectl with the handoff in KUBECONFIG and no path of its own.
func TestKubectlAsRootKeepsConfigReads(t *testing.T) {
	setupRootKubectl(t)
	tests := map[string][]string{
		"view":                     {"config", "view"},
		"view --minify":            {"config", "view", "--minify"},
		"view -o json":             {"config", "view", "-o", "json"},
		"current-context":          {"config", "current-context"},
		"get-contexts":             {"config", "get-contexts"},
		"get-clusters":             {"config", "get-clusters"},
		"get-users":                {"config", "get-users"},
		"bare":                     {"config"},
		"help of a write":          {"config", "use-context", "--help"},
		"short help of a write":    {"config", "set-context", "-h"},
		"help verb":                {"help", "config", "use-context"},
		"a configmap called so":    {"get", "configmap", "config", "use-context"},
		"a resource called config": {"get", "config", "use-context"},
		"in a pod":                 {"exec", "web", "--", "kubectl", "config", "use-context", "c"},
	}
	for name, args := range tests {
		t.Run(name, func(t *testing.T) {
			run, err := recordKubectl(t, args...)
			if err != nil {
				t.Fatalf("runKubectl: %v", err)
			}
			if !reflect.DeepEqual(run.argv[1:], args) {
				t.Errorf("argv = %q, want %q", run.argv[1:], args)
			}
			if run.loaded == nil || len(run.loaded.Clusters) != 1 {
				t.Errorf("handoff holds %+v", run.loaded)
			}
		})
	}
}

// TestKubectlAsRootNamedConfigReadUsesTheHandoff pins that naming a file does not
// give kubectl a path to write back to: the only kubeconfig it knows is the handoff.
func TestKubectlAsRootNamedConfigReadUsesTheHandoff(t *testing.T) {
	setupRootKubectl(t)
	named := writeNamedKubeconfig(t, kubeconfigWithUser("{token: named-token}"))
	run, err := recordKubectl(t, "--kubeconfig", named, "config", "view")
	if err != nil {
		t.Fatalf("runKubectl: %v", err)
	}
	if want := []string{"config", "view"}; !reflect.DeepEqual(run.argv[1:], want) {
		t.Errorf("argv = %q, want %q", run.argv[1:], want)
	}
	if got := run.kubeconfigEnv(); !strings.HasPrefix(got, "/dev/fd/") {
		t.Errorf("KUBECONFIG = %q, want the handoff", got)
	}
	if run.loaded == nil || run.loaded.AuthInfos["k3sm"] == nil || run.loaded.AuthInfos["k3sm"].Token != "named-token" {
		t.Errorf("handoff holds %+v", run.loaded)
	}
}

// TestKubectlWithoutRootRunsConfigWrites pins that this refusal is root's: another
// account's kubectl edits that account's own file.
func TestKubectlWithoutRootRunsConfigWrites(t *testing.T) {
	workDir := t.TempDir()
	for path, mode := range map[string]os.FileMode{executor.KubeconfigPath(workDir): 0o600, executor.KubectlPath(workDir): 0o755} {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("apiVersion: v1\nkind: Config\n"), mode); err != nil {
			t.Fatal(err)
		}
	}
	prev := processEuid
	processEuid = func() int { return 501 }
	t.Cleanup(func() { processEuid = prev })
	t.Setenv("K3SM_WORK_DIR", workDir)
	args := []string{"config", "use-context", "c"}
	run, err := recordKubectl(t, args...)
	if err != nil {
		t.Fatalf("runKubectl: %v", err)
	}
	if !reflect.DeepEqual(run.argv[1:], args) {
		t.Errorf("argv = %q, want %q", run.argv[1:], args)
	}
}

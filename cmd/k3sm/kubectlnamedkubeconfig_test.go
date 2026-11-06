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
	"encoding/base64"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"

	"k3sm.io/k3sm/pkg/executor"
)

// rootKubectlRun is what `k3sm kubectl` handed the exec, read at the exec.
type rootKubectlRun struct {
	calls  int
	argv   []string
	env    []string
	loaded *clientcmdapi.Config
}

// kubeconfigEnv is the KUBECONFIG the exec was given.
func (r rootKubectlRun) kubeconfigEnv() string {
	for _, kv := range r.env {
		if path, ok := strings.CutPrefix(kv, "KUBECONFIG="); ok {
			return path
		}
	}
	return ""
}

// recordKubectl runs the verb with the exec replaced by a recording of it.
func recordKubectl(t *testing.T, args ...string) (rootKubectlRun, error) {
	t.Helper()
	var run rootKubectlRun
	prev := kubectlExec
	kubectlExec = func(_ string, argv, env []string) error {
		run.calls++
		run.argv, run.env = argv, env
		if path := run.kubeconfigEnv(); strings.HasPrefix(path, "/dev/fd/") {
			cfg, err := clientcmd.LoadFromFile(path)
			if err != nil {
				return err
			}
			run.loaded = cfg
		}
		return nil
	}
	t.Cleanup(func() { kubectlExec = prev })
	err := runKubectl(args)
	return run, err
}

// setupRootKubectl runs the verb as root over a work dir holding an inline
// kubeconfig, with this test's account as the person who ran sudo, so a file the
// test writes has an accepted owner.
func setupRootKubectl(t *testing.T) {
	t.Helper()
	asRoot(t)
	useInstalledKubectl(t)
	workDir := t.TempDir()
	writeInlineKubeconfig(t, executor.KubeconfigPath(workDir))
	t.Setenv("K3SM_WORK_DIR", workDir)
	t.Setenv("KUBECONFIG", "")
	me, err := user.Current()
	if err != nil {
		t.Fatalf("current user: %v", err)
	}
	t.Setenv("SUDO_USER", me.Username)
}

// namedFlagForms are the ways kubectl takes a file by flag.
func namedFlagForms(path string) map[string][]string {
	return map[string][]string{
		"--kubeconfig X before the verb": {"--kubeconfig", path, "get", "pods"},
		"--kubeconfig=X before the verb": {"--kubeconfig=" + path, "get", "pods"},
		"--kubeconfig X after the verb":  {"get", "pods", "--kubeconfig", path},
		"--kubeconfig=X after the verb":  {"get", "pods", "--kubeconfig=" + path},
	}
}

func TestKubectlAsRootHandsOverANamedKubeconfig(t *testing.T) {
	setupRootKubectl(t)
	path := writeNamedKubeconfig(t, kubeconfigWithUser("{token: named-token}"))
	for name, args := range namedFlagForms(path) {
		t.Run(name, func(t *testing.T) {
			run, err := recordKubectl(t, args...)
			if err != nil {
				t.Fatalf("runKubectl: %v", err)
			}
			if want := []string{run.argv[0], "get", "pods"}; !reflect.DeepEqual(run.argv, want) {
				t.Errorf("argv = %q, want %q", run.argv, want)
			}
			if got := run.kubeconfigEnv(); !strings.HasPrefix(got, "/dev/fd/") {
				t.Errorf("KUBECONFIG = %q, want the handoff", got)
			}
			if run.loaded == nil || run.loaded.AuthInfos["k3sm"] == nil || run.loaded.AuthInfos["k3sm"].Token != "named-token" {
				t.Errorf("handoff holds %+v, want the named file's entries", run.loaded)
			}
		})
	}
}

func TestKubectlAsRootNamedKubeconfigWinsWithNoOtherFile(t *testing.T) {
	setupRootKubectl(t)
	t.Setenv("K3SM_WORK_DIR", t.TempDir())
	path := writeNamedKubeconfig(t, kubeconfigWithUser("{token: named-token}"))
	run, err := recordKubectl(t, "--kubeconfig", path, "get", "pods")
	if err != nil {
		t.Fatalf("runKubectl: %v", err)
	}
	if run.loaded == nil || run.loaded.AuthInfos["k3sm"] == nil {
		t.Errorf("handoff holds %+v, want the named file's entries", run.loaded)
	}
}

// TestKubectlAsRootKeepsANamedFilesOwnTrust pins that a named file keeps its own CA
// and server name: it may name another cluster, so the root-held CA is not applied.
func TestKubectlAsRootKeepsANamedFilesOwnTrust(t *testing.T) {
	setupRootKubectl(t)
	ca := fixtureCA(t)
	path := writeNamedKubeconfig(t, kubeconfigWithCluster(fmt.Sprintf(
		`{server: "https://192.0.2.9:6443", certificate-authority-data: %q, tls-server-name: elsewhere.example}`,
		base64.StdEncoding.EncodeToString(ca))))
	run, err := recordKubectl(t, "--kubeconfig="+path, "get", "pods")
	if err != nil {
		t.Fatalf("runKubectl: %v", err)
	}
	if run.loaded == nil || run.loaded.Clusters["k3sm"] == nil {
		t.Fatalf("handoff holds %+v", run.loaded)
	}
	cluster := run.loaded.Clusters["k3sm"]
	if cluster.TLSServerName != "elsewhere.example" || string(cluster.CertificateAuthorityData) != string(ca) {
		t.Errorf("cluster trust = name %q, CA %d bytes; want the file's own", cluster.TLSServerName, len(cluster.CertificateAuthorityData))
	}
}

func TestKubectlAsRootRefusesANamedKubeconfigNotInline(t *testing.T) {
	setupRootKubectl(t)
	tests := []struct {
		name, body, want string
	}{
		{"exec", kubeconfigWithUser(execUser), "credential plugin"},
		{"auth provider", kubeconfigWithUser(`{auth-provider: {name: oidc}}`), "credential plugin"},
		{"token file", kubeconfigWithUser(`{tokenFile: /elsewhere/token}`), "from a file"},
		{"client certificate path", kubeconfigWithUser(`{client-certificate: /elsewhere/crt}`), "from a file"},
		{"client key path", kubeconfigWithUser(`{client-key: /elsewhere/key}`), "from a file"},
		{"CA path", kubeconfigWithCluster(`{server: "https://192.0.2.9:6443", certificate-authority: /elsewhere/ca}`), "CA from a file"},
		{"proxy-url", kubeconfigWithCluster(`{server: "https://192.0.2.9:6443", proxy-url: "http://192.0.2.10:3128"}`), "proxy-url"},
	}
	for _, tc := range tests {
		for form, args := range namedFlagForms(writeNamedKubeconfig(t, tc.body)) {
			t.Run(tc.name+"/"+form, func(t *testing.T) {
				run, err := recordKubectl(t, args...)
				if run.calls != 0 {
					t.Errorf("kubectl was exec'd with %q", run.argv)
				}
				if err == nil {
					t.Fatal("runKubectl = nil, want a refusal")
				}
				for _, want := range []string{tc.want, "refused", "`kubectl`", "without sudo", "inline"} {
					if !strings.Contains(err.Error(), want) {
						t.Errorf("error = %q, want it to say %q", err, want)
					}
				}
			})
		}
	}
}

func TestKubectlAsRootDoesNotRunANamedFilesPlugin(t *testing.T) {
	setupRootKubectl(t)
	path := writeNamedKubeconfig(t, kubeconfigWithUser("{token: t}"))
	ran := saveExecEntry(t, path)
	run, err := recordKubectl(t, "--kubeconfig", path, "get", "pods")
	if err == nil || run.calls != 0 {
		t.Errorf("runKubectl = %v after %d execs, want a refusal and none", err, run.calls)
	}
	assertNeverRan(t, ran)
}

func TestKubectlAsRootRefusesKubeconfigArgsItCannotCheck(t *testing.T) {
	setupRootKubectl(t)
	a := writeNamedKubeconfig(t, kubeconfigWithUser("{token: a}"))
	b := writeNamedKubeconfig(t, kubeconfigWithUser("{token: b}"))
	tests := []struct {
		name string
		args []string
		want string
	}{
		{"repeated, separate", []string{"--kubeconfig", a, "--kubeconfig", b, "get", "pods"}, "more than once"},
		{"repeated, either side of the verb", []string{"--kubeconfig=" + a, "get", "pods", "--kubeconfig=" + b}, "more than once"},
		{"repeated, the same file", []string{"--kubeconfig", a, "--kubeconfig", a, "get", "pods"}, "more than once"},
		{"a path list", []string{"--kubeconfig", a + string(os.PathListSeparator) + b, "get", "pods"}, "list"},
		{"a path list with =", []string{"--kubeconfig=" + a + string(os.PathListSeparator) + b, "get", "pods"}, "list"},
		{"standard input", []string{"--kubeconfig", "-", "get", "pods"}, "standard input"},
		{"standard input with =", []string{"--kubeconfig=-", "get", "pods"}, "standard input"},
		{"no value", []string{"get", "pods", "--kubeconfig"}, "no file"},
		{"an empty value", []string{"--kubeconfig=", "get", "pods"}, "no file"},
		{"after a -- a flag may take as its value", []string{"-n", "--", "--kubeconfig=" + a, "get", "pods"}, "--"},
		{"preferences, separate", []string{"--kuberc", a, "get", "pods"}, "--kuberc"},
		{"preferences, with =", []string{"get", "pods", "--kuberc=" + a}, "--kuberc"},
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
			for _, want := range []string{tc.want, "`kubectl`", "without sudo", "inline"} {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("error = %q, want it to say %q", err, want)
				}
			}
		})
	}
}

func TestKubectlAsRootNamedKubeconfigFileChecks(t *testing.T) {
	setupRootKubectl(t)
	t.Run("a file others can write", func(t *testing.T) {
		path := writeNamedKubeconfig(t, kubeconfigWithUser("{token: t}"))
		if err := os.Chmod(path, 0o666); err != nil {
			t.Fatal(err)
		}
		run, err := recordKubectl(t, "--kubeconfig", path, "get", "pods")
		if run.calls != 0 || err == nil || !strings.Contains(err.Error(), "group- or world-writable") {
			t.Errorf("exec calls %d, error %v; want a mode refusal", run.calls, err)
		}
	})
	t.Run("another account's file", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("the fixture's owner is the test account, which must not be root")
		}
		t.Setenv("SUDO_USER", "")
		path := writeNamedKubeconfig(t, kubeconfigWithUser("{token: t}"))
		run, err := recordKubectl(t, "--kubeconfig", path, "get", "pods")
		if run.calls != 0 || err == nil || !strings.Contains(err.Error(), "not root") {
			t.Errorf("exec calls %d, error %v; want an owner refusal", run.calls, err)
		}
	})
	t.Run("a missing file does not fall through to another", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "absent.yaml")
		run, err := recordKubectl(t, "--kubeconfig", path, "get", "pods")
		if run.calls != 0 || err == nil || !strings.Contains(err.Error(), path) {
			t.Errorf("exec calls %d, error %v; want a refusal naming the file", run.calls, err)
		}
	})
	t.Run("a directory", func(t *testing.T) {
		path := t.TempDir()
		run, err := recordKubectl(t, "--kubeconfig", path, "get", "pods")
		if run.calls != 0 || err == nil || !strings.Contains(err.Error(), "not a regular file") {
			t.Errorf("exec calls %d, error %v; want a refusal", run.calls, err)
		}
	})
}

// TestKubectlAsRootNamedKubeconfigContext pins which entries of a named file are
// checked and kept: the context on kubectl's command line, or the current one.
func TestKubectlAsRootNamedKubeconfigContext(t *testing.T) {
	setupRootKubectl(t)
	path := writeNamedKubeconfig(t, inlineKubeconfigText)
	tests := []struct {
		name    string
		args    []string
		wantErr string
	}{
		{name: "--context X", args: []string{"--kubeconfig", path, "--context", "k3sm", "get", "pods"}},
		{name: "--context=X after the verb", args: []string{"get", "pods", "--context=k3sm", "--kubeconfig=" + path}},
		{name: "the last --context wins", args: []string{"--context=other", "--context=k3sm", "--kubeconfig=" + path, "get", "pods"}},
		{name: "the current context", args: []string{"--kubeconfig", path, "get", "pods"}, wantErr: "credential plugin"},
		{name: "a context that holds a plugin", args: []string{"--kubeconfig", path, "--context", "other", "get", "pods"}, wantErr: "credential plugin"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			run, err := recordKubectl(t, tc.args...)
			if tc.wantErr != "" {
				if run.calls != 0 || err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Errorf("exec calls %d, error %v; want %q", run.calls, err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("runKubectl: %v", err)
			}
			if run.loaded == nil || len(run.loaded.AuthInfos) != 1 || run.loaded.AuthInfos["k3sm"] == nil || run.loaded.CurrentContext != "k3sm" {
				t.Errorf("handoff holds %+v, want only the k3sm context", run.loaded)
			}
			if !slices.ContainsFunc(run.argv, func(a string) bool { return strings.Contains(a, "--context") }) {
				t.Errorf("argv = %q lost the person's --context", run.argv)
			}
		})
	}
}

// TestKubectlAsRootLeavesWhatFollowsTheFlagsAlone pins the arguments of a command
// run in a pod: they are not kubectl's, so the work dir's kubeconfig is still used.
func TestKubectlAsRootLeavesWhatFollowsTheFlagsAlone(t *testing.T) {
	setupRootKubectl(t)
	args := []string{"exec", "-it", "web", "--", "kubectl", "--kubeconfig=/in/the/pod", "--kuberc", "/in/the/pod", "get", "pods"}
	run, err := recordKubectl(t, args...)
	if err != nil {
		t.Fatalf("runKubectl: %v", err)
	}
	if !reflect.DeepEqual(run.argv[1:], args) {
		t.Errorf("argv = %q, want %q", run.argv[1:], args)
	}
	if run.loaded == nil || run.loaded.AuthInfos["u"] == nil {
		t.Errorf("handoff holds %+v, want the work dir's kubeconfig", run.loaded)
	}
}

// TestKubectlWithoutRootPassesAKubeconfigFlagThrough pins the other accounts:
// kubectl's own rules and flags, with nothing checked or moved.
func TestKubectlWithoutRootPassesAKubeconfigFlagThrough(t *testing.T) {
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
	args := []string{"--kubeconfig", "/elsewhere/a", "--kubeconfig=/elsewhere/b:/elsewhere/c", "--kuberc=/elsewhere/rc", "get", "pods"}
	run, err := recordKubectl(t, args...)
	if err != nil {
		t.Fatalf("runKubectl: %v", err)
	}
	if !reflect.DeepEqual(run.argv[1:], args) {
		t.Errorf("argv = %q, want %q", run.argv[1:], args)
	}
}

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
	"os/user"
	"path/filepath"
	"strings"
	"testing"

	"k3sm.io/k3sm/pkg/executor"
	"k3sm.io/k3sm/pkg/install"
)

// sudoTestKubeconfig is a one-context kubeconfig whose cluster and user carry the
// given extra lines (each indented under its stanza).
func sudoTestKubeconfig(cluster, auth string) string {
	return "apiVersion: v1\nkind: Config\n" +
		"clusters:\n- name: k3sm\n  cluster:\n    server: https://127.0.0.1:6443\n" + cluster +
		"users:\n- name: k3sm\n  user:\n" + auth +
		"contexts:\n- name: k3sm\n  context:\n    cluster: k3sm\n    user: k3sm\ncurrent-context: k3sm\n"
}

const sudoTestInlineUser = "    token: an-inline-token\n"

func writeSudoTestFile(t *testing.T, path, data string, mode os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

func envValue(env []string, key string) (string, bool) {
	for _, kv := range env {
		if v, ok := strings.CutPrefix(kv, key+"="); ok {
			return v, true
		}
	}
	return "", false
}

// TestSudoKubectlRefusesAnExecKubeconfigFromHome: root run by sudo does not act on
// a kubeconfig the invoker wrote. `k3sm kubectl` and the builder verbs refuse one
// that would have root run a program, read a file or use a proxy for its author,
// in any file kubectl would read, and one root cannot trust as a file; they hand
// kubectl a root-only copy of what they checked. Root's own admin kubeconfig, an
// inline-credential kubeconfig, and every non-root run go ahead.
func TestSudoKubectlRefusesAnExecKubeconfigFromHome(t *testing.T) {
	me, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	type setup struct {
		home string
		// kubeconfigEnv, when non-empty, is $KUBECONFIG.
		kubeconfigEnv string
	}
	userConfig := func(home string) string { return filepath.Join(home, ".kube", "config") }
	homeFile := func(cluster, auth string) func(t *testing.T, home string) setup {
		return func(t *testing.T, home string) setup {
			writeSudoTestFile(t, userConfig(home), sudoTestKubeconfig(cluster, auth), 0o600)
			return setup{home: home}
		}
	}

	for _, tc := range []struct {
		name  string
		euid  int
		write func(t *testing.T, home string) setup
		// refusal is what the error must name besides the refused file; "" means
		// the run goes ahead.
		refusal string
		// refusedFile is the file the refusal must name (default ~/.kube/config).
		refusedFile func(home string) string
		// wantKubeconfig is what kubectl must be handed: "copy" for a root-only
		// copy of the checked bytes, else the exact value of KUBECONFIG.
		wantKubeconfig func(home string) string
	}{
		{name: "exec", euid: 0, refusal: `user "k3sm" exec`,
			write: homeFile("", "    exec:\n      apiVersion: client.authentication.k8s.io/v1\n      interactiveMode: Never\n      command: /tmp/a-program\n")},
		{name: "auth-provider", euid: 0, refusal: `user "k3sm" auth-provider`,
			write: homeFile("", "    auth-provider:\n      name: oidc\n")},
		{name: "tokenFile", euid: 0, refusal: `user "k3sm" tokenFile`,
			write: homeFile("", "    tokenFile: /var/root/token\n")},
		{name: "client-certificate path", euid: 0, refusal: `user "k3sm" client-certificate`,
			write: homeFile("", "    client-certificate: /var/root/client.crt\n")},
		{name: "client-key path", euid: 0, refusal: `user "k3sm" client-key`,
			write: homeFile("", "    token: x\n    client-key: /var/root/client.key\n")},
		{name: "certificate-authority path", euid: 0, refusal: `cluster "k3sm" certificate-authority`,
			write: homeFile("    certificate-authority: /var/root/ca.crt\n", sudoTestInlineUser)},
		{name: "proxy-url", euid: 0, refusal: `cluster "k3sm" proxy-url`,
			write: homeFile("    proxy-url: http://127.0.0.1:3128\n", sudoTestInlineUser)},
		{name: "KUBECONFIG list with exec in its second file", euid: 0, refusal: `user "k3sm" exec`,
			write: func(t *testing.T, home string) setup {
				first, second := filepath.Join(home, "a.yaml"), filepath.Join(home, "b.yaml")
				writeSudoTestFile(t, first, sudoTestKubeconfig("", sudoTestInlineUser), 0o600)
				writeSudoTestFile(t, second, sudoTestKubeconfig("", "    exec:\n      apiVersion: client.authentication.k8s.io/v1\n      command: /tmp/a-program\n"), 0o600)
				return setup{home: home, kubeconfigEnv: first + string(filepath.ListSeparator) + second}
			},
			refusedFile: func(home string) string { return filepath.Join(home, "b.yaml") }},
		{name: "symlinked file", euid: 0, refusal: "is a symlink",
			write: func(t *testing.T, home string) setup {
				target := filepath.Join(home, "real.yaml")
				writeSudoTestFile(t, target, sudoTestKubeconfig("", sudoTestInlineUser), 0o600)
				if err := os.MkdirAll(filepath.Join(home, ".kube"), 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(target, userConfig(home)); err != nil {
					t.Fatal(err)
				}
				return setup{home: home}
			}},
		{name: "group-writable file", euid: 0, refusal: "group- or world-writable",
			write: func(t *testing.T, home string) setup {
				writeSudoTestFile(t, userConfig(home), sudoTestKubeconfig("", sudoTestInlineUser), 0o660)
				return setup{home: home}
			}},
		{name: "admin kubeconfig under the work dir is accepted", euid: 0,
			write: func(t *testing.T, home string) setup {
				writeSudoTestFile(t, executor.KubeconfigPath(filepath.Join(home, "server")),
					sudoTestKubeconfig("    certificate-authority: /var/lib/k3sm/server/ca.crt\n", "    client-certificate: /var/lib/k3sm/server/admin.crt\n"), 0o600)
				return setup{home: home}
			},
			wantKubeconfig: func(home string) string { return executor.KubeconfigPath(filepath.Join(home, "server")) }},
		{name: "non-root run is unchanged", euid: 501,
			write:          homeFile("", "    exec:\n      apiVersion: client.authentication.k8s.io/v1\n      command: /tmp/a-program\n"),
			wantKubeconfig: func(string) string { return "" }},
		{name: "inline-credential user kubeconfig under sudo is accepted", euid: 0,
			write:          homeFile("    insecure-skip-tls-verify: true\n", sudoTestInlineUser),
			wantKubeconfig: func(string) string { return "copy" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			prevCredential, prevEUID, prevExec, prevCopyDir := installedNodeCredential, kubectlGeteuid, kubectlExec, sudoKubeconfigCopyDir
			t.Cleanup(func() {
				installedNodeCredential, kubectlGeteuid, kubectlExec, sudoKubeconfigCopyDir = prevCredential, prevEUID, prevExec, prevCopyDir
			})
			installedNodeCredential = func() (install.Role, string) { return install.RoleServer, "" }
			kubectlGeteuid = func() int { return tc.euid }
			var execs [][]string
			kubectlExec = func(_ string, _, env []string) error {
				execs = append(execs, env)
				return nil
			}
			copyDir := t.TempDir()
			sudoKubeconfigCopyDir = copyDir

			bin := t.TempDir()
			if err := os.WriteFile(filepath.Join(bin, "kubectl"), nil, 0o755); err != nil {
				t.Fatal(err)
			}
			home := t.TempDir()
			s := tc.write(t, home)
			t.Setenv("PATH", bin)
			t.Setenv("HOME", s.home)
			t.Setenv("KUBECONFIG", s.kubeconfigEnv)
			t.Setenv("K3SM_WORK_DIR", "")
			t.Setenv("SUDO_USER", me.Username)

			kerr := runKubectl([]string{"get", "nodes"})
			// The builder loads the kubeconfig itself; where its fixture names
			// files that do not exist, only its choice is checked.
			builderIn := builderKubeInputs(builderOptions{workDir: workDirFromEnv()})
			_, _, berr := builderClients(builderIn)
			if tc.refusal == "" && tc.wantKubeconfig(home) != "copy" {
				_, berr = builderKubeconfig(builderIn)
			}

			if tc.refusal != "" {
				file := userConfig(home)
				if tc.refusedFile != nil {
					file = tc.refusedFile(home)
				}
				for verb, err := range map[string]error{"k3sm kubectl": kerr, "builder": berr} {
					if err == nil {
						t.Errorf("%s went ahead as root with %s, want a refusal naming %q", verb, file, tc.refusal)
						continue
					}
					for _, want := range []string{tc.refusal, file} {
						if !strings.Contains(err.Error(), want) {
							t.Errorf("%s err = %v, want it to contain %q", verb, err, want)
						}
					}
				}
				if len(execs) != 0 {
					t.Errorf("kubectl ran %d time(s), want none", len(execs))
				}
				return
			}

			if kerr != nil {
				t.Fatalf("k3sm kubectl: %v", kerr)
			}
			if berr != nil {
				t.Errorf("builder: %v", berr)
			}
			if len(execs) != 1 {
				t.Fatalf("kubectl ran %d time(s), want 1", len(execs))
			}
			got, _ := envValue(execs[0], "KUBECONFIG")
			want := tc.wantKubeconfig(home)
			if want != "copy" {
				if got != want {
					t.Errorf("kubectl KUBECONFIG = %q, want %q", got, want)
				}
				return
			}
			if !strings.HasPrefix(got, copyDir+string(filepath.Separator)) || strings.Contains(got, string(filepath.ListSeparator)) {
				t.Fatalf("kubectl KUBECONFIG = %q, want one root-only copy under %s", got, copyDir)
			}
			copied, err := os.ReadFile(got)
			if err != nil {
				t.Fatal(err)
			}
			orig, err := os.ReadFile(userConfig(home))
			if err != nil {
				t.Fatal(err)
			}
			if string(copied) != string(orig) {
				t.Errorf("kubectl's copy holds %q, want the checked bytes %q", copied, orig)
			}
			fi, err := os.Stat(got)
			if err != nil {
				t.Fatal(err)
			}
			if fi.Mode().Perm() != 0o600 {
				t.Errorf("copy mode = %04o, want 0600", fi.Mode().Perm())
			}
		})
	}
}

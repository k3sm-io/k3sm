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
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"

	"k3sm.io/k3sm/pkg/executor"
	"k3sm.io/k3sm/pkg/install"
	"k3sm.io/k3sm/pkg/registrysvc"
)

// asRole states this Mac's installed role for a test.
func asRole(t *testing.T, role install.Role) {
	t.Helper()
	prev := installedNodeCredential
	t.Cleanup(func() { installedNodeCredential = prev })
	installedNodeCredential = func() (install.Role, string) { return role, "" }
}

// TestKubeconfigVerbIgnoresAWorkersLeftover holds `k3sm kubeconfig`, whose output
// is an admin credential, to the node's role: a worker never hands on a server-era
// file unless K3SM_WORK_DIR names it, and says where the real one is.
func TestKubeconfigVerbIgnoresAWorkersLeftover(t *testing.T) {
	leftoverCA, userCA := testClusterCAPEM(t), testClusterCAPEM(t)
	for _, tc := range []struct {
		name    string
		role    install.Role
		pin     bool
		user    bool
		wantCA  []byte
		wantErr []string
	}{
		{name: "a worker takes the account's context over the leftover", role: install.RoleAgent, user: true, wantCA: userCA},
		{name: "a worker with only the leftover refuses and names the server", role: install.RoleAgent, wantErr: []string{"on this worker", "k3sm kubeconfig > k3sm.yaml", "KUBECONFIG"}},
		{name: "K3SM_WORK_DIR still names the file on a worker", role: install.RoleAgent, pin: true, user: true, wantCA: leftoverCA},
		{name: "a server still reads its work dir first", role: install.RoleServer, user: true, wantCA: leftoverCA},
	} {
		t.Run(tc.name, func(t *testing.T) {
			asRole(t, tc.role)
			home := t.TempDir()
			t.Setenv("HOME", home)
			t.Setenv("K3SM_WORK_DIR", "")
			workDir := workDirFromEnv()
			if workDir != filepath.Join(home, "server") {
				t.Skipf("the work dir %s is not under the test's home, so a leftover cannot be staged there", workDir)
			}
			writeKubeconfigWithCA(t, executor.KubeconfigPath(workDir), "https://192.0.2.1:6444", leftoverCA)
			if tc.pin {
				t.Setenv("K3SM_WORK_DIR", workDir)
			}
			kc := filepath.Join(t.TempDir(), "kubeconfig")
			if tc.user {
				writeKubeconfigWithCA(t, kc, "https://100.64.0.1:6444", userCA)
			} else if err := os.WriteFile(kc, []byte("apiVersion: v1\nkind: Config\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			t.Setenv("KUBECONFIG", kc)

			got, err := loadKubeconfigSource("k3sm")
			if tc.wantErr != nil {
				if err == nil {
					t.Fatalf("loadKubeconfigSource = %+v, want a refusal", got)
				}
				for _, s := range tc.wantErr {
					if !strings.Contains(err.Error(), s) {
						t.Errorf("err = %v, want it to contain %q", err, s)
					}
				}
				return
			}
			if err != nil {
				t.Fatalf("loadKubeconfigSource: %v", err)
			}
			cl := got.Clusters[got.Contexts["k3sm"].Cluster]
			if !bytes.Equal(cl.CertificateAuthorityData, tc.wantCA) {
				t.Errorf("source CA = %q, want %q", cl.CertificateAuthorityData, tc.wantCA)
			}
		})
	}
}

// TestLocalRegistryStateIgnoresAWorkersLeftover: a "serving" record left by an
// earlier server would send a worker's push to a loopback gate nothing listens
// on, so a worker reads only a work dir the caller named.
func TestLocalRegistryStateIgnoresAWorkersLeftover(t *testing.T) {
	const gatePort = 7451
	stage := func(t *testing.T, dir string) {
		t.Helper()
		for _, d := range []string{dir, filepath.Join(filepath.Dir(dir), "status")} {
			if err := os.MkdirAll(d, 0o755); err != nil {
				t.Fatal(err)
			}
		}
		if err := registrysvc.WriteState(dir, registrysvc.State{State: registrysvc.StateServing, Port: 7450, GatePort: gatePort}); err != nil {
			t.Fatal(err)
		}
	}
	for _, tc := range []struct {
		name string
		role install.Role
		// workDir is which work dir the verb was given.
		workDir  string
		pin      bool
		wantPort int
	}{
		{name: "a worker's default work dir", role: install.RoleAgent, workDir: "default"},
		{name: "a worker asked for the installed server's work dir", role: install.RoleAgent, workDir: "installed"},
		{name: "a worker's default work dir finds no other record", role: install.RoleAgent, workDir: "empty"},
		{name: "K3SM_WORK_DIR names a work dir on a worker", role: install.RoleAgent, workDir: "default", pin: true, wantPort: gatePort},
		{name: "--work-dir names another work dir on a worker", role: install.RoleAgent, workDir: "named", wantPort: gatePort},
		{name: "a server reads its own record", role: install.RoleServer, workDir: "default", wantPort: gatePort},
		{name: "a server's account reads the installed record", role: install.RoleServer, workDir: "empty", wantPort: gatePort},
	} {
		t.Run(tc.name, func(t *testing.T) {
			asRole(t, tc.role)
			home := t.TempDir()
			t.Setenv("HOME", home)
			t.Setenv("K3SM_WORK_DIR", "")
			def := workDirFromEnv()
			if def != filepath.Join(home, "server") {
				t.Skipf("the work dir %s is not under the test's home", def)
			}
			installed := filepath.Join(t.TempDir(), "server")
			stage(t, installed)
			prev := installedServerWorkDir
			installedServerWorkDir = installed
			t.Cleanup(func() { installedServerWorkDir = prev })

			workDir := def
			switch tc.workDir {
			case "default":
				stage(t, def)
			case "installed":
				workDir = installed
			case "named":
				workDir = filepath.Join(t.TempDir(), "server")
				stage(t, workDir)
			}
			if tc.pin {
				t.Setenv("K3SM_WORK_DIR", workDir)
			}
			if got := localGatePort(workDir); got != tc.wantPort {
				t.Errorf("localGatePort(%s) = %d, want %d", workDir, got, tc.wantPort)
			}
		})
	}
}

// TestCredentialAccessIgnoresAWorkersLeftover: a push credential an earlier server
// left in the server work dir names a loopback registry nothing serves on a worker,
// so a worker uses it only from a work dir the caller named, as it does the record.
func TestCredentialAccessIgnoresAWorkersLeftover(t *testing.T) {
	for _, tc := range []struct {
		name string
		role install.Role
		// workDir is which work dir the verb was given.
		workDir string
		pin     bool
		want    bool
	}{
		{name: "a worker's default work dir", role: install.RoleAgent, workDir: "default"},
		{name: "a worker asked for the installed server's work dir", role: install.RoleAgent, workDir: "installed"},
		{name: "K3SM_WORK_DIR names the default work dir on a worker", role: install.RoleAgent, workDir: "default", pin: true, want: true},
		{name: "--work-dir names another work dir on a worker", role: install.RoleAgent, workDir: "named", want: true},
		{name: "a server uses the credential in its work dir", role: install.RoleServer, workDir: "default", want: true},
		{name: "a server's root run names the installed work dir", role: install.RoleServer, workDir: "installed", want: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			asRole(t, tc.role)
			home := t.TempDir()
			t.Setenv("HOME", home)
			t.Setenv("K3SM_WORK_DIR", "")
			def := workDirFromEnv()
			if def != filepath.Join(home, "server") {
				t.Skipf("the work dir %s is not under the test's home", def)
			}
			installed := filepath.Join(t.TempDir(), "server")
			prev := installedServerWorkDir
			installedServerWorkDir = installed
			t.Cleanup(func() { installedServerWorkDir = prev })

			workDir := def
			switch tc.workDir {
			case "installed":
				workDir = installed
			case "named":
				workDir = filepath.Join(t.TempDir(), "named")
			}
			if err := os.MkdirAll(registrysvc.StateDir(workDir), 0o700); err != nil {
				t.Fatal(err)
			}
			cred := registrysvc.Credential{Address: "127.0.0.1:6450", Username: "k3sm", Password: "per-boot-secret"}
			if err := registrysvc.WriteCredential(workDir, cred); err != nil {
				t.Fatal(err)
			}
			if tc.pin {
				t.Setenv("K3SM_WORK_DIR", workDir)
			}
			_, ok, err := credentialAccess(t.Context(), workDir)
			if err != nil {
				t.Fatalf("credentialAccess: %v", err)
			}
			if ok != tc.want {
				t.Errorf("credentialAccess(%s) ok = %v, want %v", workDir, ok, tc.want)
			}
			if tc.want {
				return
			}
			// What a verb does next: a delete names the server run that has the
			// credential, rather than presenting the leftover.
			if _, err := registryDeleteAccess(t.Context(), workDir); err == nil || !strings.Contains(err.Error(), "run it on the server as root") {
				t.Errorf("registryDeleteAccess = %v, want it to name the run on the server", err)
			}
		})
	}
}

// TestWorkerReadersIgnoreALeftoverCredential holds every reader of the push
// credential to the same rule as credentialAccess: on a worker, one an earlier
// server left in the server work dir is not this Mac's. It is not presented to
// whatever now listens on its loopback port, its port does not name the cluster
// registry, and prune does not plan against the registry it came from.
func TestWorkerReadersIgnoreALeftoverCredential(t *testing.T) {
	const leftover = "localhost:7450"
	for _, tc := range []struct {
		name string
		role install.Role
		// workDir is which work dir the verb was given.
		workDir string
		pin     bool
		// want is whether the credential is this Mac's to use.
		want bool
	}{
		{name: "a worker's default work dir", role: install.RoleAgent, workDir: "default"},
		{name: "a worker asked for the installed server's work dir", role: install.RoleAgent, workDir: "installed"},
		{name: "K3SM_WORK_DIR names the default work dir on a worker", role: install.RoleAgent, workDir: "default", pin: true, want: true},
		{name: "--work-dir names another work dir on a worker", role: install.RoleAgent, workDir: "named", want: true},
		{name: "a server uses the credential in its work dir", role: install.RoleServer, workDir: "default", want: true},
		{name: "a server's root run names the installed work dir", role: install.RoleServer, workDir: "installed", want: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			asRole(t, tc.role)
			home := t.TempDir()
			t.Setenv("HOME", home)
			t.Setenv("K3SM_WORK_DIR", "")
			def := workDirFromEnv()
			if def != filepath.Join(home, "server") {
				t.Skipf("the work dir %s is not under the test's home", def)
			}
			installed := filepath.Join(t.TempDir(), "server")
			prev := installedServerWorkDir
			installedServerWorkDir = installed
			t.Cleanup(func() { installedServerWorkDir = prev })

			workDir := def
			switch tc.workDir {
			case "installed":
				workDir = installed
			case "named":
				workDir = filepath.Join(t.TempDir(), "named")
			}
			if err := os.MkdirAll(registrysvc.StateDir(workDir), 0o700); err != nil {
				t.Fatal(err)
			}
			cred := registrysvc.Credential{Address: "127.0.0.1:7450", Username: "k3sm", Password: "per-boot-secret"}
			if err := registrysvc.WriteCredential(workDir, cred); err != nil {
				t.Fatal(err)
			}
			if tc.pin {
				t.Setenv("K3SM_WORK_DIR", workDir)
			}

			ref, err := name.ParseReference(leftover + "/probe:t")
			if err != nil {
				t.Fatal(err)
			}
			if got := localRegistryAuth(ref, workDir) != nil; got != tc.want {
				t.Errorf("localRegistryAuth presents the credential = %v, want %v", got, tc.want)
			}
			if got := isClusterRegistryHost(leftover, workDir); got != tc.want {
				t.Errorf("isClusterRegistryHost(%s) = %v, want %v", leftover, got, tc.want)
			}
			got, skipped, err := pruneCredential(workDir)
			if err != nil {
				t.Fatalf("pruneCredential: %v", err)
			}
			if tc.want && (skipped != "" || got != cred) {
				t.Errorf("pruneCredential = %+v, skipped %q; want the credential", got, skipped)
			}
			if !tc.want && (!strings.Contains(skipped, "this node runs no registry") || got != (registrysvc.Credential{})) {
				t.Errorf("pruneCredential = %+v, skipped %q; want the registry half skipped", got, skipped)
			}
			authority, err := nodeRegistryAuthority(workDir)
			if tc.want && (err != nil || authority != leftover) {
				t.Errorf("nodeRegistryAuthority = %q, %v; want %s", authority, err, leftover)
			}
			if !tc.want && !errors.Is(err, errNoNodeRegistry) {
				t.Errorf("nodeRegistryAuthority = %q, %v; want errNoNodeRegistry", authority, err)
			}
		})
	}
}

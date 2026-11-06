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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"k3sm.io/k3sm/pkg/bootstrap"
	"k3sm.io/k3sm/pkg/install"
)

// installWrittenNodeCredential writes the node credential the way a join does,
// with a real keypair, because building a client parses it.
func installWrittenNodeCredential(t *testing.T, path string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "system:node:worker-1", Organization: []string{"system:nodes"}},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	res := &bootstrap.JoinResult{
		ClusterCAPEM:      testClusterCAPEM(t),
		NodeClientCertPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		NodeClientKeyPEM:  pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}),
	}
	if err := writeNodeKubeconfig(path, nodeServer, "worker-1", res); err != nil {
		t.Fatal(err)
	}
}

// nodeCredentialWith is a node credential whose user entry is userEntry.
func nodeCredentialWith(t *testing.T, path, userEntry string) {
	t.Helper()
	body := fmt.Sprintf(`apiVersion: v1
kind: Config
clusters:
- name: k3sm
  cluster:
    server: %s
    certificate-authority-data: %s
contexts:
- name: k3sm
  context:
    cluster: k3sm
    user: node
current-context: k3sm
users:
- name: node
  user:
%s
`, nodeServer, base64.StdEncoding.EncodeToString(testClusterCAPEM(t)), userEntry)
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

// saysOnlyTheMintingFix fails on the fixes that do not work for a verb that mints a
// registry push token on a worker: $KUBECONFIG is ignored under sudo, these verbs may
// need root, and a worker cannot write a user kubeconfig.
func saysOnlyTheMintingFix(t *testing.T, err error) {
	t.Helper()
	for _, wrong := range []string{"set KUBECONFIG", "without sudo", rootNodeCredentialFix, "--write", "build engine"} {
		if strings.Contains(err.Error(), wrong) {
			t.Errorf("err = %v, want no %q on a minting verb", err, wrong)
		}
	}
}

// TestAWorkerAccountThatCannotSeeTheNodeCredentialGetsItsVerbsFix: the account that
// is neither root nor the service user reaches no node credential, and is told what
// works for the verb it ran.
func TestAWorkerAccountThatCannotSeeTheNodeCredentialGetsItsVerbsFix(t *testing.T) {
	absent := filepath.Join(t.TempDir(), "absent")
	var warn bytes.Buffer
	in, sudo := refusalWorker(t, absent, "", nil, &warn, nil)
	sudo.euid = 501
	sudo.sudoUser = ""

	_, err := clusterRegistryAPIFrom(in, sudo)
	if err == nil || !strings.Contains(err.Error(), workerMintRemedy) {
		t.Fatalf("minting: err = %v, want the minting fix", err)
	}
	saysOnlyTheMintingFix(t, err)

	_, err = builderKubeconfig(in)
	if err == nil || !strings.Contains(err.Error(), "set KUBECONFIG") || strings.Contains(err.Error(), workerMintRemedy) {
		t.Errorf("builder: err = %v, want the builder fix and not the minting one", err)
	}
}

// TestTheBuilderFixWorks: the builder verbs' fix is true because they run as an
// ordinary account and read $KUBECONFIG, on a worker as anywhere.
func TestTheBuilderFixWorks(t *testing.T) {
	copied := filepath.Join(t.TempDir(), "k3sm.yaml")
	if err := os.WriteFile(copied, inlineKubeconfig(testClusterCAPEM(t), ""), 0o600); err != nil {
		t.Fatal(err)
	}
	var warn bytes.Buffer
	in, _ := refusalWorker(t, filepath.Join(t.TempDir(), "absent"), copied, nil, &warn, nil)
	restCfg, _, err := builderClients(in)
	if err != nil {
		t.Fatalf("builderClients: %v", err)
	}
	if restCfg.Host != checkedServer {
		t.Errorf("server = %q, want the copy's %q", restCfg.Host, checkedServer)
	}
}

// TestRootDoesNotUseTheNodeCredential: a system:node identity can neither mint a
// push token nor run the build engine, so these verbs lose nothing by refusing it.
// Each row is a file that could be there, the one a real join wrote included, and
// each way root reaches the choice ends with no client at all and a fix a person
// can follow.
func TestRootDoesNotUseTheNodeCredential(t *testing.T) {
	dir := t.TempDir()
	ranFlag := filepath.Join(dir, "plugin-ran")
	plugin := filepath.Join(dir, "plugin.sh")
	if err := os.WriteFile(plugin, []byte("#!/bin/sh\ntouch "+ranFlag+"\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	secret := filepath.Join(dir, "root-only-secret")
	if err := os.WriteFile(secret, []byte("a file only root may read"), 0o600); err != nil {
		t.Fatal(err)
	}

	files := []struct {
		name  string
		write func(t *testing.T, path string)
	}{
		{"a kubeconfig that names a program", func(t *testing.T, path string) {
			nodeCredentialWith(t, path, "    exec:\n      apiVersion: client.authentication.k8s.io/v1\n      interactiveMode: Never\n      command: "+plugin)
		}},
		{"an auth provider", func(t *testing.T, path string) {
			nodeCredentialWith(t, path, "    auth-provider:\n      name: oidc\n      config:\n        cmd-path: "+plugin)
		}},
		{"a token file", func(t *testing.T, path string) {
			nodeCredentialWith(t, path, "    tokenFile: "+secret)
		}},
		{"client cert paths", func(t *testing.T, path string) {
			nodeCredentialWith(t, path, "    client-certificate: "+secret+"\n    client-key: "+secret)
		}},
		{"a file that does not parse", func(t *testing.T, path string) {
			if err := os.WriteFile(path, []byte("{not yaml"), 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{"what a join wrote", installWrittenNodeCredential},
	}

	refusesOnRegistry := func(t *testing.T, node string, in kubectlInputs, sudo topSudoInputs) {
		t.Helper()
		restCfg, cs, hint, err := registryClients(in, sudo)
		if err == nil {
			t.Fatalf("registryClients gave root a client at %s (exec %v, token file %q, cert file %q), want a refusal",
				restCfg.Host, restCfg.ExecProvider, restCfg.BearerTokenFile, restCfg.CertFile)
		}
		if restCfg != nil || cs != nil || hint != "" {
			t.Errorf("a refusal came with a client %v, %v or a hint %q", restCfg, cs, hint)
		}
		api, err := clusterRegistryAPIFrom(in, sudo)
		if err == nil {
			t.Fatalf("clusterRegistryAPIFrom gave root an API: %+v", api)
		}
		if !errors.Is(err, errNoUserKubeconfig) {
			t.Errorf("err = %v, want errNoUserKubeconfig", err)
		}
		for _, want := range []string{node, "root does not", workerMintRemedy} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("err = %v, want it to contain %q", err, want)
			}
		}
		saysOnlyTheMintingFix(t, err)
	}

	for _, f := range files {
		t.Run(f.name, func(t *testing.T) {
			node := filepath.Join(t.TempDir(), "node.kubeconfig")
			f.write(t, node)

			t.Run("minting under sudo", func(t *testing.T) {
				var warn bytes.Buffer
				var asked []string
				in, sudo := refusalWorker(t, node, "", nil, &warn, &asked)
				refusesOnRegistry(t, node, in, sudo)
				if slices.Contains(asked, node) {
					t.Errorf("a sudo run looked for the node credential it does not use")
				}
			})
			t.Run("minting as root without sudo", func(t *testing.T) {
				var warn bytes.Buffer
				in, sudo := refusalWorker(t, node, "", nil, &warn, nil)
				sudo.sudoUser = ""
				refusesOnRegistry(t, node, in, sudo)
			})
			t.Run("builder verbs as root", func(t *testing.T) {
				var warn bytes.Buffer
				in, _ := refusalWorker(t, node, "", nil, &warn, nil)
				in.asRoot = true
				restCfg, cs, err := builderClients(in)
				if err == nil {
					t.Fatalf("builderClients gave root a client at %s (exec %v, token file %q, cert file %q), want a refusal",
						restCfg.Host, restCfg.ExecProvider, restCfg.BearerTokenFile, restCfg.CertFile)
				}
				if restCfg != nil || cs != nil {
					t.Errorf("a refusal came with a client %v, %v", restCfg, cs)
				}
				for _, want := range []string{node, "may not run the build engine", rootNodeCredentialFix} {
					if !strings.Contains(err.Error(), want) {
						t.Errorf("err = %v, want it to contain %q", err, want)
					}
				}
				if strings.Contains(err.Error(), workerMintRemedy) {
					t.Errorf("err = %v gives a builder verb the minting verbs' fix", err)
				}
				if _, err := builderKubeconfig(in); err == nil {
					t.Errorf("builderKubeconfig chose the node credential for root, which is the choice a buildx session stages from")
				}
			})
			if _, err := os.Stat(ranFlag); err == nil {
				t.Errorf("the plugin the node credential names ran")
			}
		})
	}
}

// TestAJoinWrittenNodeCredentialStillWorksWhereItIsUsed: a refusal for root on the
// minting, builder, kubectl and interconnect verbs leaves the file useful everywhere
// else. The service user reads its own file on those verbs, with the hint a refused
// token earns, and `sudo k3sm status` reads with it as a worker's only identity.
func TestAJoinWrittenNodeCredentialStillWorksWhereItIsUsed(t *testing.T) {
	node := filepath.Join(t.TempDir(), "node.kubeconfig")
	installWrittenNodeCredential(t, node)
	carriesTheKeypair := func(t *testing.T, restCfg *rest.Config, cs kubernetes.Interface) {
		t.Helper()
		if cs == nil || restCfg == nil {
			t.Fatalf("no client: %v, %v", restCfg, cs)
		}
		if restCfg.Host != nodeServer {
			t.Errorf("server = %q, want %q", restCfg.Host, nodeServer)
		}
		if len(restCfg.CertData) == 0 || len(restCfg.KeyData) == 0 || len(restCfg.CAData) == 0 {
			t.Errorf("the client does not carry the file's inline CA and keypair: %d, %d, %d bytes", len(restCfg.CAData), len(restCfg.CertData), len(restCfg.KeyData))
		}
	}

	t.Run("the service user's minting verbs", func(t *testing.T) {
		var warn bytes.Buffer
		in, sudo := refusalWorker(t, node, "", nil, &warn, nil)
		sudo.euid = 501
		sudo.sudoUser = ""
		restCfg, cs, hint, err := registryClients(in, sudo)
		if err != nil {
			t.Fatalf("registryClients: %v", err)
		}
		carriesTheKeypair(t, restCfg, cs)
		if !strings.Contains(hint, node) {
			t.Errorf("hint = %q, want it to name %s", hint, node)
		}
	})
	t.Run("the service user's builder verbs", func(t *testing.T) {
		var warn bytes.Buffer
		in, _ := refusalWorker(t, node, "", nil, &warn, nil)
		restCfg, cs, err := builderClients(in)
		if err != nil {
			t.Fatalf("builderClients: %v", err)
		}
		carriesTheKeypair(t, restCfg, cs)
	})
	t.Run("the service user's k3sm kubectl", func(t *testing.T) {
		var warn bytes.Buffer
		in, _ := refusalWorker(t, node, "", nil, &warn, nil)
		cfg, err := kubectlVerbConfig("k3sm kubectl", in)
		if err != nil {
			t.Fatalf("kubectlVerbConfig: %v", err)
		}
		if cfg.kubeconfig != node {
			t.Errorf("kubeconfig = %q, want the node credential %s", cfg.kubeconfig, node)
		}
	})
	t.Run("sudo k3sm status", func(t *testing.T) {
		cfg, err := statusKubeconfig(statusKubeInputs{
			role:           install.RoleAgent,
			nodeKubeconfig: node,
		})
		if err != nil {
			t.Fatalf("statusKubeconfig: %v", err)
		}
		kube, source, err := buildStatusKube(cfg)
		if err != nil {
			t.Fatalf("buildStatusKube: %v", err)
		}
		if kube == nil || !strings.Contains(source, node) {
			t.Errorf("kube = %v from %q, want a client from %s", kube, source, node)
		}
	})
}

// workerRunBy makes this process a worker whose node credential is node, run by
// euid, with no kubeconfig of its own and a kubectl to find. It returns the home
// the account's own kubeconfig would sit under and the record of every kubectl exec.
func workerRunBy(t *testing.T, node string, euid int) (home string, execs *[][]string) {
	t.Helper()
	prevCredential, prevEUID, prevExec := installedNodeCredential, kubectlGeteuid, kubectlExec
	t.Cleanup(func() { installedNodeCredential, kubectlGeteuid, kubectlExec = prevCredential, prevEUID, prevExec })
	installedNodeCredential = func() (install.Role, string) { return install.RoleAgent, node }
	kubectlGeteuid = func() int { return euid }
	execs = new([][]string)
	kubectlExec = func(_ string, _, env []string) error {
		*execs = append(*execs, env)
		return nil
	}

	bin := t.TempDir()
	if err := os.WriteFile(filepath.Join(bin, "kubectl"), nil, 0o755); err != nil {
		t.Fatal(err)
	}
	home = t.TempDir()
	t.Setenv("PATH", bin)
	t.Setenv("HOME", home)
	t.Setenv("KUBECONFIG", "")
	t.Setenv("K3SM_WORK_DIR", "")
	return home, execs
}

// TestRootOnAWorkerDoesNotHandKubectlTheNodeCredential: a node identity holds only
// what its kubelet needs, so root does not start kubectl with it. `k3sm kubectl` and
// `k3sm interconnect` stop instead, whatever the file says, and say the fix those two
// verbs can use. The service user keeps its path.
func TestRootOnAWorkerDoesNotHandKubectlTheNodeCredential(t *testing.T) {
	refused := func(t *testing.T, err error, node, verb string) {
		t.Helper()
		if err == nil {
			t.Fatalf("%s went ahead as root with the node credential, want a refusal", verb)
		}
		for _, want := range []string{
			verb, node,
			"root does not use the node credential",
			"copy the admin kubeconfig from the server (`k3sm kubeconfig > k3sm.yaml` there), set KUBECONFIG and run this without sudo",
		} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("err = %v, want it to contain %q", err, want)
			}
		}
		if strings.Contains(err.Error(), workerMintRemedy) {
			t.Errorf("err = %v gives %s the minting verbs' fix", err, verb)
		}
	}

	for _, f := range []struct {
		name  string
		write func(t *testing.T, path string)
	}{
		{"a kubeconfig that names a program", func(t *testing.T, path string) {
			nodeCredentialWith(t, path, "    exec:\n      apiVersion: client.authentication.k8s.io/v1\n      interactiveMode: Never\n      command: /tmp/a-program")
		}},
		{"what a join wrote", installWrittenNodeCredential},
	} {
		t.Run(f.name, func(t *testing.T) {
			node := filepath.Join(t.TempDir(), "node.kubeconfig")
			f.write(t, node)

			t.Run("k3sm kubectl", func(t *testing.T) {
				_, execs := workerRunBy(t, node, 0)
				refused(t, runKubectl([]string{"get", "nodes"}), node, "k3sm kubectl")
				if len(*execs) != 0 {
					t.Errorf("kubectl ran for root: %v", *execs)
				}
			})
			t.Run("k3sm interconnect", func(t *testing.T) {
				workerRunBy(t, node, 0)
				cs, dyn, err := interconnectClients("")
				refused(t, err, node, "k3sm interconnect")
				if cs != nil || dyn != nil {
					t.Errorf("a refusal came with clients %v, %v", cs, dyn)
				}
			})
		})
	}

	node := filepath.Join(t.TempDir(), "node.kubeconfig")
	installWrittenNodeCredential(t, node)

	t.Run("root's own kubeconfig is still used", func(t *testing.T) {
		home, execs := workerRunBy(t, node, 0)
		own := filepath.Join(home, ".kube", "config")
		if err := os.MkdirAll(filepath.Dir(own), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(own, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := runKubectl([]string{"get", "nodes"}); err != nil {
			t.Fatalf("runKubectl: %v", err)
		}
		if len(*execs) != 1 {
			t.Fatalf("kubectl ran %d times, want once", len(*execs))
		}
		if slices.Contains((*execs)[0], "KUBECONFIG="+node) {
			t.Errorf("kubectl was handed the node credential: %v", (*execs)[0])
		}
	})
	t.Run("the service user's k3sm kubectl", func(t *testing.T) {
		_, execs := workerRunBy(t, node, 501)
		if err := runKubectl([]string{"get", "nodes"}); err != nil {
			t.Fatalf("runKubectl: %v", err)
		}
		if len(*execs) != 1 || !slices.Contains((*execs)[0], "KUBECONFIG="+node) {
			t.Errorf("kubectl env = %v, want one run with KUBECONFIG=%s", *execs, node)
		}
	})
	t.Run("the service user's k3sm interconnect", func(t *testing.T) {
		workerRunBy(t, node, 501)
		cs, dyn, err := interconnectClients("")
		if err != nil {
			t.Fatalf("interconnectClients: %v", err)
		}
		if cs == nil || dyn == nil {
			t.Errorf("no clients: %v, %v", cs, dyn)
		}
	})
}

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
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"k8s.io/client-go/tools/clientcmd"

	"k3sm.io/k3sm/pkg/certs"
	"k3sm.io/k3sm/pkg/executor"
	"k3sm.io/k3sm/pkg/install"
	"k3sm.io/k3sm/pkg/kubeclient"
)

// absentFile is the read of a file that is not there.
func absentFile(string) (sudoKubeconfigFile, error) {
	return sudoKubeconfigFile{}, fmt.Errorf("open: %w", fs.ErrNotExist)
}

// withClusterAnchor answers the root-held CA reads a lifecycle verb makes.
func withClusterAnchor(t *testing.T, read func(string) (sudoKubeconfigFile, error)) {
	t.Helper()
	prev := clusterAnchorFile
	clusterAnchorFile = read
	t.Cleanup(func() { clusterAnchorFile = prev })
}

// TestNetdEstablishesItsTrustFromItsFlags walks every flag pair a plist has carried
// and the pairs only a person running netd by hand gives.
func TestNetdEstablishesItsTrustFromItsFlags(t *testing.T) {
	workerCredential := install.AgentCredentialPath(install.DefaultDataRoot)
	serverKubeconfig := executor.KubeconfigPath(executor.DefaultWorkDir)
	otherRoot := "/Volumes/k3sm/server"
	tests := []struct {
		name    string
		root    bool
		opts    netdOptions
		want    string
		refused bool
	}{
		{name: "worker", root: true, opts: netdOptions{kubeconfig: workerCredential, clusterCA: install.AgentClusterCAPath}, want: install.AgentClusterCAPath},
		{name: "worker whose plist has no --cluster-ca", root: true, opts: netdOptions{kubeconfig: workerCredential}, want: install.AgentClusterCAPath},
		{name: "server", root: true, opts: netdOptions{kubeconfig: serverKubeconfig, clusterCA: install.AgentClusterCAPath}, want: install.AgentClusterCAPath},
		{name: "server on the plist of an earlier release", root: true, opts: netdOptions{kubeconfig: serverKubeconfig, clusterCA: certs.ClusterCACertPath(executor.DefaultWorkDir)}, want: install.AgentClusterCAPath},
		{name: "server whose plist has no --cluster-ca", root: true, opts: netdOptions{kubeconfig: serverKubeconfig}, want: install.AgentClusterCAPath},
		{name: "server on a data root of its own", root: true, opts: netdOptions{kubeconfig: executor.KubeconfigPath(otherRoot), clusterCA: certs.ClusterCACertPath(otherRoot)}, want: install.AgentClusterCAPath},
		{name: "a named kubeconfig with a CA of the person's own", root: true, opts: netdOptions{kubeconfig: "/etc/custom.kubeconfig", clusterCA: "/etc/custom-ca.crt"}, want: "/etc/custom-ca.crt"},
		{name: "a named kubeconfig with the root-held CA", root: true, opts: netdOptions{kubeconfig: "/etc/custom.kubeconfig", clusterCA: install.AgentClusterCAPath}, want: install.AgentClusterCAPath},
		{name: "a named kubeconfig with no CA as root", root: true, opts: netdOptions{kubeconfig: "/etc/custom.kubeconfig"}, refused: true},
		{name: "a named kubeconfig with no CA as another account", opts: netdOptions{kubeconfig: "/etc/custom.kubeconfig"}},
		{name: "no kubeconfig", root: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			prev := processEuid
			processEuid = func() int {
				if tt.root {
					return 0
				}
				return 501
			}
			t.Cleanup(func() { processEuid = prev })
			got := tt.opts.authorizerKube()
			if got.clusterCA != tt.want || got.kubeconfig != tt.opts.kubeconfig {
				t.Errorf("authorizerKube() = %+v, want clusterCA %q", got, tt.want)
			}
			if got.refuseUnpinned != tt.refused {
				t.Errorf("refuseUnpinned = %t, want %t", got.refuseUnpinned, tt.refused)
			}
		})
	}
}

// TestRootHelperDoesNotLoadAKubeconfigWithNoCA pins that a helper with no established
// trust builds no client, and tells the person running it what to pass.
func TestRootHelperDoesNotLoadAKubeconfigWithNoCA(t *testing.T) {
	asRoot(t)
	path := writeServiceKubeconfig(t)
	k := netdOptions{kubeconfig: path}.authorizerKube()
	_, cs, err := k.load()
	if err == nil || cs != nil {
		t.Fatalf("load = %v, %v, want a refusal", cs, err)
	}
	if !errors.Is(err, errNoClusterCAFlag) {
		t.Fatalf("err = %v, want errNoClusterCAFlag", err)
	}
	h := &levelCounter{}
	var l authorizerFailureLog
	l.note(slog.New(h), path, err)
	if got := h.count(slog.LevelWarn); got != 1 {
		t.Errorf("WARN records = %d, want 1", got)
	}
	for _, want := range []string{"--cluster-ca", "root-owned", path} {
		if !strings.Contains(h.text.String(), want) {
			t.Errorf("log lacks %q:\n%s", want, h.text.String())
		}
	}
}

// TestServerInformerTakesItsTrustFromTheRootCopy reads a server's kubeconfig that
// names another CA, on each plist a server can have.
func TestServerInformerTakesItsTrustFromTheRootCopy(t *testing.T) {
	asRoot(t)
	res, _, _ := nodeCredFixture(t, nodeCredClientTTL, nodeCredClientTTL)
	store := savedStore(t, res)
	raw, err := os.ReadFile(store.kubeconfigPath())
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	path := executor.KubeconfigPath(dir)
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	fileCfg, err := clientcmd.RESTConfigFromKubeConfig(raw)
	if err != nil {
		t.Fatal(err)
	}
	anchor := fixtureCA(t)
	k := netdOptions{kubeconfig: path, clusterCA: certs.ClusterCACertPath(dir)}.authorizerKube()
	var read []string
	k.readFile = func(p string) (sudoKubeconfigFile, error) {
		read = append(read, p)
		return regular(0, 0o644, string(anchor)), nil
	}
	cfg, cs, err := k.load()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cs == nil || !bytes.Equal(cfg.CAData, anchor) || cfg.ServerName != kubeclient.APIServerName() || cfg.Host != fileCfg.Host {
		t.Errorf("CA pinned %t, ServerName %q, host %q, want the file's %q", bytes.Equal(cfg.CAData, anchor), cfg.ServerName, cfg.Host, fileCfg.Host)
	}
	if len(read) != 1 || read[0] != install.AgentClusterCAPath {
		t.Errorf("read %v, want only %s", read, install.AgentClusterCAPath)
	}
}

// TestMissingClusterCAIsWarnedAfterTheBootWindow pins what a person reads on a node
// with no root-held CA, on either role, and that a first install's few seconds
// without one stay quiet.
func TestMissingClusterCAIsWarnedAfterTheBootWindow(t *testing.T) {
	path := writeServiceKubeconfig(t)
	_, err := startServiceInformer(context.Background(), authorizerKube{kubeconfig: path, clusterCA: install.AgentClusterCAPath, readFile: absentFile})
	if !isClusterAnchorError(err) {
		t.Fatalf("err = %v", err)
	}
	reason, class, window := authorizerFailureReason(err)
	if class != failWindowed || window != missingKubeconfigWarnAfter {
		t.Errorf("class %v, window %d, want the missing-file window", class, window)
	}
	if !strings.Contains(reason, "root-only cluster CA") || strings.Contains(reason, "worker") {
		t.Errorf("reason = %q", reason)
	}
	remedy := authorizerRemedy(err)
	for _, want := range []string{"on a server run `sudo k3sm install`", "on a worker run `sudo k3sm install --agent", install.AgentClusterCAPath} {
		if !strings.Contains(remedy, want) {
			t.Errorf("remedy lacks %q: %s", want, remedy)
		}
	}
	unusable := fmt.Errorf("%w: wrong owner", errClusterAnchor)
	if _, class, _ := authorizerFailureReason(unusable); class != failImmediate {
		t.Errorf("a copy that is there and unusable has class %v, want failImmediate", class)
	}
}

// TestRootWorkDirKubeconfigUsesTheRootCopy covers `sudo k3sm kubectl` and everything
// else that resolves the work dir's kubeconfig as root.
func TestRootWorkDirKubeconfigUsesTheRootCopy(t *testing.T) {
	asRoot(t)
	const workDir = "/var/lib/k3sm/server"
	const body = `apiVersion: v1
kind: Config
current-context: k3sm
clusters:
- name: k3sm
  cluster: {server: "https://192.0.2.1:6443", insecure-skip-tls-verify: true}
contexts:
- name: k3sm
  context: {cluster: k3sm, user: admin}
users:
- name: admin
  user: {token: inline-token}
`
	anchor := fixtureCA(t)
	in := kubectlInputs{workDir: workDir}
	kc := executor.KubeconfigPath(workDir)

	t.Run("pinned", func(t *testing.T) {
		src := fakeRootSources("", map[string]sudoKubeconfigFile{
			kc:                         regular(271, 0o600, body),
			install.AgentClusterCAPath: regular(0, 0o644, string(anchor)),
		}, nil)
		got, err := src.resolve(in)
		if err != nil {
			t.Fatalf("resolve: %v", err)
		}
		cfg, err := got.checked.restConfig()
		if err != nil {
			t.Fatalf("restConfig: %v", err)
		}
		if !bytes.Equal(cfg.CAData, anchor) || cfg.Insecure || cfg.ServerName != kubeclient.APIServerName() || cfg.Host != "https://192.0.2.1:6443" {
			t.Errorf("CA pinned %t, insecure %t, ServerName %q, host %q", bytes.Equal(cfg.CAData, anchor), cfg.Insecure, cfg.ServerName, cfg.Host)
		}
		f, handoff, err := got.checked.handoff()
		if err != nil {
			t.Fatalf("handoff: %v", err)
		}
		defer f.Close()
		given, err := clientcmd.BuildConfigFromFlags("", handoff)
		if err != nil {
			t.Fatalf("load the handoff: %v", err)
		}
		if !bytes.Equal(given.CAData, anchor) || given.Insecure || given.ServerName != kubeclient.APIServerName() || given.Host != "https://192.0.2.1:6443" {
			t.Errorf("handoff CA pinned %t, insecure %t, ServerName %q, host %q", bytes.Equal(given.CAData, anchor), given.Insecure, given.ServerName, given.Host)
		}
	})
	refusals := []struct {
		name string
		file *sudoKubeconfigFile
		want string
	}{
		{name: "no copy", want: "does not exist"},
		{name: "a copy with another owner", file: fileRef(regular(271, 0o644, string(anchor))), want: "owned by uid 271, not root"},
		{name: "a group-writable copy", file: fileRef(regular(0, 0o664, string(anchor))), want: "group- or world-writable"},
	}
	for _, tt := range refusals {
		t.Run(tt.name, func(t *testing.T) {
			files := map[string]sudoKubeconfigFile{kc: regular(271, 0o600, body)}
			if tt.file != nil {
				files[install.AgentClusterCAPath] = *tt.file
			}
			_, err := fakeRootSources("", files, nil).resolve(in)
			if !errors.Is(err, errClusterAnchor) {
				t.Fatalf("resolve err = %v, want a refusal of the root copy", err)
			}
			for _, want := range []string{tt.want, "sudo k3sm install", "without sudo"} {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("err lacks %q: %v", want, err)
				}
			}
		})
	}
}

// TestRootLifecycleUsesTheRootCopy pins a stop or start as root on either role:
// the file gives the address and credential, the root-held copy the trust.
func TestRootLifecycleUsesTheRootCopy(t *testing.T) {
	res, _, _ := nodeCredFixture(t, nodeCredClientTTL, nodeCredClientTTL)
	raw, err := os.ReadFile(savedStore(t, res).kubeconfigPath())
	if err != nil {
		t.Fatal(err)
	}
	fileCfg, err := clientcmd.RESTConfigFromKubeConfig(raw)
	if err != nil {
		t.Fatal(err)
	}
	anchor := fixtureCA(t)
	dataRoot := t.TempDir()
	worker := install.AgentCredentialPath(dataRoot)
	if err := os.MkdirAll(filepath.Dir(worker), 0o700); err != nil {
		t.Fatal(err)
	}
	server := filepath.Join(dataRoot, "k3sm.kubeconfig")
	for _, p := range []string{worker, server} {
		if err := os.WriteFile(p, raw, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for name, path := range map[string]string{"worker": worker, "server": server} {
		t.Run(name, func(t *testing.T) {
			asRoot(t)
			var read []string
			withClusterAnchor(t, func(p string) (sudoKubeconfigFile, error) {
				read = append(read, p)
				return regular(0, 0o644, string(anchor)), nil
			})
			cfg, cs, err := lifecycleClient(dataRoot, path)
			if err != nil {
				t.Fatalf("lifecycleClient: %v", err)
			}
			if cs == nil || !bytes.Equal(cfg.CAData, anchor) || cfg.ServerName != kubeclient.APIServerName() || cfg.Host != fileCfg.Host {
				t.Errorf("CA pinned %t, ServerName %q, host %q", bytes.Equal(cfg.CAData, anchor), cfg.ServerName, cfg.Host)
			}
			if len(read) != 1 || read[0] != install.AgentClusterCAPath {
				t.Errorf("read %v, want only %s", read, install.AgentClusterCAPath)
			}
		})
		t.Run(name+" with no root copy", func(t *testing.T) {
			asRoot(t)
			withClusterAnchor(t, absentFile)
			_, _, err := lifecycleClient(dataRoot, path)
			if !errors.Is(err, errClusterAnchor) || !errors.Is(err, install.ErrNodeIdentity) {
				t.Fatalf("err = %v, want a refusal a retry cannot fix", err)
			}
			if !strings.Contains(err.Error(), "sudo k3sm install") {
				t.Errorf("err names no remedy: %v", err)
			}
		})
	}
}

// TestServerAPIServerCertVerifiesAgainstTheClusterCA verifies a server's own leaf the
// way a root client does: with the cluster CA alone and the Service address, over
// both of the ways a server's kubeconfig addresses it.
func TestServerAPIServerCertVerifiesAgainstTheClusterCA(t *testing.T) {
	for _, mesh := range []string{"", tlsSANTestMesh} {
		dir, ca := tlsSANWorkDir(t)
		if _, _, err := writeAPIServerServingCert(dir, ca, mesh, "", "k3sm-cp", nil, tlsSANTestLogger); err != nil {
			t.Fatalf("issue: %v", err)
		}
		data, err := os.ReadFile(certs.APIServerServingCertPath(dir))
		if err != nil {
			t.Fatal(err)
		}
		block, _ := pem.Decode(data)
		leaf, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(ca.CertPEM) {
			t.Fatal("the CA did not load")
		}
		opts := x509.VerifyOptions{Roots: pool, DNSName: kubeclient.APIServerName(), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
		if _, err := leaf.Verify(opts); err != nil {
			t.Errorf("mesh %q: %v", mesh, err)
		}
		if ca.Cert.MaxPathLen != 0 || !ca.Cert.MaxPathLenZero {
			t.Errorf("the cluster CA allows an intermediate: MaxPathLen %d", ca.Cert.MaxPathLen)
		}
		if err := ca.Cert.CheckSignatureFrom(ca.Cert); err != nil {
			t.Errorf("the cluster CA is not self-signed: %v", err)
		}
		if err := checkClusterCAIssuer(leaf, ca.Cert); err != nil {
			t.Error(err)
		}
	}
}

// checkClusterCAIssuer reports a leaf the CA did not sign directly.
func checkClusterCAIssuer(leaf, ca *x509.Certificate) error {
	if err := leaf.CheckSignatureFrom(ca); err != nil {
		return fmt.Errorf("the serving leaf is not signed directly by the cluster CA: %w", err)
	}
	return nil
}

// fileRef is a pointer to a described file, for a table row where none means absent.
func fileRef(f sudoKubeconfigFile) *sudoKubeconfigFile { return &f }

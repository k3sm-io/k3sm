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
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net/url"
	"strings"
	"testing"
	"time"

	corev1listers "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/rest"

	"k3sm.io/k3sm/pkg/certs"
	"k3sm.io/k3sm/pkg/install"
	"k3sm.io/k3sm/pkg/kubeclient"
)

// fixtureCA mints a cluster CA as PEM.
func fixtureCA(t *testing.T) []byte {
	t.Helper()
	ca, err := certs.NewCA("k3sm-cluster-ca")
	if err != nil {
		t.Fatalf("mint a CA: %v", err)
	}
	return ca.CertPEM
}

// anchorReader reads one described file.
func anchorReader(f sudoKubeconfigFile, err error) func(string) (sudoKubeconfigFile, error) {
	return func(string) (sudoKubeconfigFile, error) { return f, err }
}

func TestNetdPinsTheInformersOnAWorkerOnly(t *testing.T) {
	workerCredential := install.AgentCredentialPath(install.DefaultDataRoot)
	tests := []struct {
		name string
		opts netdOptions
		want string
	}{
		{name: "worker", opts: netdOptions{kubeconfig: workerCredential, clusterCA: install.AgentClusterCAPath}, want: install.AgentClusterCAPath},
		{name: "worker on a data root of its own", opts: netdOptions{kubeconfig: "/Volumes/k3sm/agent/kubeconfig", clusterCA: install.AgentClusterCAPath}, want: install.AgentClusterCAPath},
		{name: "worker whose plist has no --cluster-ca", opts: netdOptions{kubeconfig: workerCredential}, want: install.AgentClusterCAPath},
		{name: "server", opts: netdOptions{kubeconfig: "/var/lib/k3sm/server/k3sm.kubeconfig", clusterCA: "/var/lib/k3sm/server/pki/cluster-ca.crt"}},
		{name: "server whose plist has no --cluster-ca", opts: netdOptions{kubeconfig: "/var/lib/k3sm/server/k3sm.kubeconfig"}},
		{name: "no kubeconfig"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.opts.authorizerKube()
			if got.clusterCA != tt.want || got.kubeconfig != tt.opts.kubeconfig {
				t.Errorf("authorizerKube() = %+v, want clusterCA %q", got, tt.want)
			}
		})
	}
}

// TestWorkerInformerTakesItsCAFromTheRootCopy reads a node kubeconfig that names
// another CA and asks for what the informers would trust.
func TestWorkerInformerTakesItsCAFromTheRootCopy(t *testing.T) {
	res, _, _ := nodeCredFixture(t, nodeCredClientTTL, nodeCredClientTTL)
	path := savedStore(t, res).kubeconfigPath()
	anchor := fixtureCA(t)
	if bytes.Equal(anchor, res.ClusterCAPEM) {
		t.Fatal("the fixture's two CAs are one, so this would prove nothing")
	}

	t.Run("worker", func(t *testing.T) {
		k := authorizerKube{kubeconfig: path, clusterCA: "/root/ca.crt", readFile: anchorReader(regular(0, 0o644, string(anchor)), nil)}
		cfg, cs, err := k.load()
		if err != nil {
			t.Fatalf("load: %v", err)
		}
		if cs == nil || !bytes.Equal(cfg.CAData, anchor) {
			t.Errorf("clientset = %v, the informers' CA is the root copy = %t", cs, bytes.Equal(cfg.CAData, anchor))
		}
		if len(cfg.CertData) == 0 || len(cfg.KeyData) == 0 {
			t.Error("the node's client credential did not come from the kubeconfig")
		}
	})
	t.Run("server", func(t *testing.T) {
		k := authorizerKube{kubeconfig: path, readFile: func(string) (sudoKubeconfigFile, error) {
			t.Error("a server read a root CA copy")
			return sudoKubeconfigFile{}, nil
		}}
		cfg, _, err := k.load()
		if err != nil {
			t.Fatalf("load: %v", err)
		}
		if !bytes.Equal(cfg.CAData, res.ClusterCAPEM) {
			t.Error("a server's informers no longer take their CA from its kubeconfig")
		}
	})
}

// TestWorkerInformerRefusesAnUnusableCA drives each way the root copy can be
// unusable through the WARN a person reads.
func TestWorkerInformerRefusesAnUnusableCA(t *testing.T) {
	anchor := string(fixtureCA(t))
	tests := []struct {
		name string
		read func(string) (sudoKubeconfigFile, error)
		want string
	}{
		{name: "missing", read: anchorReader(sudoKubeconfigFile{}, fmt.Errorf("open: %w", fs.ErrNotExist)), want: "does not exist"},
		{name: "another owner", read: anchorReader(regular(501, 0o644, anchor), nil), want: "owned by uid 501, not root"},
		{name: "group-writable", read: anchorReader(regular(0, 0o664, anchor), nil), want: "group- or world-writable"},
		{name: "not a regular file", read: anchorReader(sudoKubeconfigFile{uid: 0, mode: fs.ModeNamedPipe}, nil), want: "not a regular file"},
		{name: "no certificate", read: anchorReader(regular(0, 0o644, "not pem"), nil), want: "holds no PEM certificate"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := writeServiceKubeconfig(t)
			k := authorizerKube{kubeconfig: path, clusterCA: "/root/ca.crt", readFile: tt.read}

			_, svcErr := startServiceInformer(context.Background(), k)
			_, _, podErr := startVMPodInformers(context.Background(), k)
			for name, err := range map[string]error{"service": svcErr, "pod": podErr} {
				if !isClusterAnchorError(err) || !strings.Contains(err.Error(), tt.want) {
					t.Errorf("%s informer err = %v, want a CA refusal naming %q", name, err, tt.want)
				}
			}

			h := &levelCounter{}
			var l authorizerFailureLog
			l.note(slog.New(h), path, svcErr)
			if got := h.count(slog.LevelWarn); got != 1 {
				t.Errorf("WARN records = %d, want 1 on first sighting", got)
			}
			for _, want := range []string{"root-only cluster CA is missing or unusable", "sudo k3sm install --agent --server", "--token-file"} {
				if !strings.Contains(h.text.String(), want) {
					t.Errorf("log lacks %q:\n%s", want, h.text.String())
				}
			}
		})
	}
}

// TestAuthorizerKeepsRetryingWithoutTheClusterCA pins that the refusal leaves the
// retry loop running, so a later install's copy is taken up with no restart.
func TestAuthorizerKeepsRetryingWithoutTheClusterCA(t *testing.T) {
	k := authorizerKube{
		kubeconfig: writeServiceKubeconfig(t),
		clusterCA:  "/root/ca.crt",
		readFile:   anchorReader(sudoKubeconfigFile{}, fmt.Errorf("open: %w", fs.ErrNotExist)),
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	h := &attemptCounter{want: 2, done: make(chan struct{})}
	installed := make(chan struct{}, 1)
	returned := make(chan struct{})
	go func() {
		defer close(returned)
		activateServiceAuthorizer(ctx, k, slog.New(h), func(corev1listers.ServiceLister) {
			installed <- struct{}{}
		})
	}()
	select {
	case <-h.done:
	case <-returned:
		t.Fatal("the retry loop returned on a refused CA")
	case <-ctx.Done():
		t.Fatal("no second attempt within the test's bound")
	}
	cancel()
	<-returned
	select {
	case <-installed:
		t.Error("a lister was installed with no usable CA")
	default:
	}
}

// TestAuthorizerNamesAServerOutsideTheClusterCA pins that a certificate failure,
// which never clears on its own, is warned once its window has held.
func TestAuthorizerNamesAServerOutsideTheClusterCA(t *testing.T) {
	err := fmt.Errorf("service cache did not sync: %w", &url.Error{Op: "Get", URL: "https://192.0.2.1:6443", Err: x509.UnknownAuthorityError{}})
	reason, class, window := authorizerFailureReason(err)
	if class != failWindowed || window != credentialRejectedWarnAfter || !strings.Contains(reason, "does not chain") {
		t.Errorf("reason %q, class %v, window %d", reason, class, window)
	}
	if got := authorizerRemedy(err); got != clusterAnchorRemedy {
		t.Errorf("remedy = %q", got)
	}
	if _, class, _ := authorizerFailureReason(errors.New("dial tcp: connection refused")); class != failDebug {
		t.Errorf("a dial failure's class = %v, want failDebug", class)
	}
}

// TestPinnedConfigBuildsATLSConfig is the check on the node kubeconfig's real
// shape: with the file's inline CA replaced, client-go still accepts the config.
func TestPinnedConfigBuildsATLSConfig(t *testing.T) {
	res, _, _ := nodeCredFixture(t, nodeCredClientTTL, nodeCredClientTTL)
	cfg, _, err := kubeclient.FromCheckedPathWithCA(savedStore(t, res).kubeconfigPath(), res.ClusterCAPEM)
	if err != nil {
		t.Fatalf("FromCheckedPathWithCA: %v", err)
	}
	if _, err := rest.TLSConfigFor(cfg); err != nil {
		t.Errorf("TLSConfigFor: %v", err)
	}
}

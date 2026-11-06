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
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	corev1listers "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"

	"k3sm.io/k3sm/pkg/install"
	"k3sm.io/k3sm/pkg/kubeclient"
)

// saveExecEntry adds an exec entry to the current user of the kubeconfig at path.
// It names a harmless program that records being run, and it returns that record's
// path for assertNeverRan.
func saveExecEntry(t *testing.T, path string) (ran string) {
	t.Helper()
	dir := t.TempDir()
	ran = filepath.Join(dir, "ran")
	helper := filepath.Join(dir, "helper.sh")
	if err := os.WriteFile(helper, []byte("#!/bin/sh\n: > '"+ran+"'\n"), 0o700); err != nil {
		t.Fatalf("write helper: %v", err)
	}
	raw, err := clientcmd.LoadFromFile(path)
	if err != nil {
		t.Fatalf("load kubeconfig: %v", err)
	}
	raw.AuthInfos[raw.Contexts[raw.CurrentContext].AuthInfo].Exec = &clientcmdapi.ExecConfig{
		APIVersion:      "client.authentication.k8s.io/v1",
		Command:         helper,
		InteractiveMode: clientcmdapi.NeverExecInteractiveMode,
	}
	if err := clientcmd.WriteToFile(*raw, path); err != nil {
		t.Fatalf("write kubeconfig: %v", err)
	}
	return ran
}

func assertNeverRan(t *testing.T, ran string) {
	t.Helper()
	if _, err := os.Stat(ran); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("the exec entry ran: stat %s = %v", ran, err)
	}
}

// writeServiceKubeconfig writes a token kubeconfig of the executor's shape.
func writeServiceKubeconfig(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "k3sm.kubeconfig")
	cfg := clientcmdapi.NewConfig()
	cfg.Clusters["k3sm"] = &clientcmdapi.Cluster{Server: "https://127.0.0.1:1", InsecureSkipTLSVerify: true}
	cfg.AuthInfos["admin"] = &clientcmdapi.AuthInfo{Token: "fixture-token"}
	cfg.Contexts["k3sm"] = &clientcmdapi.Context{Cluster: "k3sm", AuthInfo: "admin"}
	cfg.CurrentContext = "k3sm"
	if err := clientcmd.WriteToFile(*cfg, path); err != nil {
		t.Fatalf("write kubeconfig: %v", err)
	}
	return path
}

// TestNodeKubeconfigIsInlineOnly pins the file the join writes to what its readers
// accept: a worker's netd loads it through FromCheckedPath.
func TestNodeKubeconfigIsInlineOnly(t *testing.T) {
	res, _, _ := nodeCredFixture(t, nodeCredClientTTL, nodeCredClientTTL)
	store := savedStore(t, res)
	cfg, _, err := kubeclient.FromCheckedPath(store.kubeconfigPath())
	if err != nil {
		t.Fatalf("FromCheckedPath: %v", err)
	}
	if len(cfg.CertData) == 0 || len(cfg.KeyData) == 0 || len(cfg.CAData) == 0 {
		t.Errorf("cert, key and CA bytes = %d, %d, %d, want all carried inline", len(cfg.CertData), len(cfg.KeyData), len(cfg.CAData))
	}
}

// TestStartServiceInformerAcceptsOnlyInlineCredentials pins the refusal's wrap and
// the WARN a person reads: one line, naming the reason and not the entry, repeated
// only at the reminder cadence.
func TestStartServiceInformerAcceptsOnlyInlineCredentials(t *testing.T) {
	path := writeServiceKubeconfig(t)
	ran := saveExecEntry(t, path)

	_, err := startServiceInformer(context.Background(), path)
	if !errors.Is(err, kubeclient.ErrCredentialsNotInline) {
		t.Fatalf("err = %v, want ErrCredentialsNotInline", err)
	}
	if !strings.HasPrefix(err.Error(), "load kubeconfig: ") {
		t.Errorf("err = %q, want netd's own `load kubeconfig: ` wrap", err)
	}
	assertNeverRan(t, ran)

	h := &levelCounter{}
	var l authorizerFailureLog
	l.note(slog.New(h), path, err)
	l.note(slog.New(h), path, err)
	if got := h.count(slog.LevelWarn); got != 1 {
		t.Errorf("WARN records = %d, want 1\n%s", got, h.text.String())
	}
	if !strings.Contains(h.text.String(), "netd accepts only inline credentials") {
		t.Errorf("log does not name the reason:\n%s", h.text.String())
	}
}

// attemptCounter is a slog handler that signals once it has seen want records.
// activateServiceAuthorizer logs once per failed attempt, so records count attempts.
type attemptCounter struct {
	levelCounter
	want int
	seen int
	done chan struct{}
}

func (h *attemptCounter) Handle(ctx context.Context, r slog.Record) error {
	h.seen++
	if h.seen == h.want {
		close(h.done)
	}
	return h.levelCounter.Handle(ctx, r)
}

// TestAuthorizerKeepsRetryingARefusedKubeconfig pins that a refused file neither
// ends the retry loop nor installs a lister: the file can be corrected without
// restarting netd.
func TestAuthorizerKeepsRetryingARefusedKubeconfig(t *testing.T) {
	path := writeServiceKubeconfig(t)
	ran := saveExecEntry(t, path)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	h := &attemptCounter{want: 2, done: make(chan struct{})}
	installed := make(chan struct{}, 1)
	returned := make(chan struct{})
	go func() {
		defer close(returned)
		activateServiceAuthorizer(ctx, path, slog.New(h), func(corev1listers.ServiceLister) {
			installed <- struct{}{}
		})
	}()

	select {
	case <-h.done:
	case <-returned:
		t.Fatal("the retry loop returned on a refused kubeconfig")
	case <-ctx.Done():
		t.Fatal("no second attempt within the test's bound")
	}
	cancel()
	<-returned

	select {
	case <-installed:
		t.Error("a lister was installed from a refused kubeconfig")
	default:
	}
	assertNeverRan(t, ran)
}

// plistPresentSystem reports every plist as installed, which makes the node a
// worker for lifecycleNodeIdentity.
type plistPresentSystem struct{ install.System }

func (plistPresentSystem) ReadFile(string) ([]byte, error) { return []byte("<plist/>"), nil }

// TestLifecycleVerbsAcceptOnlyInlineCredentials drives the two lifecycle loads
// against a worker whose stored credential is otherwise valid, so the refusal is
// the only thing that can stop them.
func TestLifecycleVerbsAcceptOnlyInlineCredentials(t *testing.T) {
	dataRoot := t.TempDir()
	store := nodeCredentialStore{dir: filepath.Dir(install.AgentCredentialPath(dataRoot))}
	if err := os.MkdirAll(store.dir, 0o700); err != nil {
		t.Fatal(err)
	}
	res, _, _ := nodeCredFixture(t, nodeCredClientTTL, nodeCredClientTTL)
	if err := store.Save("https://127.0.0.1:1", nodeCredTestNode, res); err != nil {
		t.Fatalf("save credential: %v", err)
	}
	ran := saveExecEntry(t, store.kubeconfigPath())
	sys := plistPresentSystem{}

	t.Run("node marker", func(t *testing.T) {
		err := nodeMarker(sys, dataRoot)(context.Background(), true, "actor", "reason")
		if !errors.Is(err, kubeclient.ErrCredentialsNotInline) {
			t.Fatalf("err = %v, want ErrCredentialsNotInline", err)
		}
		if !strings.Contains(err.Error(), store.kubeconfigPath()) {
			t.Errorf("err = %q, want it to name the file", err)
		}
	})
	t.Run("joined workers", func(t *testing.T) {
		_, err := joinedWorkers(sys, dataRoot)(context.Background())
		if !errors.Is(err, kubeclient.ErrCredentialsNotInline) {
			t.Fatalf("err = %v, want ErrCredentialsNotInline", err)
		}
	})
	assertNeverRan(t, ran)
}

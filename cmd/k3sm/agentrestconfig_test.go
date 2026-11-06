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
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"k3sm.io/k3sm/pkg/bootstrap"
	"k3sm.io/k3sm/pkg/hostnet"
	"k3sm.io/k3sm/pkg/install"
	"k3sm.io/k3sm/pkg/kubeclient"
)

// TestRootAgentLoadsAreChecked pins the agent's own loads as root, with their wraps
// kept, and that another account keeps kubeconfig's full loader.
func TestRootAgentLoadsAreChecked(t *testing.T) {
	res, _, _ := nodeCredFixture(t, nodeCredClientTTL, nodeCredClientTTL)
	saved := savedStore(t, res).kubeconfigPath()
	plain, err := os.ReadFile(saved)
	if err != nil {
		t.Fatal(err)
	}
	withExec := filepath.Join(t.TempDir(), "kubeconfig")
	if err := os.WriteFile(withExec, plain, 0o600); err != nil {
		t.Fatal(err)
	}
	ran := saveExecEntry(t, withExec)
	t.Cleanup(func() { assertNeverRan(t, ran) })

	netserve := func(path string) error {
		_, err := startWorkerNetserve(context.Background(), agentOptions{workDir: t.TempDir()},
			&bootstrap.JoinResult{PodCIDR: "100.64.2.0/24", MeshIP: "100.64.2.1"}, hostnet.Mode{Backend: hostnet.BackendNone},
			path, workerNetserveRotation{}, quietLogger())
		return err
	}
	peers := func(path string) error {
		_, err := meshPeerLister(path)(context.Background())
		return err
	}
	mesh := func(path string) error {
		_, err := agentRESTConfig(path)
		return err
	}

	t.Run("root refuses an entry that is not inline", func(t *testing.T) {
		asRoot(t)
		for name, load := range map[string]func(string) error{"netserve": netserve, "peers": peers, "mesh watch": mesh} {
			if err := load(withExec); !errors.Is(err, kubeclient.ErrCredentialsNotInline) {
				t.Errorf("%s: err = %v, want ErrCredentialsNotInline", name, err)
			}
		}
		if err := netserve(withExec); !strings.HasPrefix(err.Error(), "load the netserve kubeconfig for the node-local datapath: ") {
			t.Errorf("netserve err = %q, want the site's wrap", err)
		}
		if err := peers(withExec); !strings.HasPrefix(err.Error(), "load kubeconfig for the MeshPeer list: ") {
			t.Errorf("peers err = %q, want the site's wrap", err)
		}
	})
	t.Run("root takes an inline file", func(t *testing.T) {
		asRoot(t)
		cfg, err := agentRESTConfig(saved)
		if err != nil || cfg.Host == "" {
			t.Errorf("load = %+v, %v", cfg, err)
		}
	})
	t.Run("another account keeps the full loader", func(t *testing.T) {
		prev := processEuid
		processEuid = func() int { return 501 }
		t.Cleanup(func() { processEuid = prev })
		cfg, err := agentRESTConfig(withExec)
		if err != nil || cfg.ExecProvider == nil {
			t.Errorf("load = %+v, %v", cfg, err)
		}
	})
}

// TestRootNodeAndServerLoadsAreChecked pins the node's client, the flat registry
// lookup and the server's admin client: as root they take only inline credentials,
// the files k3sm itself writes pass, and another account keeps the full loader.
func TestRootNodeAndServerLoadsAreChecked(t *testing.T) {
	res, _, _ := nodeCredFixture(t, nodeCredClientTTL, nodeCredClientTTL)
	saved := savedStore(t, res).kubeconfigPath()
	plain, err := os.ReadFile(saved)
	if err != nil {
		t.Fatal(err)
	}
	withExec := filepath.Join(t.TempDir(), "kubeconfig")
	if err := os.WriteFile(withExec, plain, 0o600); err != nil {
		t.Fatal(err)
	}
	ran := saveExecEntry(t, withExec)
	t.Cleanup(func() { assertNeverRan(t, ran) })
	admin, err := install.AdminKubeconfig(install.Config{ClusterCA: fixtureCA(t), AdminToken: "admin-token"})
	if err != nil {
		t.Fatal(err)
	}
	adminPath := filepath.Join(t.TempDir(), "k3sm.kubeconfig")
	if err := os.WriteFile(adminPath, admin, 0o600); err != nil {
		t.Fatal(err)
	}

	t.Run("root refuses an entry that is not inline", func(t *testing.T) {
		asRoot(t)
		_, err := nodeRESTConfig(withExec)
		if !errors.Is(err, kubeclient.ErrCredentialsNotInline) {
			t.Fatalf("nodeRESTConfig err = %v, want ErrCredentialsNotInline", err)
		}
		if !strings.HasPrefix(err.Error(), "load kubeconfig: ") {
			t.Errorf("nodeRESTConfig err = %q, want the site's wrap", err)
		}
		if _, _, err := rootCheckedClient(withExec); !errors.Is(err, kubeclient.ErrCredentialsNotInline) {
			t.Errorf("rootCheckedClient err = %v, want ErrCredentialsNotInline", err)
		}
	})
	t.Run("root's flat registry lookup logs the refusal and maps nothing", func(t *testing.T) {
		asRoot(t)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		var logged bytes.Buffer
		got := agentFlatRegistry(ctx, withExec, res, slog.New(slog.NewTextHandler(&logged, nil)))
		if got.Addr != "" {
			t.Errorf("agentFlatRegistry = %+v, want the zero endpoint", got)
		}
		if !strings.Contains(logged.String(), kubeclient.ErrCredentialsNotInline.Error()) {
			t.Errorf("log lacks the refusal:\n%s", logged.String())
		}
	})
	t.Run("root takes the node credential and the admin kubeconfig k3sm writes", func(t *testing.T) {
		asRoot(t)
		cfg, err := nodeRESTConfig(saved)
		if err != nil {
			t.Fatalf("nodeRESTConfig: %v", err)
		}
		if cfg.Timeout != nodeAPIRequestTimeout || cfg.QPS != 50 || cfg.Burst != 100 {
			t.Errorf("budget = %s, %v, %d", cfg.Timeout, cfg.QPS, cfg.Burst)
		}
		for _, path := range []string{saved, adminPath} {
			if cfg, cs, err := rootCheckedClient(path); err != nil || cs == nil || cfg.Host == "" {
				t.Errorf("rootCheckedClient(%s) = %+v, %v, %v", path, cfg, cs, err)
			}
			if _, err := agentRESTConfig(path); err != nil {
				t.Errorf("agentRESTConfig(%s): %v", path, err)
			}
		}
	})
	t.Run("another account keeps the full loader", func(t *testing.T) {
		prev := processEuid
		processEuid = func() int { return 501 }
		t.Cleanup(func() { processEuid = prev })
		cfg, err := nodeRESTConfig(withExec)
		if err != nil || cfg.ExecProvider == nil {
			t.Errorf("nodeRESTConfig = %+v, %v", cfg, err)
		}
		if cfg, _, err := rootCheckedClient(withExec); err != nil || cfg.ExecProvider == nil {
			t.Errorf("rootCheckedClient = %+v, %v", cfg, err)
		}
	})
}

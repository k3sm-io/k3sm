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
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"k3sm.io/k3sm/pkg/bootstrap"
	"k3sm.io/k3sm/pkg/executor"
	"k3sm.io/k3sm/pkg/hostnet"
)

// writeKubeconfigAt writes a minimal kubeconfig naming server at path (creating
// its parent), and returns path. Same shape as writeNodeRESTKubeconfig, but the
// caller chooses the path: the sites below load a kubeconfig at a location they
// derive themselves (the builder's work dir), so the test must be able to put a
// real file exactly there.
func writeKubeconfigAt(t *testing.T, path, server string) string {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatalf("mkdir kubeconfig dir: %v", err)
	}
	body := fmt.Sprintf(`apiVersion: v1
kind: Config
clusters:
- name: k3sm
  cluster:
    server: %s
contexts:
- name: k3sm
  context:
    cluster: k3sm
    user: k3sm
current-context: k3sm
users:
- name: k3sm
  user: {}
`, server)
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write kubeconfig: %v", err)
	}
	return path
}

// writeUnparseableKubeconfigAt writes a file that EXISTS but cannot be parsed as
// a kubeconfig, so a site's existence pre-check passes and the failure lands in
// the loader — which is the only way to observe a site's own wrap of a load
// error without standing up an apiserver.
func writeUnparseableKubeconfigAt(t *testing.T, path string) string {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatalf("mkdir kubeconfig dir: %v", err)
	}
	if err := os.WriteFile(path, []byte("{{ this is not a kubeconfig\n"), 0o600); err != nil {
		t.Fatalf("write kubeconfig: %v", err)
	}
	return path
}

// TestNewKubeClientResolution is the characterization table for every command
// site that loads an explicitly-named kubeconfig and builds a client from it
// (B251). It is written against the pre-refactor behaviour and KEPT afterwards:
// folding those inline clientcmd+kubernetes pairs onto one helper is a refactor
// only if every one of these verdicts is unchanged.
//
// What it pins, per site: which file the site reads (an absent kubeconfig at the
// site's own path is an error, and the message is the SITE's, not the loader's),
// and that a present-but-unparseable file still surfaces through the site's own
// wrap. What it deliberately does not pin here is the resolved rest.Config Host
// — none of these sites returns its rest.Config, and inventing a seam to observe
// one would change the code the table is supposed to hold still. That assertion
// lives in pkg/kubeclient's own test, against the loader all of them share.
//
// Each site keeps its own credential and its own precedence: the helper resolves
// an explicit path and nothing else, so nothing here may start resolving
// KUBECONFIG or ~/.kube/config (see pkg/kubeclient's doc comment).
//
// The sixth migrated site, server.go's post-bring-up admin client, has NO row:
// it sits mid-runServer, after exec.Start has fork/exec'd a real control plane,
// so there is no way to reach its loader without one. What holds it still
// instead is that its wrap ("load kubeconfig: %w" over exec.Kubeconfig()) is
// unchanged in the diff and the helper adds nothing to a load error — the same
// two facts every row below checks mechanically. Saying so here is the honest
// version of an assertion that cannot be written.
func TestNewKubeClientResolution(t *testing.T) {
	t.Run("builder loads the work-dir kubeconfig", func(t *testing.T) {
		workDir := t.TempDir()
		writeKubeconfigAt(t, executor.KubeconfigPath(workDir), "https://127.0.0.1:6443")
		mgr, err := newBuilderManager(builderOptions{workDir: workDir})
		if err != nil {
			t.Fatalf("newBuilderManager with a real kubeconfig: %v", err)
		}
		if mgr == nil {
			t.Fatal("newBuilderManager returned a nil manager and no error")
		}
	})

	t.Run("builder absent kubeconfig names `k3sm server` verbatim", func(t *testing.T) {
		workDir := t.TempDir()
		kc := executor.KubeconfigPath(workDir)
		_, err := newBuilderManager(builderOptions{workDir: workDir})
		if err == nil {
			t.Fatal("expected an error for a missing kubeconfig")
		}
		want := fmt.Sprintf("kubeconfig %s not found — run `k3sm server` first (set --work-dir or K3SM_WORK_DIR if you used a non-default `k3sm server --work-dir`)", kc)
		if err.Error() != want {
			t.Errorf("error = %q, want %q", err.Error(), want)
		}
	})

	t.Run("builder unparseable kubeconfig keeps the site's load wrap", func(t *testing.T) {
		workDir := t.TempDir()
		kc := writeUnparseableKubeconfigAt(t, executor.KubeconfigPath(workDir))
		_, err := newBuilderManager(builderOptions{workDir: workDir})
		if err == nil {
			t.Fatal("expected an error for an unparseable kubeconfig")
		}
		if !strings.HasPrefix(err.Error(), fmt.Sprintf("load kubeconfig %s: ", kc)) {
			t.Errorf("error = %q, want the site's own `load kubeconfig %s: ` wrap", err.Error(), kc)
		}
	})

	t.Run("netd absent kubeconfig fails its existence check", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, err := startServiceInformer(ctx, filepath.Join(t.TempDir(), "absent.kubeconfig"))
		if err == nil {
			t.Fatal("expected an error for a missing kubeconfig")
		}
		if !strings.HasPrefix(err.Error(), "stat kubeconfig: ") {
			t.Errorf("error = %q, want netd's own `stat kubeconfig: ` pre-check wrap", err.Error())
		}
	})

	t.Run("netd unparseable kubeconfig keeps the site's load wrap", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		kc := writeUnparseableKubeconfigAt(t, filepath.Join(t.TempDir(), "kubeconfig"))
		_, err := startServiceInformer(ctx, kc)
		if err == nil {
			t.Fatal("expected an error for an unparseable kubeconfig")
		}
		if !strings.HasPrefix(err.Error(), "load kubeconfig: ") {
			t.Errorf("error = %q, want netd's own `load kubeconfig: ` wrap", err.Error())
		}
	})

	t.Run("agent datapath absent kubeconfig keeps the site's wrap", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, err := startWorkerNetserve(ctx, agentOptions{workDir: t.TempDir()},
			&bootstrap.JoinResult{PodCIDR: "100.64.2.0/24", MeshIP: "100.64.2.1"},
			hostnet.Mode{Backend: hostnet.BackendNone},
			filepath.Join(t.TempDir(), "absent.kubeconfig"), quietLogger())
		if err == nil {
			t.Fatal("expected an error for a missing kubeconfig")
		}
		if !strings.HasPrefix(err.Error(), "load node kubeconfig for node-local datapath: ") {
			t.Errorf("error = %q, want the agent's own datapath wrap", err.Error())
		}
	})

	t.Run("agent datapath unparseable kubeconfig keeps the site's wrap", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		kc := writeUnparseableKubeconfigAt(t, filepath.Join(t.TempDir(), "kubeconfig"))
		_, err := startWorkerNetserve(ctx, agentOptions{workDir: t.TempDir()},
			&bootstrap.JoinResult{PodCIDR: "100.64.2.0/24", MeshIP: "100.64.2.1"},
			hostnet.Mode{Backend: hostnet.BackendNone},
			kc, quietLogger())
		if err == nil {
			t.Fatal("expected an error for an unparseable kubeconfig")
		}
		if !strings.HasPrefix(err.Error(), "load node kubeconfig for node-local datapath: ") {
			t.Errorf("error = %q, want the agent's own datapath wrap", err.Error())
		}
	})
}

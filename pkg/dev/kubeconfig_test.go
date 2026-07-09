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

package dev

import (
	"os"
	"path/filepath"
	"testing"

	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
)

// writeKubeconfigFile renders cfg to path (test helper).
func writeKubeconfigFile(path string, cfg *clientcmdapi.Config) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return clientcmd.WriteToFile(*cfg, path)
}

// loadKubeconfigFile reads a kubeconfig back (test helper).
func loadKubeconfigFile(t *testing.T, path string) *clientcmdapi.Config {
	t.Helper()
	cfg, err := clientcmd.LoadFromFile(path)
	if err != nil {
		t.Fatalf("load %s: %v", path, err)
	}
	return cfg
}

// writeExecutable creates a non-empty 0755 file (a stand-in native binary) for
// the `load` staging test.
func writeExecutable(path string) error {
	return os.WriteFile(path, []byte("#!/bin/sh\n"), 0o755)
}

// instanceKubeconfig is a minimal k3sm admin kubeconfig (one cluster/user/context
// under the well-known names) — the shape the executor writes.
func instanceKubeconfig() *clientcmdapi.Config {
	c := clientcmdapi.NewConfig()
	c.Clusters["k3sm"] = &clientcmdapi.Cluster{Server: "https://127.0.0.1:16450", InsecureSkipTLSVerify: true}
	c.AuthInfos["admin"] = &clientcmdapi.AuthInfo{Token: "dev-token"}
	c.Contexts["k3sm"] = &clientcmdapi.Context{Cluster: "k3sm", AuthInfo: "admin"}
	c.CurrentContext = "k3sm"
	return c
}

func TestMergeIntoRewiresAndSetsCurrent(t *testing.T) {
	dst := clientcmdapi.NewConfig()
	// A pre-existing unrelated context must be preserved.
	dst.Clusters["other"] = &clientcmdapi.Cluster{Server: "https://example:6443"}
	dst.AuthInfos["other"] = &clientcmdapi.AuthInfo{Token: "x"}
	dst.Contexts["other"] = &clientcmdapi.Context{Cluster: "other", AuthInfo: "other"}
	dst.CurrentContext = "other"

	merged, err := mergeInto(dst, instanceKubeconfig(), "k3sm-dev-alpha")
	if err != nil {
		t.Fatalf("mergeInto: %v", err)
	}
	if merged.CurrentContext != "k3sm-dev-alpha" {
		t.Errorf("current-context = %q, want k3sm-dev-alpha", merged.CurrentContext)
	}
	kctx := merged.Contexts["k3sm-dev-alpha"]
	if kctx == nil || kctx.Cluster != "k3sm-dev-alpha" || kctx.AuthInfo != "k3sm-dev-alpha" {
		t.Errorf("merged context = %+v, want it rewired to the dev name", kctx)
	}
	if _, ok := merged.Contexts["other"]; !ok {
		t.Error("merge dropped the pre-existing 'other' context")
	}
}

func TestMergeIntoMissingParts(t *testing.T) {
	empty := clientcmdapi.NewConfig()
	if _, err := mergeInto(clientcmdapi.NewConfig(), empty, "k3sm-dev-x"); err == nil {
		t.Error("mergeInto with an empty src = nil, want an error (missing cluster/user/context)")
	}
}

func TestKubeMergerMergeAndRemoveRoundTrip(t *testing.T) {
	home := t.TempDir()
	srcPath := filepath.Join(home, "instance.kubeconfig")
	if err := writeKubeconfigFile(srcPath, instanceKubeconfig()); err != nil {
		t.Fatal(err)
	}
	// chownUID<0 → not-under-sudo; dest is home/.kube/config.
	km := &kubeMerger{chownUID: -1, chownGID: -1}
	dest := filepath.Join(home, ".kube", "config")
	t.Setenv("HOME", home) // userHomeFor falls back to os.UserHomeDir with no chownUser

	if err := km.merge(srcPath, "k3sm-dev-alpha"); err != nil {
		t.Fatalf("merge: %v", err)
	}
	got := loadKubeconfigFile(t, dest)
	if got.CurrentContext != "k3sm-dev-alpha" {
		t.Errorf("after merge current-context = %q, want k3sm-dev-alpha", got.CurrentContext)
	}
	if _, ok := got.Contexts["k3sm-dev-alpha"]; !ok {
		t.Fatal("merge did not add the dev context")
	}

	if err := km.remove("k3sm-dev-alpha"); err != nil {
		t.Fatalf("remove: %v", err)
	}
	got = loadKubeconfigFile(t, dest)
	if _, ok := got.Contexts["k3sm-dev-alpha"]; ok {
		t.Error("remove did not drop the dev context")
	}
	if got.CurrentContext == "k3sm-dev-alpha" {
		t.Error("remove did not clear current-context pointing at the dev context")
	}
}

func TestKubeMergerRemoveMissingConfigNoop(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	km := &kubeMerger{chownUID: -1, chownGID: -1}
	if err := km.remove("k3sm-dev-none"); err != nil {
		t.Errorf("remove on a missing ~/.kube/config = %v, want nil (no-op)", err)
	}
}

func TestKubeMergerDestPrecedence(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	def := filepath.Join(home, ".kube", "config")

	t.Run("default is ~/.kube/config when no override or env", func(t *testing.T) {
		t.Setenv("KUBECONFIG", "")
		km := &kubeMerger{chownUID: -1, chownGID: -1}
		got, err := km.dest()
		if err != nil {
			t.Fatalf("dest: %v", err)
		}
		if got != def {
			t.Errorf("dest = %q, want %q", got, def)
		}
	})

	t.Run("$KUBECONFIG first entry wins over the default", func(t *testing.T) {
		want := filepath.Join(home, "envkube.yaml")
		other := filepath.Join(home, "second.yaml")
		t.Setenv("KUBECONFIG", want+string(os.PathListSeparator)+other)
		km := &kubeMerger{chownUID: -1, chownGID: -1}
		got, err := km.dest()
		if err != nil {
			t.Fatalf("dest: %v", err)
		}
		if got != want {
			t.Errorf("dest = %q, want first $KUBECONFIG entry %q", got, want)
		}
	})

	t.Run("explicit override wins over $KUBECONFIG and the default", func(t *testing.T) {
		t.Setenv("KUBECONFIG", filepath.Join(home, "envkube.yaml"))
		want := filepath.Join(home, "explicit.yaml")
		km := &kubeMerger{chownUID: -1, chownGID: -1, path: want}
		got, err := km.dest()
		if err != nil {
			t.Fatalf("dest: %v", err)
		}
		if got != want {
			t.Errorf("dest = %q, want explicit override %q", got, want)
		}
	})
}

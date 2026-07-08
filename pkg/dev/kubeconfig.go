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
	"fmt"
	"os"
	"path/filepath"

	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
)

// kubeMerger merges an instance kubeconfig into the invoking user's
// ~/.kube/config under a dev context name (kind-parity: `up` selects it, `down`
// removes it). Under sudo it targets (and chowns to) the invoking human, not
// root, so kubectl works for the human after a datapath run. chownUID < 0 means
// "not under sudo — leave ownership alone."
type kubeMerger struct {
	chownUser string
	chownUID  int
	chownGID  int
	// path, when non-empty, overrides the default destination — set from
	// `--kubeconfig` / UpOptions.Kubeconfig so an existing ~/.kube/config is left
	// untouched.
	path string
}

// dest resolves the kubeconfig to merge into, in precedence order: an explicit
// override (--kubeconfig), then $KUBECONFIG (first entry, kubectl convention),
// then ~/.kube/config for the target user (the SUDO_USER human under sudo, else
// the current user).
func (k *kubeMerger) dest() (string, error) {
	if k.path != "" {
		return k.path, nil
	}
	if env := firstPathEntry(os.Getenv("KUBECONFIG")); env != "" {
		return env, nil
	}
	home, err := userHomeFor(k.chownUser)
	if err != nil {
		return "", fmt.Errorf("resolve ~/.kube/config home: %w", err)
	}
	return filepath.Join(home, ".kube", "config"), nil
}

// firstPathEntry returns the first non-empty entry of an os.PathListSeparator-
// joined list (KUBECONFIG is a colon-separated list; writes target its head).
func firstPathEntry(list string) string {
	for _, p := range filepath.SplitList(list) {
		if p != "" {
			return p
		}
	}
	return ""
}

// merge copies the sole cluster/user/context out of the instance kubeconfig at
// srcPath into ~/.kube/config under contextName, rewiring the context to
// reference it and setting it current (kind-parity). Atomic (temp + rename); the
// file is 0600 (bearer token). Under sudo the file is chowned to the human.
func (k *kubeMerger) merge(srcPath, contextName string) error {
	src, err := clientcmd.LoadFromFile(srcPath)
	if err != nil {
		return fmt.Errorf("load instance kubeconfig %s: %w", srcPath, err)
	}
	dest, err := k.dest()
	if err != nil {
		return err
	}
	dst := clientcmdapi.NewConfig()
	if existing, lerr := clientcmd.LoadFromFile(dest); lerr == nil {
		dst = existing
	} else if !os.IsNotExist(lerr) {
		return fmt.Errorf("load %s: %w", dest, lerr)
	}
	merged, err := mergeInto(dst, src, contextName)
	if err != nil {
		return err
	}
	return k.write(dest, merged)
}

// remove drops the dev context (plus its cluster/user of the same name) from
// ~/.kube/config and clears current-context if it pointed there. A missing
// config is a no-op (nothing to clean). Atomic + chowned like merge.
func (k *kubeMerger) remove(contextName string) error {
	dest, err := k.dest()
	if err != nil {
		return err
	}
	cfg, err := clientcmd.LoadFromFile(dest)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("load %s: %w", dest, err)
	}
	delete(cfg.Contexts, contextName)
	delete(cfg.Clusters, contextName)
	delete(cfg.AuthInfos, contextName)
	if cfg.CurrentContext == contextName {
		cfg.CurrentContext = ""
	}
	return k.write(dest, cfg)
}

// write renders cfg and atomically replaces dest (0600), creating ~/.kube. Under
// sudo it chowns the dir + file to the invoking human.
func (k *kubeMerger) write(dest string, cfg *clientcmdapi.Config) error {
	dir := filepath.Dir(dest)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("mkdir %s: %w", dir, err)
	}
	data, err := clientcmd.Write(*cfg)
	if err != nil {
		return fmt.Errorf("render kubeconfig: %w", err)
	}
	tmp, err := os.CreateTemp(dir, ".k3sm-dev-kubeconfig-*")
	if err != nil {
		return fmt.Errorf("create temp kubeconfig: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return fmt.Errorf("chmod temp kubeconfig: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("write temp kubeconfig: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp kubeconfig: %w", err)
	}
	if err := os.Rename(tmpName, dest); err != nil {
		return fmt.Errorf("rename kubeconfig into place: %w", err)
	}
	if k.chownUID >= 0 {
		_ = os.Chown(dir, k.chownUID, k.chownGID)
		_ = os.Chown(dest, k.chownUID, k.chownGID)
	}
	return nil
}

// mergeInto copies the sole cluster/user/context of src into dst under name,
// rewiring the context and setting current-context. Pure (no IO) so it is
// unit-testable. It errors if src is missing any of the three.
func mergeInto(dst, src *clientcmdapi.Config, name string) (*clientcmdapi.Config, error) {
	cl, user, kctx := sole(src.Clusters), soleAuth(src.AuthInfos), soleCtx(src.Contexts)
	if cl == nil || user == nil || kctx == nil {
		return nil, fmt.Errorf("instance kubeconfig is missing a cluster, user, or context")
	}
	if dst.Clusters == nil {
		dst.Clusters = map[string]*clientcmdapi.Cluster{}
	}
	if dst.AuthInfos == nil {
		dst.AuthInfos = map[string]*clientcmdapi.AuthInfo{}
	}
	if dst.Contexts == nil {
		dst.Contexts = map[string]*clientcmdapi.Context{}
	}
	dst.Clusters[name] = cl.DeepCopy()
	dst.AuthInfos[name] = user.DeepCopy()
	c := kctx.DeepCopy()
	c.Cluster = name
	c.AuthInfo = name
	dst.Contexts[name] = c
	dst.CurrentContext = name
	return dst, nil
}

// sole returns the k3sm cluster from a map that has exactly one (the instance
// admin kubeconfig), preferring the well-known "k3sm" name.
func sole(m map[string]*clientcmdapi.Cluster) *clientcmdapi.Cluster {
	if v, ok := m["k3sm"]; ok {
		return v
	}
	for _, v := range m {
		return v
	}
	return nil
}

func soleAuth(m map[string]*clientcmdapi.AuthInfo) *clientcmdapi.AuthInfo {
	if v, ok := m["admin"]; ok {
		return v
	}
	for _, v := range m {
		return v
	}
	return nil
}

func soleCtx(m map[string]*clientcmdapi.Context) *clientcmdapi.Context {
	if v, ok := m["k3sm"]; ok {
		return v
	}
	for _, v := range m {
		return v
	}
	return nil
}

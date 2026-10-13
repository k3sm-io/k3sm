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

package install

import (
	"fmt"
	"regexp"
	"strings"

	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
)

// adminContextName is the context/cluster/user name k3sm's admin kubeconfig
// carries (see AdminKubeconfig) and the name the merged context is keyed under in
// the user's ~/.kube/config.
const adminContextName = "k3sm"

// DefaultKubeconfigName is the cluster/user/context name the admin kubeconfig is
// merged under when `k3sm install` is not given --kubeconfig-name.
const DefaultKubeconfigName = adminContextName

// kubeconfigNameFlag is the `k3sm install` flag, and the server-argument name
// the chosen value is recorded under (the daemon ignores it; see
// Config.KubeconfigName).
const kubeconfigNameFlag = "kubeconfig-name"

var kubeconfigNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$`)

// ValidateKubeconfigName reports why name cannot key a kubeconfig cluster, user
// and context, or nil. The shape is narrow on purpose: the value is recorded in
// a root-owned argument record and rendered into a LaunchDaemon argv.
func ValidateKubeconfigName(name string) error {
	if !kubeconfigNamePattern.MatchString(name) {
		return fmt.Errorf("kubeconfig name %q is not valid: use 1 to 63 letters, digits, '.', '_' or '-', starting with a letter or digit", name)
	}
	return nil
}

// CheckAdminNameFree refuses a non-default name that already keys an entry in
// cfg that k3sm did not write. The default name keeps its historical behaviour
// (a merge replaces it). A custom name is ours only when the context, cluster
// and user all exist under it, the context wires them together, and the user
// carries a k3sm admin token; anything else, including a lone cluster or user
// of that name, belongs to someone else and is never overwritten or removed.
func CheckAdminNameFree(cfg *clientcmdapi.Config, name string) error {
	if name == DefaultKubeconfigName {
		return nil
	}
	kctx, cl, au := cfg.Contexts[name], cfg.Clusters[name], cfg.AuthInfos[name]
	if kctx == nil && cl == nil && au == nil {
		return nil
	}
	if ownedAdminEntry(cfg, name) {
		return nil
	}
	var kinds []string
	if kctx != nil {
		kinds = append(kinds, "context")
	}
	if cl != nil {
		kinds = append(kinds, "cluster")
	}
	if au != nil {
		kinds = append(kinds, "user")
	}
	return fmt.Errorf("the kubeconfig already has a %s named %q that k3sm did not create; choose another --kubeconfig-name", strings.Join(kinds, "/"), name)
}

// ownedAdminEntry reports whether name keys a complete admin entry k3sm wrote.
func ownedAdminEntry(cfg *clientcmdapi.Config, name string) bool {
	kctx, cl, au := cfg.Contexts[name], cfg.Clusters[name], cfg.AuthInfos[name]
	return kctx != nil && cl != nil && au != nil &&
		kctx.Cluster == name && kctx.AuthInfo == name &&
		strings.HasPrefix(au.Token, "k3sm-")
}

// mergeAdminKubeconfig merges the sole cluster/user/context from the k3sm admin
// kubeconfig `incoming` into `existing` (the user's ~/.kube/config, which may
// already hold unrelated clusters) under adminContextName, selects it as
// current-context, and returns the rendered result. Every pre-existing
// cluster/user/context is PRESERVED — install must never clobber a developer's
// other kubeconfig entries (uninstall likewise preserves the file). When
// `existing` is empty a fresh config is produced. Pure (no I/O) so the merge is
// unit-tested without a home dir.
func mergeAdminKubeconfig(existing, incoming []byte, name string) ([]byte, error) {
	src, err := clientcmd.Load(incoming)
	if err != nil {
		return nil, fmt.Errorf("parse admin kubeconfig: %w", err)
	}
	dst := clientcmdapi.NewConfig()
	if len(existing) > 0 {
		d, lerr := clientcmd.Load(existing)
		if lerr != nil {
			return nil, fmt.Errorf("parse existing kubeconfig: %w", lerr)
		}
		dst = d
	}
	if err := CheckAdminNameFree(dst, name); err != nil {
		return nil, err
	}
	merged, err := mergeContext(dst, src, name)
	if err != nil {
		return nil, err
	}
	out, err := clientcmd.Write(*merged)
	if err != nil {
		return nil, fmt.Errorf("render merged kubeconfig: %w", err)
	}
	return out, nil
}

// mergeContext copies the sole cluster/user/context of src into dst under name,
// rewiring the context to reference them and setting current-context. Entries
// already in dst are left untouched. Pure. Errors if src lacks a cluster, user,
// or context.
func mergeContext(dst, src *clientcmdapi.Config, name string) (*clientcmdapi.Config, error) {
	cl, user, kctx := soleCluster(src.Clusters), soleAuth(src.AuthInfos), soleContext(src.Contexts)
	if cl == nil || user == nil || kctx == nil {
		return nil, fmt.Errorf("admin kubeconfig is missing a cluster, user, or context")
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

// soleCluster returns the k3sm cluster from a map that has exactly one (the admin
// kubeconfig), preferring the well-known adminContextName.
func soleCluster(m map[string]*clientcmdapi.Cluster) *clientcmdapi.Cluster {
	if v, ok := m[adminContextName]; ok {
		return v
	}
	for _, v := range m {
		return v
	}
	return nil
}

func soleAuth(m map[string]*clientcmdapi.AuthInfo) *clientcmdapi.AuthInfo {
	if v, ok := m[adminContextName]; ok {
		return v
	}
	for _, v := range m {
		return v
	}
	return nil
}

func soleContext(m map[string]*clientcmdapi.Context) *clientcmdapi.Context {
	if v, ok := m[adminContextName]; ok {
		return v
	}
	for _, v := range m {
		return v
	}
	return nil
}

// unmergeAdminKubeconfig is mergeAdminKubeconfig's inverse, for `k3sm
// uninstall --purge`: it removes the context named name from existing and,
// only when they are also named name and no remaining context references them,
// the cluster and user that context referenced. current-context is cleared only
// when it was name. Every other entry is kept. changed is false (and out nil)
// when there is no such context, so a caller leaves the file untouched. Pure.
func unmergeAdminKubeconfig(existing []byte, name string) (out []byte, changed bool, err error) {
	if len(existing) == 0 {
		return nil, false, nil
	}
	cfg, err := clientcmd.Load(existing)
	if err != nil {
		return nil, false, fmt.Errorf("parse existing kubeconfig: %w", err)
	}
	kctx, ok := cfg.Contexts[name]
	if !ok {
		return nil, false, nil
	}
	if name != DefaultKubeconfigName && !ownedAdminEntry(cfg, name) {
		return nil, false, nil
	}
	delete(cfg.Contexts, name)
	referenced := func(cluster, user string) bool {
		for _, c := range cfg.Contexts {
			if (cluster != "" && c.Cluster == cluster) || (user != "" && c.AuthInfo == user) {
				return true
			}
		}
		return false
	}
	if kctx.Cluster == name && !referenced(name, "") {
		delete(cfg.Clusters, name)
	}
	if kctx.AuthInfo == name && !referenced("", name) {
		delete(cfg.AuthInfos, name)
	}
	if cfg.CurrentContext == name {
		cfg.CurrentContext = ""
	}
	out, err = clientcmd.Write(*cfg)
	if err != nil {
		return nil, false, fmt.Errorf("render kubeconfig: %w", err)
	}
	return out, true, nil
}

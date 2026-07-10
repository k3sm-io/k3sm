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

	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
)

// adminContextName is the context/cluster/user name k3sm's admin kubeconfig
// carries (see AdminKubeconfig) and the name the merged context is keyed under in
// the user's ~/.kube/config.
const adminContextName = "k3sm"

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

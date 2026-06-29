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
	"flag"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"

	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"

	"k3sm.io/k3sm/pkg/executor"
)

// runKubeconfig implements `k3sm kubeconfig`: print the admin kubeconfig, or
// (--write) merge the k3sm cluster/user/context into an existing kubeconfig
// (default ~/.kube/config) with an atomic write + .bak backup so the operator's
// own kubectl can reach the cluster. --server retargets the API endpoint for
// remote access; for any non-loopback server a CA (--certificate-authority) is
// REQUIRED — k3sm refuses to persist an insecure (skip-TLS-verify) admin context
// to a durable config off loopback.
func runKubeconfig(args []string) error {
	fs := flag.NewFlagSet("kubeconfig", flag.ExitOnError)
	var (
		write   bool
		path    string
		server  string
		caFile  string
		name    string
		setCurr bool
	)
	fs.BoolVar(&write, "write", false, "merge into an existing kubeconfig instead of printing to stdout")
	fs.StringVar(&path, "path", defaultKubeconfigDest(), "kubeconfig to merge into (with --write)")
	fs.StringVar(&server, "server", "", "override the apiserver URL (e.g. for remote access)")
	fs.StringVar(&caFile, "certificate-authority", "", "PEM CA bundle to embed (required when --server is non-loopback)")
	fs.StringVar(&name, "context-name", "k3sm", "name for the merged cluster/user/context")
	fs.BoolVar(&setCurr, "set-current", true, "set the merged context as current-context (with --write)")
	_ = fs.Parse(args)

	workDir := workDirFromEnv()
	srcPath := executor.KubeconfigPath(workDir)
	src, err := clientcmd.LoadFromFile(srcPath)
	if err != nil {
		return fmt.Errorf("load k3sm kubeconfig %s (run `k3sm server` first): %w", srcPath, err)
	}
	if err := retarget(src, server, caFile); err != nil {
		return err
	}

	if !write {
		out, err := clientcmd.Write(*src)
		if err != nil {
			return fmt.Errorf("render kubeconfig: %w", err)
		}
		_, err = os.Stdout.Write(out)
		return err
	}

	dst := clientcmdapi.NewConfig()
	if existing, err := clientcmd.LoadFromFile(path); err == nil {
		dst = existing
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("load %s: %w", path, err)
	}
	merged, err := mergeKubeconfig(dst, src, name, setCurr)
	if err != nil {
		return err
	}
	if cl := merged.Clusters[name]; cl != nil && cl.InsecureSkipTLSVerify {
		fmt.Fprintf(os.Stderr, "warning: merged context %q has insecure-skip-tls-verify (loopback dev posture) — do not use it off loopback\n", name)
	}
	data, err := clientcmd.Write(*merged)
	if err != nil {
		return fmt.Errorf("render merged kubeconfig: %w", err)
	}
	if err := atomicWriteWithBackup(path, data); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "merged k3sm context %q into %s\n", name, path)
	return nil
}

// retarget rewrites the k3sm cluster's server and/or CA in place. It refuses to
// leave skip-TLS-verify on for a non-loopback server with no CA — the security
// posture for a credential written into a durable kubeconfig.
func retarget(src *clientcmdapi.Config, server, caFile string) error {
	if server == "" && caFile == "" {
		return nil
	}
	cl := soleCluster(src)
	if cl == nil {
		return fmt.Errorf("k3sm kubeconfig has no cluster to retarget")
	}
	if server != "" {
		if !isLoopbackServer(server) && caFile == "" && len(cl.CertificateAuthorityData) == 0 && cl.CertificateAuthority == "" {
			return fmt.Errorf("refusing to write an insecure (skip-TLS-verify) context for non-loopback server %q; pass --certificate-authority <pem>", server)
		}
		cl.Server = server
	}
	if caFile != "" {
		data, err := os.ReadFile(caFile)
		if err != nil {
			return fmt.Errorf("read CA %s: %w", caFile, err)
		}
		cl.CertificateAuthorityData = data
		cl.CertificateAuthority = ""
		cl.InsecureSkipTLSVerify = false
	}
	return nil
}

// mergeKubeconfig copies the k3sm cluster/user/context out of src into dst under
// the given name (rewiring the context to reference that name), returning dst. It
// is pure (no IO) so it is unit-testable. With setCurrent, dst's current-context
// becomes name.
func mergeKubeconfig(dst, src *clientcmdapi.Config, name string, setCurrent bool) (*clientcmdapi.Config, error) {
	cl, user, kctx := soleCluster(src), soleAuthInfo(src), soleContext(src)
	if cl == nil || user == nil || kctx == nil {
		return nil, fmt.Errorf("k3sm kubeconfig is missing a cluster, user, or context")
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
	if setCurrent {
		dst.CurrentContext = name
	}
	return dst, nil
}

// soleCluster/soleAuthInfo/soleContext return the k3sm entry from a config that
// has exactly one of each (the admin kubeconfig the executor writes), preferring
// the well-known name.
func soleCluster(c *clientcmdapi.Config) *clientcmdapi.Cluster {
	if v, ok := c.Clusters["k3sm"]; ok {
		return v
	}
	for _, v := range c.Clusters {
		return v
	}
	return nil
}

func soleAuthInfo(c *clientcmdapi.Config) *clientcmdapi.AuthInfo {
	if v, ok := c.AuthInfos["admin"]; ok {
		return v
	}
	for _, v := range c.AuthInfos {
		return v
	}
	return nil
}

func soleContext(c *clientcmdapi.Config) *clientcmdapi.Context {
	if v, ok := c.Contexts["k3sm"]; ok {
		return v
	}
	for _, v := range c.Contexts {
		return v
	}
	return nil
}

// isLoopbackServer reports whether a server URL targets the local host, where an
// insecure-skip-tls-verify context cannot be MITM'd.
func isLoopbackServer(server string) bool {
	u, err := url.Parse(server)
	if err != nil {
		return false
	}
	host := u.Hostname()
	if host == "localhost" {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	return false
}

// defaultKubeconfigDest is ~/.kube/config (the merge target operators expect).
func defaultKubeconfigDest() string {
	if h, err := os.UserHomeDir(); err == nil {
		return filepath.Join(h, ".kube", "config")
	}
	return filepath.Join(".kube", "config")
}

// atomicWriteWithBackup writes data to path via a same-dir temp file + rename,
// backing up any existing file to path+".bak" first. Mode 0o600 — the file holds
// a bearer token.
func atomicWriteWithBackup(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("mkdir %s: %w", dir, err)
	}
	if fileExists(path) {
		prev, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("read existing %s: %w", path, err)
		}
		if err := os.WriteFile(path+".bak", prev, 0o600); err != nil {
			return fmt.Errorf("back up %s: %w", path, err)
		}
	}
	tmp, err := os.CreateTemp(dir, ".k3sm-kubeconfig-*")
	if err != nil {
		return fmt.Errorf("create temp: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return fmt.Errorf("chmod temp: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("write temp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("rename into place: %w", err)
	}
	return nil
}

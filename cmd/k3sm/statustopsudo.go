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
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"syscall"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"

	"k3sm.io/k3sm/pkg/status"
)

// sudoKubeconfigMaxBytes bounds how much of the invoking user's kubeconfig the
// top view reads as root. An installed kubeconfig is a few kilobytes.
const sudoKubeconfigMaxBytes = 1 << 20

// topWithoutSudoHint is what the top view says when it ran under sudo and no
// credential it could pick may list nodes.
const topWithoutSudoHint = "run `k3sm status top` without sudo to read with your own kubeconfig"

// sudoKubeconfigFile is the invoking user's kubeconfig as root read it: the
// bytes, and the owner and mode of the file those bytes came from.
type sudoKubeconfigFile struct {
	data []byte
	uid  uint32
	mode fs.FileMode
}

// topSudoInputs is everything the top view's sudo-aware client choice reads,
// injected so the choice is testable without root, a real user or a cluster.
type topSudoInputs struct {
	// euid is this process's effective uid; only 0 consults the sudo user.
	euid int
	// sudoUser is $SUDO_USER verbatim. Nothing else of the sudo environment is
	// read: $HOME and $KUBECONFIG are root's, or were passed through by sudo
	// from a caller root does not trust, so the file is found from the user's
	// home as the user database records it.
	sudoUser string
	// lookup resolves a user by name (user.Lookup in production).
	lookup func(name string) (*user.User, error)
	// readFile reads a file and reports the owner and mode of what it read
	// (readOwnedFile in production).
	readFile func(path string) (sudoKubeconfigFile, error)
	// contextName is the installed context the user's kubeconfig is pinned to.
	contextName string
	// build makes a client from the parsed kubeconfig and its context.
	build func(cfg *clientcmdapi.Config, context string) (status.Kube, error)
	// warn receives the one-line notice when the user's kubeconfig is refused.
	warn io.Writer
}

// topSudoInputsFromEnv gathers the production inputs.
func topSudoInputsFromEnv() topSudoInputs {
	return topSudoInputs{
		euid:        os.Geteuid(),
		sudoUser:    os.Getenv("SUDO_USER"),
		lookup:      user.Lookup,
		readFile:    readOwnedFile,
		contextName: installedKubeconfigName(),
		build:       buildSudoUserKube,
		warn:        os.Stderr,
	}
}

// underSudo reports whether the choice should consult the sudo user at all:
// root, with a SUDO_USER that is not root itself.
func (in topSudoInputs) underSudo() bool {
	return in.euid == 0 && in.sudoUser != "" && in.sudoUser != "root"
}

// errSudoKubeconfigRefused marks a user kubeconfig root found and would not use.
var errSudoKubeconfigRefused = errors.New("refused")

// chooseTopKube picks the top view's apiserver client.
//
// Without sudo it is today's choice (fallback), unchanged. Under sudo the node
// credential a worker holds may read only its own Node, so the view first tries
// the invoking user's own ~/.kube/config with the installed context, and uses it
// when it can list nodes; otherwise it falls back. When neither can list nodes,
// the error says to run the view without sudo.
func chooseTopKube(ctx context.Context, in topSudoInputs, fallback func() (status.Kube, error)) (status.Kube, error) {
	if !in.underSudo() {
		return fallback()
	}
	kube, why := in.userKube(ctx)
	if kube != nil {
		return kube, nil
	}
	if errors.Is(why, errSudoKubeconfigRefused) && in.warn != nil {
		fmt.Fprintf(in.warn, "k3sm status: %v\n", why)
	}
	hint := fmt.Sprintf("%v; %s", why, topWithoutSudoHint)
	fb, err := fallback()
	if fb == nil {
		if err == nil {
			err = errors.New("no apiserver client")
		}
		return nil, fmt.Errorf("%w; %s", err, hint)
	}
	if _, err := fb.Nodes(ctx); err != nil {
		return sudoHintKube{Kube: fb, hint: hint}, nil
	}
	return fb, nil
}

// userKube returns a client from the sudo user's kubeconfig that can list
// nodes, or nil and why not.
func (in topSudoInputs) userKube(ctx context.Context) (status.Kube, error) {
	u, err := in.lookup(in.sudoUser)
	if err != nil {
		return nil, fmt.Errorf("SUDO_USER %s is not a user on this Mac: %w", in.sudoUser, err)
	}
	uid, err := strconv.ParseUint(u.Uid, 10, 32)
	if err != nil {
		return nil, fmt.Errorf("SUDO_USER %s has a uid %q that is not a number", in.sudoUser, u.Uid)
	}
	if uid == 0 {
		return nil, fmt.Errorf("SUDO_USER %s is root", in.sudoUser)
	}
	if !filepath.IsAbs(u.HomeDir) {
		return nil, fmt.Errorf("SUDO_USER %s has no home directory", in.sudoUser)
	}
	path := filepath.Join(u.HomeDir, ".kube", "config")
	f, err := in.readFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("%s's kubeconfig %s does not exist", in.sudoUser, path)
	}
	if err != nil {
		return nil, fmt.Errorf("read %s's kubeconfig: %w", in.sudoUser, err)
	}
	switch {
	case !f.mode.IsRegular():
		return nil, fmt.Errorf("%s's kubeconfig %s is not a regular file, %w", in.sudoUser, path, errSudoKubeconfigRefused)
	case f.uid != uint32(uid):
		return nil, fmt.Errorf("%s's kubeconfig %s is owned by uid %d, not by %s, %w", in.sudoUser, path, f.uid, in.sudoUser, errSudoKubeconfigRefused)
	case f.mode.Perm()&0o022 != 0:
		return nil, fmt.Errorf("%s's kubeconfig %s is group- or world-writable (mode %04o), %w", in.sudoUser, path, f.mode.Perm(), errSudoKubeconfigRefused)
	}
	cfg, err := parseSudoUserKubeconfig(f.data, path, in.contextName)
	if err != nil {
		return nil, fmt.Errorf("%s's kubeconfig %s: %w", in.sudoUser, path, err)
	}
	kube, err := in.build(cfg, in.contextName)
	if err != nil {
		return nil, fmt.Errorf("%s's kubeconfig %s context %q: %w", in.sudoUser, path, in.contextName, err)
	}
	if _, err := kube.Nodes(ctx); err != nil {
		return nil, fmt.Errorf("%s's kubeconfig %s context %q cannot list nodes: %w", in.sudoUser, path, in.contextName, err)
	}
	return kube, nil
}

// parseSudoUserKubeconfig parses the user's kubeconfig and checks that the
// pinned context can be used as root without acting for the file's author: it
// must exist, and the credentials it selects must be inline. An exec or
// auth-provider plugin would run a program the user named as root, and a file
// reference (a token file, a client key, a CA path) would have root read a
// file the user may not; both are refused. The kubeconfig `k3sm install`
// writes carries the CA and the token inline.
func parseSudoUserKubeconfig(data []byte, path, contextName string) (*clientcmdapi.Config, error) {
	cfg, err := clientcmd.Load(data)
	if err != nil {
		return nil, fmt.Errorf("parse: %w", err)
	}
	kctx, ok := cfg.Contexts[contextName]
	if !ok || kctx == nil {
		return nil, fmt.Errorf("has no %q context", contextName)
	}
	cluster, ok := cfg.Clusters[kctx.Cluster]
	if !ok || cluster == nil {
		return nil, fmt.Errorf("context %q names a cluster %q it does not define", contextName, kctx.Cluster)
	}
	if cluster.CertificateAuthority != "" {
		return nil, fmt.Errorf("cluster %q reads its CA from a file, which root does not read on a user's behalf, %w", kctx.Cluster, errSudoKubeconfigRefused)
	}
	if auth, ok := cfg.AuthInfos[kctx.AuthInfo]; ok && auth != nil {
		switch {
		case auth.Exec != nil || auth.AuthProvider != nil:
			return nil, fmt.Errorf("user %q runs a credential plugin, which root does not run on a user's behalf, %w", kctx.AuthInfo, errSudoKubeconfigRefused)
		case auth.TokenFile != "" || auth.ClientCertificate != "" || auth.ClientKey != "":
			return nil, fmt.Errorf("user %q reads its credential from a file, which root does not read on a user's behalf, %w", kctx.AuthInfo, errSudoKubeconfigRefused)
		}
	}
	for _, c := range cfg.Clusters {
		c.LocationOfOrigin = path
	}
	for _, a := range cfg.AuthInfos {
		a.LocationOfOrigin = path
	}
	return cfg, nil
}

// buildSudoUserKube builds the report's client from an already-read kubeconfig.
func buildSudoUserKube(cfg *clientcmdapi.Config, contextName string) (status.Kube, error) {
	restCfg, err := clientcmd.NewNonInteractiveClientConfig(*cfg, contextName, &clientcmd.ConfigOverrides{}, nil).ClientConfig()
	if err != nil {
		return nil, err
	}
	restCfg.Timeout = statusAPITimeout
	cs, err := kubernetes.NewForConfig(restCfg)
	if err != nil {
		return nil, err
	}
	return restKube{client: cs, server: restCfg.Host, tls: tlsPosture(restCfg), cfg: restCfg}, nil
}

// readOwnedFile reads path and reports the owner and mode of the file it read,
// from the open descriptor, so the checks apply to the bytes returned and not
// to whatever the path names a moment later.
func readOwnedFile(path string) (sudoKubeconfigFile, error) {
	// O_NONBLOCK keeps a FIFO planted at the path from holding root in open.
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return sudoKubeconfigFile{}, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return sudoKubeconfigFile{}, err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return sudoKubeconfigFile{}, fmt.Errorf("stat %s: no owner", path)
	}
	out := sudoKubeconfigFile{uid: st.Uid, mode: fi.Mode()}
	if !fi.Mode().IsRegular() {
		return out, nil
	}
	data, err := io.ReadAll(io.LimitReader(f, sudoKubeconfigMaxBytes+1))
	if err != nil {
		return sudoKubeconfigFile{}, err
	}
	if len(data) > sudoKubeconfigMaxBytes {
		return sudoKubeconfigFile{}, fmt.Errorf("%s is larger than %d bytes", path, sudoKubeconfigMaxBytes)
	}
	out.data = data
	return out, nil
}

// sudoHintKube is the fallback client when it cannot list nodes either: its
// node-list error carries why the user's kubeconfig was not used and says to
// run the view without sudo.
type sudoHintKube struct {
	status.Kube
	hint string
}

// Nodes lists nodes, adding the hint to a failure.
func (k sudoHintKube) Nodes(ctx context.Context) ([]corev1.Node, error) {
	nodes, err := k.Kube.Nodes(ctx)
	if err != nil {
		return nil, fmt.Errorf("%w; %s", err, k.hint)
	}
	return nodes, nil
}

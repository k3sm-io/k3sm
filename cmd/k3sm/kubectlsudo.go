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
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/user"
	"path/filepath"
	"sort"
	"strconv"
	"syscall"

	"k8s.io/client-go/tools/clientcmd"

	"k3sm.io/k3sm/pkg/executor"
)

// sudoKubeconfigCopyDir is where root writes the checked copies of an invoker's
// kubeconfig that kubectl and the builder verbs then read. It is /tmp, not
// $TMPDIR: sudo may pass the invoker's $TMPDIR through, and in a directory the
// invoker can write they could rename root's copy away and put their own file at
// its path. /tmp is sticky, so only root can move what root made there. It is a
// variable so a test can point it at its own directory.
var sudoKubeconfigCopyDir = "/tmp"

// vettedKubeconfig is one kubeconfig file root read and checked, with the bytes
// it checked.
type vettedKubeconfig struct {
	path string
	data []byte
}

// sudoKubeconfigRefusal is vetSudoKubeconfig's refusal, so a caller that words
// its own "no kubeconfig" error passes this one through instead.
type sudoKubeconfigRefusal struct{ err error }

func (r sudoKubeconfigRefusal) Error() string { return r.err.Error() }
func (r sudoKubeconfigRefusal) Unwrap() error { return r.err }

// withSudoInvoker records $SUDO_USER, so resolveKubectlConfig checks an
// invoker's kubeconfig before root uses it. Only the verbs that hand the choice
// to kubectl or load it themselves (`k3sm kubectl`, the builder verbs) set it.
func (in kubectlInputs) withSudoInvoker() kubectlInputs {
	in.sudoUser = os.Getenv("SUDO_USER")
	return in
}

// underSudo reports whether this run is root on behalf of another account.
func (in kubectlInputs) underSudo() bool {
	return in.asRoot && in.sudoUser != "" && in.sudoUser != "root"
}

// vetSudoKubeconfig checks, for root run by sudo, every kubeconfig file cfg would
// have root read, and returns cfg carrying the checked bytes. Root's own admin
// kubeconfig in its default work dir, and the node credential (which every caller
// refuses as root), pass as they are. Anything else (a file under the invoker's
// home, every entry of $KUBECONFIG, or a work dir K3SM_WORK_DIR named) must be a
// regular file, not a symlink, owned by root or the invoker and writable by
// nobody else, and may carry no credential root would act on for its author: an
// exec or auth-provider plugin runs a program, a token, client certificate, key
// or CA file has root read a file the invoker may not, and a proxy-url sends
// root's traffic where the file says.
//
// kubectl reads its kubeconfig itself, after this check, so the caller hands it
// the checked bytes (writeVettedKubeconfigs) rather than the invoker's path.
func vetSudoKubeconfig(in kubectlInputs, cfg kubectlConfig) (kubectlConfig, error) {
	if !in.underSudo() {
		return cfg, nil
	}
	var paths []string
	switch {
	case cfg.kubeconfig == "":
		paths = kubectlRuleFiles(in)
	case in.workDirOverride == "" && cfg.kubeconfig == executor.KubeconfigPath(in.workDir):
		return cfg, nil
	case in.nodeKubeconfig != "" && cfg.kubeconfig == in.nodeKubeconfig:
		return cfg, nil
	default:
		paths = []string{cfg.kubeconfig}
	}
	u, err := user.Lookup(in.sudoUser)
	if err != nil {
		return kubectlConfig{}, sudoKubeconfigRefusal{fmt.Errorf("SUDO_USER %s is not a user on this Mac, so root does not read a kubeconfig on its behalf: %w", in.sudoUser, err)}
	}
	uid, err := strconv.ParseUint(u.Uid, 10, 32)
	if err != nil {
		return kubectlConfig{}, sudoKubeconfigRefusal{fmt.Errorf("SUDO_USER %s has a uid %q that is not a number", in.sudoUser, u.Uid)}
	}
	var files []vettedKubeconfig
	for _, p := range paths {
		f, err := readKubeconfigNoFollow(p)
		if errors.Is(err, fs.ErrNotExist) {
			continue // kubectl skips a missing entry too
		}
		if err != nil {
			return kubectlConfig{}, sudoKubeconfigRefusal{fmt.Errorf("kubeconfig %s: %w; root does not read it on %s's behalf, run this without sudo", p, err, in.sudoUser)}
		}
		if problem := sudoKubeconfigFileProblem(f, uint32(uid), in.sudoUser); problem != "" {
			return kubectlConfig{}, sudoKubeconfigRefusal{fmt.Errorf("kubeconfig %s %s, so root does not use it on %s's behalf; run this without sudo", p, problem, in.sudoUser)}
		}
		if field, err := sudoKubeconfigCredentialField(f.data); err != nil {
			return kubectlConfig{}, sudoKubeconfigRefusal{fmt.Errorf("kubeconfig %s: %w", p, err)}
		} else if field != "" {
			return kubectlConfig{}, sudoKubeconfigRefusal{fmt.Errorf("kubeconfig %s sets %s, which root does not act on for %s; run this without sudo", p, field, in.sudoUser)}
		}
		files = append(files, vettedKubeconfig{path: p, data: f.data})
	}
	cfg.vetted = &files
	return cfg, nil
}

// kubectlRuleFiles is every file kubectl's default loading rules read: each entry
// of $KUBECONFIG when it is set, else ~/.kube/config.
func kubectlRuleFiles(in kubectlInputs) []string {
	if in.kubeconfigEnv != "" {
		var out []string
		for _, p := range filepath.SplitList(in.kubeconfigEnv) {
			if p != "" {
				out = append(out, p)
			}
		}
		return out
	}
	if in.home == "" {
		return nil
	}
	return []string{filepath.Join(in.home, ".kube", "config")}
}

// readKubeconfigNoFollow reads path without following a symlink at it, and
// reports the owner and mode of the open file the bytes came from.
func readKubeconfigNoFollow(path string) (sudoKubeconfigFile, error) {
	// O_NONBLOCK keeps a FIFO planted at the path from holding root in open.
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if errors.Is(err, syscall.ELOOP) {
		return sudoKubeconfigFile{}, errors.New("is a symlink")
	}
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
		return sudoKubeconfigFile{}, errors.New("has no owner")
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
		return sudoKubeconfigFile{}, fmt.Errorf("is larger than %d bytes", sudoKubeconfigMaxBytes)
	}
	out.data = data
	return out, nil
}

// sudoKubeconfigFileProblem says why root may not trust f, as what follows the
// file's name, or "": a regular file owned by root or the invoker uid, named
// owner, that nobody else can write.
func sudoKubeconfigFileProblem(f sudoKubeconfigFile, uid uint32, owner string) string {
	switch {
	case !f.mode.IsRegular():
		return "is not a regular file"
	case f.uid != 0 && f.uid != uid:
		return fmt.Sprintf("is owned by uid %d, not by %s or root", f.uid, owner)
	case f.mode.Perm()&0o022 != 0:
		return fmt.Sprintf("is group- or world-writable (mode %04o)", f.mode.Perm())
	}
	return ""
}

// sudoKubeconfigCredentialField names the first field in data that would have
// root run a program, read a file or use a proxy for the file's author, as
// `user "x" exec` or `cluster "y" proxy-url`, or "" when there is none. Every
// cluster and user is checked, not only the pinned context's: kubectl's own
// --context and --user arguments pick any of them.
func sudoKubeconfigCredentialField(data []byte) (string, error) {
	cfg, err := clientcmd.Load(data)
	if err != nil {
		return "", fmt.Errorf("parse: %w", err)
	}
	for _, name := range sortedNames(cfg.Clusters) {
		c := cfg.Clusters[name]
		if c == nil {
			continue
		}
		switch {
		case c.CertificateAuthority != "":
			return fmt.Sprintf("cluster %q certificate-authority", name), nil
		case c.ProxyURL != "":
			return fmt.Sprintf("cluster %q proxy-url", name), nil
		}
	}
	for _, name := range sortedNames(cfg.AuthInfos) {
		a := cfg.AuthInfos[name]
		if a == nil {
			continue
		}
		switch {
		case a.Exec != nil:
			return fmt.Sprintf("user %q exec", name), nil
		case a.AuthProvider != nil:
			return fmt.Sprintf("user %q auth-provider", name), nil
		case a.TokenFile != "":
			return fmt.Sprintf("user %q tokenFile", name), nil
		case a.ClientCertificate != "":
			return fmt.Sprintf("user %q client-certificate", name), nil
		case a.ClientKey != "":
			return fmt.Sprintf("user %q client-key", name), nil
		}
	}
	return "", nil
}

func sortedNames[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// writeVettedKubeconfigs writes the checked bytes to a new root-only directory,
// one file per entry in the same order, and returns the directory and the paths
// to hand kubectl in their place. With no file to write it returns one path that
// does not exist, inside that directory, so kubectl loads nothing rather than
// whatever appears at the invoker's paths after the check.
func writeVettedKubeconfigs(files []vettedKubeconfig) (string, []string, error) {
	dir, err := os.MkdirTemp(sudoKubeconfigCopyDir, "k3sm-kubeconfig-")
	if err != nil {
		return "", nil, fmt.Errorf("copy the checked kubeconfig: %w", err)
	}
	if len(files) == 0 {
		return dir, []string{filepath.Join(dir, "none")}, nil
	}
	paths := make([]string, 0, len(files))
	for i, f := range files {
		p := filepath.Join(dir, strconv.Itoa(i)+".kubeconfig")
		if err := os.WriteFile(p, f.data, 0o600); err != nil {
			_ = os.RemoveAll(dir)
			return "", nil, fmt.Errorf("copy the checked kubeconfig %s: %w", f.path, err)
		}
		paths = append(paths, p)
	}
	return dir, paths, nil
}

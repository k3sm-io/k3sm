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
	"io/fs"
	"os"
	"os/user"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"

	"k3sm.io/k3sm/pkg/executor"
	"k3sm.io/k3sm/pkg/install"
)

// rootUID is root's uid in the form the user database takes.
const rootUID = "0"

// rootKubeconfigRemedy closes a refusal of a file root would otherwise read.
const rootKubeconfigRemedy = "run the command without sudo to use your own kubeconfig, or run `sudo k3sm install` to merge an inline k3sm context into it"

// rootKubeSources is what root reads to choose a kubeconfig. It is nil for any
// other account, which keeps kubectl's own loading rules. $HOME is not among its
// inputs: homes come from the user database.
type rootKubeSources struct {
	// sudoUser is $SUDO_USER verbatim.
	sudoUser string
	// lookup resolves a user by name (user.Lookup in production).
	lookup func(name string) (*user.User, error)
	// lookupID resolves a user by uid (user.LookupId in production).
	lookupID func(id string) (*user.User, error)
	// readFile reads a file and reports its owner and mode (readOwnedFile in
	// production).
	readFile func(path string) (sudoKubeconfigFile, error)
}

// rootKubeSourcesFromEnv gathers the production inputs, or nil when this process
// is not root.
func rootKubeSourcesFromEnv() *rootKubeSources {
	if processEuid() != 0 {
		return nil
	}
	return &rootKubeSources{
		sudoUser: os.Getenv("SUDO_USER"),
		lookup:   user.Lookup,
		lookupID: user.LookupId,
		readFile: readOwnedFile,
	}
}

// kubeHome is the home a kubeconfig is looked for under: root's from the user
// database as root, $HOME otherwise. "" when it cannot be resolved.
func kubeHome() string {
	if processEuid() == 0 {
		u, err := user.LookupId(rootUID)
		if err != nil {
			return ""
		}
		return u.HomeDir
	}
	home, _ := os.UserHomeDir()
	return home
}

// checkedKubeconfig is a kubeconfig root read once and accepted, cut down to the
// one context it was accepted for. Every use takes these bytes rather than
// reading the file again.
type checkedKubeconfig struct {
	cfg *clientcmdapi.Config
}

// checkKubeconfig parses data and keeps only the entries contextName selects
// after parseSudoUserKubeconfig has accepted them. Keeping nothing else is what
// makes a file usable when it also holds other clusters' plugin entries: a
// `--context` on kubectl's command line can only name what is left. An empty
// contextName means the file's current context.
func checkKubeconfig(data []byte, path, contextName string) (*checkedKubeconfig, error) {
	if contextName == "" {
		raw, err := clientcmd.Load(data)
		if err != nil {
			return nil, fmt.Errorf("parse: %w", err)
		}
		if raw.CurrentContext == "" {
			return nil, errors.New("names no current context")
		}
		contextName = raw.CurrentContext
	}
	parsed, err := parseSudoUserKubeconfig(data, path, contextName)
	if err != nil {
		return nil, err
	}
	kctx := parsed.Contexts[contextName]
	out := clientcmdapi.NewConfig()
	out.CurrentContext = contextName
	out.Contexts[contextName] = kctx
	out.Clusters[kctx.Cluster] = parsed.Clusters[kctx.Cluster]
	if auth, ok := parsed.AuthInfos[kctx.AuthInfo]; ok {
		out.AuthInfos[kctx.AuthInfo] = auth
	}
	return &checkedKubeconfig{cfg: out}, nil
}

// restConfig builds the client config from the checked entries. It reads no file.
func (c *checkedKubeconfig) restConfig() (*rest.Config, error) {
	return clientcmd.NewNonInteractiveClientConfig(*c.cfg, c.cfg.CurrentContext, &clientcmd.ConfigOverrides{}, nil).ClientConfig()
}

// kubeconfigHandoffDir is where the handoff file is created and at once removed.
// It is a variable so a test can use its own directory.
var kubeconfigHandoffDir = "/private/tmp"

// handoff gives kubectl the checked bytes rather than the path they came from:
// it returns an open file holding them, and the /dev/fd path of that descriptor,
// which an exec keeps. The file loses its name before it gets any content, so the
// credentials never have a name and go when kubectl exits, however it exits. The
// caller keeps the file open until the exec.
func (c *checkedKubeconfig) handoff() (*os.File, string, error) {
	data, err := clientcmd.Write(*c.cfg)
	if err != nil {
		return nil, "", fmt.Errorf("encode the checked kubeconfig: %w", err)
	}
	f, err := os.CreateTemp(kubeconfigHandoffDir, ".k3sm-kubectl-*")
	if err != nil {
		return nil, "", fmt.Errorf("create the kubectl handoff file: %w", err)
	}
	if err := fillHandoff(f, data); err != nil {
		f.Close()
		return nil, "", fmt.Errorf("prepare the kubectl handoff file: %w", err)
	}
	return f, fmt.Sprintf("/dev/fd/%d", f.Fd()), nil
}

// fillHandoff removes f's name, writes data, rewinds, and lets an exec keep f.
func fillHandoff(f *os.File, data []byte) error {
	if err := os.Remove(f.Name()); err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		return err
	}
	if _, err := f.Seek(0, 0); err != nil {
		return err
	}
	_, err := unix.FcntlInt(f.Fd(), unix.F_SETFD, 0)
	return err
}

// rootKubectlEnv is kubectl's environment as root: KUBECONFIG is the handoff, and
// HOME is root's, since kubectl reads its preferences from there and a preference
// can name another kubeconfig. KUBERC, which names that file directly, is dropped.
func rootKubectlEnv(env []string, kubeconfig, home string) []string {
	out := make([]string, 0, len(env)+2)
	for _, kv := range env {
		switch {
		case strings.HasPrefix(kv, "KUBECONFIG="), strings.HasPrefix(kv, "KUBERC="), strings.HasPrefix(kv, "HOME="):
		default:
			out = append(out, kv)
		}
	}
	if home != "" {
		out = append(out, "HOME="+home)
	}
	return append(out, "KUBECONFIG="+kubeconfig)
}

// checkFileShape refuses anything but a regular file with no group or other
// write bit, owned by one of owners. owners nil accepts any owner.
func checkFileShape(path string, f sudoKubeconfigFile, owners map[uint32]string) error {
	if !f.mode.IsRegular() {
		return fmt.Errorf("%s is not a regular file, %w", path, errSudoKubeconfigRefused)
	}
	if owners != nil {
		if _, ok := owners[f.uid]; !ok {
			names := make([]string, 0, len(owners))
			for _, name := range owners {
				names = append(names, name)
			}
			return fmt.Errorf("%s is owned by uid %d, not %s, %w", path, f.uid, strings.Join(sortedNames(names), " or "), errSudoKubeconfigRefused)
		}
	}
	if f.mode.Perm()&0o022 != 0 {
		return fmt.Errorf("%s is group- or world-writable (mode %04o), %w", path, f.mode.Perm(), errSudoKubeconfigRefused)
	}
	return nil
}

// sortedNames orders owner names so one file always gives one message.
func sortedNames(names []string) []string {
	slices.SortFunc(names, func(a, b string) int {
		switch {
		case a == "root":
			return -1
		case b == "root":
			return 1
		}
		return strings.Compare(a, b)
	})
	return names
}

// namedOwners is who may own a file root was pointed at by name: root, and the
// person who ran sudo.
func (s *rootKubeSources) namedOwners() map[uint32]string {
	owners := map[uint32]string{0: "root"}
	if s.sudoUser == "" || s.sudoUser == "root" {
		return owners
	}
	u, err := s.lookup(s.sudoUser)
	if err != nil {
		return owners
	}
	if uid, err := strconv.ParseUint(u.Uid, 10, 32); err == nil {
		owners[uint32(uid)] = s.sudoUser
	}
	return owners
}

// loadNamed reads a file root was pointed at by $KUBECONFIG or --kubeconfig.
// contextName "" takes the file's current context.
func (s *rootKubeSources) loadNamed(path, contextName string) (*checkedKubeconfig, error) {
	f, err := s.readFile(path)
	if err != nil {
		return nil, err
	}
	if err := checkFileShape(path, f, s.namedOwners()); err != nil {
		return nil, fmt.Errorf("%w; %s", err, rootKubeconfigRemedy)
	}
	c, err := checkKubeconfig(f.data, path, contextName)
	if err != nil {
		return nil, fmt.Errorf("kubeconfig %s: %w; %s", path, err, rootKubeconfigRemedy)
	}
	return c, nil
}

// loadWorkDir reads the work dir's admin kubeconfig. It takes any owner, because
// which account that is depends on how the server was installed. It still has to
// be inline, so it is used the way any other file is.
func (s *rootKubeSources) loadWorkDir(path string, f sudoKubeconfigFile) (*checkedKubeconfig, error) {
	remedy := "`sudo k3sm restart` makes a server write this file again"
	if err := checkFileShape(path, f, nil); err != nil {
		return nil, fmt.Errorf("%w; %s", err, remedy)
	}
	c, err := checkKubeconfig(f.data, path, "")
	if err != nil {
		return nil, fmt.Errorf("kubeconfig %s: %w; %s", path, err, remedy)
	}
	return c, nil
}

// resolve is resolveKubectlConfig as root, in order:
//
//  1. K3SM_WORK_DIR or --work-dir set: that work dir's admin kubeconfig, or an
//     error, as for any other account.
//  2. The resolved work dir's admin kubeconfig, when it is there. Not on a
//     worker, whose file there is left over from an earlier server install.
//  3. $KUBECONFIG when set: its first entry that exists, owned by root or by the
//     person who ran sudo, with the installed context. A file that fails is
//     refused rather than passed over for a file naming another cluster, and the
//     list is not merged.
//  4. The ~/.kube/config of the person who ran sudo, from the user database's
//     home, with the installed context.
//  5. Root's own ~/.kube/config, from the user database's home, likewise.
//
// A worker's node credential is never among them.
func (s *rootKubeSources) resolve(in kubectlInputs) (kubectlConfig, error) {
	kc := executor.KubeconfigPath(in.workDir)
	worker := in.role == install.RoleAgent
	reasons := []string{}
	if !worker || in.workDirOverride != "" {
		f, err := s.readFile(kc)
		switch {
		case err == nil:
			c, err := s.loadWorkDir(kc, f)
			if err != nil {
				return kubectlConfig{}, err
			}
			return kubectlConfig{kubeconfig: kc, checked: c}, nil
		case !errors.Is(err, fs.ErrNotExist):
			return kubectlConfig{}, fmt.Errorf("read kubeconfig %s: %w", kc, err)
		case in.workDirOverride != "":
			return kubectlConfig{}, fmt.Errorf("kubeconfig %s not found — run `k3sm server` first (set K3SM_WORK_DIR if you used a non-default --work-dir)", kc)
		}
		reasons = append(reasons, fmt.Sprintf("%s does not exist", kc))
	}
	if in.kubeconfigEnv != "" {
		return s.resolveEnv(in)
	}
	top := topSudoInputs{euid: 0, sudoUser: s.sudoUser, lookup: s.lookup, readFile: s.readFile}
	if top.underSudo() {
		data, path, err := top.userKubeconfigFile()
		if err == nil {
			var c *checkedKubeconfig
			if c, err = checkKubeconfig(data, path, in.contextName); err == nil {
				return kubectlConfig{context: in.contextName, checked: c}, nil
			}
			err = fmt.Errorf("%s's kubeconfig %s: %w", s.sudoUser, path, err)
		}
		reasons = append(reasons, err.Error())
	}
	c, err := s.loadRootHome(in.contextName)
	if err == nil {
		return kubectlConfig{context: in.contextName, checked: c}, nil
	}
	reasons = append(reasons, err.Error())
	if worker {
		return kubectlConfig{}, fmt.Errorf("no kubeconfig to use as root on this worker: %s; root does not use the node credential %s, which is a node identity and holds only what its kubelet needs; %s", strings.Join(reasons, "; "), in.nodeKubeconfig, rootNodeCredentialFix)
	}
	return kubectlConfig{}, fmt.Errorf("no kubeconfig to use as root: %s; %s", strings.Join(reasons, "; "), rootKubeconfigRemedy)
}

// resolveEnv takes the first entry of $KUBECONFIG that exists.
func (s *rootKubeSources) resolveEnv(in kubectlInputs) (kubectlConfig, error) {
	for _, p := range filepath.SplitList(in.kubeconfigEnv) {
		if p == "" {
			continue
		}
		c, err := s.loadNamed(p, in.contextName)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return kubectlConfig{}, fmt.Errorf("$KUBECONFIG: %w", err)
		}
		return kubectlConfig{context: in.contextName, checked: c}, nil
	}
	return kubectlConfig{}, fmt.Errorf("no file named by $KUBECONFIG exists (%s); set it to a file that exists, or unset it", in.kubeconfigEnv)
}

// loadRootHome reads root's own kubeconfig from the home the user database gives.
func (s *rootKubeSources) loadRootHome(contextName string) (*checkedKubeconfig, error) {
	u, err := s.lookupID(rootUID)
	if err != nil {
		return nil, fmt.Errorf("root's home: %w", err)
	}
	if !filepath.IsAbs(u.HomeDir) {
		return nil, errors.New("root has no home directory")
	}
	path := filepath.Join(u.HomeDir, ".kube", "config")
	f, err := s.readFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("%s does not exist", path)
	}
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	if err := checkFileShape(path, f, map[uint32]string{0: "root"}); err != nil {
		return nil, err
	}
	c, err := checkKubeconfig(f.data, path, contextName)
	if err != nil {
		return nil, fmt.Errorf("root's kubeconfig %s: %w", path, err)
	}
	return c, nil
}

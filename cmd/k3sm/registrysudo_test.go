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
	"encoding/base64"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/user"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	authnv1 "k8s.io/api/authentication/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/rest"
	ktesting "k8s.io/client-go/testing"

	"k3sm.io/k3sm/pkg/executor"
	"k3sm.io/k3sm/pkg/install"
	"k3sm.io/k3sm/pkg/registrysvc"
)

// The addresses the worker's kubeconfigs name, so a case tells which one a client
// came from by where it would dial. The invoker's checked file differs from the
// node credential's on purpose: a person's file may use another address.
const (
	checkedServer  = "https://100.64.0.1:6444"
	leftoverServer = "https://192.0.2.1:6444"
	pinServer      = "https://192.0.2.2:6444"
	nodeServer     = "https://198.51.100.1:6444"
	rootServer     = "https://198.51.100.2:6444"
	envServer      = "https://198.51.100.3:6444"
	homeServer     = "https://198.51.100.4:6444"
)

// inlineKubeconfig is a kubeconfig with the k3sm context whose CA and token are
// inline, as `k3sm kubeconfig --write` writes it. userExtra is appended to the
// user entry.
func inlineKubeconfig(caPEM []byte, userExtra string) []byte {
	return fmt.Appendf(nil, `apiVersion: v1
kind: Config
clusters:
- name: k3sm
  cluster:
    server: https://100.64.0.1:6444
    certificate-authority-data: %s
contexts:
- name: k3sm
  context:
    cluster: k3sm
    user: k3sm
current-context: k3sm
users:
- name: k3sm
  user:
    token: abc123
%s`, base64.StdEncoding.EncodeToString(caPEM), userExtra)
}

// anchoredAt answers a read of the worker's root-only cluster CA copy with caPEM,
// as `k3sm install` leaves it, and every other read with read.
func anchoredAt(caPEM []byte, read func(string) (sudoKubeconfigFile, error)) func(string) (sudoKubeconfigFile, error) {
	return func(path string) (sudoKubeconfigFile, error) {
		if path == install.AgentClusterCAPath {
			return sudoKubeconfigFile{data: caPEM, uid: 0, mode: 0o644}, nil
		}
		return read(path)
	}
}

// TestWorkerUnderSudoChoosesTheInvokersKubeconfig is the gate on the kubeconfig
// `sudo k3sm image migrate` mints its token through on a worker. Each case tells
// the choice by the server the client would dial, which no dial is needed to see.
func TestWorkerUnderSudoChoosesTheInvokersKubeconfig(t *testing.T) {
	nodeCA, otherCA := testClusterCAPEM(t), testClusterCAPEM(t)
	const execUser = "    exec:\n      apiVersion: client.authentication.k8s.io/v1\n      command: /tmp/evil\n"
	regular := fs.FileMode(0o600)

	cases := []struct {
		name string
		// sudoUser is $SUDO_USER; euid defaults to root.
		sudoUser string
		euid     int
		role     install.Role
		// aliceFile is what the read of alice's kubeconfig answers; nil is a
		// missing file.
		aliceFile *sudoKubeconfigFile
		// noNode removes the node credential, rootFile gives root a kubeconfig,
		// envFile sets $KUBECONFIG, and pin sets K3SM_WORK_DIR.
		noNode, rootFile, envFile, pin bool
		// noAccount leaves nothing at the $HOME the test's process would use.
		noAccount bool

		wantServer string
		// wantReads is how many times root read a sudo user's file.
		wantReads int
		// wantHint is in the node-credential hint; "" means no hint at all.
		wantHint string
		wantWarn string
		wantErr  []string
	}{
		{
			name: "the invoker's kubeconfig beats the node credential and the leftover", sudoUser: "alice", role: install.RoleAgent,
			aliceFile:  &sudoKubeconfigFile{data: inlineKubeconfig(nodeCA, ""), uid: 501, mode: regular},
			wantServer: checkedServer, wantReads: 1,
		},
		{
			name: "a kubeconfig not owned by the invoker stops the run", sudoUser: "alice", role: install.RoleAgent,
			aliceFile: &sudoKubeconfigFile{data: inlineKubeconfig(nodeCA, ""), uid: 502, mode: regular},
			wantReads: 1, wantWarn: "is owned by uid 502, not by alice", wantErr: []string{"is owned by uid 502, not by alice", "root does not use the node credential"},
		},
		{
			name: "a root-owned kubeconfig in the invoker's home is refused", sudoUser: "alice", role: install.RoleAgent,
			aliceFile: &sudoKubeconfigFile{data: inlineKubeconfig(nodeCA, ""), uid: 0, mode: regular},
			wantReads: 1, wantWarn: "refused", wantErr: []string{"is owned by uid 0, not by alice", "root does not use the node credential"},
		},
		{
			name: "a group-writable kubeconfig is refused", sudoUser: "alice", role: install.RoleAgent,
			aliceFile: &sudoKubeconfigFile{data: inlineKubeconfig(nodeCA, ""), uid: 501, mode: 0o660},
			wantReads: 1, wantWarn: "refused", wantErr: []string{"group- or world-writable", "root does not use the node credential"},
		},
		{
			name: "a non-regular kubeconfig is refused", sudoUser: "alice", role: install.RoleAgent,
			aliceFile: &sudoKubeconfigFile{uid: 501, mode: fs.ModeNamedPipe | 0o600},
			wantReads: 1, wantWarn: "refused", wantErr: []string{"not a regular file", "root does not use the node credential"},
		},
		{
			name: "a credential plugin is refused and not run", sudoUser: "alice", role: install.RoleAgent,
			aliceFile: &sudoKubeconfigFile{data: inlineKubeconfig(nodeCA, execUser), uid: 501, mode: regular},
			wantReads: 1, wantWarn: "refused", wantErr: []string{"credential plugin", "root does not use the node credential"},
		},
		{
			name: "a missing kubeconfig stops the run with no warning", sudoUser: "alice", role: install.RoleAgent,
			wantReads: 1, wantErr: []string{"does not exist", "root does not use the node credential"},
		},
		{
			name: "a kubeconfig without the context is not used", sudoUser: "alice", role: install.RoleAgent,
			aliceFile: &sudoKubeconfigFile{data: []byte("apiVersion: v1\nkind: Config\n"), uid: 501, mode: regular},
			wantReads: 1, wantErr: []string{`has no "k3sm" context`, "root does not use the node credential"},
		},
		{
			name: "a traversal in SUDO_USER never reaches a path", sudoUser: "../../tmp/evil", role: install.RoleAgent,
			wantErr: []string{"is not a user on this Mac", "root does not use the node credential"},
		},
		{
			name: "a second name in SUDO_USER never reaches a path", sudoUser: "alice/../bob", role: install.RoleAgent,
			wantErr: []string{"is not a user on this Mac", "root does not use the node credential"},
		},
		{
			name: "a newline in SUDO_USER never reaches a path", sudoUser: "alice\nroot", role: install.RoleAgent,
			wantErr: []string{"is not a user on this Mac", "root does not use the node credential"},
		},
		{
			name: "a second uid 0 account is refused", sudoUser: "toor", role: install.RoleAgent,
			wantErr: []string{"SUDO_USER toor is root", "root does not use the node credential"},
		},
		{
			name: "an account with a relative home is refused", sudoUser: "homeless", role: install.RoleAgent,
			wantErr: []string{"has no home directory", "root does not use the node credential"},
		},
		{
			name: "an account with a uid that is not a number is refused", sudoUser: "badnum", role: install.RoleAgent,
			wantErr: []string{"that is not a number", "root does not use the node credential"},
		},
		{
			name: "SUDO_USER root is not consulted, so $HOME's rules apply", sudoUser: "root", role: install.RoleAgent,
			wantServer: homeServer,
		},
		{
			name: "root's own kubeconfig beats the invoker's", sudoUser: "alice", role: install.RoleAgent, rootFile: true,
			aliceFile:  &sudoKubeconfigFile{data: inlineKubeconfig(nodeCA, ""), uid: 501, mode: regular},
			wantServer: rootServer,
		},
		{
			name: "a KUBECONFIG sudo let through is not loaded, and the invoker's is", sudoUser: "alice", role: install.RoleAgent, envFile: true,
			aliceFile:  &sudoKubeconfigFile{data: inlineKubeconfig(nodeCA, ""), uid: 501, mode: regular},
			wantServer: checkedServer, wantReads: 1, wantWarn: "ignoring $KUBECONFIG",
		},
		{
			name: "a KUBECONFIG sudo let through is no fallback either", sudoUser: "alice", role: install.RoleAgent, envFile: true,
			wantReads: 1, wantWarn: "ignoring $KUBECONFIG", wantErr: []string{"does not exist", "root does not use the node credential"},
		},
		{
			name: "without sudo KUBECONFIG is the account's own choice", sudoUser: "alice", euid: 501, role: install.RoleAgent, envFile: true,
			wantServer: envServer,
		},
		{
			name: "a server still honours KUBECONFIG under sudo, behind its work dir", sudoUser: "alice", role: install.RoleServer, envFile: true,
			wantServer: leftoverServer,
		},
		{
			name: "K3SM_WORK_DIR still pins that work dir", sudoUser: "alice", role: install.RoleAgent, pin: true,
			aliceFile:  &sudoKubeconfigFile{data: inlineKubeconfig(nodeCA, ""), uid: 501, mode: regular},
			wantServer: pinServer,
		},
		{
			name: "a server's work-dir kubeconfig is unchanged under sudo", sudoUser: "alice", role: install.RoleServer,
			aliceFile:  &sudoKubeconfigFile{data: inlineKubeconfig(nodeCA, ""), uid: 501, mode: regular},
			wantServer: leftoverServer,
		},
		{
			name: "without sudo the account's own file is read as itself", sudoUser: "alice", euid: 501, role: install.RoleAgent,
			wantServer: homeServer,
		},
		{
			name: "with no account kubeconfig the node credential carries the hint", sudoUser: "alice", euid: 501, role: install.RoleAgent, noAccount: true,
			wantServer: nodeServer, wantHint: "node credential",
		},
		{
			name: "nothing usable names why and what to do", sudoUser: "alice", role: install.RoleAgent, noNode: true,
			aliceFile: &sudoKubeconfigFile{data: inlineKubeconfig(nodeCA, ""), uid: 502, mode: regular},
			wantReads: 1, wantWarn: "refused",
			wantErr: []string{"is owned by uid 502", "no kubeconfig to mint a registry push token with", workerMintRemedy},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			workDir := filepath.Join(dir, "server")
			pinDir := filepath.Join(dir, "pinned")
			aliceHome := filepath.Join(dir, "alice")
			rootHome := filepath.Join(dir, "root")
			node := filepath.Join(dir, "agent", "kubeconfig")
			writeKubeconfigWithCA(t, executor.KubeconfigPath(workDir), leftoverServer, otherCA)
			writeKubeconfigWithCA(t, executor.KubeconfigPath(pinDir), pinServer, otherCA)
			if !tc.noNode {
				writeKubeconfigWithCA(t, node, nodeServer, nodeCA)
			}
			if tc.rootFile {
				writeKubeconfigWithCA(t, filepath.Join(rootHome, ".kube", "config"), rootServer, otherCA)
			}
			// sudo may keep the invoker's $HOME, and a real file sits there, so a
			// choice that read $HOME would take homeServer past every check.
			if !tc.noAccount {
				writeKubeconfigWithCA(t, filepath.Join(aliceHome, ".kube", "config"), homeServer, otherCA)
			}
			in := kubectlInputs{
				workDir:        workDir,
				home:           aliceHome,
				contextName:    "k3sm",
				exists:         fileExists,
				role:           tc.role,
				nodeKubeconfig: node,
			}
			if tc.pin {
				in.workDir, in.workDirOverride = pinDir, pinDir
			}
			if tc.envFile {
				in.kubeconfigEnv = filepath.Join(dir, "env-kubeconfig")
				writeKubeconfigWithCA(t, in.kubeconfigEnv, envServer, otherCA)
			}
			var warn bytes.Buffer
			reads := 0
			sudo := topSudoInputs{
				euid:     tc.euid,
				sudoUser: tc.sudoUser,
				lookup: func(name string) (*user.User, error) {
					switch name {
					case "root":
						return &user.User{Username: "root", Uid: "0", HomeDir: rootHome}, nil
					case "alice":
						return &user.User{Username: "alice", Uid: "501", HomeDir: aliceHome}, nil
					case "toor":
						return &user.User{Username: "toor", Uid: "0", HomeDir: rootHome}, nil
					case "homeless":
						return &user.User{Username: "homeless", Uid: "503", HomeDir: "relative/home"}, nil
					case "badnum":
						return &user.User{Username: "badnum", Uid: "not-a-number", HomeDir: aliceHome}, nil
					}
					return nil, user.UnknownUserError(name)
				},
				readFile: anchoredAt(nodeCA, func(path string) (sudoKubeconfigFile, error) {
					reads++
					if want := filepath.Join(aliceHome, ".kube", "config"); path != want {
						t.Errorf("root read %s, want only %s", path, want)
					}
					if tc.aliceFile == nil {
						return sudoKubeconfigFile{}, fs.ErrNotExist
					}
					return *tc.aliceFile, nil
				}),
				contextName: "k3sm",
				warn:        &warn,
			}

			var restServer, hint string
			var err error
			if tc.wantErr != nil {
				_, err = clusterRegistryAPIFrom(in, sudo)
			} else {
				var restCfg *rest.Config
				if restCfg, _, hint, err = registryClients(in, sudo); err == nil {
					restServer = restCfg.Host
				}
			}
			if reads != tc.wantReads {
				t.Errorf("root read the sudo user's kubeconfig %d times, want %d", reads, tc.wantReads)
			}
			if tc.wantWarn == "" && warn.Len() != 0 {
				t.Errorf("warned %q, want nothing", warn.String())
			}
			if !strings.Contains(warn.String(), tc.wantWarn) {
				t.Errorf("warned %q, want it to contain %q", warn.String(), tc.wantWarn)
			}
			if tc.wantErr != nil {
				if err == nil {
					t.Fatal("clusterRegistryAPIFrom succeeded, want a refusal")
				}
				if !errors.Is(err, errNoUserKubeconfig) {
					t.Errorf("err = %v, want errNoUserKubeconfig", err)
				}
				for _, s := range tc.wantErr {
					if !strings.Contains(err.Error(), s) {
						t.Errorf("err = %v, want it to contain %q", err, s)
					}
				}
				return
			}
			if err != nil {
				t.Fatalf("registryClients: %v", err)
			}
			if restServer != tc.wantServer {
				t.Errorf("the client's server = %q, want %q", restServer, tc.wantServer)
			}
			if tc.wantHint == "" && hint != "" {
				t.Errorf("nodeHint = %q, want none", hint)
			}
			if !strings.Contains(hint, tc.wantHint) {
				t.Errorf("nodeHint = %q, want it to contain %q", hint, tc.wantHint)
			}
		})
	}
}

// refusalWorker is a worker under sudo with a real node credential, for a test
// that decides what alice's kubeconfig and $KUBECONFIG hold.
func refusalWorker(t *testing.T, node string, env string, alice []byte, warn *bytes.Buffer, asked *[]string) (kubectlInputs, topSudoInputs) {
	t.Helper()
	dir := t.TempDir()
	in := kubectlInputs{
		workDir:     filepath.Join(dir, "server"),
		home:        filepath.Join(dir, "alice"),
		contextName: "k3sm",
		exists: func(p string) bool {
			if asked != nil {
				*asked = append(*asked, p)
			}
			return fileExists(p)
		},
		role:           install.RoleAgent,
		nodeKubeconfig: node,
		kubeconfigEnv:  env,
	}
	sudo := topSudoInputs{
		euid:     0,
		sudoUser: "alice",
		lookup: func(name string) (*user.User, error) {
			switch name {
			case "root":
				return &user.User{Username: "root", Uid: "0", HomeDir: filepath.Join(dir, "root")}, nil
			case "alice":
				return &user.User{Username: "alice", Uid: "501", HomeDir: filepath.Join(dir, "alice")}, nil
			}
			return nil, user.UnknownUserError(name)
		},
		readFile: func(string) (sudoKubeconfigFile, error) {
			if alice == nil {
				return sudoKubeconfigFile{}, fs.ErrNotExist
			}
			return sudoKubeconfigFile{data: alice, uid: 501, mode: 0o600}, nil
		},
		contextName: "k3sm",
		warn:        warn,
	}
	return in, sudo
}

// TestWorkerUnderSudoNeverLoadsKubeconfigEnv: under sudo $KUBECONFIG may
// name any file, so root must not use it, run a program it names, read its
// token file or read the CA file it names. The invoker's file is reached through
// the checked path instead.
func TestWorkerUnderSudoNeverLoadsKubeconfigEnv(t *testing.T) {
	dir := t.TempDir()
	secret := filepath.Join(dir, "root-only-secret")
	if err := os.WriteFile(secret, []byte("a file only root may read"), 0o600); err != nil {
		t.Fatal(err)
	}
	env := filepath.Join(dir, "env-kubeconfig")
	body := fmt.Sprintf(`apiVersion: v1
kind: Config
clusters:
- name: k3sm
  cluster:
    server: %s
    certificate-authority: %s
contexts:
- name: k3sm
  context:
    cluster: k3sm
    user: k3sm
current-context: k3sm
users:
- name: k3sm
  user:
    tokenFile: %s
    exec:
      apiVersion: client.authentication.k8s.io/v1
      command: /tmp/evil
      interactiveMode: Never
`, envServer, secret, secret)
	if err := os.WriteFile(env, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	nodeCA := testClusterCAPEM(t)
	node := filepath.Join(dir, "node.kubeconfig")
	writeKubeconfigWithCA(t, node, nodeServer, nodeCA)

	for _, tc := range []struct {
		name       string
		alice      []byte
		node       string
		wantServer string
		wantErr    string
	}{
		{name: "the checked file is used instead", alice: inlineKubeconfig(nodeCA, ""), node: node, wantServer: checkedServer},
		{name: "the node credential is no fallback", node: node, wantErr: "root does not use the node credential"},
		{name: "with nothing else the run fails rather than load it", node: filepath.Join(dir, "absent"), wantErr: "root does not use the node credential"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var warn bytes.Buffer
			var asked []string
			in, sudo := refusalWorker(t, tc.node, env, tc.alice, &warn, &asked)
			sudo.readFile = anchoredAt(nodeCA, sudo.readFile)
			restCfg, _, _, err := registryClients(in, sudo)
			if slices.Contains(asked, env) {
				t.Errorf("the choice looked at $KUBECONFIG's file %s", env)
			}
			if !strings.Contains(warn.String(), "ignoring $KUBECONFIG") {
				t.Errorf("warned %q, want it to say $KUBECONFIG was ignored", warn.String())
			}
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want it to contain %q", err, tc.wantErr)
				}
				if strings.Contains(err.Error(), "set KUBECONFIG") {
					t.Errorf("err = %v tells a run that ignores KUBECONFIG to set it", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("registryClients: %v", err)
			}
			if restCfg.Host != tc.wantServer {
				t.Errorf("server = %q, want %q", restCfg.Host, tc.wantServer)
			}
			if restCfg.ExecProvider != nil || restCfg.BearerTokenFile != "" || restCfg.CAFile != "" {
				t.Errorf("the client carries the file's references: exec %v, token file %q, CA file %q", restCfg.ExecProvider, restCfg.BearerTokenFile, restCfg.CAFile)
			}
			api, err := clusterRegistryAPIFrom(in, sudo)
			if err != nil {
				t.Fatalf("clusterRegistryAPIFrom: %v", err)
			}
			if bytes.Contains(api.caPEM, []byte("only root")) {
				t.Errorf("root read the CA file $KUBECONFIG named: %q", api.caPEM)
			}
		})
	}
}

// checkedKubeconfig is an invoker's kubeconfig at server whose cluster entry holds
// clusterTLS, which passes parseSudoUserKubeconfig's own checks.
func checkedKubeconfig(server, clusterTLS string) []byte {
	return fmt.Appendf(nil, `apiVersion: v1
kind: Config
clusters:
- name: k3sm
  cluster:
    server: %s
%s
contexts:
- name: k3sm
  context:
    cluster: k3sm
    user: k3sm
current-context: k3sm
users:
- name: k3sm
  user:
    token: abc123
`, server, clusterTLS)
}

// TestWorkerUnderSudoPinsTheInvokersClusterByTheAnchor: the invoker's file picks
// where root pushes, so it must name the cluster this node joined. That is pinned
// by CA and not by address, because a person's file may use another address, and
// by the root-only copy of that CA, which `k3sm install` writes pinned by the join
// token.
func TestWorkerUnderSudoPinsTheInvokersClusterByTheAnchor(t *testing.T) {
	clusterCA, otherCA := testClusterCAPEM(t), testClusterCAPEM(t)
	caData := func(pem []byte) string {
		return "    certificate-authority-data: " + base64.StdEncoding.EncodeToString(pem)
	}
	const skipVerify = "    insecure-skip-tls-verify: true"
	dir := t.TempDir()
	node := filepath.Join(dir, "node.kubeconfig")
	writeKubeconfigWithCA(t, node, nodeServer, clusterCA)
	// A node credential that trusts a different CA from the cluster's.
	movedNode := filepath.Join(dir, "moved.kubeconfig")
	writeKubeconfigWithCA(t, movedNode, nodeServer, otherCA)
	garbageNode := filepath.Join(dir, "garbage")
	if err := os.WriteFile(garbageNode, []byte("{not yaml"), 0o600); err != nil {
		t.Fatal(err)
	}
	good := sudoKubeconfigFile{data: clusterCA, uid: 0, mode: 0o644}
	with := func(edit func(*sudoKubeconfigFile)) *sudoKubeconfigFile {
		f := good
		edit(&f)
		return &f
	}

	for _, tc := range []struct {
		name  string
		alice []byte
		node  string
		// anchor is the root-only CA copy, nil for the one install writes, and
		// anchorErr is what reading it fails with instead.
		anchor    *sudoKubeconfigFile
		anchorErr error
		// wantServer is who an accepted file reaches; a refusal leaves no client.
		wantServer string
		// wantRefused is in the one line a person sees; "" means no refusal.
		wantRefused string
		// wantFix says the refusal names the install that repairs the anchor.
		wantFix bool
	}{
		{
			name:       "the cluster's CA at another address is accepted",
			alice:      checkedKubeconfig(checkedServer, caData(clusterCA)),
			node:       node,
			wantServer: checkedServer,
		},
		{
			name:       "the same CA spelled with other whitespace is the same CA",
			alice:      checkedKubeconfig(checkedServer, caData(append([]byte("\n\n"), clusterCA...))),
			node:       node,
			wantServer: checkedServer,
		},
		{
			name:       "the cluster's CA with the same address is accepted",
			alice:      checkedKubeconfig(nodeServer, caData(clusterCA)),
			node:       node,
			wantServer: nodeServer,
		},
		{
			name:        "skipping TLS verification is refused",
			alice:       checkedKubeconfig(checkedServer, skipVerify),
			node:        node,
			wantRefused: "insecure-skip-tls-verify",
		},
		{
			name:        "skipping TLS verification beside the right CA is refused",
			alice:       checkedKubeconfig(checkedServer, caData(clusterCA)+"\n"+skipVerify),
			node:        node,
			wantRefused: "insecure-skip-tls-verify",
		},
		{
			name:        "a plain http server with the right CA is refused",
			alice:       checkedKubeconfig("http://100.64.0.1:6444", caData(clusterCA)),
			node:        node,
			wantRefused: "only over https",
		},
		{
			name:        "another cluster's CA is refused",
			alice:       checkedKubeconfig(checkedServer, caData(otherCA)),
			node:        node,
			wantRefused: "holds a different CA from this worker's cluster CA " + install.AgentClusterCAPath,
		},
		{
			name:        "the cluster's CA with one more beside it is refused",
			alice:       checkedKubeconfig(checkedServer, caData(append(slices.Clone(clusterCA), otherCA...))),
			node:        node,
			wantRefused: "holds a different CA from this worker's cluster CA",
		},
		{
			name:        "no CA at all is refused",
			alice:       checkedKubeconfig(checkedServer, ""),
			node:        node,
			wantRefused: "carries no inline CA",
		},
		{
			name:        "a CA that holds no certificate is refused",
			alice:       checkedKubeconfig(checkedServer, caData([]byte("not a certificate"))),
			node:        node,
			wantRefused: "carries no inline CA",
		},

		// A changed node credential does not move the pin, either way.
		{
			name:        "a node credential rewritten to the invoker's CA does not admit it",
			alice:       checkedKubeconfig(checkedServer, caData(otherCA)),
			node:        movedNode,
			wantRefused: "holds a different CA from this worker's cluster CA",
		},
		{
			name:       "a node credential rewritten to another CA does not refuse the cluster's",
			alice:      checkedKubeconfig(checkedServer, caData(clusterCA)),
			node:       movedNode,
			wantServer: checkedServer,
		},
		{
			name:       "a node credential that does not parse does not matter",
			alice:      checkedKubeconfig(checkedServer, caData(clusterCA)),
			node:       garbageNode,
			wantServer: checkedServer,
		},
		{
			name:       "a missing node credential does not matter",
			alice:      checkedKubeconfig(checkedServer, caData(clusterCA)),
			node:       filepath.Join(dir, "absent"),
			wantServer: checkedServer,
		},

		// An anchor that cannot be trusted is a refusal, and the node credential
		// is not asked instead, even when it holds the invoker's CA.
		{
			name:        "a missing anchor is refused with the node credential agreeing",
			alice:       checkedKubeconfig(checkedServer, caData(clusterCA)),
			node:        node,
			anchorErr:   fs.ErrNotExist,
			wantRefused: "does not exist",
			wantFix:     true,
		},
		{
			name:        "a missing anchor with no node credential leaves no client",
			alice:       checkedKubeconfig(checkedServer, caData(clusterCA)),
			node:        filepath.Join(dir, "absent"),
			anchorErr:   fs.ErrNotExist,
			wantRefused: "does not exist",
			wantFix:     true,
		},
		{
			name:        "an anchor that cannot be read is refused",
			alice:       checkedKubeconfig(checkedServer, caData(clusterCA)),
			node:        node,
			anchorErr:   fs.ErrPermission,
			wantRefused: "permission denied",
			wantFix:     true,
		},
		{
			name:        "an anchor owned by another user is refused",
			alice:       checkedKubeconfig(checkedServer, caData(clusterCA)),
			node:        node,
			anchor:      with(func(f *sudoKubeconfigFile) { f.uid = 501 }),
			wantRefused: "is owned by uid 501, not by root",
			wantFix:     true,
		},
		{
			name:        "a group-writable anchor is refused",
			alice:       checkedKubeconfig(checkedServer, caData(clusterCA)),
			node:        node,
			anchor:      with(func(f *sudoKubeconfigFile) { f.mode = 0o664 }),
			wantRefused: "group- or world-writable (mode 0664)",
			wantFix:     true,
		},
		{
			name:        "a world-writable anchor is refused",
			alice:       checkedKubeconfig(checkedServer, caData(clusterCA)),
			node:        node,
			anchor:      with(func(f *sudoKubeconfigFile) { f.mode = 0o646 }),
			wantRefused: "group- or world-writable (mode 0646)",
			wantFix:     true,
		},
		{
			name:        "an anchor that is not a regular file is refused",
			alice:       checkedKubeconfig(checkedServer, caData(clusterCA)),
			node:        node,
			anchor:      &sudoKubeconfigFile{uid: 0, mode: fs.ModeNamedPipe | 0o600},
			wantRefused: "is not a regular file",
			wantFix:     true,
		},
		{
			name:        "an anchor that holds no certificate is refused",
			alice:       checkedKubeconfig(checkedServer, caData(clusterCA)),
			node:        node,
			anchor:      with(func(f *sudoKubeconfigFile) { f.data = []byte("not a certificate") }),
			wantRefused: "holds no certificate",
			wantFix:     true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var warn bytes.Buffer
			in, sudo := refusalWorker(t, tc.node, "", tc.alice, &warn, nil)
			readAlice := sudo.readFile
			sudo.readFile = func(path string) (sudoKubeconfigFile, error) {
				if path != install.AgentClusterCAPath {
					return readAlice(path)
				}
				if tc.anchorErr != nil {
					return sudoKubeconfigFile{}, tc.anchorErr
				}
				if tc.anchor != nil {
					return *tc.anchor, nil
				}
				return good, nil
			}
			restCfg, _, hint, err := registryClients(in, sudo)
			if tc.wantRefused == "" {
				if err != nil {
					t.Fatalf("registryClients: %v", err)
				}
				if warn.Len() != 0 || hint != "" {
					t.Errorf("warned %q with hint %q on an accepted kubeconfig", warn.String(), hint)
				}
				if restCfg.Host != tc.wantServer {
					t.Errorf("server = %q, want %q", restCfg.Host, tc.wantServer)
				}
				return
			}
			for _, what := range []string{"warning", "explanation"} {
				got := warn.String()
				if what == "explanation" {
					got = hint
					if err != nil {
						got = err.Error()
					}
				}
				if !strings.Contains(got, tc.wantRefused) {
					t.Errorf("the %s = %q, want it to contain %q", what, got, tc.wantRefused)
				}
			}
			if !strings.Contains(warn.String(), "refused") {
				t.Errorf("warned %q, want it to say refused", warn.String())
			}
			if tc.wantFix {
				for _, want := range []string{install.AgentClusterCAPath, "sudo rm -f " + install.AgentClusterCAPath, "--token-file", "k3sm token create"} {
					if !strings.Contains(warn.String(), want) {
						t.Errorf("warned %q, want the fix to name %q", warn.String(), want)
					}
				}
			}
			if err == nil {
				t.Fatalf("registryClients gave a client at %s, want none", restCfg.Host)
			}
		})
	}
}

// TestWorkerUnderSudoReadsARealFileThroughTheCheckedReader runs the choice over
// readOwnedFile and a real file, so the owner and mode the checks see are the
// ones the file has.
func TestWorkerUnderSudoReadsARealFileThroughTheCheckedReader(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("the file would be root's, and a uid 0 SUDO_USER is refused before it is read")
	}
	nodeCA := testClusterCAPEM(t)
	for _, tc := range []struct {
		name       string
		mode       fs.FileMode
		wantServer string
		wantErr    string
	}{
		{name: "the invoker's own 0600 file is used", mode: 0o600, wantServer: checkedServer},
		{name: "a world-writable file is not", mode: 0o666, wantErr: "group- or world-writable"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "alice", ".kube", "config")
			if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, inlineKubeconfig(nodeCA, ""), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(path, tc.mode); err != nil {
				t.Fatal(err)
			}
			node := filepath.Join(dir, "node-kubeconfig")
			writeKubeconfigWithCA(t, node, nodeServer, nodeCA)
			me := strconv.Itoa(os.Getuid())
			restCfg, _, _, err := registryClients(kubectlInputs{
				workDir:        filepath.Join(dir, "server"),
				contextName:    "k3sm",
				exists:         fileExists,
				role:           install.RoleAgent,
				nodeKubeconfig: node,
			}, topSudoInputs{
				euid:     0,
				sudoUser: "alice",
				lookup: func(name string) (*user.User, error) {
					if name != "alice" {
						return nil, user.UnknownUserError(name)
					}
					return &user.User{Username: "alice", Uid: me, HomeDir: filepath.Join(dir, "alice")}, nil
				},
				readFile:    anchoredAt(nodeCA, readOwnedFile),
				contextName: "k3sm",
			})
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want it to contain %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("registryClients: %v", err)
			}
			if restCfg.Host != tc.wantServer {
				t.Errorf("the client's server = %q, want %q", restCfg.Host, tc.wantServer)
			}
		})
	}
}

// TestWorkerUnderSudoReadsTheAnchorThroughTheCheckedReader gives the anchor a real
// file holding the right CA, owned by the test's own account: the owner the check
// refuses is the one the file has, and the node credential agreeing does not help.
func TestWorkerUnderSudoReadsTheAnchorThroughTheCheckedReader(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("the anchor would be root's, which is the file this test must not have")
	}
	dir := t.TempDir()
	clusterCA := testClusterCAPEM(t)
	anchor := filepath.Join(dir, "cluster-ca.crt")
	if err := os.WriteFile(anchor, clusterCA, 0o644); err != nil {
		t.Fatal(err)
	}
	node := filepath.Join(dir, "node.kubeconfig")
	writeKubeconfigWithCA(t, node, nodeServer, clusterCA)
	var warn bytes.Buffer
	in, sudo := refusalWorker(t, node, "", inlineKubeconfig(clusterCA, ""), &warn, nil)
	readAlice := sudo.readFile
	sudo.readFile = func(path string) (sudoKubeconfigFile, error) {
		if path == install.AgentClusterCAPath {
			return readOwnedFile(anchor)
		}
		return readAlice(path)
	}
	restCfg, _, _, err := registryClients(in, sudo)
	if err == nil {
		t.Fatalf("registryClients gave a client at %s, want a refusal", restCfg.Host)
	}
	if want := fmt.Sprintf("is owned by uid %d, not by root", os.Getuid()); !strings.Contains(warn.String(), want) {
		t.Errorf("warned %q, want it to contain %q", warn.String(), want)
	}
}

// forbiddenTokens is an apiserver that refuses the token request, as it refuses
// a system:node identity, and answers no other request.
func forbiddenTokens() *fake.Clientset {
	cs := fake.NewClientset()
	cs.PrependReactor("create", "serviceaccounts", func(ktesting.Action) (bool, runtime.Object, error) {
		return true, nil, apierrors.NewForbidden(schema.GroupResource{Resource: "serviceaccounts/token"}, "builder", errors.New("system:node:worker may not"))
	})
	return cs
}

// TestRefusedTokenOnANodeCredentialSaysWhatToDo: an account that reads its own node
// credential gets the token refusal that credential earns, and it says how to give
// the account a kubeconfig.
func TestRefusedTokenOnANodeCredentialSaysWhatToDo(t *testing.T) {
	cs := forbiddenTokens()
	hint := nodeCredentialHint("/var/lib/k3sm/agent/kubeconfig")
	api := clusterRegistryAPI{
		tokens:   cs.CoreV1().ServiceAccounts(registrysvc.BuilderNamespace),
		caPEM:    []byte("ca"),
		nodeHint: hint,
	}
	_, err := api.mintToken(context.Background(), pushTokenDuration, time.Now)
	if !errors.Is(err, errBuilderTokenRefused) {
		t.Fatalf("err = %v, want errBuilderTokenRefused", err)
	}
	for _, want := range []string{
		"/var/lib/k3sm/agent/kubeconfig",
		workerMintRemedy,
	} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("err = %v, want it to contain %q", err, want)
		}
	}

	api.nodeHint = ""
	if _, err := api.mintToken(context.Background(), pushTokenDuration, time.Now); err == nil || strings.Contains(err.Error(), "node credential") {
		t.Errorf("a user's own refused kubeconfig was described as a node credential: %v", err)
	}

	api.nodeHint = hint
	cs = fake.NewClientset()
	cs.PrependReactor("create", "serviceaccounts", func(ktesting.Action) (bool, runtime.Object, error) {
		return true, &authnv1.TokenRequest{Status: authnv1.TokenRequestStatus{Token: "t", ExpirationTimestamp: metav1.NewTime(time.Now().Add(pushTokenDuration))}}, nil
	})
	api.tokens = cs.CoreV1().ServiceAccounts(registrysvc.BuilderNamespace)
	if tok, err := api.mintToken(context.Background(), pushTokenDuration, time.Now); err != nil || tok.value != "t" {
		t.Errorf("mintToken = %q, %v; a node with the grant still mints", tok.value, err)
	}
}

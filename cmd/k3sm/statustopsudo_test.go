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
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime/schema"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"

	"k3sm.io/k3sm/pkg/status"
)

// sudoFakeKube is a Kube whose node list succeeds or fails as told, counting
// the lists.
type sudoFakeKube struct {
	name     string
	nodesErr error
	lists    int
}

func (k *sudoFakeKube) RawGet(context.Context, string) ([]byte, error) { return nil, nil }
func (k *sudoFakeKube) Nodes(context.Context) ([]corev1.Node, error) {
	k.lists++
	if k.nodesErr != nil {
		return nil, k.nodesErr
	}
	return []corev1.Node{{}}, nil
}
func (k *sudoFakeKube) Pods(context.Context) ([]corev1.Pod, error) { return nil, nil }
func (k *sudoFakeKube) Server() string                             { return "https://" + k.name }
func (k *sudoFakeKube) TLSPosture() string                         { return "ca pinned" }

// sudoKubeconfig is a kubeconfig with the installed context, its CA and token
// inline, the shape `k3sm install` writes; auth is the user entry's body.
func sudoKubeconfig(auth string) []byte {
	return []byte(`apiVersion: v1
kind: Config
clusters:
- name: k3sm
  cluster:
    server: https://192.0.2.10:6443
    certificate-authority-data: ` + "Zm9v" + `
contexts:
- name: k3sm
  context:
    cluster: k3sm
    user: k3sm
current-context: other
users:
- name: k3sm
  user:
` + auth)
}

const sudoInlineToken = "    token: abc123\n"

func forbiddenNodes(node string) error {
	return apierrors.NewForbidden(schema.GroupResource{Resource: "nodes"}, "", fmt.Errorf("User %q cannot list resource \"nodes\"", "system:node:"+node))
}

// TestStatusTopUnderSudoUsesTheInvokingUsersKubeconfig is the gate on the top
// view's client choice under sudo: root with a SUDO_USER reads that user's own
// ~/.kube/config, found from the user database and never from root's
// environment, pinned to the installed context, and uses it when it can list
// nodes; a file the user does not own or others can write is refused and said
// so; with no SUDO_USER the choice is today's; and when neither credential can
// list nodes the error says to run the view without sudo.
func TestStatusTopUnderSudoUsesTheInvokingUsersKubeconfig(t *testing.T) {
	const home = "/Users/alice"
	userPath := filepath.Join(home, ".kube", "config")
	cases := []struct {
		name     string
		euid     int
		sudoUser string
		file     *sudoKubeconfigFile
		readErr  error
		userErr  error // the user's client's node-list error
		fbErr    error // the fallback client's node-list error
		fbNil    bool  // the fallback has no client at all
		// want is "user" or "fallback": which client the view reads with.
		want string
		// wantRead says whether the user's kubeconfig is read at all.
		wantRead bool
		// wantWarn, when set, must appear in the warning; empty means none.
		wantWarn string
		// wantErr, when set, must appear in the view's node-list or client error.
		wantErr []string
	}{
		{
			name: "the user's kubeconfig is chosen", euid: 0, sudoUser: "alice",
			file: &sudoKubeconfigFile{data: sudoKubeconfig(sudoInlineToken), uid: 501, mode: 0o600},
			want: "user", wantRead: true,
		},
		{
			name: "a file owned by someone else is refused", euid: 0, sudoUser: "alice",
			file: &sudoKubeconfigFile{data: sudoKubeconfig(sudoInlineToken), uid: 0, mode: 0o600},
			want: "fallback", wantRead: true, wantWarn: "owned by uid 0, not by alice, refused",
		},
		{
			name: "a group-writable file is refused", euid: 0, sudoUser: "alice",
			file: &sudoKubeconfigFile{data: sudoKubeconfig(sudoInlineToken), uid: 501, mode: 0o620},
			want: "fallback", wantRead: true, wantWarn: "group- or world-writable (mode 0620), refused",
		},
		{
			name: "a world-writable file is refused", euid: 0, sudoUser: "alice",
			file: &sudoKubeconfigFile{data: sudoKubeconfig(sudoInlineToken), uid: 501, mode: 0o606},
			want: "fallback", wantRead: true, wantWarn: "group- or world-writable (mode 0606), refused",
		},
		{
			name: "a credential plugin is refused", euid: 0, sudoUser: "alice",
			file: &sudoKubeconfigFile{data: sudoKubeconfig("    exec:\n      apiVersion: client.authentication.k8s.io/v1\n      command: /bin/sh\n"), uid: 501, mode: 0o600},
			want: "fallback", wantRead: true, wantWarn: "runs a credential plugin",
		},
		{
			name: "a credential read from a file is refused", euid: 0, sudoUser: "alice",
			file: &sudoKubeconfigFile{data: sudoKubeconfig("    tokenFile: /var/root/secret\n"), uid: 501, mode: 0o600},
			want: "fallback", wantRead: true, wantWarn: "reads its credential from a file",
		},
		{
			name: "no SUDO_USER keeps today's choice", euid: 0, sudoUser: "",
			want: "fallback",
		},
		{
			name: "not root keeps today's choice", euid: 501, sudoUser: "alice",
			file: &sudoKubeconfigFile{data: sudoKubeconfig(sudoInlineToken), uid: 501, mode: 0o600},
			want: "fallback",
		},
		{
			name: "the user's kubeconfig that cannot list nodes falls back", euid: 0, sudoUser: "alice",
			file:    &sudoKubeconfigFile{data: sudoKubeconfig(sudoInlineToken), uid: 501, mode: 0o600},
			userErr: errors.New("connection refused"),
			want:    "fallback", wantRead: true,
		},
		{
			name: "neither can list nodes says to run without sudo", euid: 0, sudoUser: "alice",
			file:    &sudoKubeconfigFile{data: sudoKubeconfig(sudoInlineToken), uid: 501, mode: 0o600},
			userErr: errors.New("connection refused"), fbErr: forbiddenNodes("k3sm-worker"),
			want: "fallback", wantRead: true,
			wantErr: []string{"cannot list resource", "cannot list nodes: connection refused", "without sudo"},
		},
		{
			name: "no user kubeconfig and no fallback client says to run without sudo", euid: 0, sudoUser: "alice",
			readErr: fs.ErrNotExist, fbNil: true, wantRead: true,
			wantErr: []string{"no node credential", userPath + " does not exist", "without sudo"},
		},
		{
			name: "a missing user kubeconfig falls back quietly", euid: 0, sudoUser: "alice",
			readErr: fs.ErrNotExist, want: "fallback", wantRead: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Root's environment must not steer the choice.
			t.Setenv("HOME", "/var/root")
			t.Setenv("KUBECONFIG", "/var/root/.kube/config")

			userKube := &sudoFakeKube{name: "user", nodesErr: tc.userErr}
			fbKube := &sudoFakeKube{name: "fallback", nodesErr: tc.fbErr}
			var reads []string
			var builtCtx string
			var warn bytes.Buffer
			in := topSudoInputs{
				euid:     tc.euid,
				sudoUser: tc.sudoUser,
				lookup: func(name string) (*user.User, error) {
					if name != "alice" {
						return nil, user.UnknownUserError(name)
					}
					return &user.User{Username: "alice", Uid: "501", HomeDir: home}, nil
				},
				readFile: func(path string) (sudoKubeconfigFile, error) {
					reads = append(reads, path)
					if path != userPath {
						return sudoKubeconfigFile{}, fs.ErrNotExist
					}
					if tc.readErr != nil {
						return sudoKubeconfigFile{}, tc.readErr
					}
					return *tc.file, nil
				},
				contextName: "k3sm",
				build: func(_ *clientcmdapi.Config, ctxName string) (status.Kube, error) {
					builtCtx = ctxName
					return userKube, nil
				},
				warn: &warn,
			}
			fallback := func() (status.Kube, error) {
				if tc.fbNil {
					return nil, errors.New("no node credential at /var/lib/k3sm/agent/kubeconfig")
				}
				return fbKube, nil
			}
			kube, err := chooseTopKube(context.Background(), in, fallback)

			if tc.wantRead {
				if len(reads) != 1 || reads[0] != userPath {
					t.Fatalf("read %v, want only %s", reads, userPath)
				}
			} else if len(reads) != 0 {
				t.Fatalf("read %v, want no read of a user kubeconfig", reads)
			}
			if builtCtx != "" && builtCtx != "k3sm" {
				t.Errorf("built context %q, want the installed context k3sm", builtCtx)
			}
			if tc.wantWarn == "" {
				if warn.Len() != 0 {
					t.Errorf("warned %q, want no warning", warn.String())
				}
			} else if !strings.Contains(warn.String(), tc.wantWarn) {
				t.Errorf("warning %q does not say %q", warn.String(), tc.wantWarn)
			}

			var viewErr string
			switch {
			case kube == nil:
				if err == nil {
					t.Fatal("no client and no error")
				}
				viewErr = err.Error()
			default:
				if err != nil {
					t.Fatalf("client with error %v", err)
				}
				if got := kube.Server(); got != "https://"+tc.want {
					t.Fatalf("view reads with %s, want %s", got, tc.want)
				}
				if _, lerr := kube.Nodes(context.Background()); lerr != nil {
					viewErr = lerr.Error()
				}
			}
			for _, want := range tc.wantErr {
				if !strings.Contains(viewErr, want) {
					t.Errorf("view error %q does not say %q", viewErr, want)
				}
			}
			if len(tc.wantErr) == 0 && viewErr != "" {
				t.Errorf("view error %q, want the nodes listed", viewErr)
			}
			if tc.sudoUser == "" || tc.euid != 0 {
				if fbKube.lists != 1 {
					t.Errorf("fallback listed nodes %d times, want only the view's own list", fbKube.lists)
				}
			}
		})
	}
}

// TestReadOwnedFileReportsTheOpenedFilesOwnerAndMode checks the production
// reader against a real file: the owner and mode come from what was read.
func TestReadOwnedFileReportsTheOpenedFilesOwnerAndMode(t *testing.T) {
	p := filepath.Join(t.TempDir(), "config")
	if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, 0o620); err != nil {
		t.Fatal(err)
	}
	f, err := readOwnedFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if f.uid != uint32(os.Getuid()) || f.mode.Perm() != 0o620 || string(f.data) != "x" {
		t.Errorf("got uid %d mode %v data %q", f.uid, f.mode, f.data)
	}
	if _, err := readOwnedFile(filepath.Join(t.TempDir(), "absent")); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("absent file: %v, want ErrNotExist", err)
	}
}

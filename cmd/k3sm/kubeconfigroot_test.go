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
	"reflect"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
	"k8s.io/client-go/tools/clientcmd"

	"k3sm.io/k3sm/pkg/executor"
	"k3sm.io/k3sm/pkg/install"
)

const (
	rootTestWorkDir = "/var/lib/k3sm/server"
	aliceUID        = uint32(501)
	aliceHome       = "/Users/alice"
	rootHome        = "/var/root"
	envHome         = "/Users/elsewhere"
)

// inlineKubeconfigText holds the k3sm context, inline, and a current context named
// other whose user runs a plugin.
const inlineKubeconfigText = `apiVersion: v1
kind: Config
current-context: other
clusters:
- name: k3sm
  cluster:
    server: https://192.0.2.1:6443
- name: other
  cluster:
    server: https://192.0.2.2:6443
contexts:
- name: k3sm
  context: {cluster: k3sm, user: k3sm}
- name: other
  context: {cluster: other, user: other}
users:
- name: k3sm
  user: {token: inline-token}
- name: other
  user:
    exec:
      apiVersion: client.authentication.k8s.io/v1
      command: /elsewhere/plugin
      interactiveMode: Never
`

// kubeconfigWithUser is a k3sm context whose user is the YAML given.
func kubeconfigWithUser(userYAML string) string {
	return fmt.Sprintf(`apiVersion: v1
kind: Config
current-context: k3sm
clusters:
- name: k3sm
  cluster: {server: "https://192.0.2.1:6443"}
contexts:
- name: k3sm
  context: {cluster: k3sm, user: k3sm}
users:
- name: k3sm
  user: %s
`, userYAML)
}

const execUser = `{exec: {apiVersion: client.authentication.k8s.io/v1, command: /elsewhere/plugin, interactiveMode: Never}}`

// fakeRootSources is a rootKubeSources over a described set of files. reads, when
// given, records every path read.
func fakeRootSources(sudoUser string, files map[string]sudoKubeconfigFile, reads *[]string) *rootKubeSources {
	return &rootKubeSources{
		sudoUser: sudoUser,
		lookup: func(name string) (*user.User, error) {
			if name != "alice" {
				return nil, errors.New("no such user")
			}
			return &user.User{Username: "alice", Uid: fmt.Sprint(aliceUID), HomeDir: aliceHome}, nil
		},
		lookupID: func(id string) (*user.User, error) {
			if id != rootUID {
				return nil, errors.New("no such uid")
			}
			return &user.User{Username: "root", Uid: rootUID, HomeDir: rootHome}, nil
		},
		readFile: func(path string) (sudoKubeconfigFile, error) {
			if reads != nil {
				*reads = append(*reads, path)
			}
			f, ok := files[path]
			if !ok {
				return sudoKubeconfigFile{}, &fs.PathError{Op: "open", Path: path, Err: fs.ErrNotExist}
			}
			return f, nil
		},
	}
}

func regular(uid uint32, perm fs.FileMode, body string) sudoKubeconfigFile {
	return sudoKubeconfigFile{data: []byte(body), uid: uid, mode: perm}
}

func TestRootKubeconfigChoice(t *testing.T) {
	const (
		envFile  = "/etc/k3sm/kubeconfig"
		otherUID = uint32(502)
	)
	workFile := executor.KubeconfigPath(rootTestWorkDir)
	aliceFile := filepath.Join(aliceHome, ".kube", "config")
	rootFile := filepath.Join(rootHome, ".kube", "config")
	inline := kubeconfigWithUser("{token: inline-token}")
	withExec := kubeconfigWithUser(execUser)

	tests := []struct {
		name        string
		sudoUser    string
		override    string
		env         string
		files       map[string]sudoKubeconfigFile
		wantPath    string // kubectlConfig.kubeconfig
		wantContext string
		wantErr     []string
	}{
		{
			name:     "the work dir's file, whichever account owns it",
			files:    map[string]sudoKubeconfigFile{workFile: regular(299, 0o600, inline)},
			wantPath: workFile,
		},
		{
			name:    "the work dir's file with an exec entry is refused",
			files:   map[string]sudoKubeconfigFile{workFile: regular(299, 0o600, withExec)},
			wantErr: []string{workFile, `user "k3sm" runs a credential plugin`, "refused", "`sudo k3sm restart` makes a server write this file again"},
		},
		{
			name:    "a group-writable work dir file is refused",
			files:   map[string]sudoKubeconfigFile{workFile: regular(299, 0o660, inline)},
			wantErr: []string{workFile + " is group- or world-writable (mode 0660)"},
		},
		{
			name:     "a named work dir with no file does not fall back",
			override: rootTestWorkDir,
			files:    map[string]sudoKubeconfigFile{rootFile: regular(0, 0o600, inline)},
			wantErr:  []string{"not found", "run `k3sm server` first"},
		},
		{
			name:        "a root-owned $KUBECONFIG stays usable",
			env:         envFile,
			files:       map[string]sudoKubeconfigFile{envFile: regular(0, 0o600, inline)},
			wantContext: "k3sm",
		},
		{
			name:        "a $KUBECONFIG list takes its first entry that exists",
			env:         "/absent:" + envFile,
			files:       map[string]sudoKubeconfigFile{envFile: regular(0, 0o600, inline)},
			wantContext: "k3sm",
		},
		{
			name:        "a $KUBECONFIG of the person who ran sudo is checked and usable",
			sudoUser:    "alice",
			env:         envFile,
			files:       map[string]sudoKubeconfigFile{envFile: regular(aliceUID, 0o600, inline)},
			wantContext: "k3sm",
		},
		{
			name:     "a $KUBECONFIG of another owner is refused, not passed over",
			sudoUser: "alice",
			env:      envFile,
			files: map[string]sudoKubeconfigFile{
				envFile:   regular(otherUID, 0o600, inline),
				aliceFile: regular(aliceUID, 0o600, inline),
			},
			wantErr: []string{"$KUBECONFIG", envFile + " is owned by uid 502, not root or alice", rootKubeconfigRemedy},
		},
		{
			name:    "a $KUBECONFIG with an exec entry is refused even when root owns it",
			env:     envFile,
			files:   map[string]sudoKubeconfigFile{envFile: regular(0, 0o600, withExec)},
			wantErr: []string{"$KUBECONFIG", `user "k3sm" runs a credential plugin`, rootKubeconfigRemedy},
		},
		{
			name:    "a $KUBECONFIG naming only absent files says so",
			env:     envFile,
			files:   map[string]sudoKubeconfigFile{rootFile: regular(0, 0o600, inline)},
			wantErr: []string{"no file named by $KUBECONFIG exists", "or unset it"},
		},
		{
			name:        "the invoking user's file from the user database's home",
			sudoUser:    "alice",
			files:       map[string]sudoKubeconfigFile{aliceFile: regular(aliceUID, 0o600, inlineKubeconfigText), rootFile: regular(0, 0o600, inline)},
			wantContext: "k3sm",
		},
		{
			name:     "the invoking user's file with an exec entry gives way to root's",
			sudoUser: "alice",
			files: map[string]sudoKubeconfigFile{
				aliceFile: regular(aliceUID, 0o600, withExec),
				rootFile:  regular(0, 0o600, inline),
			},
			wantContext: "k3sm",
		},
		{
			name:     "the invoking user's file with an exec entry and nothing else",
			sudoUser: "alice",
			files:    map[string]sudoKubeconfigFile{aliceFile: regular(aliceUID, 0o600, withExec)},
			wantErr:  []string{"alice's kubeconfig " + aliceFile, `user "k3sm" runs a credential plugin`, "refused", rootKubeconfigRemedy},
		},
		{
			name:     "the invoking user's file with a path entry",
			sudoUser: "alice",
			files:    map[string]sudoKubeconfigFile{aliceFile: regular(aliceUID, 0o600, kubeconfigWithUser("{tokenFile: /elsewhere/token}"))},
			wantErr:  []string{`user "k3sm" reads its credential from a file`, "refused", rootKubeconfigRemedy},
		},
		{
			name:     "the invoking user's file with another owner",
			sudoUser: "alice",
			files:    map[string]sudoKubeconfigFile{aliceFile: regular(otherUID, 0o600, inline)},
			wantErr:  []string{"owned by uid 502, not by alice", rootKubeconfigRemedy},
		},
		{
			name:        "root's own file from the user database's home",
			files:       map[string]sudoKubeconfigFile{rootFile: regular(0, 0o600, inline)},
			wantContext: "k3sm",
		},
		{
			name:    "root's own home holding a file root does not own",
			files:   map[string]sudoKubeconfigFile{rootFile: regular(aliceUID, 0o600, inline)},
			wantErr: []string{rootFile + " is owned by uid 501, not root"},
		},
		{
			name:    "nothing to use names each place and what to do",
			files:   nil,
			wantErr: []string{"no kubeconfig to use as root", workFile + " does not exist", rootFile + " does not exist", rootKubeconfigRemedy},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var reads []string
			files := map[string]sudoKubeconfigFile{filepath.Join(envHome, ".kube", "config"): regular(0, 0o600, inline)}
			for p, f := range tt.files {
				files[p] = f
			}
			src := fakeRootSources(tt.sudoUser, files, &reads)
			got, err := resolveKubectlConfig(kubectlInputs{
				workDirOverride: tt.override,
				workDir:         rootTestWorkDir,
				kubeconfigEnv:   tt.env,
				home:            envHome,
				contextName:     "k3sm",
				exists:          func(string) bool { t.Error("the root path used exists"); return false },
				root:            src,
			})
			for _, p := range reads {
				if strings.HasPrefix(p, envHome) {
					t.Errorf("read %s, under the environment's home", p)
				}
			}
			if tt.wantErr != nil {
				if err == nil {
					t.Fatalf("resolve = %+v, want an error", got)
				}
				for _, want := range tt.wantErr {
					if !strings.Contains(err.Error(), want) {
						t.Errorf("error %q does not contain %q", err, want)
					}
				}
				return
			}
			if err != nil {
				t.Fatalf("resolve: %v", err)
			}
			if got.kubeconfig != tt.wantPath || got.context != tt.wantContext || got.checked == nil {
				t.Errorf("resolve = %+v, want kubeconfig %q context %q and checked bytes", got, tt.wantPath, tt.wantContext)
			}
		})
	}
}

// TestCheckedKubeconfigHoldsOnlyTheAcceptedContext pins why a file that also has
// plugin entries can be used: they are not in what the client or kubectl gets, so
// no `--context` can reach them.
func TestCheckedKubeconfigHoldsOnlyTheAcceptedContext(t *testing.T) {
	c, err := checkKubeconfig([]byte(inlineKubeconfigText), "/f", "k3sm")
	if err != nil {
		t.Fatalf("checkKubeconfig: %v", err)
	}
	data, err := clientcmd.Write(*c.cfg)
	if err != nil {
		t.Fatal(err)
	}
	for _, absent := range []string{"exec", "/elsewhere/plugin", "other", "192.0.2.2"} {
		if strings.Contains(string(data), absent) {
			t.Errorf("checked bytes carry %q:\n%s", absent, data)
		}
	}
	rc, err := c.restConfig()
	if err != nil {
		t.Fatalf("restConfig: %v", err)
	}
	if rc.Host != "https://192.0.2.1:6443" || rc.BearerToken != "inline-token" || rc.ExecProvider != nil {
		t.Errorf("rest config = host %q token %q exec %v", rc.Host, rc.BearerToken, rc.ExecProvider)
	}
}

// TestKubeconfigK3smWritesPassesAsRoot pins the files a default install reads as
// root to the check: the server's admin kubeconfig.
func TestKubeconfigK3smWritesPassesAsRoot(t *testing.T) {
	data, err := os.ReadFile(writeServiceKubeconfig(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := checkKubeconfig(data, "k3sm.kubeconfig", ""); err != nil {
		t.Errorf("checkKubeconfig: %v", err)
	}
}

// TestKubeconfigHandoff reads the handoff the way kubectl does and pins that the
// file has no name and that an exec keeps its descriptor.
func TestKubeconfigHandoff(t *testing.T) {
	dir := t.TempDir()
	prev := kubeconfigHandoffDir
	kubeconfigHandoffDir = dir
	t.Cleanup(func() { kubeconfigHandoffDir = prev })

	c, err := checkKubeconfig([]byte(inlineKubeconfigText), "/f", "k3sm")
	if err != nil {
		t.Fatal(err)
	}
	f, path, err := c.handoff()
	if err != nil {
		t.Fatalf("handoff: %v", err)
	}
	defer f.Close()

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Errorf("handoff dir holds %v, want nothing with a name", entries)
	}
	flags, err := unix.FcntlInt(f.Fd(), unix.F_GETFD, 0)
	if err != nil {
		t.Fatal(err)
	}
	if flags&unix.FD_CLOEXEC != 0 {
		t.Error("the handoff descriptor closes on exec")
	}
	fi, err := f.Stat()
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("handoff mode = %04o, want 0600", fi.Mode().Perm())
	}
	loaded, err := clientcmd.LoadFromFile(path)
	if err != nil {
		t.Fatalf("load %s: %v", path, err)
	}
	if loaded.CurrentContext != "k3sm" || loaded.AuthInfos["k3sm"].Token != "inline-token" {
		t.Errorf("loaded = %+v", loaded)
	}
}

func TestRootKubectlEnv(t *testing.T) {
	got := rootKubectlEnv([]string{"PATH=/bin", "HOME=" + envHome, "KUBECONFIG=/a", "KUBERC=/b", "KUBECONFIG=/c"}, "/dev/fd/9", rootHome)
	want := []string{"PATH=/bin", "HOME=" + rootHome, "KUBECONFIG=/dev/fd/9"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("env = %q, want %q", got, want)
	}
}

// useInstalledKubectl makes the installed kubectl pass the binary check.
func useInstalledKubectl(t *testing.T) {
	t.Helper()
	prev := kubectlExecCheck
	kubectlExecCheck = fakeExecCheck(rootTree(installedKubectl(install.DefaultInstallDir)), nil)
	t.Cleanup(func() { kubectlExecCheck = prev })
}

// TestKubectlAsRootHandsOverTheCheckedBytes runs the verb as root and reads what
// kubectl would, at the moment of the exec.
func TestKubectlAsRootHandsOverTheCheckedBytes(t *testing.T) {
	asRoot(t)
	useInstalledKubectl(t)
	workDir := t.TempDir()
	writeInlineKubeconfig(t, executor.KubeconfigPath(workDir))
	t.Setenv("K3SM_WORK_DIR", workDir)
	t.Setenv("SUDO_USER", "")
	t.Setenv("KUBERC", "/elsewhere/kuberc")

	var (
		calls  int
		gotEnv []string
		loaded string
	)
	prev := kubectlExec
	kubectlExec = func(_ string, _, env []string) error {
		calls++
		gotEnv = env
		for _, kv := range env {
			if path, ok := strings.CutPrefix(kv, "KUBECONFIG="); ok {
				cfg, err := clientcmd.LoadFromFile(path)
				if err != nil {
					return err
				}
				loaded = cfg.AuthInfos["u"].Token
			}
		}
		return nil
	}
	t.Cleanup(func() { kubectlExec = prev })

	if err := runKubectl([]string{"get", "pods"}); err != nil {
		t.Fatalf("runKubectl: %v", err)
	}
	if calls != 1 || loaded != "inline" {
		t.Errorf("exec calls = %d, token through the handoff = %q", calls, loaded)
	}
	for _, kv := range gotEnv {
		if strings.HasPrefix(kv, "KUBERC=") || kv == "KUBECONFIG="+executor.KubeconfigPath(workDir) {
			t.Errorf("exec env carries %q", kv)
		}
	}
}

// TestExecEntryNeverRunsAsRoot loads a kubeconfig with an exec entry through each
// verb as root: a refusal each time, and the entry's program never starts.
func TestExecEntryNeverRunsAsRoot(t *testing.T) {
	asRoot(t)
	useInstalledKubectl(t)
	t.Setenv("SUDO_USER", "")
	setup := func(t *testing.T) (workDir, ran string) {
		workDir = t.TempDir()
		path := executor.KubeconfigPath(workDir)
		writeInlineKubeconfig(t, path)
		return workDir, saveExecEntry(t, path)
	}
	const wantRefusal = "runs a credential plugin"

	t.Run("kubectl", func(t *testing.T) {
		workDir, ran := setup(t)
		t.Setenv("K3SM_WORK_DIR", workDir)
		prev := kubectlExec
		kubectlExec = func(string, []string, []string) error {
			t.Error("kubectl was exec'd")
			return nil
		}
		t.Cleanup(func() { kubectlExec = prev })
		if err := runKubectl(nil); err == nil || !strings.Contains(err.Error(), wantRefusal) {
			t.Errorf("runKubectl = %v, want %q", err, wantRefusal)
		}
		assertNeverRan(t, ran)
	})
	t.Run("builder", func(t *testing.T) {
		workDir, ran := setup(t)
		_, _, err := builderClients(builderKubeInputs(builderOptions{workDir: workDir, workDirExplicit: true}))
		if err == nil || !strings.Contains(err.Error(), wantRefusal) {
			t.Errorf("builderClients = %v, want %q", err, wantRefusal)
		}
		assertNeverRan(t, ran)
	})
	t.Run("interconnect", func(t *testing.T) {
		workDir, ran := setup(t)
		t.Setenv("K3SM_WORK_DIR", workDir)
		_, _, err := interconnectClients("")
		if err == nil || !strings.Contains(err.Error(), wantRefusal) {
			t.Errorf("interconnectClients = %v, want %q", err, wantRefusal)
		}
		assertNeverRan(t, ran)
	})
	t.Run("interconnect --kubeconfig", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("the fixture's owner is the test account, which must not be root")
		}
		workDir, ran := setup(t)
		_, _, err := interconnectClients(executor.KubeconfigPath(workDir))
		if err == nil || !strings.Contains(err.Error(), "not root") || !strings.Contains(err.Error(), rootKubeconfigRemedy) {
			t.Errorf("interconnectClients = %v, want an owner refusal and the remedy", err)
		}
		assertNeverRan(t, ran)
	})
}

// TestBuilderAsRootUsesTheCheckedKubeconfig pins the builder's client to the
// checked entries, with the context pinned rather than the file's current one.
func TestBuilderAsRootUsesTheCheckedKubeconfig(t *testing.T) {
	aliceFile := filepath.Join(aliceHome, ".kube", "config")
	in := kubectlInputs{
		workDir:     rootTestWorkDir,
		home:        rootHome,
		contextName: "k3sm",
		root:        fakeRootSources("alice", map[string]sudoKubeconfigFile{aliceFile: regular(aliceUID, 0o600, inlineKubeconfigText)}, nil),
	}
	rc, cs, err := builderClients(in)
	if err != nil {
		t.Fatalf("builderClients: %v", err)
	}
	if cs == nil || rc.Host != "https://192.0.2.1:6443" || rc.ExecProvider != nil {
		t.Errorf("client = %v, host %q, exec %v", cs, rc.Host, rc.ExecProvider)
	}

	in.root = fakeRootSources("alice", map[string]sudoKubeconfigFile{aliceFile: regular(aliceUID, 0o600, kubeconfigWithUser(execUser))}, nil)
	if _, _, err := builderClients(in); err == nil || !strings.Contains(err.Error(), "runs a credential plugin") || !strings.Contains(err.Error(), rootKubeconfigRemedy) {
		t.Errorf("builderClients = %v, want the refusal's own text", err)
	}
}

// TestRootHomeComesFromTheUserDatabase pins that root does not take $HOME, and
// that other accounts still do.
func TestRootHomeComesFromTheUserDatabase(t *testing.T) {
	t.Setenv("HOME", envHome)
	if os.Geteuid() != 0 {
		if got := kubeHome(); got != envHome {
			t.Errorf("as this account, kubeHome = %q, want %q", got, envHome)
		}
	}
	asRoot(t)
	if got := kubeHome(); got == envHome || !filepath.IsAbs(got) {
		t.Errorf("as root, kubeHome = %q, want root's home from the user database", got)
	}
}

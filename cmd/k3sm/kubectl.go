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
	"os"
	"os/exec"
	"path/filepath"

	"k3sm.io/k3sm/pkg/executor"
	"k3sm.io/k3sm/pkg/install"
)

// runKubectl is the `k3sm kubectl` passthrough: it execs a kubectl binary
// against this cluster and forwards every argument and the child's exit code
// (mirrors `k3s kubectl`).
//
// Which credentials it uses depends on who runs it. Root and the _k3sm service
// user get the control-plane work dir's admin kubeconfig (KUBECONFIG preset),
// with the bundled kubectl the server downloaded into that work dir. An ordinary
// user cannot read that directory — it is mode 0700 and owned by the service
// user — so for them k3sm falls back to kubectl's own kubeconfig loading rules
// ($KUBECONFIG, else ~/.kube/config) pinned to the `k3sm` context that
// `sudo k3sm install` merged there, run through the kubectl the installer laid
// down beside the daemon. K3SM_WORK_DIR pins a non-default `k3sm server
// --work-dir` and, when set, is used verbatim with no fallback.
func runKubectl(args []string) error {
	workDir := workDirFromEnv()
	home, _ := os.UserHomeDir()
	cfg, err := resolveKubectlConfig(kubectlInputs{
		workDirOverride: os.Getenv("K3SM_WORK_DIR"),
		workDir:         workDir,
		kubeconfigEnv:   os.Getenv("KUBECONFIG"),
		home:            home,
		contextName:     installedContextName,
		exists:          fileExists,
	})
	if err != nil {
		return err
	}
	bin, err := resolveKubectl(workDir)
	if err != nil {
		return err
	}
	cmd := exec.Command(bin, cfg.argv(args)...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	cmd.Env = os.Environ()
	if cfg.kubeconfig != "" {
		cmd.Env = append(cmd.Env, "KUBECONFIG="+cfg.kubeconfig)
	}
	if err := cmd.Run(); err != nil {
		// Forward kubectl's own exit code so scripts see the real status.
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			os.Exit(ee.ExitCode())
		}
		return fmt.Errorf("exec kubectl: %w", err)
	}
	return nil
}

// installedContextName is the cluster/user/context name `k3sm install` merges
// into the invoking user's kubeconfig (install.AdminKubeconfig), and therefore
// the context `k3sm kubectl` selects when it falls back to that kubeconfig. It
// is also the `k3sm kubeconfig --context-name` default.
const installedContextName = "k3sm"

// kubectlInputs is everything resolveKubectlConfig reads, injected so the
// resolution is a pure function of the environment rather than of this process.
type kubectlInputs struct {
	// workDirOverride is K3SM_WORK_DIR verbatim ("" when unset). Set, it pins the
	// work-dir kubeconfig with no fallback: the caller named a server work dir,
	// so silently talking to a different cluster would be a lie.
	workDirOverride string
	// workDir is the resolved control-plane work dir (executor.ResolveWorkDir).
	workDir string
	// kubeconfigEnv is $KUBECONFIG verbatim — a path LIST, of which kubectl reads
	// the first entry first.
	kubeconfigEnv string
	// home is the invoking user's home ("" when it cannot be resolved).
	home string
	// contextName is the context to select in the user's own kubeconfig.
	contextName string
	// exists reports whether a path is present (fileExists in production).
	exists func(string) bool
}

// kubectlConfig is how `k3sm kubectl` addresses the cluster: either an explicit
// kubeconfig path exported as KUBECONFIG, or kubectl's own loading rules with a
// context pinned.
type kubectlConfig struct {
	// kubeconfig, when non-empty, is exported as KUBECONFIG for the child.
	kubeconfig string
	// context, when non-empty, is prepended to the child's argv as --context.
	context string
}

// argv returns the child's arguments: the pinned context (when there is one)
// ahead of the caller's own. It goes FIRST because kubectl honors the LAST
// occurrence of a repeated flag, so a user's explicit `--context` still wins.
func (c kubectlConfig) argv(args []string) []string {
	if c.context == "" {
		return args
	}
	return append([]string{"--context=" + c.context}, args...)
}

// resolveKubectlConfig picks the credentials `k3sm kubectl` runs with, in order:
//
//  1. K3SM_WORK_DIR set — that work dir's admin kubeconfig, or an error. The
//     caller named a server, so there is no fallback to a different cluster.
//  2. The resolved work dir's admin kubeconfig, when it is there — the root and
//     _k3sm-service-user case, unchanged from before this fallback existed.
//  3. Otherwise kubectl's own rules ($KUBECONFIG, else ~/.kube/config) with the
//     installed context pinned — the ordinary-user case, where the work dir is
//     the service user's mode-0700 home and is not readable at all.
func resolveKubectlConfig(in kubectlInputs) (kubectlConfig, error) {
	kc := executor.KubeconfigPath(in.workDir)
	if in.workDirOverride != "" || in.exists(kc) {
		if !in.exists(kc) {
			return kubectlConfig{}, fmt.Errorf("kubeconfig %s not found — run `k3sm server` first (set K3SM_WORK_DIR if you used a non-default --work-dir)", kc)
		}
		return kubectlConfig{kubeconfig: kc}, nil
	}
	for _, p := range userKubeconfigCandidates(in.kubeconfigEnv, in.home) {
		if in.exists(p) {
			return kubectlConfig{context: in.contextName}, nil
		}
	}
	return kubectlConfig{}, fmt.Errorf("no kubeconfig for k3sm kubectl: %s is not readable and ~/.kube/config does not exist — run `sudo k3sm install` (it merges the k3sm admin context into your ~/.kube/config), or set KUBECONFIG", kc)
}

// userKubeconfigCandidates lists the files kubectl's default loading rules would
// read: the FIRST entry of $KUBECONFIG (the one that wins a merge), then
// ~/.kube/config. Either being present is enough for kubectl to load something;
// which one it picks is kubectl's decision, not k3sm's.
func userKubeconfigCandidates(kubeconfigEnv, home string) []string {
	var out []string
	if kubeconfigEnv != "" {
		if list := filepath.SplitList(kubeconfigEnv); len(list) > 0 && list[0] != "" {
			out = append(out, list[0])
		}
	}
	if home != "" {
		out = append(out, filepath.Join(home, ".kube", "config"))
	}
	return out
}

// resolveKubectl finds the kubectl binary to exec.
func resolveKubectl(workDir string) (string, error) {
	return resolveKubectlIn(workDir, install.DefaultInstallDir, fileExists, exec.LookPath)
}

// resolveKubectlIn is the testable core of resolveKubectl: the work dir's
// bundled kubectl (downloaded by `k3sm server`) first, then the payload kubectl
// `k3sm install` staged beside the daemon — world-executable, so it is there for
// an ordinary user whose work dir is not — then a kubectl on PATH.
func resolveKubectlIn(workDir, installDir string, exists func(string) bool, lookPath func(string) (string, error)) (string, error) {
	for _, p := range []string{executor.KubectlPath(workDir), installedKubectl(installDir)} {
		if exists(p) {
			return p, nil
		}
	}
	if p, err := lookPath("kubectl"); err == nil {
		return p, nil
	}
	return "", fmt.Errorf("no kubectl found (looked for %s, %s, and kubectl on PATH); run `sudo k3sm install`, or `k3sm server` to fetch the bundled kubectl",
		executor.KubectlPath(workDir), installedKubectl(installDir))
}

// installedKubectl is the payload kubectl `k3sm install` stages under the
// install dir. The layout is derived from executor.KubectlPath rather than
// re-typed because install stages the payload into <install dir>/bin with
// exactly the work dir's own bin layout — that is what lets the daemon boot seed
// its work dir from it.
func installedKubectl(installDir string) string { return executor.KubectlPath(installDir) }

// workDirFromEnv resolves the control-plane work dir, honoring K3SM_WORK_DIR so
// the kubectl/kubeconfig verbs agree with `k3sm server --work-dir`. With no
// override it uses the posture-aware default (the _k3sm control plane writes
// <home>/server, not the root-only const), falling back to the const on a
// resolve failure.
func workDirFromEnv() string {
	if d := os.Getenv("K3SM_WORK_DIR"); d != "" {
		return d
	}
	if wd, err := executor.ResolveWorkDir(); err == nil {
		return wd
	}
	return executor.DefaultWorkDir
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

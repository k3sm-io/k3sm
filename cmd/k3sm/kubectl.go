package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"

	"k3sm.io/k3sm/pkg/executor"
)

// runKubectl is the `k3sm kubectl` passthrough: it execs a kubectl binary with
// KUBECONFIG pointed at the k3sm admin kubeconfig and forwards every argument
// and the child's exit code (mirrors `k3s kubectl`). The control-plane work dir
// defaults to executor.DefaultWorkDir; override with K3SM_WORK_DIR to match a
// non-default `k3sm server --work-dir`.
func runKubectl(args []string) error {
	workDir := workDirFromEnv()
	kc := executor.KubeconfigPath(workDir)
	if !fileExists(kc) {
		return fmt.Errorf("kubeconfig %s not found — run `k3sm server` first (set K3SM_WORK_DIR if you used a non-default --work-dir)", kc)
	}
	bin, err := resolveKubectl(workDir)
	if err != nil {
		return err
	}
	cmd := exec.Command(bin, args...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	cmd.Env = append(os.Environ(), "KUBECONFIG="+kc)
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

// resolveKubectl prefers the bundled kubectl in the work dir's bin (downloaded
// by `k3sm server`), falling back to a kubectl on PATH.
func resolveKubectl(workDir string) (string, error) {
	if p := executor.KubectlPath(workDir); fileExists(p) {
		return p, nil
	}
	if p, err := exec.LookPath("kubectl"); err == nil {
		return p, nil
	}
	return "", fmt.Errorf("no kubectl found (looked for %s and kubectl on PATH); run `k3sm server` to fetch the bundled kubectl", executor.KubectlPath(workDir))
}

// workDirFromEnv resolves the control-plane work dir, honoring K3SM_WORK_DIR so
// the kubectl/kubeconfig verbs agree with `k3sm server --work-dir`.
func workDirFromEnv() string {
	if d := os.Getenv("K3SM_WORK_DIR"); d != "" {
		return d
	}
	return executor.DefaultWorkDir
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

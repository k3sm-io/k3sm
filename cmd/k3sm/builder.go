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
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	"k3sm.io/k3sm/pkg/builder"
	"k3sm.io/k3sm/pkg/executor"
	"k3sm.io/k3sm/pkg/kubeclient"
)

const builderUsage = `k3sm builder — manage the in-cluster buildkitd engine that powers RUN-capable builds

Usage: k3sm builder <up|down|delete|status> [flags]
       k3sm builder buildx <args...>

  up      ensure the builder Pod, Service and cache PVC, and wait for a worker
  down    delete the Pod and Service (the cache PVC is KEPT for a warm rebuild)
  delete  tear down the engine AND remove the build cache (full reset)
  status  report the engine state and, when ready, its buildx dial endpoint
  buildx  run the bundled buildx against the engine (args pass through verbatim)

"k3sm builder buildx" is the whole driver setup: it stages the pinned buildx,
registers a remote-driver builder at the engine's endpoint, and runs your
command against it — no "buildx create", no endpoint to copy.

  k3sm builder buildx build -t myapp:dev .
  k3sm builder buildx bake -f bake.hcl target

The engine is one long-lived vm Pod running the pinned upstream moby/buildkit
image. buildkitd runs guest-root inside its own micro-VM — the VM is the
isolation boundary, so the Pod carries no securityContext. COPY-only Dockerfiles
never need it: 'k3sm build' packages those natively. This engine is what a
Dockerfile with RUN needs.

Image source: by default the engine pulls docker.io/moby/buildkit at the pinned
digest directly from upstream (anonymous, no token). Pass --mirror to pull the
same digest from the k3sm GHCR mirror instead (needs a published package and, if
private, --pull-secret <name>).

Flags:
`

// builderOptions is the parsed argv for the builder verbs.
type builderOptions struct {
	namespace  string
	node       string
	image      string
	pullSecret string
	cacheSize  string
	port       int
	mirror     bool
	timeout    time.Duration
	workDir    string
	// workDirExplicit is set when the operator named the work dir (--work-dir
	// or K3SM_WORK_DIR). Its admin kubeconfig is then used verbatim, with no
	// fallback to the user's own kubeconfig: talking to a different cluster
	// than the one named would be a lie.
	workDirExplicit bool
}

// runBuilder is the `k3sm builder up|down|delete|status|buildx` entry point.
func runBuilder(args []string) error {
	if len(args) == 0 {
		fmt.Fprint(os.Stderr, builderUsage)
		return fmt.Errorf("k3sm builder needs a subcommand (up|down|delete|status|buildx)")
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "-h", "--help", "help":
		fmt.Print(builderUsage)
		return nil
	case "up", "down", "delete", "status":
		return runBuilderVerb(sub, rest)
	case "buildx":
		// Everything after `buildx` belongs to buildx: no flag parsing happens
		// here, so a buildx flag k3sm has never heard of still reaches it.
		return runBuilderBuildx(rest)
	default:
		fmt.Fprint(os.Stderr, builderUsage)
		return fmt.Errorf("unknown `k3sm builder` subcommand %q (want up|down|delete|status|buildx)", sub)
	}
}

func parseBuilderArgs(sub string, args []string) (builderOptions, error) {
	fs := flag.NewFlagSet("builder "+sub, flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	var opts builderOptions
	fs.StringVar(&opts.namespace, "namespace", builder.DefaultNamespace, "namespace for the builder stack")
	fs.StringVar(&opts.node, "node", "", "pin the engine to a node (kubernetes.io/hostname); empty schedules on any vm-capable darwin node")
	fs.StringVar(&opts.image, "image", "", "override the buildkitd image (default: the pinned upstream digest, or the mirror with --mirror)")
	fs.StringVar(&opts.pullSecret, "pull-secret", "", "imagePullSecret name for a private registry (used with --mirror on a private package)")
	fs.StringVar(&opts.cacheSize, "cache-size", builder.DefaultCacheSize, "build-cache PVC size")
	fs.IntVar(&opts.port, "port", builder.DefaultTCPPort, "buildkitd tcp port the ClusterIP Service fronts")
	fs.BoolVar(&opts.mirror, "mirror", false, "pull the buildkitd image from the k3sm GHCR mirror instead of upstream-direct")
	fs.DurationVar(&opts.timeout, "timeout", 5*time.Minute, "how long `up` waits for a registered worker")
	fs.StringVar(&opts.workDir, "work-dir", "", "control-plane work dir whose admin kubeconfig is used verbatim (default: K3SM_WORK_DIR, else the posture default with a fallback to your own kubeconfig)")
	if err := fs.Parse(args); err != nil {
		return builderOptions{}, err
	}
	opts.workDir, opts.workDirExplicit = builderWorkDir(opts.workDir)
	return opts, nil
}

// builderWorkDir resolves a builder verb's --work-dir flag value: the flag when
// given, else K3SM_WORK_DIR, else the posture default (workDirFromEnv). The
// second result reports whether the operator named the work dir, which pins its
// admin kubeconfig with no fallback.
func builderWorkDir(flagValue string) (string, bool) {
	if flagValue != "" {
		return flagValue, true
	}
	return workDirFromEnv(), os.Getenv("K3SM_WORK_DIR") != ""
}

// builderConfig maps parsed flags to a builder.Config. Pure, so the flag-to-spec
// mapping is testable without a cluster.
func builderConfig(opts builderOptions) builder.Config {
	return builder.Config{
		Namespace:  opts.namespace,
		NodeName:   opts.node,
		Image:      opts.image,
		UseMirror:  opts.mirror,
		PullSecret: opts.pullSecret,
		CacheSize:  opts.cacheSize,
		TCPPort:    opts.port,
	}
}

// newBuilderManager builds a Manager against the cluster this account can
// reach, resolved the way `k3sm kubectl` resolves it (builderKubeconfig). It is
// the legible-absence boundary for a missing control plane: no usable
// kubeconfig means the error names the fix, not a bare file-not-found.
func newBuilderManager(opts builderOptions) (*builder.Manager, error) {
	restCfg, cs, err := builderClients(builderKubeInputs(opts))
	if err != nil {
		return nil, err
	}
	return builderManagerFrom(restCfg, cs, opts), nil
}

// builderKubeInputs gathers the kubeconfig choice's inputs from this process:
// the builder's work dir (pinned when explicit), $KUBECONFIG, the home dir and
// the installed context name.
func builderKubeInputs(opts builderOptions) kubectlInputs {
	home, _ := os.UserHomeDir()
	in := kubectlInputs{
		workDir:       opts.workDir,
		kubeconfigEnv: os.Getenv("KUBECONFIG"),
		home:          home,
		contextName:   installedKubeconfigName(),
		exists:        fileExists,
	}
	if opts.workDirExplicit {
		in.workDirOverride = opts.workDir
	}
	return in
}

// builderKubeconfig picks the credentials the builder verbs run with. The
// choice is resolveKubectlConfig's, so the builder and `k3sm kubectl` agree:
// the work dir's admin kubeconfig when it is readable (root, the _k3sm service
// user) or explicitly named, else the user's $KUBECONFIG or ~/.kube/config
// pinned to the installed context. Only the errors are the builder's own: an
// explicit work dir keeps its `k3sm server` message, and the ordinary user with
// neither kubeconfig is told both paths and both ways out.
func builderKubeconfig(in kubectlInputs) (kubectlConfig, error) {
	cfg, err := resolveKubectlConfig(in)
	if err == nil {
		return cfg, nil
	}
	kc := executor.KubeconfigPath(in.workDir)
	if in.workDirOverride != "" {
		return kubectlConfig{}, fmt.Errorf("kubeconfig %s not found — run `k3sm server` first (set --work-dir or K3SM_WORK_DIR if you used a non-default `k3sm server --work-dir`)", kc)
	}
	user := "~/.kube/config"
	if c := userKubeconfigCandidates(in.kubeconfigEnv, in.home); len(c) > 0 {
		user = strings.Join(c, " or ")
	}
	return kubectlConfig{}, fmt.Errorf("no kubeconfig for the build engine: %s is not readable by this account and %s does not exist — run with sudo, or copy the admin kubeconfig into yours with `sudo k3sm kubeconfig --write`", kc, user)
}

// builderClients resolves the builder's kubeconfig and builds the rest.Config
// and clientset from it. The user-kubeconfig case reads exactly the files
// builderKubeconfig looked at ($KUBECONFIG's list when set, else ~/.kube/config
// under in.home), with the installed context pinned rather than the file's
// current-context.
func builderClients(in kubectlInputs) (*rest.Config, kubernetes.Interface, error) {
	cfg, err := builderKubeconfig(in)
	if err != nil {
		return nil, nil, err
	}
	if cfg.kubeconfig != "" {
		restCfg, cs, err := kubeclient.FromPath(cfg.kubeconfig)
		if err != nil {
			return nil, nil, fmt.Errorf("load kubeconfig %s: %w", cfg.kubeconfig, err)
		}
		return restCfg, cs, nil
	}
	rules := &clientcmd.ClientConfigLoadingRules{}
	if in.kubeconfigEnv != "" {
		rules.Precedence = filepath.SplitList(in.kubeconfigEnv)
	} else {
		rules.Precedence = []string{filepath.Join(in.home, ".kube", "config")}
	}
	restCfg, err := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(rules,
		&clientcmd.ConfigOverrides{CurrentContext: cfg.context}).ClientConfig()
	if err != nil {
		return nil, nil, fmt.Errorf("load kubeconfig context %q from %s: %w", cfg.context, strings.Join(rules.Precedence, ":"), err)
	}
	cs, err := kubernetes.NewForConfig(restCfg)
	if err != nil {
		return nil, nil, fmt.Errorf("build kubernetes client: %w", err)
	}
	return restCfg, cs, nil
}

// builderManagerFrom is the client-injected seam newBuilderManager wraps, so the
// wiring (config mapping, exec seam) is testable with a fake clientset.
func builderManagerFrom(restCfg *rest.Config, cs kubernetes.Interface, opts builderOptions) *builder.Manager {
	return builder.NewManager(cs, builder.NewPodExecer(restCfg, cs), builderConfig(opts), nil)
}

func runBuilderVerb(sub string, args []string) error {
	opts, err := parseBuilderArgs(sub, args)
	if err != nil {
		return err
	}
	mgr, err := newBuilderManager(opts)
	if err != nil {
		return err
	}
	switch sub {
	case "up":
		ctx, cancel := context.WithTimeout(context.Background(), opts.timeout)
		defer cancel()
		st, err := mgr.Up(ctx)
		if err != nil {
			return err
		}
		fmt.Printf("builder engine ready: %d worker(s), endpoint %s\n", st.Workers, st.Endpoint)
		fmt.Println("`k3sm build` uses it automatically for a Dockerfile that RUNs commands;")
		fmt.Println("`k3sm builder buildx <args...>` drives buildx against it directly.")
		return nil
	case "down":
		return mgr.Down(context.Background())
	case "delete":
		return mgr.Delete(context.Background())
	case "status":
		st, err := mgr.Status(context.Background())
		if err != nil {
			return err
		}
		printBuilderStatus(st)
		return nil
	}
	return nil
}

func printBuilderStatus(st builder.Status) {
	fmt.Printf("state:    %s\n", st.State)
	if st.PodPhase != "" {
		fmt.Printf("pod:      %s\n", st.PodPhase)
	}
	if st.State == builder.StateReady {
		fmt.Printf("workers:  %d\n", st.Workers)
	}
	if st.Endpoint != "" {
		fmt.Printf("endpoint: %s\n", st.Endpoint)
	}
	if st.Message != "" {
		fmt.Printf("note:     %s\n", st.Message)
	}
}

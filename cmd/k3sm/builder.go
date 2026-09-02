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
	"time"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	"k3sm.io/k3sm/pkg/builder"
	"k3sm.io/k3sm/pkg/executor"
)

const builderUsage = `k3sm builder — manage the in-cluster buildkitd engine that powers RUN-capable builds

Usage: k3sm builder <up|down|status> [flags]

  up      ensure the builder Pod, Service and cache PVC, and wait for a worker
  down    delete the Pod and Service (the cache PVC is KEPT for a warm rebuild)
  status  report the engine state and, when ready, its buildx dial endpoint

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
}

// runBuilder is the `k3sm builder up|down|status` entry point.
func runBuilder(args []string) error {
	if len(args) == 0 {
		fmt.Fprint(os.Stderr, builderUsage)
		return fmt.Errorf("k3sm builder needs a subcommand (up|down|status)")
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "-h", "--help", "help":
		fmt.Print(builderUsage)
		return nil
	case "up", "down", "status":
		return runBuilderVerb(sub, rest)
	default:
		fmt.Fprint(os.Stderr, builderUsage)
		return fmt.Errorf("unknown `k3sm builder` subcommand %q (want up|down|status)", sub)
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
	fs.StringVar(&opts.workDir, "work-dir", "", "control-plane work dir holding the admin kubeconfig (default: K3SM_WORK_DIR or the posture default)")
	if err := fs.Parse(args); err != nil {
		return builderOptions{}, err
	}
	if opts.workDir == "" {
		opts.workDir = workDirFromEnv()
	}
	return opts, nil
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

// newBuilderManager builds a Manager against the admin kubeconfig. It is the
// legible-absence boundary for a missing control plane: no kubeconfig means the
// error names `k3sm server`, not a bare file-not-found.
func newBuilderManager(opts builderOptions) (*builder.Manager, error) {
	kc := executor.KubeconfigPath(opts.workDir)
	if !fileExists(kc) {
		return nil, fmt.Errorf("kubeconfig %s not found — run `k3sm server` first (set --work-dir or K3SM_WORK_DIR if you used a non-default `k3sm server --work-dir`)", kc)
	}
	restCfg, err := clientcmd.BuildConfigFromFlags("", kc)
	if err != nil {
		return nil, fmt.Errorf("load kubeconfig %s: %w", kc, err)
	}
	cs, err := kubernetes.NewForConfig(restCfg)
	if err != nil {
		return nil, fmt.Errorf("build kube client: %w", err)
	}
	return builderManagerFrom(restCfg, cs, opts), nil
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
		fmt.Println("drive it with `k3sm build` on a Dockerfile that uses RUN (COPY-only builds stay native).")
		return nil
	case "down":
		return mgr.Down(context.Background())
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

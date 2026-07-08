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
	"os/signal"
	"syscall"
	"text/tabwriter"
	"time"

	"k3sm.io/k3sm/pkg/dev"
)

// devUsage is the `k3sm dev --help` text. It BLESSES the SAFE operator class
// (reconcile-only CRD operators + macOS-native workloads develop freely) and
// routes UNSAFE classes (Service-datapath / DNS / NetworkPolicy / metrics /
// EventRecorder-dependent) to the ceiling doc rather than letting a dev hit an
// invisible wall.
const devUsage = `k3sm dev — a disposable single-node dev cluster (more than envtest: a REAL control plane + a real node)

Usage: k3sm dev <up|down|list|load> [flags]

  up   [--name N] [--datapath]   boot a disposable instance and select its kubeconfig context
  down [--name N] [--all]        tear an instance (or every instance) down + reclaim its aliases/context
  list                           the durable instance registry (survives sleep/reboot)
  load <path>                    stage a native-arm64 binary → print its non-portable 'image: <abs>' line

Tiers:
  rootless (default): runtimed + network=none — real apiserver + CRD/SSA/CEL + real pod lifecycle +
                      Seatbelt, NO root. Datapath is INERT (Service traffic needs --datapath).
  --datapath (root):  runtimed + network=direct — real Service/ClusterIP/DNS/pod-IP. Requires euid 0.

Develop freely here (SAFE): reconcile-only CRD operators (CRD-ensure/render/CEL/conditions up to Ready)
and macOS-native single-process workloads. Operators that depend on Service/ClusterIP delivery, cluster
DNS, Service-backed webhooks, NetworkPolicy isolation, metrics.k8s.io, or lifecycle Events diverge here —
see docs/conformance-profile.md and docs/UPSTREAM-ALIGNMENT.md before relying on those.

NOT kind: k3sm is deliberately non-conformant. This framing is internal dev tooling.
`

// runDev is the `k3sm dev up|down|list|load` verb: arg-parse → pkg/dev (mirrors
// cmd/k3sm/kubectl.go's thin-passthrough pattern).
func runDev(args []string) error {
	if len(args) == 0 {
		fmt.Fprint(os.Stderr, devUsage)
		return fmt.Errorf("k3sm dev needs a subcommand (up|down|list|load)")
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "-h", "--help", "help":
		fmt.Print(devUsage)
		return nil
	case "up":
		return runDevUp(rest)
	case "down":
		return runDevDown(rest)
	case "list", "ls":
		return runDevList(rest)
	case "load":
		return runDevLoad(rest)
	default:
		fmt.Fprint(os.Stderr, devUsage)
		return fmt.Errorf("unknown `k3sm dev` subcommand %q (want up|down|list|load)", sub)
	}
}

// newDevManager builds a dev.Manager for the current process: the durable
// registry under the user's home, the production System seam, and this binary's
// own path re-exec'd as `k3sm server`.
func newDevManager() (*dev.Manager, error) {
	root, err := dev.DefaultRegistryRoot()
	if err != nil {
		return nil, err
	}
	self, err := os.Executable()
	if err != nil {
		return nil, fmt.Errorf("resolve own binary path: %w", err)
	}
	return dev.NewManager(dev.ManagerConfig{
		Registry: dev.NewRegistry(root),
		System:   dev.NewSystem(),
		Self:     self,
		EUID:     os.Geteuid(),
		Out:      os.Stdout,
	}), nil
}

// devContext is a signal-cancellable context for the up/down bring-up waits.
func devContext() (context.Context, context.CancelFunc) {
	return signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
}

func runDevUp(args []string) error {
	fs := flag.NewFlagSet("dev up", flag.ExitOnError)
	var opts dev.UpOptions
	fs.StringVar(&opts.Name, "name", "dev", "instance name")
	fs.BoolVar(&opts.Datapath, "datapath", false, "boot the root datapath tier (network=direct; requires sudo/euid 0) for real Service/DNS/pod-IP")
	_ = fs.Parse(args)

	mgr, err := newDevManager()
	if err != nil {
		return err
	}
	ctx, cancel := devContext()
	defer cancel()
	_, err = mgr.Up(ctx, opts)
	return err
}

func runDevDown(args []string) error {
	fs := flag.NewFlagSet("dev down", flag.ExitOnError)
	var opts dev.DownOptions
	fs.StringVar(&opts.Name, "name", "dev", "instance name to tear down")
	fs.BoolVar(&opts.All, "all", false, "tear down every instance + reclaim residual aliases/contexts")
	_ = fs.Parse(args)

	mgr, err := newDevManager()
	if err != nil {
		return err
	}
	ctx, cancel := devContext()
	defer cancel()
	return mgr.Down(ctx, opts)
}

func runDevList(args []string) error {
	fs := flag.NewFlagSet("dev list", flag.ExitOnError)
	_ = fs.Parse(args)

	mgr, err := newDevManager()
	if err != nil {
		return err
	}
	statuses, err := mgr.List()
	if err != nil {
		return err
	}
	if len(statuses) == 0 {
		fmt.Println("no k3sm dev instances (run `k3sm dev up`)")
		return nil
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "NAME\tTIER\tDATAPATH\tAPI\tPID\tSTATUS\tAGE\tCONTEXT")
	for _, s := range statuses {
		status := "stale"
		if s.Alive {
			status = "running"
		}
		age := time.Since(s.CreatedAt).Round(time.Second)
		fmt.Fprintf(w, "%s\t%s\t%s\t%d\t%d\t%s\t%s\t%s\n",
			s.Name, s.Tier, s.Datapath, s.APIPort, s.PID, status, age, s.KubeContext)
	}
	return w.Flush()
}

func runDevLoad(args []string) error {
	fs := flag.NewFlagSet("dev load", flag.ExitOnError)
	_ = fs.Parse(args)
	if fs.NArg() != 1 {
		return fmt.Errorf("k3sm dev load needs exactly one path (the native-arm64 binary to stage)")
	}
	mgr, err := newDevManager()
	if err != nil {
		return err
	}
	_, err = mgr.Load(fs.Arg(0))
	return err
}

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

// Command k3sm is the single-binary entrypoint for k3sm, the macOS-native
// Kubernetes distribution. See docs/DESIGN.md for the full architecture.
package main

import (
	"fmt"
	"os"

	"k3sm.io/k3sm/pkg/version"
)

const usage = `k3sm %s — Kubernetes for macOS, natively

Usage: k3sm <command> [flags]

Commands ("server", "agent", "node", "netd", "install", "uninstall", "token", "kubectl", "kubeconfig", "doctor" are implemented; others are planned):
  server      run the control plane + a node on this Mac (M1; --mesh-ip enables multi-node join)
  agent       join this Mac to an existing cluster as a worker node (M3)
  node        run a Virtual Kubelet node here (HostProcess or runtimed runtime)
  netd        run the root privileged-network helper (launched by the io.k3sm.netd LaunchDaemon)
  install     install the netd + server launchd daemons (run as root via sudo)
  uninstall   remove the netd + server launchd daemons (run as root via sudo)
  token       mint cluster join tokens (token create)
  build       build a native-macOS (OCI artifact) image
  kubectl     run the bundled kubectl against this cluster (KUBECONFIG preset)
  kubeconfig  print the admin kubeconfig, or --write/merge it into ~/.kube/config
  doctor      run preflight environment + datastore-posture checks
  version     print version

See docs/DESIGN.md for the roadmap.
`

func main() {
	ver := version.Get()
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, usage, ver.Version)
		os.Exit(2)
	}
	switch os.Args[1] {
	case "version", "-v", "--version":
		fmt.Print(ver)
	case "-h", "--help", "help":
		fmt.Printf(usage, ver.Version)
	case "server":
		if err := runServer(os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, "k3sm server:", err)
			os.Exit(1)
		}
	case "node":
		if err := runNode(os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, "k3sm node:", err)
			os.Exit(1)
		}
	case "agent":
		if err := runAgent(os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, "k3sm agent:", err)
			os.Exit(1)
		}
	case "netd":
		if err := runNetd(os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, "k3sm netd:", err)
			os.Exit(1)
		}
	case "install":
		if err := runInstall(os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, "k3sm install:", err)
			os.Exit(1)
		}
	case "uninstall":
		if err := runUninstall(os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, "k3sm uninstall:", err)
			os.Exit(1)
		}
	case "token":
		if err := runToken(os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, "k3sm token:", err)
			os.Exit(1)
		}
	case "kubectl":
		if err := runKubectl(os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, "k3sm kubectl:", err)
			os.Exit(1)
		}
	case "kubeconfig":
		if err := runKubeconfig(os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, "k3sm kubeconfig:", err)
			os.Exit(1)
		}
	case "doctor":
		if err := runDoctor(os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, "k3sm doctor:", err)
			os.Exit(1)
		}
	default:
		fmt.Fprintf(os.Stderr, "k3sm: unknown command %q (pre-M0 scaffold)\n\n", os.Args[1])
		fmt.Fprintf(os.Stderr, usage, ver.Version)
		os.Exit(2)
	}
}

// Command k3sm is the single-binary entrypoint for k3sm, the macOS-native
// Kubernetes distribution. See docs/DESIGN.md for the full architecture.
package main

import (
	"fmt"
	"os"
)

// version is overridden at build time via -ldflags "-X main.version=...".
var version = "0.0.0-dev"

const usage = `k3sm %s — Kubernetes for macOS, natively

Usage: k3sm <command> [flags]

Commands ("server", "node", "kubectl", "kubeconfig" are implemented; others are planned):
  server      run the control plane + a node on this Mac (M1)
  agent       join this Mac to an existing cluster as a node
  node        run a Virtual Kubelet node here (HostProcess or runtimed runtime)
  install     install the launchd service (run as root)
  uninstall   remove the launchd service
  token       manage cluster join tokens
  build       build a native-macOS (OCI artifact) image
  kubectl     run the bundled kubectl against this cluster (KUBECONFIG preset)
  kubeconfig  print the admin kubeconfig, or --write/merge it into ~/.kube/config
  version     print version

See docs/DESIGN.md for the roadmap.
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, usage, version)
		os.Exit(2)
	}
	switch os.Args[1] {
	case "version", "-v", "--version":
		fmt.Printf("k3sm %s\n", version)
	case "-h", "--help", "help":
		fmt.Printf(usage, version)
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
	default:
		fmt.Fprintf(os.Stderr, "k3sm: unknown command %q (pre-M0 scaffold)\n\n", os.Args[1])
		fmt.Fprintf(os.Stderr, usage, version)
		os.Exit(2)
	}
}

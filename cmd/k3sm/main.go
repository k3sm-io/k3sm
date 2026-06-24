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

Commands (planned — pre-M0 scaffold):
  server      run the control plane + a node on this Mac
  agent       join this Mac to an existing cluster as a node
  install     install the launchd service (run as root)
  uninstall   remove the launchd service
  token       manage cluster join tokens
  build       build a native-macOS (OCI artifact) image
  kubectl     embedded kubectl
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
	default:
		fmt.Fprintf(os.Stderr, "k3sm: unknown command %q (pre-M0 scaffold)\n\n", os.Args[1])
		fmt.Fprintf(os.Stderr, usage, version)
		os.Exit(2)
	}
}

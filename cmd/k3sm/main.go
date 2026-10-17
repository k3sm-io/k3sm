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
	"context"
	"fmt"
	"os"

	"k3sm.io/k3sm/pkg/version"
)

const usage = `k3sm %s — Kubernetes for macOS, natively

Usage: k3sm <command> [flags]

Commands ("server", "agent", "node", "netd", "install", "uninstall", "stop", "start", "restart", "network", "datavol", "token", "certificate", "snapshot", "secrets-encrypt", "interconnect", "build", "builder", "image", "kubectl", "kubeconfig", "status", "update", "doctor", "dev" are implemented; others are planned):
  server      run the control plane + a node on this Mac (--mesh-ip enables multi-node join)
  agent       join this Mac to an existing cluster as a worker node
  node        run a Virtual Kubelet node here (HostProcess or runtimed runtime)
  dev         disposable single-node dev cluster (up|down|list|load) — internal dev tooling
  netd        run the root privileged-network helper (launched by the io.k3sm.netd LaunchDaemon)
  install     install the netd + server launchd daemons (run as root via sudo)
  uninstall   remove the k3sm daemons, keeping cluster data (run as root via sudo;
              --purge --yes also removes the data, logs and _k3sm user)
  stop        stop k3sm completely and keep it stopped across reboots (run as root
              via sudo; see k3sm stop --help for what it does and its exit codes)
  start       start k3sm again after a stop (run as root via sudo)
  restart     restart the k3sm daemons, pods keep running (run as root via sudo;
              --start also starts a stopped node)
  network     LAN access for this node's NodePort, LoadBalancer and ingress
              listeners (network lan on|off|status; on/off run as root via sudo)
  datavol     the APFS volume the data root lives on (datavol mount|status|delete)
  token       mint cluster join tokens (token create)
  certificate re-issue the control-plane leaf certs over the existing CA (certificate rotate)
  build       build an image from a Dockerfile (COPY-only natively; RUN via the build engine)
  builder     manage the in-cluster buildkitd engine (builder up|down|delete|status|buildx)
  image       ingest, publish and reclaim this node's images (image load|import|push|prune|ls|df)
  kubectl     run the bundled kubectl against this cluster (KUBECONFIG preset)
  kubeconfig  print the admin kubeconfig, or --write/merge it into ~/.kube/config
  status      show what is running (daemons, apiserver, node, workloads, data root; status top for CPU and memory) — the exit code is the verdict, see k3sm status --help
  update      check for a newer k3sm release and which nodes are behind it (update check)
  doctor      run preflight environment + datastore-posture checks
              (--report writes a redacted bug-report bundle)
  snapshot    back up, restore, list and prune datastore snapshots (snapshot save|restore|ls|delete|prune)
  secrets-encrypt  report secrets encryption at rest (secrets-encrypt status)
  interconnect     arm or disarm the Thunderbolt cable as an opt-in network (interconnect enable|disable)
  version     print version (--short: the release version alone)

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
		// --short prints the release version alone, the machine-readable
		// answer the installer reads off an installed binary.
		if len(os.Args) > 2 && os.Args[2] == "--short" {
			fmt.Println(ver.Version)
			return
		}
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
	case "payload":
		if err := runPayload(os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, "k3sm payload:", err)
			os.Exit(1)
		}
	case "stop":
		if code := runStop(os.Args[2:], os.Stderr); code != 0 {
			os.Exit(code)
		}
	case "start":
		if code := runStart(os.Args[2:], os.Stdout, os.Stderr); code != 0 {
			os.Exit(code)
		}
	case "restart":
		if code := runRestart(os.Args[2:], os.Stderr); code != 0 {
			os.Exit(code)
		}
	case "network":
		if code := runNetwork(os.Args[2:], os.Stdout, os.Stderr); code != 0 {
			os.Exit(code)
		}
	case netdRemoveMeshVerb:
		if code := runNetdRemoveMesh(os.Args[2:], os.Stderr); code != 0 {
			os.Exit(code)
		}
	case "uninstall":
		if err := runUninstall(os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, "k3sm uninstall:", err)
			os.Exit(1)
		}
	case "datavol":
		if err := runDatavol(os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, "k3sm datavol:", err)
			os.Exit(1)
		}
	case "token":
		if err := runToken(os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, "k3sm token:", err)
			os.Exit(1)
		}
	case "certificate":
		if err := runCertificate(os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, "k3sm certificate:", err)
			os.Exit(1)
		}
	case "snapshot":
		if err := runSnapshot(os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, "k3sm snapshot:", err)
			os.Exit(1)
		}
	case "secrets-encrypt":
		// The exit code is the verdict: a refused or unreadable state is
		// non-zero, so a script can gate on it.
		os.Exit(runSecretsEncrypt(os.Args[2:], os.Stdout, os.Stderr))
	case "interconnect":
		if err := runInterconnect(os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, "k3sm interconnect:", err)
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
	case "status":
		// status returns its own exit code: the code IS the verdict (running,
		// stopped, degraded, not-installed, unknown), so the generic exit-1
		// wrapper the other verbs use would throw the answer away.
		os.Exit(runStatus(os.Args[2:]))
	case "update":
		os.Exit(runUpdate(context.Background(), os.Args[2:], newUpdateEnv()))
	case "doctor":
		// doctor returns its own exit code for the same reason status does: the
		// code is the verdict (1 for a failed check, 4 for a WARN-only run),
		// and the generic exit-1 wrapper would collapse the two.
		os.Exit(runDoctor(os.Args[2:]))
	case "dev":
		if err := runDev(os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, "k3sm dev:", err)
			os.Exit(1)
		}
	case "build":
		if err := runBuild(os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, "k3sm build:", err)
			os.Exit(1)
		}
	case "builder":
		if err := runBuilder(os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, "k3sm builder:", err)
			os.Exit(1)
		}
	case "image":
		if err := runImage(os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, "k3sm image:", err)
			os.Exit(1)
		}
	default:
		fmt.Fprintf(os.Stderr, "k3sm: unknown command %q\n\n", os.Args[1])
		fmt.Fprintf(os.Stderr, usage, ver.Version)
		os.Exit(2)
	}
}

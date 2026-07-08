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

package dev

import (
	"fmt"
	"strings"
)

// FidelityBanner returns the SAFE/NEEDS-datapath/UNFAITHFUL text `k3sm dev up`
// prints so the fidelity axis (docs/UPSTREAM-ALIGNMENT.md, docs/conformance-
// profile.md) is surfaced at the entry point, not buried. The datapath argument
// is DatapathNone (rootless — datapath INERT) or DatapathDirect (root — datapath
// live). The text is golden-tested (banner_test.go) so its warnings cannot
// silently regress. It is deliberately verbatim between tiers except the leading
// posture line — the SAFE/UNFAITHFUL classes are the same on both tiers (they are
// properties of k3sm, not of the privilege posture).
func FidelityBanner(datapath string) string {
	var b strings.Builder
	b.WriteString("k3sm dev — more than envtest: a REAL control plane (kube-apiserver + KCM + scheduler) + a REAL single node.\n")
	b.WriteString("This is NOT kind — k3sm is deliberately non-conformant. Develop against the SAFE surface; the rest is documented.\n\n")

	switch datapath {
	case DatapathDirect:
		b.WriteString("posture: --datapath (root, network=direct) — Service/ClusterIP/DNS/pod-IP datapath is LIVE.\n")
	default:
		b.WriteString("posture: rootless (network=none) — datapath INERT (rootless): Service traffic needs --datapath.\n")
	}
	b.WriteString("\n")

	b.WriteString("SAFE — faithful, develop freely (real upstream apiserver):\n")
	b.WriteString("  CRD structural schemas · SSA field-managers · CEL validation · admission registration ·\n")
	b.WriteString("  RBAC/Node authz · scheduling · GC/finalizers/ownerReferences · conditions-driven reconcile up to Ready;\n")
	b.WriteString("  plus macOS-native single-process workloads (Seatbelt-confined via runtimed).\n\n")

	b.WriteString("NEEDS --datapath (root) — anything that routes:\n")
	b.WriteString("  Service/ClusterIP reachability · cluster DNS · Service-backed admission webhooks ·\n")
	b.WriteString("  the operator's terminal Ready/Endpoint. (url+host-port webhooks work rootless.)\n\n")

	b.WriteString("UNFAITHFUL — won't reproduce on real k8s regardless of tier (documented ceilings):\n")
	b.WriteString("  no SRV/PTR/headless DNS (A-only resolver) · NetworkPolicy is a hint, not isolation ·\n")
	b.WriteString("  no cgroup CPU limits / HPA-on-cpu · no EventRecorder (kubectl describe shows no events) ·\n")
	b.WriteString("  no metrics.k8s.io · native-process pods (Linux images need the vm RuntimeClass).\n")
	b.WriteString("  See docs/UPSTREAM-ALIGNMENT.md and docs/conformance-profile.md for the full register.\n")

	return b.String()
}

// LoadStamp is the NON-PORTABLE warning `k3sm dev load` stamps on every staged
// binary path — the honest `kind load` analog. k3sm has no Docker images; the
// staged path is consumed via the runtimed host-binary convention (an absolute
// `image:` path with no command; see runtimed resolveBinary), which is
// dev-cluster-only.
const LoadStamp = "k3sm-dev-only, NON-PORTABLE: real k8s + k3sm OCI/vm need a registry ref."

// LoadImageLine renders the `image: <abs>` line a pod spec uses to run a staged
// binary (the no-command host-binary convention), followed by the non-portable
// stamp. absPath must be absolute (the caller validates); this is pure string
// formatting.
func LoadImageLine(absPath string) string {
	return fmt.Sprintf("image: %s   # %s", absPath, LoadStamp)
}

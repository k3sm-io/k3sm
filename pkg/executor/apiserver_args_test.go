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

package executor

import (
	"strconv"
	"strings"
	"testing"

	"k3sm.io/k3sm/pkg/certs"
	"k3sm.io/k3sm/pkg/ports"
)

// flagValue returns the value following the first occurrence of name in args
// (space-separated --flag value form), or "" if name is absent / has no value.
func flagValue(args []string, name string) string {
	for i, a := range args {
		if a == name && i+1 < len(args) {
			return args[i+1]
		}
	}
	return ""
}

// hasArg reports whether args contains exact (e.g. an --flag=value token).
func hasArg(args []string, exact string) bool {
	for _, a := range args {
		if a == exact {
			return true
		}
	}
	return false
}

// TestApiserverFlagsMeshBindAnonOff asserts the M3 multi-node apiserver trust
// posture: the secure port binds the wireguard mesh interface (NOT 0.0.0.0, NOT
// loopback), --anonymous-auth=false, and both --client-ca-file (node client-cert
// auth, so M4's Node,RBAC flip is a pure authorizer switch) and
// --kubelet-certificate-authority (remote exec/logs not MITM-able) are set.
func TestApiserverFlagsMeshBindAnonOff(t *testing.T) {
	anon := false
	const meshIP = "100.64.0.1"
	cfg := Config{
		WorkDir:       "/var/lib/k3sm/server",
		KinePort:      2379,
		APIServerPort: 6444,
		NodeIP:        meshIP,
		BindAddress:   meshIP,
		ClientCAFile:  "/var/lib/k3sm/server/tls/signing-ca.crt",
		KubeletCAFile: "/var/lib/k3sm/server/tls/cluster-ca.crt",
		AnonymousAuth: &anon,
	}
	args := apiServerArgs(cfg)

	if got := flagValue(args, "--bind-address"); got != meshIP {
		t.Errorf("--bind-address = %q, want the mesh IP %q", got, meshIP)
	}
	if got := flagValue(args, "--bind-address"); got == "0.0.0.0" || got == "127.0.0.1" {
		t.Errorf("--bind-address = %q must NOT expose 0.0.0.0/loopback (mesh-only)", got)
	}
	if !hasArg(args, "--anonymous-auth=false") {
		t.Errorf("--anonymous-auth=false must be set in M3, args=%v", args)
	}
	if got := flagValue(args, "--client-ca-file"); got != cfg.ClientCAFile {
		t.Errorf("--client-ca-file = %q, want %q", got, cfg.ClientCAFile)
	}
	if got := flagValue(args, "--kubelet-certificate-authority"); got != cfg.KubeletCAFile {
		t.Errorf("--kubelet-certificate-authority = %q, want %q", got, cfg.KubeletCAFile)
	}
}

// TestApiserverNodePortRangeSingleSourced is the M3.1 wiring guard, RE-BASED by
// B116: the apiserver pins --service-node-port-range, and it pins it from
// pkg/ports — the SAME constants the reserved-port admission CEL and the svclb
// bind refusal derive from, so the range k3sm allocates NodePorts out of cannot
// desync from the range it guards against a colliding LoadBalancer port.
//
// The bounds are also still asserted >=1024. That is now a conservatism, NOT the
// EACCES claim the M3.1 comment made: re-measured on macOS 26, a WILDCARD bind
// below 1024 succeeds as an ordinary uid (it is the SPECIFIC-address bind that
// returns EACCES — inverted from Linux; see the cmd/k3sm integration canary).
func TestApiserverNodePortRangeSingleSourced(t *testing.T) {
	cfg := Config{WorkDir: "/wd", KinePort: 2379, APIServerPort: 6444, NodeIP: "127.0.0.1"}
	args := apiServerArgs(cfg)

	rng := flagValue(args, "--service-node-port-range")
	if rng == "" {
		t.Fatalf("--service-node-port-range must be pinned, args=%v", args)
	}
	if rng != ports.NodePortRange() {
		t.Errorf("--service-node-port-range = %q, want %q from pkg/ports (never a hand-written literal)", rng, ports.NodePortRange())
	}
	lo, hi, ok := strings.Cut(rng, "-")
	if !ok {
		t.Fatalf("--service-node-port-range = %q, want lo-hi form", rng)
	}
	for _, bound := range []string{lo, hi} {
		n, err := strconv.Atoi(bound)
		if err != nil {
			t.Fatalf("node-port-range bound %q not an int: %v", bound, err)
		}
		if n < 1024 {
			t.Errorf("node-port-range bound %d < 1024: k3sm keeps the whole range in the unprivileged band by convention (NOT because a wildcard bind there would EACCES — on Darwin it does not)", n)
		}
	}
}

// TestApiserverArgsNodeRBAC is the M4.1 flip guard: the apiserver defaults to
// --authorization-mode=Node,RBAC (NOT the old AlwaysAllow) and additively enables
// the NodeRestriction admission plugin — even for a RAW Config (the pure function
// self-defaults the mode, as it does the bind address). An explicit AuthorizationMode
// (a deliberate diagnostic bring-up) is honored verbatim.
func TestApiserverArgsNodeRBAC(t *testing.T) {
	// Raw single-node Config (NOT run through withDefaults): the flip is the default.
	cfg := Config{WorkDir: "/wd", KinePort: 2379, APIServerPort: 6444, NodeIP: "127.0.0.1"}
	args := apiServerArgs(cfg)

	if got := flagValue(args, "--authorization-mode"); got != "Node,RBAC" {
		t.Errorf("--authorization-mode = %q, want Node,RBAC (the M4.1 default flip)", got)
	}
	if got := flagValue(args, "--authorization-mode"); got == "AlwaysAllow" {
		t.Errorf("--authorization-mode must no longer be AlwaysAllow")
	}
	if !hasArg(args, "--enable-admission-plugins=NodeRestriction") {
		t.Errorf("--enable-admission-plugins=NodeRestriction must be set (additive), args=%v", args)
	}
	// B76: the MutatingAdmissionPolicy that injects the provider toleration into DS pods
	// is BETA + off by default at the pin, so the apiserver must enable BOTH the v1beta1
	// runtime-config AND the feature gate or the policy is a runtime no-op.
	if !hasArg(args, "--runtime-config=admissionregistration.k8s.io/v1beta1=true") {
		t.Errorf("--runtime-config for admissionregistration v1beta1 must be set (B76), args=%v", args)
	}
	if !hasArg(args, "--feature-gates=MutatingAdmissionPolicy=true") {
		t.Errorf("--feature-gates=MutatingAdmissionPolicy=true must be set (B76), args=%v", args)
	}

	// withDefaults fills the same value (so the running executor matches the args).
	if got := flagValue(apiServerArgs(cfg.withDefaults()), "--authorization-mode"); got != "Node,RBAC" {
		t.Errorf("withDefaults --authorization-mode = %q, want Node,RBAC", got)
	}

	// An explicit mode is honored (e.g. a diagnostic AlwaysAllow bring-up).
	diag := cfg
	diag.AuthorizationMode = "AlwaysAllow"
	if got := flagValue(apiServerArgs(diag), "--authorization-mode"); got != "AlwaysAllow" {
		t.Errorf("explicit --authorization-mode = %q, want AlwaysAllow (honored verbatim)", got)
	}
}

// TestApiserverArgsSingleNodeDefault confirms the M1/M2 single-node path: with the new
// fields zero, the apiserver binds loopback (via NodeIP) and the kubelet-CA /
// anonymous-auth flags are omitted. --client-ca-file is NO LONGER omitted single-node —
// it is unconditional now (TestClientCAFileAlwaysSet covers it) so the per-component +
// system:node client certs authenticate.
func TestApiserverArgsSingleNodeDefault(t *testing.T) {
	cfg := Config{WorkDir: "/wd", KinePort: 2379, APIServerPort: 6444, NodeIP: "127.0.0.1"}
	args := apiServerArgs(cfg)
	if got := flagValue(args, "--bind-address"); got != "127.0.0.1" {
		t.Errorf("single-node --bind-address = %q, want 127.0.0.1", got)
	}
	joined := strings.Join(args, " ")
	for _, absent := range []string{"--kubelet-certificate-authority", "--anonymous-auth"} {
		if strings.Contains(joined, absent) {
			t.Errorf("single-node path must not set %s, args=%v", absent, args)
		}
	}
}

// TestApiserverArgs_AuditPolicyWired is the M10.0 argv guard (B70 supplementary
// build check — the milestone proof is the enforcement e2e): the apiserver loads
// the provisioned audit policy + admission-control config, the audit log lands at
// the single-sourced AuditLogPath with bounded rotation, --audit-log-mode is
// ABSENT (the upstream blocking default — a write failure drops events, never
// stalls serving; blocking-strict is deliberately not used), and the SHIPPED
// policy content is structurally Metadata/None-only (asserting the LEVEL, not
// just that --audit-* is wired).
func TestApiserverArgs_AuditPolicyWired(t *testing.T) {
	cfg := Config{WorkDir: "/wd", KinePort: 2379, APIServerPort: 6444, NodeIP: "127.0.0.1"}
	args := apiServerArgs(cfg)

	if got := flagValue(args, "--audit-policy-file"); got != auditPolicyPath("/wd") {
		t.Errorf("--audit-policy-file = %q, want %q", got, auditPolicyPath("/wd"))
	}
	if got := flagValue(args, "--audit-log-path"); got != AuditLogPath("/wd") {
		t.Errorf("--audit-log-path = %q, want the single-sourced %q", got, AuditLogPath("/wd"))
	}
	for _, want := range []string{"--audit-log-maxsize=100", "--audit-log-maxbackup=3", "--audit-log-maxage=30"} {
		if !hasArg(args, want) {
			t.Errorf("bounded rotation token %s missing, args=%v", want, args)
		}
	}
	if got := flagValue(args, "--admission-control-config-file"); got != admissionConfigPath("/wd") {
		t.Errorf("--admission-control-config-file = %q, want %q", got, admissionConfigPath("/wd"))
	}
	for _, a := range args {
		if strings.HasPrefix(a, "--audit-log-mode") {
			t.Errorf("--audit-log-mode must be ABSENT (upstream blocking default; blocking-strict deliberately unused), got %q", a)
		}
	}

	// The LEVEL: the shipped policy document itself is Metadata/None-only.
	if strings.Contains(auditPolicyDoc, "Request") {
		t.Errorf("shipped audit policy must never contain a Request/RequestResponse level:\n%s", auditPolicyDoc)
	}
	if !strings.Contains(auditPolicyDoc, "level: Metadata") {
		t.Errorf("shipped audit policy must pin level: Metadata:\n%s", auditPolicyDoc)
	}
}

// TestClientCAFileAlwaysSet is the deliverable-3 guard: --client-ca-file is wired in
// BOTH postures so the per-component (system:kube-scheduler / system:kube-controller-
// manager) and system:node client certs authenticate. Single-node (no explicit
// ClientCAFile) defaults to the signing CA under the work-dir PKI dir; the mesh path's
// explicit ClientCAFile is honored verbatim. The M4.1 review flagged the prior
// mesh-only gating.
func TestClientCAFileAlwaysSet(t *testing.T) {
	single := Config{WorkDir: "/wd", KinePort: 2379, APIServerPort: 6444, NodeIP: "127.0.0.1"}
	wantDefault := certs.SigningCACertPath("/wd")
	if got := flagValue(apiServerArgs(single), "--client-ca-file"); got != wantDefault {
		t.Errorf("single-node --client-ca-file = %q, want the defaulted signing CA %q", got, wantDefault)
	}

	mesh := single
	mesh.ClientCAFile = "/var/lib/k3sm/server/tls/signing-ca.crt"
	if got := flagValue(apiServerArgs(mesh), "--client-ca-file"); got != mesh.ClientCAFile {
		t.Errorf("mesh --client-ca-file = %q, want the explicit %q (honored verbatim)", got, mesh.ClientCAFile)
	}
}

// TestLoopbackComponentsBindLoopbackOnly pins the posture of the two co-located
// control-plane components at the level the dev tier cannot see: their WHOLE argv,
// not just the flags one helper renders.
//
// The scheduler and the controller-manager serve /healthz and /metrics over HTTPS
// to the co-located control plane and to nothing else. Their ports are now
// per-server, so that a second control plane on one Mac does not lose the bind —
// and the risk a renumbering carries is that it becomes the edit which also moves
// the address. So: exactly ONE --bind-address per component, and it is loopback.
// Exactly one matters on its own, because these binaries take the LAST value for a
// repeated flag, and a second one appended anywhere would silently win.
func TestLoopbackComponentsBindLoopbackOnly(t *testing.T) {
	cfg := Config{WorkDir: "/var/lib/k3sm/server"}.withDefaults()
	for _, tc := range []struct {
		name     string
		args     []string
		wantPort int
	}{
		{"kube-scheduler", schedulerArgs(cfg), DefaultSchedulerPort},
		{"kube-controller-manager", controllerManagerArgs(cfg), DefaultControllerManagerPort},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var binds, secure []string
			for i, a := range tc.args {
				if i+1 >= len(tc.args) {
					continue
				}
				switch a {
				case "--bind-address":
					binds = append(binds, tc.args[i+1])
				case "--secure-port":
					secure = append(secure, tc.args[i+1])
				}
			}
			if len(binds) != 1 {
				t.Fatalf("%s carries %d --bind-address flags (%v), want exactly 1: the last one wins, so a second is an invisible override", tc.name, len(binds), binds)
			}
			if binds[0] != "127.0.0.1" {
				t.Errorf("%s --bind-address = %q, want 127.0.0.1", tc.name, binds[0])
			}
			if len(secure) != 1 || secure[0] != strconv.Itoa(tc.wantPort) {
				t.Errorf("%s --secure-port = %v, want exactly [%d]", tc.name, secure, tc.wantPort)
			}
		})
	}
}

// TestLoopbackComponentPortsAreConfigurable pins that the two components' ports
// come from Config and not from a literal — the property that lets a second
// control plane exist at all. Rendering the DEFAULT when nothing is set is the
// other half: a plain `k3sm server` must land byte-for-byte where it always did.
func TestLoopbackComponentPortsAreConfigurable(t *testing.T) {
	cfg := Config{WorkDir: "/var/lib/k3sm/server", SchedulerPort: 11455, ControllerManagerPort: 13460}.withDefaults()
	if got := flagValue(schedulerArgs(cfg), "--secure-port"); got != "11455" {
		t.Errorf("scheduler --secure-port = %q, want the configured 11455", got)
	}
	if got := flagValue(controllerManagerArgs(cfg), "--secure-port"); got != "13460" {
		t.Errorf("controller-manager --secure-port = %q, want the configured 13460", got)
	}
	// An unset Config still renders the upstream defaults, through the accessor,
	// so a hand-built Config never yields `--secure-port 0` (which upstream reads
	// as "any free port" — a listener nothing could then find).
	if got := flagValue(schedulerArgs(Config{}), "--secure-port"); got != strconv.Itoa(DefaultSchedulerPort) {
		t.Errorf("scheduler --secure-port on a zero Config = %q, want %d", got, DefaultSchedulerPort)
	}
	if got := flagValue(controllerManagerArgs(Config{}), "--secure-port"); got != strconv.Itoa(DefaultControllerManagerPort) {
		t.Errorf("controller-manager --secure-port on a zero Config = %q, want %d", got, DefaultControllerManagerPort)
	}
}

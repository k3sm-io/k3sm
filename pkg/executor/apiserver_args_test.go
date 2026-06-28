package executor

import (
	"strconv"
	"strings"
	"testing"

	"k3sm.io/k3sm/pkg/certs"
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

// TestApiserverNodePortRangeUnprivileged is the M3.1 wiring guard: the apiserver
// pins --service-node-port-range and both bounds stay >=1024, because k3sm's
// userspace Service proxy binds *:NodePort directly as the unprivileged _k3sm
// user (a <1024 bind would EACCES). It pins the contract the design relies on so
// an upstream default change cannot silently allocate an unbindable NodePort.
func TestApiserverNodePortRangeUnprivileged(t *testing.T) {
	cfg := Config{WorkDir: "/wd", KinePort: 2379, APIServerPort: 6444, NodeIP: "127.0.0.1"}
	args := apiServerArgs(cfg)

	rng := flagValue(args, "--service-node-port-range")
	if rng == "" {
		t.Fatalf("--service-node-port-range must be pinned, args=%v", args)
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
			t.Errorf("node-port-range bound %d < 1024: the unprivileged _k3sm proxy cannot bind it", n)
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

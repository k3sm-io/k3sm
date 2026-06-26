package executor

import (
	"strings"
	"testing"
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

// TestApiserverArgsSingleNodeDefault confirms the M1/M2 single-node path is
// unchanged: with the new fields zero, the apiserver binds loopback (via NodeIP) and
// the new M3 flags are omitted.
func TestApiserverArgsSingleNodeDefault(t *testing.T) {
	cfg := Config{WorkDir: "/wd", KinePort: 2379, APIServerPort: 6444, NodeIP: "127.0.0.1"}
	args := apiServerArgs(cfg)
	if got := flagValue(args, "--bind-address"); got != "127.0.0.1" {
		t.Errorf("single-node --bind-address = %q, want 127.0.0.1", got)
	}
	joined := strings.Join(args, " ")
	for _, absent := range []string{"--client-ca-file", "--kubelet-certificate-authority", "--anonymous-auth"} {
		if strings.Contains(joined, absent) {
			t.Errorf("single-node path must not set %s, args=%v", absent, args)
		}
	}
}

package hostnet

import (
	"context"
	"errors"
	"net"
	"path/filepath"
	"testing"

	"k3sm.io/darwin-net/pkg/netd"
)

// TestResolveModeBackends proves the `--network` backend selection: auto
// resolves by privilege (root → direct, unprivileged → helper); none disables
// the datapath regardless of privilege; direct requires root; helper forces the
// helper path; an unknown value errors.
func TestResolveModeBackends(t *testing.T) {
	cases := []struct {
		name        string
		network     string
		euid        int
		wantBackend Backend
		wantSocket  string
		wantErr     bool
	}{
		{name: "auto+root → direct", network: "auto", euid: 0, wantBackend: BackendDirect},
		{name: "auto+unprivileged → helper", network: "auto", euid: 1000, wantBackend: BackendHelper, wantSocket: netd.DefaultSocketPath},
		{name: "empty defaults to auto (unprivileged)", network: "", euid: 501, wantBackend: BackendHelper, wantSocket: netd.DefaultSocketPath},
		{name: "none+unprivileged → none", network: "none", euid: 1000, wantBackend: BackendNone},
		{name: "none+root → none", network: "none", euid: 0, wantBackend: BackendNone},
		{name: "direct+root → direct", network: "direct", euid: 0, wantBackend: BackendDirect},
		{name: "direct+unprivileged → error", network: "direct", euid: 1000, wantErr: true},
		{name: "helper → helper", network: "helper", euid: 0, wantBackend: BackendHelper, wantSocket: netd.DefaultSocketPath},
		{name: "unknown → error", network: "bogus", euid: 0, wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m, err := resolveMode(tc.network, tc.euid, netd.DefaultSocketPath)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("resolveMode(%q, %d) = %+v, want error", tc.network, tc.euid, m)
				}
				return
			}
			if err != nil {
				t.Fatalf("resolveMode(%q, %d): unexpected err %v", tc.network, tc.euid, err)
			}
			if m.Backend != tc.wantBackend {
				t.Errorf("Backend = %v, want %v", m.Backend, tc.wantBackend)
			}
			if m.Socket != tc.wantSocket {
				t.Errorf("Socket = %q, want %q", m.Socket, tc.wantSocket)
			}
		})
	}
}

// TestNoneBackendIsNoopAndProbeless is the fails-before/passes-after for the M1
// regression fix: the `none` backend runs NO datapath and its Probe is a no-op
// even with no helper socket present — so the non-root CI bring-up
// (`server --network none`) never fail-fasts on a missing helper. Before this
// change, a non-root server resolved to the helper backend and Probe errored.
func TestNoneBackendIsNoopAndProbeless(t *testing.T) {
	none, err := resolveMode(NetworkNone, 1000, netd.DefaultSocketPath)
	if err != nil {
		t.Fatalf("resolveMode(none): %v", err)
	}
	if none.DataPath() {
		t.Error("none backend must report DataPath()=false (no proxy/mesh datapath)")
	}
	if none.UsesHelper() {
		t.Error("none backend must not use the helper")
	}
	if len(none.ProxyOptions()) != 0 || len(none.MeshOptions("ref")) != 0 {
		t.Error("none backend must select no proxy/mesh helper options")
	}
	// The probe must be a no-op even though no helper socket exists.
	if err := none.Probe(context.Background()); err != nil {
		t.Errorf("none backend Probe must be a no-op, got %v", err)
	}

	// Contrast: auto+unprivileged DOES probe and fails fast with no helper.
	helper, _ := resolveMode(NetworkAuto, 1000, filepath.Join(t.TempDir(), "absent.sock"))
	if !helper.DataPath() || !helper.UsesHelper() {
		t.Fatal("auto+unprivileged must select the helper datapath")
	}
	if err := helper.Probe(context.Background()); !errors.Is(err, ErrHelperUnreachable) {
		t.Errorf("auto+unprivileged Probe with no helper must fail fast, got %v", err)
	}
}

// TestModeOptionsSelection proves the helper option is wired into the Proxy and
// Mesh constructors for the helper backend and omitted for direct (the direct
// root path) — the "not-root → netd-client impls selected" deliverable.
func TestModeOptionsSelection(t *testing.T) {
	helper, _ := resolveMode(NetworkHelper, 0, "/run/netd.sock")
	if got := helper.ProxyOptions(); len(got) != 1 {
		t.Errorf("helper ProxyOptions len = %d, want 1 (WithNetdHelper)", len(got))
	}
	if got := helper.MeshOptions("key-ref"); len(got) != 1 {
		t.Errorf("helper MeshOptions len = %d, want 1 (WithNetdHelper)", len(got))
	}

	direct, _ := resolveMode(NetworkDirect, 0, "/run/netd.sock")
	if got := direct.ProxyOptions(); len(got) != 0 {
		t.Errorf("direct ProxyOptions len = %d, want 0 (direct ops)", len(got))
	}
	if got := direct.MeshOptions("key-ref"); len(got) != 0 {
		t.Errorf("direct MeshOptions len = %d, want 0 (direct ops)", len(got))
	}
	if !direct.DataPath() {
		t.Error("direct backend must run the datapath")
	}
}

// TestProbeReachable proves a reachable helper socket passes the startup probe:
// a real unix listener on a temp socket connects successfully.
func TestProbeReachable(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "netd.sock")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("listen unix: %v", err)
	}
	defer l.Close()

	m := Mode{Backend: BackendHelper, Socket: sock}
	if err := m.Probe(context.Background()); err != nil {
		t.Errorf("Probe of a reachable helper: %v", err)
	}
}

// TestProbeUnreachable proves a missing helper socket fails fast with the
// actionable ErrHelperUnreachable (never a hang, never silent success).
func TestProbeUnreachable(t *testing.T) {
	m := Mode{Backend: BackendHelper, Socket: filepath.Join(t.TempDir(), "absent.sock")}
	if err := m.Probe(context.Background()); !errors.Is(err, ErrHelperUnreachable) {
		t.Fatalf("Probe of an unreachable helper err = %v, want ErrHelperUnreachable", err)
	}
}

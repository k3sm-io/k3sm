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

package install

import (
	"bytes"
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"k3sm.io/k3sm/pkg/bootstrap"
)

// meshKeyCalls returns the recorded seam calls for one path prefix, so a
// subtest can say "this file was written once, at this mode" rather than
// scanning the whole call list by hand.
func meshKeyCalls(f *fakeSystem, prefix string) []string {
	var out []string
	for _, c := range f.calls {
		if strings.HasPrefix(c, prefix) {
			out = append(out, c)
		}
	}
	return out
}

// wantCall fails unless the fake recorded exactly the given call.
func wantCall(t *testing.T, f *fakeSystem, call string) {
	t.Helper()
	for _, c := range f.calls {
		if c == call {
			return
		}
	}
	t.Errorf("the install never recorded %q; it recorded %v", call, f.calls)
}

// serverCfg is the control-plane Config the role half of this gate installs —
// agentCfg's sibling, with nothing about joining.
func serverCfg() Config {
	return Config{
		Role:         RoleServer,
		BinarySource: "/tmp/k3sm",
		TargetUser:   "alice",
	}
}

// TestAgentInstallProvisionsTheMeshHelperKey is the B325 gate.
//
// The defect: `k3sm install` never put this node's wireguard private key in the
// root-only directory netd's MeshKeyResolver reads, and did not even create that
// directory — a fresh single-node install had no <DataRoot>/run/keys at all. The
// only thing that ever wrote there was the node daemon's best-effort runtime
// write, which in the posture k3sm ships (an unprivileged _k3sm daemon, a
// root-owned key dir) cannot succeed. So a worker in helper mode handed netd a
// key ref that resolved to nothing and its mesh never came up.
//
// The fix is that the privileged install owns provisioning, for both roles, with
// the WORK-DIR key as the source of truth. Each subtest below is one way that
// could still be got wrong:
//
//   - a first install has no work-dir key, so one is minted and BOTH copies must
//     come from those same bytes (a second mint would give the daemon and netd
//     two different identities);
//   - a node that already has an identity must keep it — the helper copy is a
//     copy, never a re-mint;
//   - a helper copy whose bytes differ is stale and must be repaired, not left
//     for netd to hand wireguard while the node advertises another public key;
//   - a reinstall must change neither file;
//   - and the control plane is not a special case: it provisions its own ref the
//     same way, which is the half a worker-only fix would have missed.
//
// The modes are asserted at the seam (root 0600 inside a 0700 root-owned dir,
// service-user 0600 in the work dir) because that is the whole difference
// between the two copies: the root-only one is what keeps the key unreadable by
// every other account on the Mac.
func TestAgentInstallProvisionsTheMeshHelperKey(t *testing.T) {
	agentWork := filepath.Join(DefaultDataRoot, agentWorkSubdir, MeshKeyRefAgent)
	agentHelper := filepath.Join(MeshKeyDir, MeshKeyRefAgent)
	serverWork := filepath.Join(DefaultDataRoot, "server", MeshKeyRefServer)
	serverHelper := filepath.Join(MeshKeyDir, MeshKeyRefServer)

	t.Run("a fresh agent install mints one key and writes both copies", func(t *testing.T) {
		shrinkRestartBudgets(t)
		f := &fakeSystem{}
		seedJoinedAgent(t, f)
		if err := Install(context.Background(), f, agentCfg(t)); err != nil {
			t.Fatalf("Install: %v", err)
		}

		work, ok := f.files[agentWork]
		if !ok {
			t.Fatalf("install wrote no work-dir mesh key at %s", agentWork)
		}
		helper, ok := f.files[agentHelper]
		if !ok {
			t.Fatalf("install provisioned no root-only mesh key at %s (netd resolves the ref there)", agentHelper)
		}
		if !bytes.Equal(work, helper) {
			t.Errorf("the two copies differ: work-dir %q, helper %q — the daemon and netd would hold different identities", work, helper)
		}
		// Non-vacuity: the bytes are a usable wireguard private key, not a
		// placeholder a byte-equality check would happily compare against itself.
		if _, err := bootstrap.WireguardPublicKey(string(work)); err != nil {
			t.Errorf("the provisioned key is not a usable wireguard private key: %v", err)
		}

		// The root-only dir is carved before anything is written into it, at
		// root:wheel 0700, and the key inside it root 0600.
		wantCall(t, f, fmt.Sprintf("EnsureMeshKeyDir:%s:%#o", MeshKeyDir, MeshKeyDirMode))
		wantCall(t, f, fmt.Sprintf("WriteRootOnlyFile:%s:%#o", agentHelper, MeshKeyFileMode))
		if idx(f.calls, fmt.Sprintf("EnsureMeshKeyDir:%s:%#o", MeshKeyDir, MeshKeyDirMode)) >=
			idx(f.calls, fmt.Sprintf("WriteRootOnlyFile:%s:%#o", agentHelper, MeshKeyFileMode)) {
			t.Error("the key dir must be carved before the key is written into it")
		}
		// The work-dir copy goes through the service-user seam at 0600 in a 0700
		// directory — the daemon must be able to read it, and nothing else.
		wantCall(t, f, fmt.Sprintf("WriteServiceUserFile:%s:%#o:%#o:%d", agentWork, MeshKeyFileMode, AgentTokenDirMode, 271))
		// Never handed to the service user: that would erase the only difference
		// between the two copies.
		for _, c := range f.calls {
			if strings.HasPrefix(c, "WriteServiceUserFile:"+MeshKeyDir) || strings.HasPrefix(c, "EnsureRunDir:"+MeshKeyDir) {
				t.Errorf("the root-only key dir was handed to the service user: %q", c)
			}
		}
		// And before the daemon that needs it is bootstrapped.
		if idx(f.calls, fmt.Sprintf("WriteRootOnlyFile:%s:%#o", agentHelper, MeshKeyFileMode)) >= idx(f.calls, "Bootstrap:"+NetdLabel) {
			t.Error("the key must be provisioned before netd is bootstrapped")
		}
	})

	t.Run("an existing work-dir key is copied, never re-minted", func(t *testing.T) {
		shrinkRestartBudgets(t)
		priv, _, err := bootstrap.GenerateWireguardKey()
		if err != nil {
			t.Fatalf("mint a key for the fixture: %v", err)
		}
		f := &fakeSystem{}
		seedJoinedAgent(t, f)
		f.putFile(agentWork, []byte(priv))
		if err := Install(context.Background(), f, agentCfg(t)); err != nil {
			t.Fatalf("Install: %v", err)
		}
		if got := string(f.files[agentWork]); got != priv {
			t.Errorf("install rewrote the node's identity: work-dir key = %q, want %q (a re-mint strands every peer's AllowedIPs)", got, priv)
		}
		if got := string(f.files[agentHelper]); got != priv {
			t.Errorf("helper copy = %q, want the work-dir key %q", got, priv)
		}
		if calls := meshKeyCalls(f, "WriteServiceUserFile:"+agentWork); len(calls) != 0 {
			t.Errorf("install rewrote the existing work-dir key: %v", calls)
		}
	})

	t.Run("a stale helper copy is re-provisioned from the work dir", func(t *testing.T) {
		shrinkRestartBudgets(t)
		priv, _, err := bootstrap.GenerateWireguardKey()
		if err != nil {
			t.Fatalf("mint a key for the fixture: %v", err)
		}
		stale, _, err := bootstrap.GenerateWireguardKey()
		if err != nil {
			t.Fatalf("mint the stale key for the fixture: %v", err)
		}
		f := &fakeSystem{}
		seedJoinedAgent(t, f)
		f.putFile(agentWork, []byte(priv))
		f.putFile(agentHelper, []byte(stale))
		if err := Install(context.Background(), f, agentCfg(t)); err != nil {
			t.Fatalf("Install: %v", err)
		}
		if got := string(f.files[agentHelper]); got != priv {
			t.Errorf("stale helper copy survived: %q, want the work-dir key %q (netd would hand wireguard a key whose public half nothing advertises)", got, priv)
		}
		wantCall(t, f, fmt.Sprintf("WriteRootOnlyFile:%s:%#o", agentHelper, MeshKeyFileMode))
	})

	t.Run("a second install changes neither copy", func(t *testing.T) {
		shrinkRestartBudgets(t)
		f := &fakeSystem{}
		seedJoinedAgent(t, f)
		cfg := agentCfg(t)
		if err := Install(context.Background(), f, cfg); err != nil {
			t.Fatalf("first Install: %v", err)
		}
		work := append([]byte(nil), f.files[agentWork]...)
		helper := append([]byte(nil), f.files[agentHelper]...)
		before := len(f.calls)
		if err := Install(context.Background(), f, cfg); err != nil {
			t.Fatalf("second Install: %v", err)
		}
		if !bytes.Equal(f.files[agentWork], work) {
			t.Errorf("the reinstall changed the work-dir key: %q, want %q", f.files[agentWork], work)
		}
		if !bytes.Equal(f.files[agentHelper], helper) {
			t.Errorf("the reinstall changed the helper key: %q, want %q", f.files[agentHelper], helper)
		}
		// Nothing was rewritten at all: both copies already agreed, so the second
		// run is a read and a no-op.
		for _, c := range f.calls[before:] {
			if strings.HasPrefix(c, "WriteRootOnlyFile:") || strings.HasPrefix(c, "WriteServiceUserFile:"+agentWork) {
				t.Errorf("the reinstall rewrote a key that had not changed: %q", c)
			}
		}
	})

	t.Run("the server role provisions its own ref the same way", func(t *testing.T) {
		shrinkRestartBudgets(t)
		f := &fakeSystem{}
		if err := Install(context.Background(), f, serverCfg()); err != nil {
			t.Fatalf("Install: %v", err)
		}
		work, ok := f.files[serverWork]
		if !ok {
			t.Fatalf("a server install wrote no work-dir mesh key at %s", serverWork)
		}
		helper, ok := f.files[serverHelper]
		if !ok {
			t.Fatalf("a server install provisioned no root-only mesh key at %s", serverHelper)
		}
		if !bytes.Equal(work, helper) {
			t.Errorf("the control plane's two copies differ: %q vs %q", work, helper)
		}
		if _, err := bootstrap.WireguardPublicKey(string(work)); err != nil {
			t.Errorf("the provisioned key is not a usable wireguard private key: %v", err)
		}
		wantCall(t, f, fmt.Sprintf("WriteRootOnlyFile:%s:%#o", serverHelper, MeshKeyFileMode))
		wantCall(t, f, fmt.Sprintf("WriteServiceUserFile:%s:%#o:%#o:%d", serverWork, MeshKeyFileMode, ServerTokenDirMode, 271))
		// The two roles never collide in the one key dir: a server install writes
		// server.key and nothing under the agent's name.
		if _, ok := f.files[agentHelper]; ok {
			t.Errorf("a server install wrote the agent's key ref %s", agentHelper)
		}
	})

	t.Run("the root-only copy restores a wiped work dir instead of minting", func(t *testing.T) {
		shrinkRestartBudgets(t)
		priv, _, err := bootstrap.GenerateWireguardKey()
		if err != nil {
			t.Fatalf("mint a key for the fixture: %v", err)
		}
		f := &fakeSystem{}
		seedJoinedAgent(t, f)
		// The identity every peer knows this node by survives only in the key
		// dir: the work dir was wiped (a data-root repair, a hand-deleted file).
		f.putFile(agentHelper, []byte(priv))
		if err := Install(context.Background(), f, agentCfg(t)); err != nil {
			t.Fatalf("Install: %v", err)
		}
		if got := string(f.files[agentWork]); got != priv {
			t.Errorf("work-dir key = %q, want the root-only copy %q restored (a mint here orphans the node from every peer's AllowedIPs)", got, priv)
		}
		if got := string(f.files[agentHelper]); got != priv {
			t.Errorf("the root-only copy was rewritten: %q, want it untouched at %q", got, priv)
		}
		wantCall(t, f, fmt.Sprintf("WriteServiceUserFile:%s:%#o:%#o:%d", agentWork, MeshKeyFileMode, AgentTokenDirMode, 271))
		if calls := meshKeyCalls(f, "WriteRootOnlyFile:"); len(calls) != 0 {
			t.Errorf("the restore rewrote the root-only copy it read from: %v", calls)
		}
	})

	t.Run("a symlinked work-dir key is refused, never followed", func(t *testing.T) {
		shrinkRestartBudgets(t)
		f := &fakeSystem{}
		seedOperatorToken(f)
		// What a service-uid writer plants in its own work dir: a link whose
		// target root can read. The target holds a PERFECTLY VALID key — somebody
		// else's — so nothing but the refusal to follow the link can catch this.
		// A validate-only check would see a usable key and copy it in as "the
		// existing identity".
		planted, _, err := bootstrap.GenerateWireguardKey()
		if err != nil {
			t.Fatalf("mint the planted key for the fixture: %v", err)
		}
		f.putFile(agentWork, []byte(planted))
		f.putSymlink(agentWork)
		if err := Install(context.Background(), f, agentCfg(t)); err == nil {
			t.Fatal("install accepted a symlinked work-dir mesh key")
		} else if !strings.Contains(err.Error(), agentWork) {
			t.Errorf("error %q does not name the path to look at", err)
		}
		if calls := meshKeyCalls(f, "WriteRootOnlyFile:"); len(calls) != 0 {
			t.Errorf("install wrote the root-only copy anyway: %v", calls)
		}
		if _, ok := f.files[agentHelper]; ok {
			t.Errorf("the symlink target's bytes reached the root-only copy: %q", f.files[agentHelper])
		}
	})

	t.Run("undecodable work-dir bytes are refused, never minted over", func(t *testing.T) {
		shrinkRestartBudgets(t)
		f := &fakeSystem{}
		seedOperatorToken(f)
		f.putFile(agentWork, []byte("not a wireguard key at all"))
		err := Install(context.Background(), f, agentCfg(t))
		if err == nil {
			t.Fatal("install accepted a work-dir mesh key that is not a key")
		}
		if !strings.Contains(err.Error(), agentWork) {
			t.Errorf("error %q does not name the path to look at", err)
		}
		// Refusing is the whole point: minting here would replace whatever that
		// file actually was, and a corrupted key file is evidence.
		if got := string(f.files[agentWork]); got != "not a wireguard key at all" {
			t.Errorf("install rewrote the unusable file: %q", got)
		}
	})

	t.Run("an unusable root-only copy with no work dir to repair from is refused", func(t *testing.T) {
		shrinkRestartBudgets(t)
		f := &fakeSystem{}
		seedOperatorToken(f)
		f.putFile(agentHelper, []byte("not a wireguard key at all"))
		err := Install(context.Background(), f, agentCfg(t))
		if err == nil {
			t.Fatal("install minted over an unusable root-only copy with no work-dir key to repair from")
		}
		if !strings.Contains(err.Error(), agentHelper) {
			t.Errorf("error %q does not name the path to look at", err)
		}
	})

	t.Run("an unusable root-only copy IS repaired when the work dir holds the identity", func(t *testing.T) {
		shrinkRestartBudgets(t)
		priv, _, err := bootstrap.GenerateWireguardKey()
		if err != nil {
			t.Fatalf("mint a key for the fixture: %v", err)
		}
		f := &fakeSystem{}
		seedJoinedAgent(t, f)
		f.putFile(agentWork, []byte(priv))
		f.putFile(agentHelper, []byte("not a wireguard key at all"))
		if err := Install(context.Background(), f, agentCfg(t)); err != nil {
			t.Fatalf("Install: %v", err)
		}
		if got := string(f.files[agentHelper]); got != priv {
			t.Errorf("root-only copy = %q, want it repaired from the work-dir key %q", got, priv)
		}
	})

	t.Run("the refs are distinct bare file names pkg/install owns", func(t *testing.T) {
		if MeshKeyRefServer == MeshKeyRefAgent {
			t.Fatalf("both roles name their key %q: a server and a worker on one Mac would overwrite each other's identity", MeshKeyRefAgent)
		}
		for _, ref := range []string{MeshKeyRefServer, MeshKeyRefAgent} {
			if ref != filepath.Base(ref) {
				t.Errorf("mesh key ref %q must be a bare file name — netd's MeshKeyResolver rejects anything else", ref)
			}
		}
		if MeshKeyDirMode != 0o700 || MeshKeyFileMode != 0o600 {
			t.Errorf("mesh key policy = dir %#o file %#o, want 0700/0600 (root-only: no other account on the Mac reads this key)",
				MeshKeyDirMode, MeshKeyFileMode)
		}
	})
}

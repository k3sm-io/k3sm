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
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
)

// newTestManager builds a Manager over a fake System + a temp-rooted registry,
// with kubeconfig chown disabled (not-under-sudo). euid selects the privilege
// posture under test.
func newTestManager(t *testing.T, sys System, euid int) *Manager {
	t.Helper()
	m := NewManager(ManagerConfig{
		Registry: NewRegistry(t.TempDir()),
		System:   sys,
		Self:     "/usr/local/bin/k3sm",
		EUID:     euid,
		Out:      &bytes.Buffer{},
	})
	// Force not-under-sudo chown semantics regardless of the test environment's
	// SUDO_USER, so the merge/chown paths are deterministic.
	m.kubeMg.chownUser, m.kubeMg.chownUID, m.kubeMg.chownGID = "", -1, -1
	return m
}

func TestUpDatapathRequiresRoot(t *testing.T) {
	m := newTestManager(t, newFakeSystem(), 501) // non-root
	_, err := m.Up(context.Background(), UpOptions{Name: "dev", Datapath: true})
	if !errors.Is(err, ErrDatapathRequiresRoot) {
		t.Fatalf("Up(--datapath) as non-root = %v, want ErrDatapathRequiresRoot", err)
	}
	// The error must carry the actionable sudo line.
	if !bytes.Contains([]byte(err.Error()), []byte("sudo")) {
		t.Errorf("error %q missing the sudo remediation line", err)
	}
}

func TestUpDatapathSingletonLiveAlias(t *testing.T) {
	sys := newFakeSystem()
	// A live datapath instance's pod-CIDR lo0 alias is already present → a second
	// --datapath up must fail fast BEFORE its pre-flight flush tears it down.
	sys.aliases = []string{"100.64.0.1"}
	m := newTestManager(t, sys, 0) // root
	_, err := m.Up(context.Background(), UpOptions{Name: "b", Datapath: true})
	if !errors.Is(err, ErrDatapathSingleton) {
		t.Fatalf("second --datapath up with a live alias = %v, want ErrDatapathSingleton", err)
	}
	// It must NOT have removed the live alias (the whole point of the assert).
	if len(sys.removed) != 0 {
		t.Errorf("singleton violation removed aliases %v, want none (live datapath preserved)", sys.removed)
	}
}

func TestUpDatapathSingletonLockHeld(t *testing.T) {
	sys := newFakeSystem()
	m := newTestManager(t, sys, 0)
	// Simulate a concurrent holder of the datapath lock.
	sys.lockHeld[m.datapathLockPath()] = true
	_, err := m.Up(context.Background(), UpOptions{Name: "c", Datapath: true})
	if !errors.Is(err, ErrDatapathSingleton) {
		t.Fatalf("Up with the datapath lock held = %v, want ErrDatapathSingleton", err)
	}
}

func TestPreflightReclaimNoManifest(t *testing.T) {
	m := newTestManager(t, newFakeSystem(), 501)
	// A missing manifest is a clean first boot — no error, nothing reaped.
	if err := m.preflightReclaim("fresh"); err != nil {
		t.Fatalf("preflightReclaim on absent manifest = %v, want nil", err)
	}
}

func TestPreflightReclaimReapsStalePidAndAliases(t *testing.T) {
	sys := newFakeSystem()
	sys.alivePIDs[9999] = true                         // the prior server is still alive
	sys.aliases = []string{"10.43.0.10", "100.64.0.7"} // its datapath aliases persist
	m := newTestManager(t, sys, 0)                     // root (so lo0 flush runs)
	prior := sampleInstance("crashed")
	prior.PID = 9999
	prior.Tier = tierRoot
	prior.Datapath = DatapathDirect
	if err := m.reg.Save(prior); err != nil {
		t.Fatalf("seed prior manifest: %v", err)
	}

	if err := m.preflightReclaim("crashed"); err != nil {
		t.Fatalf("preflightReclaim: %v", err)
	}
	// The stale pid was terminated.
	if len(sys.terminated) != 1 || sys.terminated[0] != 9999 {
		t.Errorf("terminated = %v, want [9999] (stale pid reaped)", sys.terminated)
	}
	// Its Service+pod lo0 aliases were flushed.
	wantRemoved := map[string]bool{"10.43.0.10": true, "100.64.0.7": true}
	for _, r := range sys.removed {
		delete(wantRemoved, r)
	}
	if len(wantRemoved) != 0 {
		t.Errorf("reclaim did not flush %v", wantRemoved)
	}
}

func TestPreflightReclaimRootlessSkipsFlush(t *testing.T) {
	sys := newFakeSystem()
	sys.aliases = []string{"10.43.0.10"} // a stray alias, but the prior run was rootless
	m := newTestManager(t, sys, 501)     // non-root
	prior := sampleInstance("rl")
	prior.PID = 0 // rootless: no live server recorded
	prior.Datapath = DatapathNone
	if err := m.reg.Save(prior); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := m.preflightReclaim("rl"); err != nil {
		t.Fatalf("preflightReclaim: %v", err)
	}
	// Rootless reclaim never removes lo0 aliases (it allocates none; removal needs root).
	if len(sys.removed) != 0 {
		t.Errorf("rootless reclaim removed %v, want none", sys.removed)
	}
}

func TestLoadValidatesPath(t *testing.T) {
	m := newTestManager(t, newFakeSystem(), 501)
	// A non-existent path is rejected here, not at pod admission.
	if _, err := m.Load("/definitely/not/a/real/binary/xyz"); err == nil {
		t.Error("Load on a missing path = nil, want an error")
	}
	// A real file yields the stamped image line.
	f := t.TempDir() + "/mybin"
	if err := writeExecutable(f); err != nil {
		t.Fatal(err)
	}
	line, err := m.Load(f)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !bytes.Contains([]byte(line), []byte("NON-PORTABLE")) {
		t.Errorf("Load line %q missing the non-portable stamp", line)
	}
}

// TestDevUpWaitsForNodeRegistration is the B155 gate.
//
// `k3sm dev up` returned ~90 seconds before the node registered: measured on lab
// hardware 2026-08-27, the server logged `starting k3sm node` at 12:34:36 and
// `node ... ready` at 12:36:06, while `dev up` had already returned at 12:34. Any
// caller that listed nodes right after `up` saw ZERO, and every pod it created sat
// `Unschedulable: no nodes available to schedule pods` — which is what killed the
// m10.3 ingress gate (`items: []`) and TestM3_PVCPersistsAcrossRestart.
//
// Scope note: `Up` itself is not unit-reachable (it fork/execs a real server), so
// this pins the WAIT's semantics and the seam Up consults — not end-to-end
// registration, which is the lab's to prove.
func TestDevUpWaitsForNodeRegistration(t *testing.T) {
	ready := func(registered, readyCount int) func(context.Context) (int, int, error) {
		return func(context.Context) (int, int, error) { return registered, readyCount, nil }
	}

	t.Run("returns once a Ready node exists", func(t *testing.T) {
		if err := awaitReadyNode(context.Background(), 2*time.Second, "kc", ready(1, 1)); err != nil {
			t.Fatalf("one Ready node: err = %v, want nil", err)
		}
	})

	t.Run("keeps waiting while ZERO nodes are registered", func(t *testing.T) {
		err := awaitReadyNode(context.Background(), 300*time.Millisecond, "kc", ready(0, 0))
		if err == nil {
			t.Fatal("no nodes: err = nil, want a timeout error")
		}
		if !strings.Contains(err.Error(), "registered=0") {
			t.Errorf("error %q must report that no node registered", err)
		}
	})

	t.Run("a registered node that is NOT Ready does not count", func(t *testing.T) {
		err := awaitReadyNode(context.Background(), 300*time.Millisecond, "kc", ready(1, 0))
		if err == nil {
			t.Fatal("registered-but-NotReady node: err = nil, want a timeout error")
		}
		if !strings.Contains(err.Error(), "registered=1") || !strings.Contains(err.Error(), "ready=0") {
			t.Errorf("error %q must report the node as registered but not Ready", err)
		}
	})

	t.Run("names what it was waiting for on timeout", func(t *testing.T) {
		err := awaitReadyNode(context.Background(), 50*time.Millisecond, "/tmp/some.kubeconfig", ready(0, 0))
		if err == nil {
			t.Fatal("err = nil, want a timeout error")
		}
		for _, want := range []string{"no node registered Ready", "/tmp/some.kubeconfig"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("error %q must contain %q", err, want)
			}
		}
	})

	t.Run("a probe error is transient but surfaces in the timeout", func(t *testing.T) {
		probeErr := errors.New("connection refused")
		calls := 0
		flapping := func(context.Context) (int, int, error) {
			calls++
			if calls < 3 {
				return 0, 0, probeErr
			}
			return 1, 1, nil
		}
		if err := awaitReadyNode(context.Background(), 5*time.Second, "kc", flapping); err != nil {
			t.Fatalf("transient probe errors: err = %v, want nil once a Ready node appears", err)
		}
		always := func(context.Context) (int, int, error) { return 0, 0, probeErr }
		err := awaitReadyNode(context.Background(), 50*time.Millisecond, "kc", always)
		if err == nil || !strings.Contains(err.Error(), "connection refused") {
			t.Errorf("err = %v, must carry the last probe error", err)
		}
	})

	t.Run("honors context cancellation", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if err := awaitReadyNode(ctx, time.Minute, "kc", ready(0, 0)); !errors.Is(err, context.Canceled) {
			t.Errorf("err = %v, want context.Canceled", err)
		}
	})

	t.Run("readiness is the Ready condition, not the node's existence", func(t *testing.T) {
		cases := []struct {
			name string
			node corev1.Node
			want bool
		}{
			{"no conditions at all (just registered)", corev1.Node{}, false},
			{"Ready=False", corev1.Node{Status: corev1.NodeStatus{Conditions: []corev1.NodeCondition{
				{Type: corev1.NodeReady, Status: corev1.ConditionFalse}}}}, false},
			{"Ready=Unknown", corev1.Node{Status: corev1.NodeStatus{Conditions: []corev1.NodeCondition{
				{Type: corev1.NodeReady, Status: corev1.ConditionUnknown}}}}, false},
			{"only an unrelated condition is True", corev1.Node{Status: corev1.NodeStatus{Conditions: []corev1.NodeCondition{
				{Type: corev1.NodeMemoryPressure, Status: corev1.ConditionTrue}}}}, false},
			{"Ready=True", corev1.Node{Status: corev1.NodeStatus{Conditions: []corev1.NodeCondition{
				{Type: corev1.NodeMemoryPressure, Status: corev1.ConditionFalse},
				{Type: corev1.NodeReady, Status: corev1.ConditionTrue}}}}, true},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				if got := nodeIsReady(&tc.node); got != tc.want {
					t.Errorf("nodeIsReady = %t, want %t", got, tc.want)
				}
			})
		}
	})

	t.Run("Up consults the seam and propagates its failure", func(t *testing.T) {
		m := newTestManager(t, newFakeSystem(), 501)
		if m.awaitNodeRegistration != nil {
			t.Fatal("a fresh Manager must leave the seam nil so Up falls back to the production wait")
		}
		// The wait Up applies with no seam set must be the production one: reachable,
		// non-panicking, and an error on a kubeconfig that is not there.
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if err := m.nodeRegistrationWait()(ctx, filepath.Join(t.TempDir(), "absent.kubeconfig")); err == nil {
			t.Error("production wait on an absent kubeconfig = nil, want an error")
		}
		// An injected wait is the one Up runs, and its failure is what Up returns —
		// a failed registration must never be reported as an instance that is up.
		boom := errors.New("node never registered")
		m.awaitNodeRegistration = func(context.Context, string) error { return boom }
		if err := m.nodeRegistrationWait()(context.Background(), "kc"); !errors.Is(err, boom) {
			t.Errorf("seam failure = %v, want it propagated verbatim", err)
		}
	})

	t.Run("the timeout budget clears the observed registration latency", func(t *testing.T) {
		// Registration was observed at ~90s, which is exactly
		// defaultNamespaceBootstrapTimeout — reusing that budget here would sit on
		// top of the observation and flake.
		const observed = 90 * time.Second
		if nodeRegistrationTimeout <= observed {
			t.Errorf("nodeRegistrationTimeout = %s; must exceed the ~%s registration observed on lab hardware",
				nodeRegistrationTimeout, observed)
		}
		if nodeRegistrationTimeout < 2*observed {
			t.Errorf("nodeRegistrationTimeout = %s; too close to the observed ~%s to be flake-proof",
				nodeRegistrationTimeout, observed)
		}
		if nodeRegistrationTimeout > 15*time.Minute {
			t.Errorf("nodeRegistrationTimeout = %s; too long to be a useful bound", nodeRegistrationTimeout)
		}
	})
}

// TestPodRootOutsideProtectedTree pins the one property that decides whether a
// PVC-backed pod can run in a `k3sm dev` cluster: the runtimed root the detached
// server is given must not live under /Users.
//
// runtimed derives each claim's dir from ITS work-dir (<root>/storage/<ns>/<claim>)
// and hands it to the SBPL generator as the pod's read/write scope; that generator
// refuses any such grant under one of its FIXED system-protected prefixes, of
// which /Users is one (runtimed pkg/sandbox, systemProtectedPrefixes). With the
// root derived from the work-dir parent — the registry root under the invoking
// user's home — every PVC pod was rejected at sandbox setup ("extra path is under
// a protected deny-set") and sat Pending until deleted, while the same criterion
// passed under hack/acceptance/m3.sh, whose --pod-root is /tmp/k3sm-cluster/pods.
func TestPodRootOutsideProtectedTree(t *testing.T) {
	// The runtimed prefixes a confined pod may never be granted, quoted here
	// because k3sm cannot import them: /private/var/db and the cryptexes are the
	// rest of that fixed list, kept so a future base is checked against all of it.
	protected := []string{"/Users", "/private/var/db", "/System/Volumes/Preboot/Cryptexes", "/System/Cryptexes"}

	t.Run("the derived root escapes the registry root and every protected prefix", func(t *testing.T) {
		for _, euid := range []int{0, 501} {
			m := newTestManager(t, newFakeSystem(), euid)
			root := m.podRoot("dev")
			for _, pre := range protected {
				if root == pre || strings.HasPrefix(root, pre+"/") {
					t.Errorf("euid %d: podRoot = %q, which is under the runtimed-protected prefix %q — every PVC pod would be rejected at sandbox setup", euid, root, pre)
				}
			}
			// The work-dir parent is what the server would derive on its own
			// (executor.RuntimeRoot); the whole point is that the two differ.
			if derived := filepath.Dir(filepath.Clean(m.workDir("dev"))); root == derived {
				t.Errorf("euid %d: podRoot = %q, want it OFF the work-dir parent (the registry root under $HOME)", euid, root)
			}
			if want := PodRootBasePrefix + "-" + strconv.Itoa(euid) + "/dev"; root != want {
				t.Errorf("euid %d: podRoot = %q, want %q (the euid-scoped base keeps a root and a rootless instance off one another's 0700 tree)", euid, root, want)
			}
		}
	})

	t.Run("serverArgs hands it to the server as --pod-root", func(t *testing.T) {
		args := serverArgs("dev", "/w", "/private/var/tmp/k3sm-dev-0/dev", testPorts, "direct", runtimeRuntimed, "", "")
		i := slices.Index(args, "--pod-root")
		if i < 0 {
			t.Fatalf("serverArgs = %v, want a --pod-root flag (without it the server derives the root from the work-dir parent)", args)
		}
		if i+1 >= len(args) || args[i+1] != "/private/var/tmp/k3sm-dev-0/dev" {
			t.Errorf("serverArgs --pod-root value = %v, want the instance root", args[i+1:])
		}
	})
}

// TestTeardownRemovesPodRoot pins the other half of the split: the runtime root
// now lives outside the instance dir Registry.Remove wipes, so teardown must
// delete it explicitly — and must refuse a path it cannot vouch for, since in the
// datapath tier that RemoveAll runs as root.
func TestTeardownRemovesPodRoot(t *testing.T) {
	t.Run("the recorded root is deleted", func(t *testing.T) {
		base := t.TempDir()
		m := newTestManager(t, newFakeSystem(), 501)
		m.podRootBase = base
		inst := sampleInstance("gone")
		inst.PID = 0
		inst.PodRoot = filepath.Join(base, "gone")
		if err := os.MkdirAll(filepath.Join(inst.PodRoot, "storage", "default", "data-m3-pvc-0"), 0o755); err != nil {
			t.Fatalf("seed pod root: %v", err)
		}
		if err := m.reg.Save(inst); err != nil {
			t.Fatalf("seed manifest: %v", err)
		}
		if err := m.teardown(inst); err != nil {
			t.Fatalf("teardown: %v", err)
		}
		if _, err := os.Stat(inst.PodRoot); !os.IsNotExist(err) {
			t.Errorf("pod root %q survived teardown (stat err = %v) — every torn-down instance would leak its pod dirs, blob cache and PVC storage", inst.PodRoot, err)
		}
	})

	t.Run("removablePodRoot refuses anything it cannot vouch for", func(t *testing.T) {
		const base = "/private/var/tmp/k3sm-dev-0"
		cases := []struct {
			name    string
			podRoot string
			base    string
			want    string
		}{
			{"a proper descendant is removable", base + "/dev", base, base + "/dev"},
			{"an older manifest records none", "", base, ""},
			{"the base itself is not removable", base, base, ""},
			{"a sibling outside the base is refused", "/private/var/tmp/other/dev", base, ""},
			{"a relative path is refused", "relative/dev", base, ""},
			{"an unclean path is refused", base + "/../../../etc", base, ""},
			{"a prefix-string near-match is refused", base + "-elsewhere/dev", base, ""},
			{"an empty base disables removal", base + "/dev", "", ""},
			{"a root base is refused", "/anything", "/", ""},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				inst := sampleInstance("x")
				inst.PodRoot = tc.podRoot
				if got := removablePodRoot(inst, tc.base); got != tc.want {
					t.Errorf("removablePodRoot(%q, %q) = %q, want %q", tc.podRoot, tc.base, got, tc.want)
				}
			})
		}
	})
}

// TestDevUpSurfacesColdCacheBootTimeout is the boot-timeout surfacing gate.
//
// `dev up` spawns a DETACHED server and waits for it to write its kubeconfig. When that
// wait expired the error said only that the file had not appeared and pointed vaguely
// at "the server.log beside it" — so the operator of the observed failure, whose log
// held nothing but `go: downloading` lines (the datastore binary being built from a
// cold module cache), had no way to learn that anything was progressing at all. The
// deadline is deliberately NOT the fix and is NOT raised here: a bound that grows to
// fit the worst run has stopped bounding anything. The fix is that the failure carries
// the evidence.
func TestDevUpSurfacesColdCacheBootTimeout(t *testing.T) {
	writeLog := func(t *testing.T, lines ...string) string {
		t.Helper()
		p := serverLogPath(t.TempDir())
		if err := os.WriteFile(p, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}

	t.Run("the timeout names the log and quotes its tail", func(t *testing.T) {
		logPath := writeLog(t,
			"time=2026-08-29T09:00:00Z level=INFO msg=\"starting k3sm server\"",
			"go: downloading modernc.org/sqlite v1.34.5",
			"go: downloading modernc.org/libc v1.61.0")

		err := awaitKubeconfigFile(t.Context(), 50*time.Millisecond, "/nope/k3sm.kubeconfig", logPath)
		if err == nil {
			t.Fatal("no kubeconfig: err = nil, want a timeout error")
		}
		for _, want := range []string{
			"/nope/k3sm.kubeconfig", // what it was waiting for
			logPath,                 // where the account of the boot lives
			"go: downloading modernc.org/libc v1.61.0", // the cause, quoted
			"starting k3sm server",                     // the boot did start
		} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("timeout error %q does not carry %q", err, want)
			}
		}
	})

	t.Run("the quoted tail is bounded", func(t *testing.T) {
		lines := make([]string, 0, bootLogTailLines*3)
		for i := range cap(lines) {
			lines = append(lines, "line-"+strconv.Itoa(i))
		}
		logPath := writeLog(t, lines...)

		err := awaitKubeconfigFile(t.Context(), 50*time.Millisecond, "/nope/k3sm.kubeconfig", logPath)
		if err == nil {
			t.Fatal("err = nil, want a timeout error")
		}
		if !strings.Contains(err.Error(), lines[len(lines)-1]) {
			t.Errorf("timeout error %q omits the LAST log line", err)
		}
		if strings.Contains(err.Error(), "line-0\n") {
			t.Errorf("timeout error %q dumped the whole log instead of its tail", err)
		}
	})

	t.Run("a log that cannot be read still yields an actionable error", func(t *testing.T) {
		missing := filepath.Join(t.TempDir(), "server.log")
		err := awaitKubeconfigFile(t.Context(), 50*time.Millisecond, "/nope/k3sm.kubeconfig", missing)
		if err == nil {
			t.Fatal("err = nil, want a timeout error")
		}
		if !strings.Contains(err.Error(), missing) {
			t.Errorf("timeout error %q does not name the log it could not read", err)
		}
	})

	t.Run("returns as soon as the kubeconfig appears", func(t *testing.T) {
		work := t.TempDir()
		kc := filepath.Join(work, "k3sm.kubeconfig")
		if err := os.WriteFile(kc, []byte("apiVersion: v1\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := awaitKubeconfigFile(t.Context(), time.Second, kc, serverLogPath(work)); err != nil {
			t.Errorf("kubeconfig present: err = %v, want nil", err)
		}
	})

	t.Run("the deadline is not widened to paper over a slow boot", func(t *testing.T) {
		if kubeconfigWait != 90*time.Second {
			t.Errorf("kubeconfigWait = %s, want 90s — surfacing the cause is the fix, not a bigger number", kubeconfigWait)
		}
	})
}

// TestDevUpFailsWhenServerDies is the report-vs-reality gate: `k3sm dev up` may
// only say an instance is up while the server it spawned is still running.
//
// It printed `instance "b" up` for a server whose datastore had FATAL'd, and the
// report was not wrong about anything it had checked — the kubeconfig existed,
// the default namespace was bootstrapped, a node was Ready. Every one of those is
// a readiness SIGNAL, and a signal already emitted stays true after the process
// emitting it dies. So the fixture here is exactly that shape: a server that
// writes its readiness file and then exits. Both directions are asserted, because
// a check that only ever fails is as useless as one that only ever passes.
func TestDevUpFailsWhenServerDies(t *testing.T) {
	for _, tc := range []struct {
		name     string
		fixture  string // shell run after the kubeconfig is written
		wantFail bool
	}{
		{
			name: "the server exits right after its readiness file appears",
			// The exit status and the log line are distinctive so the assertions
			// below prove the ERROR carries the server's own account, not a
			// synthesised one.
			fixture:  "echo 'FATAL: kine: listen tcp 127.0.0.1:2379: bind: address already in use' >&2\nexit 7\n",
			wantFail: true,
		},
		{
			name:     "a server that stays alive still comes up",
			fixture:  "sleep 120\n",
			wantFail: false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sys := newFakeSystem()
			// The spawned server is a REAL process, so the liveness seam must answer
			// about it truthfully — the in-memory pid table cannot.
			sys.aliveProbe = func(pid int) bool { return syscall.Kill(pid, 0) == nil }
			m := newTestManager(t, sys, 501)
			out := &bytes.Buffer{}
			m.out = out
			m.builder = &fakeBuilder{}
			m.podRootBase = filepath.Join(t.TempDir(), "podroot")
			m.self = writeFakeServer(t, tc.fixture)
			// The two cluster-shaped waits have no cluster here; the defect under
			// test is upstream of both, in what `up` concludes from them.
			m.awaitNamespaceBootstrap = func(context.Context, string) error { return nil }
			m.awaitNodeRegistration = func(context.Context, string) error { return nil }

			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			defer cancel()
			inst, err := m.Up(ctx, UpOptions{Name: "b", Kubeconfig: filepath.Join(t.TempDir(), "kubeconfig")})
			if inst.PID > 0 {
				t.Cleanup(func() { _ = syscall.Kill(-inst.PID, syscall.SIGKILL) })
			}

			if !tc.wantFail {
				if err != nil {
					t.Fatalf("Up over a live server = %v, want nil", err)
				}
				if !strings.Contains(out.String(), `instance "b" up`) {
					t.Errorf("output %q must report the instance up", out)
				}
				return
			}

			if err == nil {
				t.Fatalf("Up over a server that exited = nil; it reported %q for a dead control plane", out)
			}
			if !errors.Is(err, ErrServerExited) {
				t.Fatalf("Up error = %v, want ErrServerExited", err)
			}
			// The exit REASON, not merely the fact of it: an operator whose kine lost
			// a port bind must be told that, not told a probe failed.
			for _, want := range []string{"exit status 7", "bind: address already in use", "server.log"} {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("error %q must carry %q from the server's own exit", err, want)
				}
			}
			if strings.Contains(out.String(), `instance "b" up`) {
				t.Errorf("output %q reported an instance up over a dead server", out)
			}
			// A dead server leaves no durable manifest to mislead `list`/`down`.
			if _, lerr := m.reg.Load("b"); !errors.Is(lerr, ErrNotFound) {
				t.Errorf("registry Load after a failed up = %v, want ErrNotFound", lerr)
			}
		})
	}
}

// writeFakeServer writes an executable stand-in for `k3sm server` that writes the
// admin kubeconfig into $K3SM_WORK_DIR — the readiness signal `up` waits on — and
// then runs after. Its argv is ignored: what is under test is what `up` concludes
// from the signal, not what the server does with its flags.
func writeFakeServer(t *testing.T, after string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "fake-k3sm-server")
	// Written temp-then-rename, as the real server writes it: a reader polling for
	// the file must never observe a half-written one, or this fixture would fail
	// bring-up at the kubeconfig PARSE and stop exercising the defect.
	script := "#!/bin/sh\nset -e\ncat > \"$K3SM_WORK_DIR/.kubeconfig.tmp\" <<'KC'\n" +
		fakeKubeconfig + "KC\n" +
		"mv \"$K3SM_WORK_DIR/.kubeconfig.tmp\" \"$K3SM_WORK_DIR/k3sm.kubeconfig\"\n" + after
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatalf("write fake server: %v", err)
	}
	return path
}

// fakeKubeconfig is a minimal admin kubeconfig with the sole cluster/user/context
// the merge expects.
const fakeKubeconfig = `apiVersion: v1
kind: Config
clusters:
- name: k3sm
  cluster:
    server: https://127.0.0.1:16440
    insecure-skip-tls-verify: true
users:
- name: admin
  user:
    token: fake-token
contexts:
- name: k3sm
  context:
    cluster: k3sm
    user: admin
current-context: k3sm
`

// TestListReportsUnknownNotStaleWhenUnprobeable is the B211 gate: an instance
// whose pid EXISTS but cannot be signalled from this uid must never be reported
// stale.
//
// Observed in the M8 gate run: an unprivileged `k3sm dev list` printed STATUS
// stale for a healthy root-owned `--datapath` instance. The probe was
// `kill(pid, 0) == nil`, which folds ESRCH (no such process) and EPERM (the
// process exists, you may not signal it) into one "dead" answer. `stale` is the
// word that invites a cleanup, so the misreport aimed the operator at a live
// cluster.
//
// The table walks all three kernel answers through the faked seam, and asserts
// both directions: unknown for EPERM, and — the anti-overcorrection half — still
// stale for a genuinely-gone pid, so a fix that simply reported everything alive
// would not pass.
func TestListReportsUnknownNotStaleWhenUnprobeable(t *testing.T) {
	const (
		rootOwnedPID = 4242
		livePID      = 1111
		deadPID      = 2222
	)
	sys := newFakeSystem()
	sys.unprobeable[rootOwnedPID] = true // kill -0 -> EPERM: exists, not signallable
	sys.alivePIDs[livePID] = true        // kill -0 -> nil
	// deadPID is in neither map: kill -0 -> ESRCH.

	m := newTestManager(t, sys, 501) // unprivileged shell, the reported posture
	for _, inst := range []Instance{
		{Version: registryVersion, Name: "rootowned", PID: rootOwnedPID, Tier: "root", Datapath: DatapathDirect},
		{Version: registryVersion, Name: "mine", PID: livePID, Tier: "rootless", Datapath: DatapathNone},
		{Version: registryVersion, Name: "crashed", PID: deadPID, Tier: "rootless", Datapath: DatapathNone},
		{Version: registryVersion, Name: "nopid", PID: 0, Tier: "rootless", Datapath: DatapathNone},
	} {
		if err := m.reg.Save(inst); err != nil {
			t.Fatalf("save %s: %v", inst.Name, err)
		}
	}

	statuses, err := m.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	got := map[string]InstanceStatus{}
	for _, s := range statuses {
		got[s.Name] = s
	}
	for _, tc := range []struct {
		name     string
		want     Liveness
		wantWord string
		// exists is the predicate every teardown/reclaim path signals on: an
		// unprobeable instance must NOT be reapable, or the fix would only have
		// moved the hazard from the report to the reclaim.
		wantExists bool
	}{
		{"rootowned", LivenessUnknown, "unknown", true},
		{"mine", LivenessRunning, "running", true},
		{"crashed", LivenessDead, "stale", false},
		{"nopid", LivenessDead, "stale", false},
	} {
		s, ok := got[tc.name]
		if !ok {
			t.Fatalf("List omitted instance %q", tc.name)
		}
		if s.Liveness != tc.want {
			t.Errorf("%s: Liveness = %v (%s), want %v (%s)", tc.name, s.Liveness, s.Liveness, tc.want, tc.want)
		}
		if s.Liveness.String() != tc.wantWord {
			t.Errorf("%s: STATUS word = %q, want %q", tc.name, s.Liveness.String(), tc.wantWord)
		}
		if s.Liveness.Exists() != tc.wantExists {
			t.Errorf("%s: Exists() = %v, want %v", tc.name, s.Liveness.Exists(), tc.wantExists)
		}
	}
	// The load-bearing assertion, named separately so the failure line says what
	// the operator would have been told: never `stale` for a process that is there.
	if w := got["rootowned"].Liveness.String(); w == "stale" {
		t.Errorf("a root-owned instance whose pid EXISTS (kill EPERM) is reported %q — the word that invites a cleanup of a live cluster", w)
	}
	if got["rootowned"].Alive() {
		t.Errorf("an unprobeable instance must not claim Alive() either — its state beyond existence is genuinely unknown")
	}

	// The faked seam above proves List's plumbing. This subtest proves the
	// PRODUCTION classifier, because a fix that only taught the fake to say
	// LivenessUnknown would leave the real kill(2) errno folded exactly as before.
	// pid 1 is launchd: root-owned, always present, and kill -0 on it from an
	// unprivileged process is the very EPERM the M8 run hit. Signal 0 changes
	// nothing on the host — no privilege is taken, no process is touched.
	t.Run("realSystem classifies a live root-owned pid", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("running as root: kill(1, 0) succeeds, so EPERM cannot be observed here")
		}
		if got := NewSystem().ProcessLiveness(1); got != LivenessUnknown {
			t.Errorf("ProcessLiveness(1) = %v, want unknown — launchd exists and is root-owned, so an unprivileged kill -0 is EPERM, not ESRCH", got)
		}
		if got := NewSystem().ProcessLiveness(0); got != LivenessDead {
			t.Errorf("ProcessLiveness(0) = %v, want dead — a zero pid is no recorded process", got)
		}
	})
}

// TestUnprobeableInstanceIsNotReaped pins the reclaim half of B211: teardown
// signals an instance it cannot probe rather than skipping it as already-dead.
// Skipping would leave a live server running while its registry entry, kubeconfig
// context and lo0 aliases were removed — a worse outcome than the misreport that
// started this, and the reason Liveness.Exists (not == Running) is the predicate.
func TestUnprobeableInstanceIsNotReaped(t *testing.T) {
	const pid = 4242
	sys := newFakeSystem()
	sys.unprobeable[pid] = true
	m := newTestManager(t, sys, 501)
	if err := m.reg.Save(Instance{Version: registryVersion, Name: "rootowned", PID: pid, Tier: "root", Datapath: DatapathDirect}); err != nil {
		t.Fatalf("save: %v", err)
	}
	if err := m.teardown(Instance{Name: "rootowned", PID: pid, Tier: "root", Datapath: DatapathDirect}); err != nil {
		t.Fatalf("teardown: %v", err)
	}
	if !slices.Contains(sys.terminated, pid) {
		t.Errorf("teardown terminated %v, want it to signal the unprobeable pid %d — an EPERM probe is not permission to walk away from a live server", sys.terminated, pid)
	}
}

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

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"golang.org/x/sys/unix"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"

	"k3sm.io/k3sm/pkg/install"
	"k3sm.io/k3sm/pkg/keystore"
	"k3sm.io/k3sm/pkg/keystore/socket"
	"k3sm.io/k3sm/pkg/provider/podlogs"
	"k3sm.io/runtimed/pkg/sandbox"
)

// stillClock is a socket.Clock whose waits never end on their own: a test
// ends them by cancelling the supervisor.
type stillClock struct{ now time.Time }

func (c stillClock) Now() time.Time { return c.now }

func (stillClock) After(time.Duration) (<-chan time.Time, func() bool) {
	return make(chan time.Time), func() bool { return true }
}

type fakePeerCreds struct{}

func (fakePeerCreds) PeerCred(net.Conn) (socket.PeerCred, error) {
	return socket.PeerCred{}, errors.New("fake")
}

type fakePeerSandbox struct{}

func (fakePeerSandbox) Sandboxed(socket.AuditToken) (bool, error) { return true, nil }

// node returns a Node with the given labels.
func node(name string, labels map[string]string) *corev1.Node {
	return &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: name, Labels: labels}}
}

// serverNode is a Node carrying the control-plane label.
func serverNode(name string) *corev1.Node {
	return node(name, map[string]string{controlPlaneNodeLabel: controlPlaneNodeLabelValue})
}

// TestKeystoreServerCount is the single-server count's table: only nodes
// carrying the control-plane label count, whatever its value, and a failed
// List is an error.
func TestKeystoreServerCount(t *testing.T) {
	for _, tt := range []struct {
		name    string
		objs    []runtime.Object
		listErr error
		want    int
	}{
		{"no server", []runtime.Object{node("w1", nil)}, nil, 0},
		{"one server", []runtime.Object{serverNode("s1"), node("w1", map[string]string{"role": "agent"})}, nil, 1},
		{"two servers", []runtime.Object{serverNode("s1"), node("s2", map[string]string{controlPlaneNodeLabel: ""}), node("w1", nil)}, nil, 2},
		{"list error", []runtime.Object{serverNode("s1")}, errors.New("apiserver unavailable"), 0},
	} {
		t.Run(tt.name, func(t *testing.T) {
			cs := fake.NewClientset(tt.objs...)
			var selector string
			cs.PrependReactor("list", "nodes", func(a k8stesting.Action) (bool, runtime.Object, error) {
				selector = a.(k8stesting.ListAction).GetListRestrictions().Labels.String()
				if tt.listErr != nil {
					return true, nil, tt.listErr
				}
				return false, nil, nil
			})
			n, err := countKeystoreServers(context.Background(), cs)
			if tt.listErr != nil {
				if err == nil || !errors.Is(err, tt.listErr) {
					t.Fatalf("count = %d, %v; want the List's error", n, err)
				}
				return
			}
			if err != nil || n != tt.want {
				t.Fatalf("count = %d, %v; want %d", n, err, tt.want)
			}
			if selector != controlPlaneNodeLabel {
				t.Errorf("the List's selector is %q, want %q", selector, controlPlaneNodeLabel)
			}
		})
	}
	if _, err := countKeystoreServers(context.Background(), nil); err == nil {
		t.Error("a nil client counted servers")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	cs := fake.NewClientset(serverNode("s1"))
	cs.PrependReactor("list", "nodes", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, ctx.Err()
	})
	if _, err := countKeystoreServers(ctx, cs); err == nil {
		t.Error("a count under a done context succeeded")
	}
}

// wiringFixture is a server work dir under a temp data root and a full set
// of fake dependencies.
type wiringFixture struct {
	dataRoot string
	deps     keystoreSocketDeps
	opened   *os.File
	sawDir   *os.File
	logger   *slog.Logger
	lnErr    error
	clock    stillClock
}

func newWiringFixture(t *testing.T) *wiringFixture {
	t.Helper()
	f := &wiringFixture{
		dataRoot: t.TempDir(),
		logger:   slog.New(slog.NewTextHandler(io.Discard, nil)),
		lnErr:    errors.New("the fake source has no socket"),
		clock:    stillClock{now: time.Unix(1_800_000_000, 0)},
	}
	f.deps = keystoreSocketDeps{
		workDir: filepath.Join(f.dataRoot, "server"),
		// The production layout, with the data root's owner this test's
		// user rather than root, so the store trusts the temp data root.
		layout: func(work string) keystore.Config {
			c := keystoreLayout(work)
			c.FloorUID, c.FloorGID = os.Getuid(), os.Getgid()
			return c
		},
		client:   fake.NewClientset(serverNode("s1"), serverNode("s2")),
		listen:   func(context.Context) (net.Listener, error) { return nil, f.lnErr },
		nodeRole: func() (install.Role, bool) { return install.RoleServer, true },
		euid:     func() int { return 277 },
		serviceIDs: func() (uint32, uint32, error) {
			return 277, 20, nil
		},
		openDataRoot: func(path string) (*os.File, error) {
			if path != f.dataRoot {
				t.Errorf("the data root opened is %q, want %q", path, f.dataRoot)
			}
			d, err := os.Open(path)
			f.opened = d
			return d, err
		},
		ignoresOwnership: func(dir *os.File) (bool, error) {
			f.sawDir = dir
			return true, nil
		},
		creds:        fakePeerCreds{},
		sandbox:      fakePeerSandbox{},
		sandboxCheck: func() error { return errFakeSandboxCheck },
		// The runtime's generator over a posture whose pod root and data
		// root are the temp data root, as on a default node.
		podProfile: func() (string, error) {
			return keystorePodProfile(sandbox.Posture{
				WorkDir:    f.dataRoot,
				DataRoot:   f.dataRoot,
				StateDir:   filepath.Join(f.dataRoot, "server"),
				PodLogsDir: podlogs.DefaultPodLogsDir,
			})
		},
		clock: f.clock,
		log:   f.logger,
	}
	return f
}

// TestKeystoreSocketWiring checks each dependency reaches the supervisor's
// config, that an installed agent builds and starts nothing, and that the
// stop waits for the supervisor's Run before closing what it holds.
func TestKeystoreSocketWiring(t *testing.T) {
	t.Run("each dependency reaches the supervisor", func(t *testing.T) {
		f := newWiringFixture(t)
		cfg, closeAll, err := keystoreSocketConfig(f.deps)
		if err != nil {
			t.Fatal(err)
		}
		defer closeAll()
		ctx := context.Background()
		if _, err := cfg.Listen(ctx); !errors.Is(err, f.lnErr) {
			t.Errorf("Listen is not the given source: %v", err)
		}
		if got := cfg.EUID(); got != 277 {
			t.Errorf("EUID = %d, want the euid source's 277", got)
		}
		if cfg.ServiceUID != 277 {
			t.Errorf("ServiceUID = %d, want the service lookup's 277", cfg.ServiceUID)
		}
		if ignores, err := cfg.IgnoresOwnership(); !ignores || err != nil {
			t.Errorf("IgnoresOwnership = %v, %v; want the fake's true", ignores, err)
		}
		if f.sawDir == nil || f.sawDir != f.opened {
			t.Errorf("the mount-flag check got %v, want the data-root descriptor %v", f.sawDir, f.opened)
		}
		if n, err := cfg.ServerCount(ctx); n != 2 || err != nil {
			t.Errorf("ServerCount = %d, %v; want the admin client's 2", n, err)
		}
		// The store's install check: a temp data root has no socket directory.
		if err := cfg.CheckInstall(ctx); err == nil || !strings.Contains(err.Error(), "keystore-sock") {
			t.Errorf("CheckInstall = %v, want the store's refusal naming the socket directory", err)
		}
		// The store's marker, read only.
		marker := filepath.Join(f.dataRoot, keystore.MaintenanceMarkerName)
		if err := os.WriteFile(marker, nil, 0o644); err != nil {
			t.Fatal(err)
		}
		if marked, err := cfg.MaintenanceMarked(); !marked || err != nil {
			t.Errorf("MaintenanceMarked = %v, %v with the marker in the data root; want true", marked, err)
		}
		if err := os.Remove(marker); err != nil {
			t.Fatal(err)
		}
		if marked, err := cfg.MaintenanceMarked(); marked || err != nil {
			t.Errorf("MaintenanceMarked = %v, %v with the marker gone; want false: the read reopens nothing", marked, err)
		}
		// The log reopen is its own step: a temp data root has no logs, so
		// it fails closed.
		if err := cfg.OpenLogs(ctx); err == nil {
			t.Error("OpenLogs succeeded with no logs to reopen; want the reopen's error")
		}
		if err := cfg.SandboxCheck(); !errors.Is(err, errFakeSandboxCheck) {
			t.Errorf("SandboxCheck = %v, want the given self-check's error", err)
		}
		if _, ok := cfg.Creds.(fakePeerCreds); !ok {
			t.Errorf("Creds = %T, want the given source", cfg.Creds)
		}
		if _, ok := cfg.Sandbox.(fakePeerSandbox); !ok {
			t.Errorf("Sandbox = %T, want the given source", cfg.Sandbox)
		}
		if _, ok := cfg.Audit.(*socket.StoreAuditor); !ok {
			t.Errorf("Audit = %T, want the store auditor", cfg.Audit)
		}
		if cfg.Handler == nil {
			t.Error("no handler")
		}
		if cfg.Clock != socket.Clock(f.clock) || cfg.Log != f.logger {
			t.Error("the clock or the logger is not the given one")
		}
		if _, err := socket.NewSupervisor(cfg); err != nil {
			t.Errorf("the supervisor refused the config: %v", err)
		}
	})

	t.Run("the handler serves the store's operations", func(t *testing.T) {
		f, peer := newInstalledWiringFixture(t)
		cfg, closeAll, err := keystoreSocketConfig(f.deps)
		if err != nil {
			t.Fatal(err)
		}
		defer closeAll()
		ctx := t.Context()
		// Before the start step every operation is the user scope off.
		c := dialHandler(t, cfg.Handler, peer)
		entry := "user/" + strconv.FormatUint(uint64(peer), 10) + "/token"
		if code := c.errCode(t, c.call(t, map[string]any{"op": socket.OpList}, nil)); code != socket.CodeUserScopeOff {
			t.Fatalf("list before the start step: code %q, want user-scope-off", code)
		}
		if cfg.StartScopes == nil {
			t.Fatal("the config runs no start step")
		}
		if err := cfg.StartScopes(ctx); err != nil {
			t.Fatalf("the start step: %v", err)
		}
		var v socket.VersionReply
		c.reply(t, c.call(t, map[string]any{"op": socket.OpPut, "entry": entry}, []byte("s3cret")), &v)
		if v.Version != 1 {
			t.Fatalf("put: version %d, want 1", v.Version)
		}
		var l socket.ListReply
		c.reply(t, c.call(t, map[string]any{"op": socket.OpList}, nil), &l)
		if len(l.Entries) != 1 || l.Entries[0].Name != entry || l.Entries[0].Version != 1 || l.Entries[0].Status != "ok" {
			t.Fatalf("list after the put: %+v, want the one entry at version 1", l.Entries)
		}
	})

	t.Run("the store waits the socket's lock bound, then answers busy", func(t *testing.T) {
		f, peer := newInstalledWiringFixture(t)
		cfg, closeAll, err := keystoreSocketConfig(f.deps)
		if err != nil {
			t.Fatal(err)
		}
		defer closeAll()
		if err := cfg.StartScopes(t.Context()); err != nil {
			t.Fatalf("the start step: %v", err)
		}
		// Another holder takes the store lock exclusively, as a root verb
		// would, and keeps it for the whole request.
		storeCfg := f.deps.layout(f.deps.workDir)
		held, err := os.Open(filepath.Join(storeCfg.Dir, ".lock"))
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = held.Close() }()
		if err := unix.Flock(int(held.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
			t.Fatal(err)
		}
		synctest.Test(t, func(t *testing.T) {
			c := dialHandler(t, cfg.Handler, peer)
			start := time.Now()
			code := c.errCode(t, c.call(t, map[string]any{"op": socket.OpList}, nil))
			waited := time.Since(start)
			if code != socket.CodeBusy {
				t.Fatalf("list with the store lock held: code %q, want busy", code)
			}
			// The store's own wait is the socket's bound, not the store's
			// default: it gives up once socket.LockWait has passed on the
			// bubble's clock, and not before.
			if waited < socket.LockWait || waited > socket.LockWait+time.Second {
				t.Fatalf("busy after %v, want just past the socket's bound of %v", waited, socket.LockWait)
			}
		})
	})

	t.Run("a start step that fails keeps the listener off with the store's reason", func(t *testing.T) {
		f, _ := newInstalledWiringFixture(t)
		cfg, closeAll, err := keystoreSocketConfig(f.deps)
		if err != nil {
			t.Fatal(err)
		}
		defer closeAll()
		audit := filepath.Join(f.dataRoot, keystore.LogsDirName, keystore.AuditDirName, keystore.AuditLogName)
		if err := os.Remove(audit); err != nil {
			t.Fatal(err)
		}
		reason, detail := socket.Preconditions{
			EUID: func() int { return 277 }, ServiceUID: 277,
			IgnoresOwnership:  func() (bool, error) { return false, nil },
			CheckInstall:      func(context.Context) error { return nil },
			MaintenanceMarked: func() (bool, error) { return false, nil },
			OpenLogs:          func(context.Context) error { return nil },
			SandboxCheck:      func() error { return nil },
			ServerCount:       func(context.Context) (int, error) { return 1, nil },
			StartScopes:       cfg.StartScopes,
		}.Check(context.Background())
		if reason != socket.OffUserScopeStart || !strings.Contains(detail, keystore.AuditLogName) {
			t.Fatalf("Check = %q %q, want the start step's reason naming the audit log", reason, detail)
		}
	})

	t.Run("the built supervisor runs the checks", func(t *testing.T) {
		f := newWiringFixture(t)
		f.deps.euid = func() int { return 501 } // a rootless server
		synctest.Test(t, func(t *testing.T) {
			ks, err := newKeystoreSocket(f.deps)
			if err != nil {
				t.Fatal(err)
			}
			stop := runKeystoreSocket(context.Background(), ks)
			synctest.Wait()
			st := ks.sup.State()
			stop()
			if st.Phase != socket.PhaseOff || st.Reason != socket.OffNotInstalledServer || !strings.Contains(st.Detail, "277") {
				t.Fatalf("state = %+v, want off for the service uid 277", st)
			}
		})
	})

	t.Run("a failed build is retried with backoff", func(t *testing.T) {
		f := newWiringFixture(t)
		f.deps.euid = func() int { return 501 } // a rootless server, so the built supervisor stays off
		var lookups atomic.Int32
		f.deps.serviceIDs = func() (uint32, uint32, error) {
			if lookups.Add(1) <= 2 {
				return 0, 0, errors.New("fake: no _k3sm user yet")
			}
			return 277, 20, nil
		}
		logs := &bytes.Buffer{}
		log := slog.New(slog.NewTextHandler(logs, nil))
		f.deps.log = log
		synctest.Test(t, func(t *testing.T) {
			var built atomic.Pointer[keystoreSocket]
			build := func() (*keystoreSocket, error) {
				ks, err := newKeystoreSocket(f.deps)
				if ks != nil {
					built.Store(ks)
				}
				return ks, err
			}
			stop := superviseKeystoreSocket(context.Background(), build, wallClock{}, log)
			defer stop()
			synctest.Wait()
			if n := lookups.Load(); n != 1 || built.Load() != nil {
				t.Fatalf("at start: %d lookups, built %v; want 1 and nothing", n, built.Load())
			}
			<-time.NewTimer(socket.MinBackoff).C
			synctest.Wait()
			if n := lookups.Load(); n != 2 || built.Load() != nil {
				t.Fatalf("after %v: %d lookups; want 2", socket.MinBackoff, n)
			}
			<-time.NewTimer(2 * socket.MinBackoff).C
			synctest.Wait()
			ks := built.Load()
			if ks == nil {
				t.Fatal("the third build did not run the supervisor")
			}
			if st := ks.sup.State(); st.Phase != socket.PhaseOff || st.Reason != socket.OffNotInstalledServer {
				t.Fatalf("state = %+v, want the built supervisor running its checks", st)
			}
			if got := strings.Count(logs.String(), "the socket listener was not built"); got != 2 {
				t.Fatalf("%d build-failure lines, want 2", got)
			}
		})
	})

	t.Run("an agent node starts nothing", func(t *testing.T) {
		deps := keystoreSocketDeps{nodeRole: func() (install.Role, bool) { return install.RoleAgent, true }}
		// Every other dependency is nil, so reaching one panics.
		ks, err := newKeystoreSocket(deps)
		if ks != nil || err != nil {
			t.Fatalf("an agent built %v, %v; want nothing", ks, err)
		}
		runKeystoreSocket(context.Background(), ks)() // stops at once
	})

	t.Run("shutdown waits for Run, bounded", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			entered := make(chan struct{})
			release := make(chan struct{})
			sup, err := socket.NewSupervisor(socket.SupervisorConfig{
				Listen:            func(context.Context) (net.Listener, error) { return nil, errors.New("none") },
				EUID:              func() int { return 277 },
				ServiceUID:        277,
				IgnoresOwnership:  func() (bool, error) { return false, nil },
				CheckInstall:      func(context.Context) error { return nil },
				MaintenanceMarked: func() (bool, error) { return false, nil },
				OpenLogs:          func(context.Context) error { return nil },
				SandboxCheck:      func() error { return nil },
				ServerCount: func(ctx context.Context) (int, error) {
					close(entered)
					<-ctx.Done()
					<-release // Run is still inside its start check
					return 0, ctx.Err()
				},
				Creds:   fakePeerCreds{},
				Sandbox: fakePeerSandbox{},
				Audit:   discardAuditor{},
				Handler: mustHandler(t),
				Clock:   stillClock{},
				Log:     slog.New(slog.NewTextHandler(io.Discard, nil)),
			})
			if err != nil {
				t.Fatal(err)
			}
			var closed atomic.Bool
			logs := &bytes.Buffer{}
			stop := runKeystoreSocket(context.Background(), &keystoreSocket{
				sup: sup, close: func() { closed.Store(true) },
				log: slog.New(slog.NewTextHandler(logs, nil)),
			})
			<-entered
			var stopped atomic.Bool
			go func() {
				stop()
				stopped.Store(true)
			}()
			synctest.Wait()
			if stopped.Load() || closed.Load() {
				t.Fatal("stop returned, or closed the descriptors, while Run was still running")
			}
			// Run outlives the bound: stop logs and returns, and the
			// descriptors stay open while Run still runs.
			<-time.NewTimer(keystoreSocketStopTimeout).C // the bubble's clock, not the wall's
			synctest.Wait()
			if !stopped.Load() || closed.Load() {
				t.Fatalf("after the stop bound: stopped %v, closed %v; want stopped and still open", stopped.Load(), closed.Load())
			}
			if !strings.Contains(logs.String(), "did not stop in time") {
				t.Fatalf("no line for the expired stop: %q", logs.String())
			}
			close(release)
			synctest.Wait()
			if !closed.Load() {
				t.Fatal("the descriptors were not closed once Run returned")
			}
			if st := sup.State(); st.Phase != socket.PhaseStopped {
				t.Fatalf("state after stop = %+v, want stopped", st)
			}
		})
	})
}

// panicOnceClock is a socket.Clock whose first Now panics; its waits never
// end on their own.
type panicOnceClock struct{ calls *atomic.Int32 }

func (c panicOnceClock) Now() time.Time {
	if c.calls.Add(1) == 1 {
		panic("fake: the supervisor's clock panicked")
	}
	return time.Time{}
}

func (panicOnceClock) After(time.Duration) (<-chan time.Time, func() bool) {
	return make(chan time.Time), func() bool { return true }
}

// TestKeystoreSocketRecoversSupervisorPanic: a panic out of the
// supervisor's Run (here its clock, which Run does not guard) is recovered
// in the supervising goroutine, logged, and after socket.MinBackoff on the
// supervising clock the same supervisor runs again; the descriptors are
// closed only once Run returns at the stop.
func TestKeystoreSocketRecoversSupervisorPanic(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var nows atomic.Int32
		sup, err := socket.NewSupervisor(socket.SupervisorConfig{
			Listen:            func(context.Context) (net.Listener, error) { return nil, errors.New("none") },
			EUID:              func() int { return 501 }, // off at once: the state's Until reads the clock
			ServiceUID:        277,
			IgnoresOwnership:  func() (bool, error) { return false, nil },
			CheckInstall:      func(context.Context) error { return nil },
			MaintenanceMarked: func() (bool, error) { return false, nil },
			OpenLogs:          func(context.Context) error { return nil },
			SandboxCheck:      func() error { return nil },
			ServerCount:       func(context.Context) (int, error) { return 1, nil },
			Creds:             fakePeerCreds{},
			Sandbox:           fakePeerSandbox{},
			Audit:             discardAuditor{},
			Handler:           mustHandler(t),
			Clock:             panicOnceClock{&nows},
			Log:               slog.New(slog.NewTextHandler(io.Discard, nil)),
		})
		if err != nil {
			t.Fatal(err)
		}
		var closed atomic.Bool
		logs := &bytes.Buffer{}
		log := slog.New(slog.NewTextHandler(logs, nil))
		stop := superviseKeystoreSocket(context.Background(), func() (*keystoreSocket, error) {
			return &keystoreSocket{sup: sup, close: func() { closed.Store(true) }, log: log}, nil
		}, wallClock{}, log)
		synctest.Wait()
		if !strings.Contains(logs.String(), "recovered a panic out of the supervisor") || !strings.Contains(logs.String(), "the supervisor's clock panicked") {
			t.Fatalf("no line for the recovered panic: %q", logs.String())
		}
		if n := nows.Load(); n != 1 {
			t.Fatalf("%d clock reads before the backoff, want 1 (Run must wait %v before running again)", n, socket.MinBackoff)
		}
		<-time.NewTimer(socket.MinBackoff).C // the bubble's clock
		synctest.Wait()
		if st := sup.State(); st.Phase != socket.PhaseOff || st.Reason != socket.OffNotInstalledServer {
			t.Fatalf("after the backoff: state %+v, want the supervisor running again and off", st)
		}
		if closed.Load() {
			t.Fatal("the descriptors were closed after a recovered panic; the same supervisor must run again")
		}
		stop()
		if !closed.Load() {
			t.Fatal("the descriptors were not closed once Run returned at the stop")
		}
	})
}

// errFakeSandboxCheck is the wiring fixture's sandbox self-check result.
var errFakeSandboxCheck = errors.New("fake: sandbox self-check")

type discardAuditor struct{}

func (discardAuditor) Refused(uint32, string) {}
func (discardAuditor) Dropped(uint32, uint64) {}

func mustHandler(t *testing.T) *socket.Handler {
	t.Helper()
	h, err := socket.NewHandler(time.Now)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

// TestDoctorKeystoreSocketLstat holds the doctor row's socket fact to an
// lstat: launchd's socket, root's at 0666, passes; nothing there, a file, a
// symlink, a socket of the service user's (the self-bind form, which does
// not ship) or one at another mode is no listening socket. The socket
// cases are judged from the mode and owner an lstat returns, so no socket
// is bound.
func TestDoctorKeystoreSocketLstat(t *testing.T) {
	const svc = 260
	if err := judgeKeystoreSocket(unix.S_IFSOCK|0o666, 0, 1, launchdSocketOwner); err != nil {
		t.Fatalf("launchd's socket: %v", err)
	}
	if err := judgeKeystoreSocket(unix.S_IFSOCK|0o666, svc, 1, launchdSocketOwner); !errors.Is(err, errNoListeningSocket) || !strings.Contains(err.Error(), "owned by uid 260, not root's") {
		t.Fatalf("the service user's socket: %v", err)
	}
	if err := judgeKeystoreSocket(unix.S_IFSOCK|0o600, 0, 1, launchdSocketOwner); !errors.Is(err, errNoListeningSocket) || !strings.Contains(err.Error(), "mode 0600, not 0666") {
		t.Fatalf("a root socket at 0600: %v", err)
	}
	if err := judgeKeystoreSocket(unix.S_IFSOCK|0o666, 0, 0, launchdSocketOwner); !errors.Is(err, errNoListeningSocket) || !strings.Contains(err.Error(), "group is 0, not daemon's 1") {
		t.Fatalf("a root:wheel socket: %v", err)
	}
	if err := judgeKeystoreSockDir(unix.S_IFDIR|0o755, 0, 0); err != nil {
		t.Fatalf("a root:wheel 0755 directory: %v", err)
	}
	for _, d := range []struct{ mode, owner, group uint32 }{{unix.S_IFDIR | 0o775, 0, 0}, {unix.S_IFDIR | 0o755, svc, 0}, {unix.S_IFDIR | 0o755, 0, 20}, {unix.S_IFREG | 0o755, 0, 0}} {
		if err := judgeKeystoreSockDir(d.mode, d.owner, d.group); !errors.Is(err, errNoListeningSocket) {
			t.Errorf("directory %#o %d:%d: %v, want no listening socket", d.mode, d.owner, d.group, err)
		}
	}
	dir := t.TempDir()
	file := filepath.Join(dir, "file")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(file, link); err != nil {
		t.Fatal(err)
	}
	me := uint32(os.Getuid())
	for _, p := range []string{filepath.Join(dir, "absent"), file, link, dir} {
		if err := lstatKeystoreSocket(p, me); !errors.Is(err, errNoListeningSocket) {
			t.Errorf("%s: %v, want no listening socket", filepath.Base(p), err)
		}
	}
}

// TestKeystoreServerCountNames checks the doctor's list names the servers,
// sorted, and only them.
func TestKeystoreServerCountNames(t *testing.T) {
	cs := fake.NewClientset(serverNode("s2"), serverNode("s1"), node("w1", nil))
	names, err := listKeystoreServers(context.Background(), cs)
	if err != nil || !slices.Equal(names, []string{"s1", "s2"}) {
		t.Fatalf("names = %v, %v; want [s1 s2]", names, err)
	}
}

// TestDoctorKeystoreKubeconfigPermission checks a kubeconfig this user may
// not read is an error wrapping fs.ErrPermission.
func TestDoctorKeystoreKubeconfigPermission(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads a 0000 file")
	}
	p := filepath.Join(t.TempDir(), "admin.kubeconfig")
	if err := os.WriteFile(p, nil, 0o000); err != nil {
		t.Fatal(err)
	}
	if _, err := readAdminKubeconfig(p); !errors.Is(err, fs.ErrPermission) {
		t.Fatalf("readAdminKubeconfig = %v, want a permission error", err)
	}
}

// TestKeystoreSocketDataRootPerPass checks that each start-check pass opens
// the data root afresh and closes it when the pass ends, and that what the
// install check and the log reopen judged is refused when it is not on the
// pass's data root's device: /dev is a mount of its own under /, so a pass
// rooted at / refuses it as a volume mounted over a judged directory would
// be refused.
func TestKeystoreSocketDataRootPerPass(t *testing.T) {
	t.Run("opened afresh, closed at the end of each pass", func(t *testing.T) {
		f := newWiringFixture(t)
		var opened []*os.File
		f.deps.openDataRoot = func(path string) (*os.File, error) {
			d, err := openKeystoreDataRoot(path)
			if err == nil {
				opened = append(opened, d)
			}
			return d, err
		}
		cfg, closeAll, err := keystoreSocketConfig(f.deps)
		if err != nil {
			t.Fatal(err)
		}
		defer closeAll()
		if len(opened) != 0 {
			t.Fatal("the data root was opened at build time")
		}
		for i := range 2 {
			if _, err := cfg.IgnoresOwnership(); err != nil {
				t.Fatal(err)
			}
			if len(opened) != i+1 {
				t.Fatalf("pass %d: %d data-root opens, want one per pass", i, len(opened))
			}
			cfg.EndPass()
			if opened[i].Fd() != ^uintptr(0) {
				t.Fatalf("pass %d: the data-root descriptor is still open after the pass", i)
			}
		}
		// The supervisor's Check ends its pass, whatever the outcome.
		p := socket.Preconditions{
			EUID: cfg.EUID, ServiceUID: cfg.ServiceUID, IgnoresOwnership: cfg.IgnoresOwnership,
			EndPass: cfg.EndPass, CheckInstall: cfg.CheckInstall, MaintenanceMarked: cfg.MaintenanceMarked,
			OpenLogs: cfg.OpenLogs, SandboxCheck: cfg.SandboxCheck, ServerCount: cfg.ServerCount,
		}
		if reason, _ := p.Check(context.Background()); reason == "" {
			t.Fatal("the checks passed on a temp data root with nothing installed")
		}
		if last := opened[len(opened)-1]; len(opened) != 3 || last.Fd() != ^uintptr(0) {
			t.Fatalf("after Check: %d opens, the last still open = %v", len(opened), last.Fd() != ^uintptr(0))
		}
	})

	t.Run("an object on another device is refused", func(t *testing.T) {
		root := t.TempDir()
		for _, d := range socketInstallDirs {
			if err := os.MkdirAll(filepath.Join(append([]string{root}, d...)...), 0o755); err != nil {
				t.Fatal(err)
			}
		}
		pass := &dataRootPass{path: root, open: openKeystoreDataRoot, ignores: func(*os.File) (bool, error) { return false, nil }}
		defer pass.end()
		if err := pass.sameDevice(socketInstallDirs...); err == nil {
			t.Fatal("sameDevice passed with no pass open")
		}
		if _, err := pass.ignoresOwnership(); err != nil {
			t.Fatal(err)
		}
		if err := pass.sameDevice(socketInstallDirs...); err != nil {
			t.Fatalf("sameDevice on one volume = %v", err)
		}
		_, dev, _ := pass.root()
		if err := pass.sameDeviceFiles(keystore.LogFileID{Dev: dev}, keystore.LogFileID{Dev: dev}); err != nil {
			t.Fatalf("sameDeviceFiles on one volume = %v", err)
		}
		if err := pass.sameDeviceFiles(keystore.LogFileID{Dev: dev}, keystore.LogFileID{Dev: dev + 1}); !errors.Is(err, errDataRootMoved) {
			t.Fatalf("sameDeviceFiles with a log on another device = %v, want errDataRootMoved", err)
		}
		if err := checkInstallOn(pass, func(context.Context) error { return nil })(context.Background()); err != nil {
			t.Fatalf("checkInstallOn on one volume = %v", err)
		}
		// A real mount point: /dev under /.
		slash := &dataRootPass{path: "/", open: openKeystoreDataRoot, ignores: func(*os.File) (bool, error) { return false, nil }}
		defer slash.end()
		if _, err := slash.ignoresOwnership(); err != nil {
			t.Fatal(err)
		}
		var st unix.Stat_t
		if err := unix.Stat("/dev", &st); err != nil {
			t.Skipf("no /dev to stand in for a mount point: %v", err)
		}
		if _, rdev, _ := slash.root(); uint64(st.Dev) == rdev {
			t.Skip("/dev is on the root volume here; no mount point to test with")
		}
		if err := slash.sameDevice([]string{"dev"}); !errors.Is(err, errDataRootMoved) {
			t.Fatalf("sameDevice across the /dev mount = %v, want errDataRootMoved", err)
		}
	})
}

// TestDoctorKeystoreReopenJudgement: doctor's log step judges what the
// server's reopen judges. An audit log past the reader's bound is refused
// by the supervisor's reopen and by doctor's read-only check with the same
// off reason and detail, and doctor's check takes no lock and writes
// nothing.
func TestDoctorKeystoreReopenJudgement(t *testing.T) {
	f := newWiringFixture(t)
	me := uint32(os.Getuid())
	f.deps.serviceIDs = func() (uint32, uint32, error) { return me, uint32(os.Getgid()), nil }
	f.deps.ignoresOwnership = func(*os.File) (bool, error) { return false, nil }
	layout := f.deps.layout
	f.deps.layout = func(work string) keystore.Config {
		c := layout(work)
		c.LogFlags = func(*os.File) (uint32, error) { return unix.SF_APPEND, nil }
		return c
	}
	storeCfg := f.deps.layout(f.deps.workDir)
	storeCfg.UID, storeCfg.GID = me, uint32(os.Getgid())
	for _, d := range []struct {
		p    string
		mode os.FileMode
	}{
		{f.deps.workDir, 0o700},
		{storeCfg.Dir, 0o700},
		{filepath.Join(f.dataRoot, "keystore-logs"), 0o755},
		{filepath.Join(f.dataRoot, "keystore-logs", "floor"), 0o755},
		{filepath.Join(f.dataRoot, "keystore-logs", "audit"), 0o755},
	} {
		if err := os.Mkdir(d.p, d.mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(d.p, d.mode); err != nil {
			t.Fatal(err)
		}
	}
	audit := filepath.Join(f.dataRoot, "keystore-logs", "audit", "keystore-audit.log")
	for _, p := range []string{audit, filepath.Join(f.dataRoot, "keystore-logs", "floor", "keystore-user-floor.log")} {
		if err := os.WriteFile(p, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(p, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// Past any reader bound the store accepts, as a sparse file.
	if err := os.Truncate(audit, 1<<40); err != nil {
		t.Skipf("no sparse 1 TiB file on this volume: %v", err)
	}
	cfg, closeAll, err := keystoreSocketConfig(f.deps)
	if err != nil {
		t.Fatal(err)
	}
	defer closeAll()
	store := keystore.New(storeCfg)
	pass := &dataRootPass{path: storeCfg.DataRoot, open: openKeystoreDataRoot, ignores: func(*os.File) (bool, error) { return false, nil }}
	defer pass.end()
	check := func(openLogs func(context.Context) error, ignores func() (bool, error), end func()) (socket.OffReason, string) {
		return socket.Preconditions{
			EUID: func() int { return 277 }, ServiceUID: 277,
			IgnoresOwnership: ignores, EndPass: end,
			CheckInstall:      func(context.Context) error { return nil },
			MaintenanceMarked: func() (bool, error) { return false, nil },
			OpenLogs:          openLogs,
			SandboxCheck:      func() error { return nil },
			ServerCount:       func(context.Context) (int, error) { return 1, nil },
		}.Check(context.Background())
	}
	supReason, supDetail := check(cfg.OpenLogs, cfg.IgnoresOwnership, cfg.EndPass)
	before, err := os.ReadDir(storeCfg.Dir)
	if err != nil {
		t.Fatal(err)
	}
	docReason, docDetail := check(doctorOpenLogs(store, pass), pass.ignoresOwnership, pass.end)
	if supReason != socket.OffLogsUnavailable || !strings.Contains(supDetail, "keystore-audit.log") {
		t.Fatalf("supervisor: %q %q, want the logs reason naming the audit log", supReason, supDetail)
	}
	if docReason != supReason || docDetail != supDetail {
		t.Fatalf("doctor: %q %q; supervisor: %q %q; want the same", docReason, docDetail, supReason, supDetail)
	}
	after, err := os.ReadDir(storeCfg.Dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(after) != len(before) {
		t.Fatalf("doctor's check changed the store directory: %v, then %v", before, after)
	}
	// Under the bound both pass, and doctor holds no descriptor after.
	if err := os.Truncate(audit, 0); err != nil {
		t.Fatal(err)
	}
	if r, d := check(doctorOpenLogs(store, pass), pass.ignoresOwnership, pass.end); r != socket.OffSandboxCheckUnusable && r != "" {
		t.Fatalf("doctor on an empty audit log: %q %q, want the log step passed", r, d)
	}
}

// newInstalledWiringFixture is newWiringFixture over a keystore installed
// in its temp data root: the test's own user stands in for the service
// user, the logs carry the append flag through a fake flag source, each
// uid has a fake GeneratedUID, and the master is minted as root's verbs
// mint it. It returns a login uid that is not the service user's.
func newInstalledWiringFixture(t *testing.T) (*wiringFixture, uint32) {
	t.Helper()
	return installedWiringFixture(t, true)
}

// installedWiringFixture is newInstalledWiringFixture; with put unset it is
// a fresh install: no store directory under the work dir and no root put,
// so no master either.
func installedWiringFixture(t *testing.T, put bool) (*wiringFixture, uint32) {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Skip("the test user stands in for the service user, which is never root")
	}
	f := newWiringFixture(t)
	me, myGID := uint32(os.Getuid()), uint32(os.Getgid())
	f.deps.serviceIDs = func() (uint32, uint32, error) { return me, myGID, nil }
	f.deps.ignoresOwnership = func(*os.File) (bool, error) { return false, nil }
	layout := f.deps.layout
	f.deps.layout = func(work string) keystore.Config {
		c := layout(work)
		c.LogFlags = func(*os.File) (uint32, error) { return unix.SF_APPEND, nil }
		c.GeneratedUID = func(uid uint32) ([16]byte, error) {
			return [16]byte{0x10, 0x20, byte(uid), byte(uid >> 8), byte(uid >> 16), byte(uid >> 24), 1}, nil
		}
		return c
	}
	storeCfg := f.deps.layout(f.deps.workDir)
	storeCfg.UID, storeCfg.GID = me, myGID
	for _, d := range []struct {
		p    string
		mode os.FileMode
	}{
		{f.deps.workDir, 0o700},
		{filepath.Join(f.dataRoot, "keystore-sock"), 0o755},
		{filepath.Join(f.dataRoot, keystore.LogsDirName), 0o755},
		{filepath.Join(f.dataRoot, keystore.LogsDirName, keystore.FloorDirName), 0o755},
		{filepath.Join(f.dataRoot, keystore.LogsDirName, keystore.AuditDirName), 0o755},
	} {
		if err := os.Mkdir(d.p, d.mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(d.p, d.mode); err != nil {
			t.Fatal(err)
		}
	}
	for _, p := range []string{
		filepath.Join(f.dataRoot, keystore.LogsDirName, keystore.AuditDirName, keystore.AuditLogName),
		filepath.Join(f.dataRoot, keystore.LogsDirName, keystore.FloorDirName, "keystore-user-floor.log"),
	} {
		if err := os.WriteFile(p, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(p, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if put {
		// A root put creates the store directory and mints the master.
		if _, err := keystore.New(storeCfg).Put(t.Context(), "seed", keystore.KindOpaque, []byte("x")); err != nil {
			t.Fatalf("minting the master: %v", err)
		}
	}
	peer := uint32(600)
	if peer == me {
		peer++
	}
	return f, peer
}

// handlerConn is one fake peer's in-memory connection to a handler, after
// HELLO.
type handlerConn struct {
	client net.Conn
}

// dialHandler serves h for a peer of uid over an in-memory pipe and
// completes HELLO.
func dialHandler(t *testing.T, h *socket.Handler, uid uint32) *handlerConn {
	t.Helper()
	client, server := net.Pipe()
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = h.Serve(t.Context(), server, socket.Peer{UID: uid, PID: 4242}) // the test reads the replies
		_ = server.Close()                                                 // as the listener closes it
	}()
	t.Cleanup(func() {
		_ = client.Close() // ends Serve
		<-done
	})
	c := &handlerConn{client: client}
	hello := fmt.Sprintf(`{"proto":%q,"min":1,"max":1}`, socket.Proto)
	if err := socket.WriteFrame(client, socket.Frame{Type: socket.TypeHello, Header: []byte(hello)}); err != nil {
		t.Fatal(err)
	}
	if f, err := socket.ReadFrame(client); err != nil || f.Type != socket.TypeHello {
		t.Fatalf("HELLO: %v, frame type %#02x", err, byte(f.Type))
	}
	return c
}

// call sends one request and returns the answer.
func (c *handlerConn) call(t *testing.T, header map[string]any, value []byte) socket.Frame {
	t.Helper()
	b, err := json.Marshal(header)
	if err != nil {
		t.Fatal(err)
	}
	if err := socket.WriteFrame(c.client, socket.Frame{Type: socket.TypeRequest, Header: b, Value: value}); err != nil {
		t.Fatal(err)
	}
	f, err := socket.ReadFrame(c.client)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

// errCode is f's error code, or "" for a reply.
func (c *handlerConn) errCode(t *testing.T, f socket.Frame) socket.Code {
	t.Helper()
	if f.Type == socket.TypeReply {
		return ""
	}
	var eh struct {
		Code socket.Code `json:"code"`
	}
	if err := json.Unmarshal(f.Header, &eh); err != nil {
		t.Fatalf("error header %s: %v", f.Header, err)
	}
	return eh.Code
}

// reply fails unless f is an ok reply, and decodes its header into out.
func (c *handlerConn) reply(t *testing.T, f socket.Frame, out any) {
	t.Helper()
	if f.Type != socket.TypeReply {
		t.Fatalf("answer %#02x %s, want an ok reply", byte(f.Type), f.Header)
	}
	if err := json.Unmarshal(f.Header, out); err != nil {
		t.Fatalf("reply header %s: %v", f.Header, err)
	}
}

// The start step holds on every pass, not only the first: once a pass has
// started the user scope, a later pass whose log bounds check fails (the
// audit log gone, or the request cancelled before the check) still fails
// the step, so the supervisor keeps the listener off.
func TestStartUserScopesStepRefusesOnLaterPass(t *testing.T) {
	f, _ := newInstalledWiringFixture(t)
	cfg, closeAll, err := keystoreSocketConfig(f.deps)
	if err != nil {
		t.Fatal(err)
	}
	defer closeAll()
	if err := cfg.StartScopes(t.Context()); err != nil {
		t.Fatalf("the first pass: %v", err)
	}
	cancelled, cancel := context.WithCancel(t.Context())
	cancel()
	if err := cfg.StartScopes(cancelled); err == nil {
		t.Fatal("a later pass whose bounds check was cancelled passed; want the step to fail")
	}
	audit := filepath.Join(f.dataRoot, keystore.LogsDirName, keystore.AuditDirName, keystore.AuditLogName)
	if err := os.Remove(audit); err != nil {
		t.Fatal(err)
	}
	if err := cfg.StartScopes(t.Context()); err == nil {
		t.Fatal("a later pass with the audit log gone passed; want the bounds check's failure")
	}
}

// runKeystoreSocket runs the built ks (superviseKeystoreSocket) on the wall
// clock. A nil ks (a worker) runs nothing and stops at once.
func runKeystoreSocket(ctx context.Context, ks *keystoreSocket) (stop func()) {
	if ks == nil {
		return noStop
	}
	return superviseKeystoreSocket(ctx, func() (*keystoreSocket, error) { return ks, nil }, wallClock{}, ks.log)
}

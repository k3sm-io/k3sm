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
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"

	"k3sm.io/k3sm/pkg/install"
	"k3sm.io/k3sm/pkg/keystore"
	"k3sm.io/k3sm/pkg/keystore/socket"
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
		euid:     func() int { return 777 },
		serviceIDs: func() (uint32, uint32, error) {
			return 777, 20, nil
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
		clock:        f.clock,
		log:          f.logger,
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
		if got := cfg.EUID(); got != 777 {
			t.Errorf("EUID = %d, want the euid source's 777", got)
		}
		if cfg.ServiceUID != 777 {
			t.Errorf("ServiceUID = %d, want the service lookup's 777", cfg.ServiceUID)
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
			if st.Phase != socket.PhaseOff || st.Reason != socket.OffNotInstalledServer || !strings.Contains(st.Detail, "777") {
				t.Fatalf("state = %+v, want off for the service uid 777", st)
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

	t.Run("shutdown waits for Run", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			entered := make(chan struct{})
			release := make(chan struct{})
			sup, err := socket.NewSupervisor(socket.SupervisorConfig{
				Listen:            func(context.Context) (net.Listener, error) { return nil, errors.New("none") },
				EUID:              func() int { return 777 },
				ServiceUID:        777,
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
			stop := runKeystoreSocket(context.Background(), &keystoreSocket{sup: sup, close: func() { closed.Store(true) }})
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
			close(release)
			synctest.Wait()
			if !stopped.Load() || !closed.Load() {
				t.Fatal("stop did not return and close once Run had")
			}
			if st := sup.State(); st.Phase != socket.PhaseStopped {
				t.Fatalf("state after stop = %+v, want stopped", st)
			}
		})
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

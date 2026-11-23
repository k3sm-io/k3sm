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
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/unix"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"k3sm.io/k3sm/pkg/executor"
	"k3sm.io/k3sm/pkg/install"
	"k3sm.io/k3sm/pkg/keystore"
	"k3sm.io/k3sm/pkg/keystore/socket"
	"k3sm.io/k3sm/pkg/kubeclient"
)

// keystoreServerCountTimeout bounds one count of the cluster's servers, so a
// List the apiserver never answers cannot hold the supervisor's start check.
const keystoreServerCountTimeout = 10 * time.Second

// countKeystoreServers is the user scope's single-server count
// (docs/design/keystore.md § "Single-server clusters only"): the nodes the
// apiserver lists carrying the controlPlaneNodeLabel key, whatever its
// value, the rule pkg/status uses to call a node a server. It lists afresh
// through the admin client every time, bounded by ctx and
// keystoreServerCountTimeout, and any error, a nil client included, is the
// count's error, which keeps the listener off.
func countKeystoreServers(ctx context.Context, cs kubernetes.Interface) (int, error) {
	if cs == nil {
		return 0, errors.New("no admin client to count the servers with")
	}
	ctx, cancel := context.WithTimeout(ctx, keystoreServerCountTimeout)
	defer cancel()
	list, err := cs.CoreV1().Nodes().List(ctx, metav1.ListOptions{LabelSelector: controlPlaneNodeLabel})
	if err != nil {
		return 0, fmt.Errorf("list the nodes labelled %s: %w", controlPlaneNodeLabel, err)
	}
	n := 0
	for i := range list.Items {
		if _, cp := list.Items[i].Labels[controlPlaneNodeLabel]; cp {
			n++
		}
	}
	return n, nil
}

// openKeystoreDataRoot opens the data root as a directory, refusing a
// symlink at its final component (O_DIRECTORY|O_NOFOLLOW), for the mount-
// flag check's fstatfs.
func openKeystoreDataRoot(path string) (*os.File, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("open the data root %s: %w", path, err)
	}
	return os.NewFile(uintptr(fd), path), nil
}

// keystoreSocketDeps is what the user socket's wiring takes from the server,
// so a test can fake each part.
type keystoreSocketDeps struct {
	// workDir is the server's work dir; layout derives the store and the
	// data root from it (keystoreLayout in production).
	workDir string
	layout  func(work string) keystore.Config
	// client is the admin client the server count lists nodes through.
	client kubernetes.Interface
	// listen supplies the listening socket. How it is obtained is the
	// caller's: this wiring never binds, unlinks or activates one.
	listen socket.ListenerSource
	// nodeRole is the role this Mac is installed as; an installed agent
	// starts nothing.
	nodeRole func() (install.Role, bool)
	// euid is the process's effective uid; serviceIDs resolves the service
	// user.
	euid       func() int
	serviceIDs func() (uid, gid uint32, err error)
	// openDataRoot opens the data root's descriptor, kept for the
	// supervisor's life; ignoresOwnership reads its mount flags.
	openDataRoot     func(path string) (*os.File, error)
	ignoresOwnership func(dir *os.File) (bool, error)
	// creds and sandbox are the listener's peer sources.
	creds   socket.PeerCredSource
	sandbox socket.PeerSandboxSource
	clock   socket.Clock
	log     *slog.Logger
}

// keystoreSocket is a built supervisor and what it holds open: the data-root
// descriptor and the server's log descriptors, closed once Run has returned.
type keystoreSocket struct {
	sup   *socket.Supervisor
	close func()
}

// newKeystoreSocket builds the user socket's supervisor for this server
// without starting it (keystoreSocketConfig). An installed agent gets nil
// and an error-free return: a worker runs no listener.
func newKeystoreSocket(deps keystoreSocketDeps) (*keystoreSocket, error) {
	if role, installed := deps.nodeRole(); installed && role == install.RoleAgent {
		return nil, nil
	}
	cfg, closeAll, err := keystoreSocketConfig(deps)
	if err != nil {
		return nil, err
	}
	sup, err := socket.NewSupervisor(cfg)
	if err != nil {
		closeAll()
		return nil, err
	}
	return &keystoreSocket{sup: sup, close: closeAll}, nil
}

// keystoreSocketConfig is the supervisor's config for this server: the
// store's server log surface and its refusal auditor, the peer sources, the
// handler and the start checks (the effective uid, the service uid, the
// mount flags of a data-root descriptor it opens and keeps open, the store's
// install check, the maintenance marker read, the log reopen and the server
// count). The returned func closes the
// descriptors the config holds.
func keystoreSocketConfig(deps keystoreSocketDeps) (socket.SupervisorConfig, func(), error) {
	if deps.listen == nil {
		return socket.SupervisorConfig{}, nil, errors.New("no listener source")
	}
	work := filepath.Clean(deps.workDir)
	if !filepath.IsAbs(work) {
		return socket.SupervisorConfig{}, nil, errors.New("the work dir is not absolute")
	}
	uid, gid, err := deps.serviceIDs()
	if err != nil {
		return socket.SupervisorConfig{}, nil, err
	}
	storeCfg := deps.layout(work)
	storeCfg.UID, storeCfg.GID = uid, gid
	store := keystore.New(storeCfg)
	logs := store.ServerLogs()
	audit, err := socket.NewStoreAuditor(logs, deps.log)
	if err != nil {
		return socket.SupervisorConfig{}, nil, err
	}
	if deps.clock == nil {
		return socket.SupervisorConfig{}, nil, errors.New("no clock")
	}
	handler, err := socket.NewHandler(deps.clock.Now)
	if err != nil {
		return socket.SupervisorConfig{}, nil, err
	}
	dir, err := deps.openDataRoot(storeCfg.DataRoot)
	if err != nil {
		return socket.SupervisorConfig{}, nil, err
	}
	closeAll := func() {
		_ = logs.Close() // the listener is stopped: nothing appends any more
		_ = dir.Close()  // read-only descriptor
	}
	cs := deps.client
	return socket.SupervisorConfig{
		Listen:            deps.listen,
		EUID:              deps.euid,
		ServiceUID:        uid,
		IgnoresOwnership:  func() (bool, error) { return deps.ignoresOwnership(dir) },
		CheckInstall:      store.CheckSocketInstall,
		ServerCount:       func(ctx context.Context) (int, error) { return countKeystoreServers(ctx, cs) },
		MaintenanceMarked: logs.MaintenanceMarked,
		OpenLogs:          logs.Reopen,
		Creds:             deps.creds,
		Sandbox:           deps.sandbox,
		Audit:             audit,
		Handler:           handler,
		Clock:             deps.clock,
		Log:               deps.log,
	}, closeAll, nil
}

// runKeystoreSocket runs ks's supervisor in its own goroutine and returns
// the stop that cancels it, waits for Run to return and only then closes
// what ks holds. A nil ks (a worker) runs nothing and stops at once.
func runKeystoreSocket(ctx context.Context, ks *keystoreSocket) (stop func()) {
	if ks == nil {
		return noStop
	}
	rctx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		ks.sup.Run(rctx)
	}()
	return func() {
		cancel()
		<-done
		ks.close()
	}
}

// wallClock is the supervisor's production clock.
type wallClock struct{}

func (wallClock) Now() time.Time { return time.Now() }

func (wallClock) After(d time.Duration) (<-chan time.Time, func() bool) {
	t := time.NewTimer(d)
	return t.C, t.Stop
}

// startKeystoreSocket is the server's one entry point for the keystore's
// user socket: it builds the supervisor over the real primitives and runs
// it, returning the stop runServer defers beside keystore-delivery's, so
// LIFO drains it before the control plane stops. listen is how the
// listening socket is obtained, which this wiring leaves to its caller. It
// logs a build failure itself and returns noStop; it is never nil.
//
//lint:ignore U1000 the server start calls it once the listening socket's source is chosen
func startKeystoreSocket(ctx context.Context, workDir string, cs kubernetes.Interface, listen socket.ListenerSource, logger *slog.Logger) (stop func()) {
	ks, err := newKeystoreSocket(keystoreSocketDeps{
		workDir:          workDir,
		layout:           keystoreLayout,
		client:           cs,
		listen:           listen,
		nodeRole:         installedRole,
		euid:             func() int { return euidSeam() },
		serviceIDs:       lookupServiceIDs,
		openDataRoot:     openKeystoreDataRoot,
		ignoresOwnership: socket.DataRootIgnoresOwnership,
		creds:            socket.KernelPeerCreds{},
		sandbox:          socket.KernelPeerSandbox{},
		clock:            wallClock{},
		log:              logger,
	})
	if err != nil {
		logger.Error("keystore user scope is off: the socket listener was not built", "err", err)
		return noStop
	}
	return runKeystoreSocket(ctx, ks)
}

// doctorKeystoreUserScope is doctor's view of the user scope's start checks
// for the server whose work dir is workDir. Doctor runs as its own process,
// so where the server's supervisor reads its own state doctor reads the
// installed one: the server's effective uid is the service uid when this
// Mac is installed as a server (its LaunchDaemon runs as the service user),
// and doctor's own otherwise, the uid a rootless server started from the
// same account runs as; the marker is read without reopening anything; the
// data root's descriptor is opened here and released by the returned func;
// and the servers are counted through the work dir's admin kubeconfig. A
// failure to open the data root or to load the kubeconfig is that check's
// error, so it is reported in its place in the order.
func doctorKeystoreUserScope(workDir string) (socket.Preconditions, func(), error) {
	uid, gid, err := lookupServiceIDs()
	if err != nil {
		return socket.Preconditions{}, nil, err
	}
	storeCfg := keystoreLayout(workDir)
	storeCfg.UID, storeCfg.GID = uid, gid
	store := keystore.New(storeCfg)
	release := func() {}
	var ignores func() (bool, error)
	if dir, err := openKeystoreDataRoot(storeCfg.DataRoot); err != nil {
		ignores = func() (bool, error) { return false, err }
	} else {
		ignores = func() (bool, error) { return socket.DataRootIgnoresOwnership(dir) }
		release = func() { _ = dir.Close() } // read-only descriptor
	}
	euid := func() int {
		if role, installed := installedRole(); installed && role == install.RoleServer {
			return int(uid)
		}
		return euidSeam()
	}
	count := func(ctx context.Context) (int, error) {
		_, cs, err := kubeclient.FromPath(executor.KubeconfigPath(workDir))
		if err != nil {
			return 0, fmt.Errorf("load the admin kubeconfig: %w", err)
		}
		return countKeystoreServers(ctx, cs)
	}
	return socket.Preconditions{
		EUID:              euid,
		ServiceUID:        uid,
		MaintenanceMarked: store.MaintenanceMarked,
		OpenLogs:          store.CheckLogFlags,
		IgnoresOwnership:  ignores,
		CheckInstall:      store.CheckSocketInstall,
		ServerCount:       count,
	}, release, nil
}

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
	"slices"
	"time"

	"golang.org/x/sys/unix"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"k3sm.io/k3sm/pkg/executor"
	"k3sm.io/k3sm/pkg/install"
	"k3sm.io/k3sm/pkg/keystore"
	"k3sm.io/k3sm/pkg/keystore/socket"
	"k3sm.io/k3sm/pkg/kubeclient"
	"k3sm.io/runtimed/pkg/keystorepaths"
)

// keystoreServerCountTimeout bounds one count of the cluster's servers, so a
// List the apiserver never answers cannot hold the supervisor's start check.
const keystoreServerCountTimeout = 10 * time.Second

// keystoreSocketStopTimeout bounds how long the server's shutdown waits for
// the supervisor's Run to return, so the listener never holds it.
const keystoreSocketStopTimeout = 10 * time.Second

// countKeystoreServers is the user scope's single-server count
// (docs/design/keystore.md § "Single-server clusters only"): the nodes the
// apiserver lists carrying the controlPlaneNodeLabel key, whatever its
// value, the rule pkg/status uses to call a node a server. It lists afresh
// through the admin client every time, bounded by ctx and
// keystoreServerCountTimeout, and any error, a nil client included, is the
// count's error, which keeps the listener off.
func countKeystoreServers(ctx context.Context, cs kubernetes.Interface) (int, error) {
	names, err := listKeystoreServers(ctx, cs)
	return len(names), err
}

// listKeystoreServers is countKeystoreServers' list: the servers' node
// names, sorted.
func listKeystoreServers(ctx context.Context, cs kubernetes.Interface) ([]string, error) {
	if cs == nil {
		return nil, errors.New("no admin client to count the servers with")
	}
	ctx, cancel := context.WithTimeout(ctx, keystoreServerCountTimeout)
	defer cancel()
	list, err := cs.CoreV1().Nodes().List(ctx, metav1.ListOptions{LabelSelector: controlPlaneNodeLabel})
	if err != nil {
		return nil, fmt.Errorf("list the nodes labelled %s: %w", controlPlaneNodeLabel, err)
	}
	var names []string
	for i := range list.Items {
		if _, cp := list.Items[i].Labels[controlPlaneNodeLabel]; cp {
			names = append(names, list.Items[i].Name)
		}
	}
	slices.Sort(names)
	return names, nil
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
	// creds and sandbox are the listener's peer sources; sandboxCheck is
	// the start-time control on the sandbox source (socket.SandboxSelfCheck).
	creds        socket.PeerCredSource
	sandbox      socket.PeerSandboxSource
	sandboxCheck func() error
	clock        socket.Clock
	log          *slog.Logger
}

// keystoreSocket is a built supervisor and what it holds open: the data-root
// descriptor and the server's log descriptors, closed once Run has returned.
// log receives the stop's line when Run outlives keystoreSocketStopTimeout.
type keystoreSocket struct {
	sup   *socket.Supervisor
	close func()
	log   *slog.Logger
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
	return &keystoreSocket{sup: sup, close: closeAll, log: deps.log}, nil
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
		SandboxCheck:      deps.sandboxCheck,
		Creds:             deps.creds,
		Sandbox:           deps.sandbox,
		Audit:             audit,
		Handler:           handler,
		Clock:             deps.clock,
		Log:               deps.log,
	}, closeAll, nil
}

// runKeystoreSocket runs ks's supervisor in its own goroutine, which closes
// what ks holds only once Run has returned, and returns the stop that
// cancels it and waits for Run at most keystoreSocketStopTimeout: past that
// it logs and returns, so the server's shutdown is never held by the
// listener, and the descriptors stay open until Run returns or the process
// exits. A nil ks (a worker) runs nothing and stops at once.
func runKeystoreSocket(ctx context.Context, ks *keystoreSocket) (stop func()) {
	if ks == nil {
		return noStop
	}
	rctx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		ks.sup.Run(rctx)
		ks.close()
	}()
	return func() {
		cancel()
		t := time.NewTimer(keystoreSocketStopTimeout)
		defer t.Stop()
		select {
		case <-done:
		case <-t.C:
			ks.log.Warn("keystore socket: the listener did not stop in time; shutdown goes on without it", "waited", keystoreSocketStopTimeout)
		}
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
		sandboxCheck:     socket.SandboxSelfCheck,
		clock:            wallClock{},
		log:              logger,
	})
	if err != nil {
		logger.Error("keystore user scope is off: the socket listener was not built", "err", err)
		return noStop
	}
	return runKeystoreSocket(ctx, ks)
}

// doctorUserScope is what doctor's user-scope row reads: the start checks
// as doctor re-runs them, the release of what they hold, the servers the
// count saw and its error, and the one fact doctor can establish about the
// listener without connecting to it (a connection from root or the service
// user would be refused and write a refusal line): what is at the socket's
// path.
type doctorUserScope struct {
	pre     socket.Preconditions
	release func()
	// servers is the last count's sorted node names, and countErr its
	// error.
	servers  func() ([]string, error)
	sockPath string
	// sockState lstats sockPath, never following or connecting: nil when a
	// socket owned by the service user is there.
	sockState func() error
}

// errNoListeningSocket is a socket path that holds no socket of the
// service user's.
var errNoListeningSocket = errors.New("no listening socket")

// lstatKeystoreSocket judges what is at path by lstat alone: nil for a
// socket owned by uid, else an error wrapping errNoListeningSocket (or the
// lstat's error) that says what is there.
func lstatKeystoreSocket(path string, uid uint32) error {
	var st unix.Stat_t
	if err := unix.Lstat(path, &st); err != nil {
		if errors.Is(err, unix.ENOENT) {
			return fmt.Errorf("%w: nothing is at the path", errNoListeningSocket)
		}
		return fmt.Errorf("lstat the socket path: %w", err)
	}
	return judgeKeystoreSocket(uint32(st.Mode), st.Uid, uid)
}

// judgeKeystoreSocket is lstatKeystoreSocket's rule over an lstat's mode
// and owner.
func judgeKeystoreSocket(mode, owner, uid uint32) error {
	switch {
	case mode&unix.S_IFMT != unix.S_IFSOCK:
		return fmt.Errorf("%w: the path is not a socket", errNoListeningSocket)
	case owner != uid:
		return fmt.Errorf("%w: the socket is owned by uid %d, not the service user's %d", errNoListeningSocket, owner, uid)
	}
	return nil
}

// readAdminKubeconfig loads the admin kubeconfig at path, opening it first
// so that a file this user may not read is an error wrapping
// fs.ErrPermission.
func readAdminKubeconfig(path string) (kubernetes.Interface, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("read the admin kubeconfig: %w", err)
	}
	_ = f.Close() // opened only to learn whether this user may read it
	_, cs, err := kubeclient.FromPath(path)
	if err != nil {
		return nil, fmt.Errorf("load the admin kubeconfig: %w", err)
	}
	return cs, nil
}

// doctorKeystoreUserScope is doctor's view of the user scope's start checks
// for the server whose work dir is workDir. Doctor runs as its own process,
// so where the server's supervisor reads its own state doctor reads the
// installed one: the server's effective uid is the service uid when this
// Mac is installed as a server (its LaunchDaemon runs as the service user),
// and doctor's own otherwise, the uid a rootless server started from the
// same account runs as; the marker is read without reopening anything, and
// the logs are judged read-only (CheckLogFlags) where the server reopens
// them; the data root's descriptor is opened here and released by the
// returned release; the servers are listed through the work dir's admin
// kubeconfig; and the socket path is only lstat'd. A failure to open the
// data root or to load the kubeconfig is that check's error, so it is
// reported in its place in the order.
func doctorKeystoreUserScope(workDir string) (doctorUserScope, error) {
	uid, gid, err := lookupServiceIDs()
	if err != nil {
		return doctorUserScope{}, err
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
	var names []string
	var countErr error
	count := func(ctx context.Context) (int, error) {
		cs, err := readAdminKubeconfig(executor.KubeconfigPath(workDir))
		if err == nil {
			names, err = listKeystoreServers(ctx, cs)
		}
		countErr = err
		return len(names), err
	}
	sock := keystorepaths.SocketPath(storeCfg.DataRoot)
	return doctorUserScope{
		pre: socket.Preconditions{
			EUID:              euid,
			ServiceUID:        uid,
			MaintenanceMarked: store.MaintenanceMarked,
			OpenLogs:          store.CheckLogFlags,
			SandboxCheck:      socket.SandboxSelfCheck,
			IgnoresOwnership:  ignores,
			CheckInstall:      store.CheckSocketInstall,
			ServerCount:       count,
		},
		release:   release,
		servers:   func() ([]string, error) { return names, countErr },
		sockPath:  sock,
		sockState: func() error { return lstatKeystoreSocket(sock, uid) },
	}, nil
}

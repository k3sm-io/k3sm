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
	"sync"
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

// dataRootPass is one start-check pass's hold on the data root: the
// mount-flag check opens it afresh (O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC),
// fstats and fstatfs's that descriptor, and the later checks of the same
// pass judge what they opened against it, so a volume mounted over the
// data root, the socket directory or the logs since an earlier pass is
// judged as it is now, never through an old descriptor. end closes it.
type dataRootPass struct {
	path    string
	open    func(path string) (*os.File, error)
	ignores func(dir *os.File) (bool, error)

	mu  sync.Mutex // guards f and dev
	f   *os.File
	dev uint64
}

// errDataRootMoved is an object a start check opened that is not on the
// pass's data root's device.
var errDataRootMoved = errors.New("not on the data root's device")

// ignoresOwnership starts the pass: it ends any earlier one, opens the
// data root afresh, records its device and reads its mount flags.
func (p *dataRootPass) ignoresOwnership() (bool, error) {
	p.end()
	f, err := p.open(p.path)
	if err != nil {
		return false, err
	}
	var st unix.Stat_t
	if err := unix.Fstat(int(f.Fd()), &st); err != nil {
		_ = f.Close() // read-only descriptor
		return false, fmt.Errorf("stat the data root %s: %w", p.path, err)
	}
	p.mu.Lock()
	p.f, p.dev = f, uint64(st.Dev)
	p.mu.Unlock()
	return p.ignores(f)
}

// root returns the pass's data-root descriptor and its device, or an
// error when no pass is open.
func (p *dataRootPass) root() (*os.File, uint64, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.f == nil {
		return nil, 0, errors.New("no data-root descriptor for this start-check pass")
	}
	return p.f, p.dev, nil
}

// sameDevice opens each of paths relative to the pass's data-root
// descriptor, one component at a time, each O_DIRECTORY|O_NOFOLLOW, and
// refuses one whose device is not the data root's: a volume mounted over
// it since the data root was judged.
func (p *dataRootPass) sameDevice(paths ...[]string) error {
	root, dev, err := p.root()
	if err != nil {
		return err
	}
	for _, comps := range paths {
		fd := int(root.Fd())
		owned := -1
		for _, c := range comps {
			next, err := unix.Openat(fd, c, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
			if owned >= 0 {
				_ = unix.Close(owned) // read-only directory descriptor
			}
			if err != nil {
				return fmt.Errorf("open %s through the data root: %w", filepath.Join(comps...), err)
			}
			fd, owned = next, next
		}
		var st unix.Stat_t
		err := unix.Fstat(fd, &st)
		if owned >= 0 {
			_ = unix.Close(owned) // read-only directory descriptor
		}
		if err != nil {
			return fmt.Errorf("stat %s: %w", filepath.Join(comps...), err)
		}
		if uint64(st.Dev) != dev {
			return fmt.Errorf("%s is %w", filepath.Join(comps...), errDataRootMoved)
		}
	}
	return nil
}

// sameDeviceFiles refuses a held log whose device is not the pass's data
// root's.
func (p *dataRootPass) sameDeviceFiles(files ...keystore.LogFileID) error {
	_, dev, err := p.root()
	if err != nil {
		return err
	}
	for _, f := range files {
		if f.Dev != dev {
			return fmt.Errorf("a reopened log is %w", errDataRootMoved)
		}
	}
	return nil
}

// end closes the pass's data-root descriptor, if one is open.
func (p *dataRootPass) end() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.f != nil {
		_ = p.f.Close() // read-only descriptor
		p.f, p.dev = nil, 0
	}
}

// socketInstallDirs are the directories the install check judges, as
// components under the data root, each re-checked on the pass's device.
var socketInstallDirs = [][]string{
	{keystorepaths.SockDir},
	{keystore.LogsDirName},
	{keystore.LogsDirName, keystore.AuditDirName},
	{keystore.LogsDirName, keystore.FloorDirName},
}

// checkInstallOn is the store's install check, then each directory it
// judged re-opened through the pass's data root and refused when it is on
// another device: the store's check opens by path, so the device is what
// ties what it judged to the data root whose flags were read.
func checkInstallOn(pass *dataRootPass, check func(context.Context) error) func(context.Context) error {
	return func(ctx context.Context) error {
		if err := check(ctx); err != nil {
			return err
		}
		return pass.sameDevice(socketInstallDirs...)
	}
}

// keystoreSocketDeps is what the user socket's wiring takes from the server,
// so a test can fake each part.
type keystoreSocketDeps struct {
	// workDir is the server's work dir; layout derives the store and the
	// data root from it (keystoreLayout in production).
	workDir string
	layout  func(work string) keystore.Config
	// opened, when set, is handed the store the config builds, where a
	// test inspects it.
	opened func(*keystore.FileStore)
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
	// openDataRoot opens the data root's descriptor afresh for each
	// start-check pass; ignoresOwnership reads its mount flags.
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

// keystoreSocket is a built supervisor and what it holds open: the server's
// log descriptors, and a pass's data-root descriptor if Run stopped inside
// one, closed once Run has returned.
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
// store (its lock wait the socket's), its server log surface and refusal
// auditor, the peer sources, the operations' handler over the store's
// bridge, and the start checks (the effective uid, the service uid, the
// mount flags of a data-root descriptor opened afresh for each pass and
// closed when it ends, the store's install check and the log reopen, each
// held to that descriptor's device, the maintenance marker read, the
// server count and the store's start step). The returned func closes the
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
	// The server's waits for the store lock are the socket's bound: past
	// it a request is answered busy.
	storeCfg.LockWait = socket.LockWait
	store := keystore.New(storeCfg)
	if deps.opened != nil {
		deps.opened(store)
	}
	logs := store.ServerLogs()
	audit, err := socket.NewStoreAuditor(logs, deps.log)
	if err != nil {
		return socket.SupervisorConfig{}, nil, err
	}
	if deps.clock == nil {
		return socket.SupervisorConfig{}, nil, errors.New("no clock")
	}
	bridge, err := socket.NewFileStoreBridge(store, deps.clock.Now)
	if err != nil {
		return socket.SupervisorConfig{}, nil, err
	}
	handler, err := socket.NewOpsHandler(deps.clock.Now, bridge)
	if err != nil {
		return socket.SupervisorConfig{}, nil, err
	}
	if deps.openDataRoot == nil || deps.ignoresOwnership == nil {
		return socket.SupervisorConfig{}, nil, errors.New("no data-root opener or mount-flag check")
	}
	pass := &dataRootPass{path: storeCfg.DataRoot, open: deps.openDataRoot, ignores: deps.ignoresOwnership}
	closeAll := func() {
		_ = logs.Close() // the listener is stopped: nothing appends any more
		pass.end()
	}
	cs := deps.client
	return socket.SupervisorConfig{
		Listen:            deps.listen,
		EUID:              deps.euid,
		ServiceUID:        uid,
		IgnoresOwnership:  pass.ignoresOwnership,
		EndPass:           pass.end,
		CheckInstall:      checkInstallOn(pass, store.CheckSocketInstall),
		ServerCount:       func(ctx context.Context) (int, error) { return countKeystoreServers(ctx, cs) },
		MaintenanceMarked: logs.MaintenanceMarked,
		OpenLogs: func(ctx context.Context) error {
			if err := logs.Reopen(ctx); err != nil {
				return err
			}
			audit, floor := logs.Files()
			if err := pass.sameDeviceFiles(audit, floor); err != nil {
				_ = logs.Close() // never append through a log off the judged data root
				return err
			}
			return nil
		},
		SandboxCheck: deps.sandboxCheck,
		StartScopes:  startUserScopesStep(store, deps.log),
		Creds:        deps.creds,
		Sandbox:      deps.sandbox,
		Audit:        audit,
		Handler:      handler,
		Clock:        deps.clock,
		Log:          deps.log,
	}, closeAll, nil
}

// startUserScopesStep is the supervisor's last start check: the store's
// start step (the log bounds check, then the delivery catch-up), run on
// every pass, so a failed one is retried. Only an error naming scopes it
// could not catch up while the bounds check passed and every other scope
// started (keystore.ScopesNotCaughtUp) is logged at Warn and the listener
// serves; any other error (the log bounds check failed, or the catch-up
// failed as a whole) keeps the listener off with the store's reason on
// every pass, the first or a later one alike (docs/design/keystore.md §
// "The user-scope floor").
func startUserScopesStep(store *keystore.FileStore, log *slog.Logger) func(context.Context) error {
	return func(ctx context.Context) error {
		err := store.StartUserScopes(ctx)
		if err != nil && keystore.ScopesNotCaughtUp(err) && store.UserScopesStarted() {
			log.Warn("keystore user scope started, but its start step named scopes it could not catch up", "err", err)
			return nil
		}
		return err
	}
}

// superviseKeystoreSocket builds the listener's supervisor with build and
// runs it, in one goroutine, and returns the stop. A build that fails (the
// service-user lookup, say) is logged and retried on the supervisor's
// backoff, from socket.MinBackoff doubling to socket.MaxBackoff on clock,
// so the user scope is not left off for the life of the process; a build
// that returns nil (an installed agent) runs nothing. A panic out of Run,
// or out of build, is recovered in that goroutine and never ends the
// process: it is logged, socket.MinBackoff passes on clock, and the same
// supervisor runs again (a panicking build counts as a failed build). What
// the supervisor holds is closed by that goroutine once Run has returned
// without panicking. The stop cancels it and waits at most
// keystoreSocketStopTimeout: past that it logs and returns, so the server's
// shutdown is never held by the listener, and the descriptors stay open
// until Run returns or the process exits.
func superviseKeystoreSocket(ctx context.Context, build func() (*keystoreSocket, error), clock socket.Clock, log *slog.Logger) (stop func()) {
	rctx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		var ks *keystoreSocket
		defer func() {
			if ks != nil {
				ks.close()
			}
		}()
		backoff := socket.MinBackoff
		for {
			wait := socket.MinBackoff
			if ks == nil {
				built, err := recoveredBuild(build)
				if err == nil {
					if built == nil {
						return // an installed agent runs nothing
					}
					ks = built
				} else {
					log.Error("keystore user scope is off: the socket listener was not built", "err", err, "retry", backoff)
					wait = backoff
					backoff = min(2*backoff, socket.MaxBackoff)
				}
			}
			if ks != nil {
				v, panicked := recoveredRun(rctx, ks)
				if !panicked {
					return
				}
				log.Error("keystore socket: recovered a panic out of the supervisor; it runs again", "panic", fmt.Sprint(v), "retry", wait)
			}
			tick, stopTick := clock.After(wait)
			select {
			case <-rctx.Done():
				stopTick()
				return
			case <-tick:
			}
		}
	}()
	return func() {
		cancel()
		t := time.NewTimer(keystoreSocketStopTimeout)
		defer t.Stop()
		select {
		case <-done:
		case <-t.C:
			log.Warn("keystore socket: the listener did not stop in time; shutdown goes on without it", "waited", keystoreSocketStopTimeout)
		}
	}
}

// recoveredBuild calls build, turning a panic in it into an error.
func recoveredBuild(build func() (*keystoreSocket, error)) (ks *keystoreSocket, err error) {
	defer func() {
		if v := recover(); v != nil {
			ks, err = nil, fmt.Errorf("keystore socket: the build panicked: %v", v)
		}
	}()
	return build()
}

// recoveredRun runs ks's supervisor until it returns, reporting a panic out
// of it, with the value, instead of letting it end the process.
func recoveredRun(ctx context.Context, ks *keystoreSocket) (v any, panicked bool) {
	defer func() {
		if r := recover(); r != nil {
			v, panicked = r, true
		}
	}()
	ks.sup.Run(ctx)
	return nil, false
}

// wallClock is the supervisor's production clock.
type wallClock struct{}

func (wallClock) Now() time.Time { return time.Now() }

func (wallClock) After(d time.Duration) (<-chan time.Time, func() bool) {
	t := time.NewTimer(d)
	return t.C, t.Stop
}

// keystoreSocketListener is the server's listener source: the socket
// launchd activated for the server plist's Sockets entry
// (install.KeystoreSocketsEntry). A server launchd did not start, or whose
// plist predates the entry, gets socket.ErrNotActivated, and the user scope
// stays off as "the listening socket is unavailable"; the server never
// binds keys.sock itself. The descriptor must be bound at the keystore
// socket's path under the work dir's data root.
func keystoreSocketListener(workDir string) socket.ListenerSource {
	return socket.ActivatedListener(install.KeystoreSocketsEntry, keystoreSocketPath(workDir), socket.LaunchdActivator{})
}

// keystoreSocketPath is the keystore socket's path for the server whose
// work dir is workDir: the path the server plist's Sockets entry names.
func keystoreSocketPath(workDir string) string {
	return keystorepaths.SocketPath(keystoreLayout(filepath.Clean(workDir)).DataRoot)
}

// startKeystoreSocket is the server's one entry point for the keystore's
// user socket: it builds the supervisor over the real primitives and runs
// it, returning the stop runServer defers beside keystore-delivery's, so
// LIFO drains it before the control plane stops. listen is how the
// listening socket is obtained (keystoreSocketListener in runServer). A
// build failure is logged and retried with backoff
// (superviseKeystoreSocket); the stop is never nil. Everything it runs is
// in its own goroutine with recover, so nothing it does stops the
// apiserver or kine.
func startKeystoreSocket(ctx context.Context, workDir string, cs kubernetes.Interface, listen socket.ListenerSource, logger *slog.Logger) (stop func()) {
	deps := keystoreSocketDeps{
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
	}
	return superviseKeystoreSocket(ctx, func() (*keystoreSocket, error) { return newKeystoreSocket(deps) }, deps.clock, logger)
}

// doctorOpenLogs is doctor's log step: the server's reopen judgement,
// read-only (keystore.FileStore.CheckServerLogs), then the same check
// that both logs lie on the pass's data root. It takes no store lock and
// writes nothing.
func doctorOpenLogs(store *keystore.FileStore, pass *dataRootPass) func(context.Context) error {
	return func(ctx context.Context) error {
		audit, floor, err := store.CheckServerLogs(ctx)
		if err != nil {
			return err
		}
		return pass.sameDeviceFiles(audit, floor)
	}
}

// doctorStartScopes is doctor's start step: the read-only half of the
// server's (keystore.FileStore.CheckLogBounds), whose refusal leaves the
// server's user scope unstarted with the same reason. The catch-up, which
// writes, is the server's alone.
func doctorStartScopes(store *keystore.FileStore) func(context.Context) error {
	return func(ctx context.Context) error {
		_, _, err := store.CheckLogBounds(ctx)
		return err
	}
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
	// sockState lstats sockPath, never following or connecting: nil when
	// launchd's socket is there (root's, at install.KeystoreSocketMode).
	sockState func() error
}

// errNoListeningSocket is a socket path that holds no socket of
// launchd's.
var errNoListeningSocket = errors.New("no listening socket")

// launchdSocketOwner is the owner of a socket launchd creates for a job's
// Sockets entry: root, whatever the job's UserName (measured 2026-11-23:
// root:daemon 0666 in the root 0755 directory).
const launchdSocketOwner = 0

// lstatKeystoreSocket judges what is at path by lstat alone: nil for a
// socket owned by owner (launchdSocketOwner in production) at
// install.KeystoreSocketMode, else an error wrapping errNoListeningSocket
// (or the lstat's error) that says what is there.
func lstatKeystoreSocket(path string, owner uint32) error {
	var st unix.Stat_t
	if err := unix.Lstat(path, &st); err != nil {
		if errors.Is(err, unix.ENOENT) {
			return fmt.Errorf("%w: nothing is at the path", errNoListeningSocket)
		}
		return fmt.Errorf("lstat the socket path: %w", err)
	}
	return judgeKeystoreSocket(uint32(st.Mode), st.Uid, owner)
}

// judgeKeystoreSocket is lstatKeystoreSocket's rule over an lstat's mode
// and owner. A socket of the service user's is the self-bind form, which
// does not ship, so it is no listening socket either.
func judgeKeystoreSocket(mode, owner, want uint32) error {
	switch {
	case mode&unix.S_IFMT != unix.S_IFSOCK:
		return fmt.Errorf("%w: the path is not a socket", errNoListeningSocket)
	case owner != want:
		return fmt.Errorf("%w: the socket is owned by uid %d, not root's, which launchd's socket is (run sudo k3sm install, which renders the server plist's Sockets entry)", errNoListeningSocket, owner)
	case mode&0o7777 != install.KeystoreSocketMode:
		return fmt.Errorf("%w: the socket is at mode %04o, not %04o", errNoListeningSocket, mode&0o7777, install.KeystoreSocketMode)
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
// the logs are judged read-only (CheckServerLogs: the reopen's flag,
// owner, size and recount checks, no lock, no write) where the server reopens
// them; the data root is opened afresh by the pass, as the server's is, and
// closed when it ends (release closes it too); the servers are listed through the work dir's admin
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
	pass := &dataRootPass{path: storeCfg.DataRoot, open: openKeystoreDataRoot, ignores: socket.DataRootIgnoresOwnership}
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
			OpenLogs:          doctorOpenLogs(store, pass),
			SandboxCheck:      socket.SandboxSelfCheck,
			IgnoresOwnership:  pass.ignoresOwnership,
			EndPass:           pass.end,
			CheckInstall:      checkInstallOn(pass, store.CheckSocketInstall),
			ServerCount:       count,
			StartScopes:       doctorStartScopes(store),
		},
		release:   pass.end,
		servers:   func() ([]string, error) { return names, countErr },
		sockPath:  sock,
		sockState: func() error { return lstatKeystoreSocket(sock, launchdSocketOwner) },
	}, nil
}

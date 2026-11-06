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

package registrysvc

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"k3sm.io/k3sm/pkg/ociregistry/api"
	"k3sm.io/k3sm/pkg/ociregistry/auth"
	"k3sm.io/k3sm/pkg/ociregistry/gc"
	"k3sm.io/k3sm/pkg/ociregistry/store"
)

// The k3sm registry server's process.
//
// `k3sm registry serve --config <work-dir>/registry-state/serve.json` serves
// pkg/ociregistry on the configured loopback listener. It parses pusher input,
// so it starts by shedding what it was handed, and in this order: descriptors
// past stdio and the environment; then the parent watch, which must be
// registered before a credential drop can make the parent another user's; then
// the credential; then the data volume check, so a missed boot mount never
// reaches store.Open, which would create the root. Nothing has touched the store
// until all of that has passed.

// Timings of the server process.
const (
	// serveGCGrace and serveGCInterval are the store's garbage-collection
	// cadence, the values of gcDelay and gcInterval; a test pins that they agree.
	serveGCGrace    = time.Hour
	serveGCInterval = 6 * time.Hour
	// serveStatusEvery is how often the server reports its live upload sessions
	// into the state record.
	serveStatusEvery = 30 * time.Second
	// serveDrain bounds a clean stop, inside the daemon's drainGrace.
	serveDrain = 4 * time.Second
)

// The refusals of `k3sm registry serve`.
var (
	// ErrServeAsRoot: the server was started as root, and no service credential
	// could take it off root.
	ErrServeAsRoot = errors.New("the registry server refuses to run as root")
	// ErrServeCredential: the server runs as a user other than the one its config
	// names, which only root could change.
	ErrServeCredential = errors.New("the registry server does not hold the configured credential")
	// ErrOffDataVolume: the store root is not on the configured data volume.
	ErrOffDataVolume = errors.New("the registry store is not on the configured data volume")
	// ErrParentExited: the daemon that spawned the server is gone.
	ErrParentExited = errors.New("the registry server's parent exited")
)

// Serve runs the registry server for the config at configPath until ctx is
// cancelled, it fails, or its parent exits. It is the whole of the process's
// life: it closes inherited descriptors and clears the environment, so it is
// called only from the verb's main path.
func Serve(ctx context.Context, configPath string) error {
	if err := closeInheritedDescriptors(); err != nil {
		return err
	}
	os.Clearenv()
	return serve(ctx, configPath, serveDeps{
		ident:       osIdentity(),
		getppid:     os.Getppid,
		listen:      func(addr string) (net.Listener, error) { return net.Listen("tcp", addr) },
		gcGrace:     serveGCGrace,
		gcInterval:  serveGCInterval,
		statusEvery: serveStatusEvery,
	})
}

// serveDeps are the seams of serve.
type serveDeps struct {
	ident   identity
	getppid func() int
	listen  func(addr string) (net.Listener, error)
	// freeSpace reports the store volume's free bytes; nil asks statfs.
	freeSpace           func() (uint64, error)
	gcGrace, gcInterval time.Duration
	statusEvery         time.Duration
	// addr, when set, receives the bound address once the server is serving.
	addr func(net.Addr)
}

// serve is Serve without the process-wide steps.
func serve(ctx context.Context, configPath string, d serveDeps) error {
	workDir, err := serveWorkDir(configPath)
	if err != nil {
		return err
	}
	cfg, err := readServeConfigAs(configPath, d.ident.geteuid())
	if err != nil {
		return err
	}
	if err := cfg.validateForServing(); err != nil {
		return err
	}
	ppid := d.getppid()
	if ppid <= launchdPID {
		return fmt.Errorf("%w: ppid is %d", ErrParentExited, ppid)
	}
	parentGone, stopWatch, err := watchParent(ppid)
	if err != nil {
		return err
	}
	defer stopWatch()
	if p := d.getppid(); p != ppid { // it died before the watch was registered
		return fmt.Errorf("%w: ppid changed from %d to %d", ErrParentExited, ppid, p)
	}
	if err := applyServeCredential(cfg, d.ident); err != nil {
		return err
	}
	if err := checkDataVolume(cfg.DataVolume, StateDir(workDir)); err != nil {
		return err
	}
	logFile, err := openServeLog(workDir)
	if err != nil {
		return err
	}
	defer logFile.Close()
	// Debug, because the servers log an anonymous refusal and an ordinary 4xx
	// there and every refusal belongs in this log. Nothing logged at any level
	// carries a credential.
	log := slog.New(slog.NewJSONHandler(logFile, &slog.HandlerOptions{Level: slog.LevelDebug}))
	if err := runServer(ctx, workDir, cfg, d, log, parentGone); err != nil {
		log.Error("registry server stopped", "err", err)
		return err
	}
	log.Info("registry server stopped")
	return nil
}

// runServer opens the store and serves it until ctx is cancelled, the parent
// goes or the listener fails, then drains.
func runServer(ctx context.Context, workDir string, cfg ServeConfig, d serveDeps, log *slog.Logger, parentGone <-chan struct{}) error {
	st, err := store.OpenWorkDir(workDir)
	if err != nil {
		return fmt.Errorf("open the registry store: %w", err)
	}
	access, err := auth.New(auth.Config{Principals: cfg.Principals, Logger: log})
	if err != nil {
		return err
	}
	server, err := auth.NewServer(access, api.Config{Store: st, Logger: log, GCGrace: d.gcGrace, FreeSpace: d.freeSpace})
	if err != nil {
		return err
	}
	collector, err := gc.New(st, gc.Options{Grace: d.gcGrace, Log: log})
	if err != nil {
		return err
	}
	ln, err := d.listen(cfg.Listen)
	if err != nil {
		return fmt.Errorf("bind the registry listener: %w", err)
	}
	httpServer := server.HTTPServer(cfg.Listen)
	log.Info("registry server serving", "addr", ln.Addr().String(), "pid", os.Getpid(), "uid", d.ident.geteuid(), "root", st.Root())
	if d.addr != nil {
		d.addr(ln.Addr())
	}

	reports := statusReporter{workDir: workDir, log: log}
	bg, stopBG := context.WithCancel(ctx)
	defer stopBG()
	var wg sync.WaitGroup
	wg.Go(func() { sweepLoop(bg, collector, d.gcGrace, d.gcInterval, reports, log) })
	wg.Go(func() { reportLoop(bg, server, d.statusEvery, reports) })

	served := make(chan error, 1)
	go func() { served <- httpServer.Serve(ln) }()
	var result error
	select {
	case <-ctx.Done():
	case <-parentGone:
		result = ErrParentExited
	case err := <-served:
		result = fmt.Errorf("serve the registry: %w", err)
	}
	stopBG()
	drain, cancel := context.WithTimeout(context.WithoutCancel(ctx), serveDrain)
	defer cancel()
	if err := httpServer.Shutdown(drain); err != nil {
		log.Warn("registry server drain cut short", "err", err)
		_ = httpServer.Close() // the drain already failed; the process is on its way out
	}
	wg.Wait()
	reports.sessions(0) // a server that has stopped holds none
	return result
}

// sweepLoop sweeps at the first moment the collector allows, a little past its
// grace, and then every interval.
func sweepLoop(ctx context.Context, c *gc.Collector, grace, interval time.Duration, reports statusReporter, log *slog.Logger) {
	wait := time.NewTimer(grace + grace/60)
	defer wait.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-wait.C:
		}
		sweepOnce(ctx, c, reports, log)
		wait.Reset(interval)
	}
}

// sweepOnce runs one sweep, logs its outcome and reports it. The collector logs
// each object and each brake itself.
func sweepOnce(ctx context.Context, c *gc.Collector, reports statusReporter, log *slog.Logger) {
	rep, err := c.Sweep(ctx)
	if err != nil && (ctx.Err() != nil || errors.Is(err, gc.ErrTooSoon)) {
		return
	}
	status := GCStatus{
		LastSweep:  time.Now().UTC(),
		ReportOnly: rep.ReportOnly,
		Stopped:    len(rep.Stopped),
		Failed:     len(rep.Failed),
	}
	if !rep.ReportOnly {
		status.Manifests = rep.Count(gc.KindManifest)
		status.Blobs = rep.Count(gc.KindBlob)
		status.Uploads = rep.Count(gc.KindUpload)
		status.Temps = rep.Count(gc.KindTemp)
		status.Repositories = rep.Count(gc.KindRepository)
	}
	level := slog.LevelInfo
	if err != nil {
		level = slog.LevelError
	}
	log.Log(ctx, level, "registry gc: sweep finished", "report_only", status.ReportOnly, "manifests", status.Manifests,
		"blobs", status.Blobs, "uploads", status.Uploads, "temps", status.Temps, "repositories", status.Repositories,
		"stopped", status.Stopped, "failed", status.Failed, "err", err)
	reports.gc(status)
}

// reportLoop reports the live upload sessions every period.
func reportLoop(ctx context.Context, server *api.Server, period time.Duration, reports statusReporter) {
	tick := time.NewTicker(period)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			reports.sessions(server.UploadSessions())
		}
	}
}

// statusReporter writes the server's fields into the daemon's state record. The
// record stays a report: a write that fails is logged and survived, and a record
// that is not there yet, because the daemon writes it once the server is ready,
// is left for the next report.
type statusReporter struct {
	workDir string
	log     *slog.Logger
}

func (r statusReporter) gc(s GCStatus) {
	r.update(func(st *State) bool {
		st.GC = &s
		return true
	})
}

func (r statusReporter) sessions(n int) {
	r.update(func(st *State) bool {
		if st.UploadSessions == n {
			return false
		}
		st.UploadSessions = n
		return true
	})
}

func (r statusReporter) update(edit func(*State) bool) {
	err := updateState(r.workDir, edit)
	switch {
	case err == nil:
	case errors.Is(err, fs.ErrNotExist):
		r.log.Debug("no registry state record to report into yet", "path", StatePath(r.workDir))
	default:
		r.log.Warn("could not report into the registry state record", "path", StatePath(r.workDir), "err", err)
	}
}

// serveWorkDir derives the work dir from the config's path, the one spelling
// the daemon spawns and the reclaim matches.
func serveWorkDir(configPath string) (string, error) {
	workDir := filepath.Dir(filepath.Dir(configPath))
	if !filepath.IsAbs(configPath) || ServeConfigPath(workDir) != configPath {
		return "", fmt.Errorf("registry serve config %q is not <work-dir>/registry-state/serve.json", configPath)
	}
	return workDir, nil
}

// identity is the process credential calls.
type identity struct {
	geteuid, getuid, getegid func() int
	setgroups                func([]int) error
	setgid, setuid           func(int) error
	// primaryGID is the primary group of the user uid, from its account record.
	primaryGID func(uid int) (int, error)
}

func osIdentity() identity {
	return identity{
		geteuid: unix.Geteuid, getuid: unix.Getuid, getegid: unix.Getegid,
		setgroups: unix.Setgroups, setgid: unix.Setgid, setuid: unix.Setuid,
		primaryGID: lookupPrimaryGID,
	}
}

// lookupPrimaryGID reads uid's primary group from its account record.
func lookupPrimaryGID(uid int) (int, error) {
	u, err := user.LookupId(strconv.Itoa(uid))
	if err != nil {
		return 0, err
	}
	return strconv.Atoi(u.Gid)
}

// applyServeCredential takes the process off root onto cfg's service credential
// when it was started as root, and otherwise checks it already holds it. A root
// process with no credential to take refuses, as does one whose group is not the
// named user's primary group or whose drop does not verify. Darwin credentials are per process, so the drop reaches every thread.
func applyServeCredential(cfg ServeConfig, id identity) error {
	if id.geteuid() != 0 && id.getuid() != 0 {
		if cfg.UID != 0 && (id.geteuid() != cfg.UID || id.getegid() != cfg.GID) {
			return fmt.Errorf("%w: running as %d:%d, the config names %d:%d", ErrServeCredential, id.geteuid(), id.getegid(), cfg.UID, cfg.GID)
		}
		return nil
	}
	if cfg.UID == 0 {
		return fmt.Errorf("%w: the config names no service credential", ErrServeAsRoot)
	}
	// Root takes the group from a config the user it names can write, so the
	// config cannot be what grants it: the group must be the one the account
	// record gives that user. A server run by launchd holds exactly that group.
	gid, err := id.primaryGID(cfg.UID)
	if err != nil {
		return fmt.Errorf("%w: read the account of uid %d: %w", ErrServeCredential, cfg.UID, err)
	}
	if gid != cfg.GID {
		return fmt.Errorf("%w: the config names group %d, and uid %d's primary group is %d", ErrServeCredential, cfg.GID, cfg.UID, gid)
	}
	if err := id.setgroups([]int{cfg.GID}); err != nil {
		return fmt.Errorf("%w: setgroups: %w", ErrServeAsRoot, err)
	}
	if err := id.setgid(cfg.GID); err != nil {
		return fmt.Errorf("%w: setgid %d: %w", ErrServeAsRoot, cfg.GID, err)
	}
	if err := id.setuid(cfg.UID); err != nil {
		return fmt.Errorf("%w: setuid %d: %w", ErrServeAsRoot, cfg.UID, err)
	}
	if id.geteuid() != cfg.UID || id.getuid() != cfg.UID || id.getegid() != cfg.GID {
		return fmt.Errorf("%w: the drop to %d:%d did not take", ErrServeAsRoot, cfg.UID, cfg.GID)
	}
	if id.setuid(0) == nil {
		return fmt.Errorf("%w: the process could return to root after the drop", ErrServeAsRoot)
	}
	return nil
}

// closeInheritedDescriptors closes every descriptor past stdio that survived the
// exec, so nothing the spawner leaked stays reachable from a process parsing
// pusher input. A descriptor that survived an exec has FD_CLOEXEC clear; the Go
// runtime and the system libraries set it on everything they open, and a guarded
// system descriptor must carry it, so testing it leaves those alone. An
// unreadable descriptor table refuses the start.
func closeInheritedDescriptors() error {
	entries, err := os.ReadDir("/dev/fd")
	if err != nil {
		return fmt.Errorf("list the inherited descriptors: %w", err)
	}
	for _, e := range entries {
		fd, err := strconv.Atoi(e.Name())
		if err != nil || fd <= int(syscall.Stderr) {
			continue
		}
		flags, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0)
		if errors.Is(err, unix.EBADF) {
			continue // the directory listing's own descriptor, now closed
		}
		if err != nil {
			return fmt.Errorf("inspect descriptor %d: %w", fd, err)
		}
		if flags&unix.FD_CLOEXEC != 0 {
			continue
		}
		if err := unix.Close(fd); err != nil {
			return fmt.Errorf("close inherited descriptor %d: %w", fd, err)
		}
	}
	return nil
}

// checkDataVolume refuses a store root off the configured data volume, before
// the store is opened. Comparing st_dev alone would pass on a missed boot mount:
// the empty mount point and the store under it are then both on the system
// volume. So the volume must also be mounted, a different device from its parent
// directory. A store root that does not exist yet is judged by its nearest
// existing ancestor, the directory it would be created on.
func checkDataVolume(volume, storeRoot string) error {
	if volume == "" {
		return nil
	}
	var vol, parent unix.Stat_t
	if err := unix.Stat(volume, &vol); err != nil {
		return fmt.Errorf("%w: stat %s: %w", ErrOffDataVolume, volume, err)
	}
	if err := unix.Stat(filepath.Dir(volume), &parent); err != nil {
		return fmt.Errorf("%w: stat the parent of %s: %w", ErrOffDataVolume, volume, err)
	}
	if vol.Dev == parent.Dev {
		return fmt.Errorf("%w: nothing is mounted at %s", ErrOffDataVolume, volume)
	}
	at := storeRoot
	var root unix.Stat_t
	for {
		err := unix.Stat(at, &root)
		if err == nil {
			break
		}
		if !errors.Is(err, unix.ENOENT) || at == filepath.Dir(at) {
			return fmt.Errorf("%w: stat %s: %w", ErrOffDataVolume, at, err)
		}
		at = filepath.Dir(at)
	}
	if root.Dev != vol.Dev {
		return fmt.Errorf("%w: %s is on device %d, %s on device %d", ErrOffDataVolume, at, root.Dev, volume, vol.Dev)
	}
	return nil
}

// openServeLog opens registry.log for appending, 0600. It appends because the
// daemon's redirect of the child's stdio shares the file.
func openServeLog(workDir string) (*os.File, error) {
	f, err := openRegistryLog(workDir, 0)
	if err != nil {
		return nil, fmt.Errorf("open the registry log: %w", err)
	}
	return f, nil
}

// openRegistryLog opens registry.log for appending, 0600, with extra flags. It
// follows no symlink and accepts only a regular file, so neither the daemon nor
// the server writes through something planted at the name. O_TRUNC touches only
// what O_NOFOLLOW opened, and a non-file ignores it.
func openRegistryLog(workDir string, extra int) (*os.File, error) {
	f, err := os.OpenFile(LogPath(workDir), os.O_WRONLY|os.O_APPEND|os.O_CREATE|syscall.O_NOFOLLOW|extra, 0o600)
	if err != nil {
		return nil, err
	}
	fi, err := f.Stat()
	if err == nil && !fi.Mode().IsRegular() {
		err = fmt.Errorf("%s is not a regular file", f.Name())
	}
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	return f, nil
}

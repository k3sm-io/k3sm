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
	"log/slog"
	"maps"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// LoopbackAddress is the ONLY address the ingest registry binds.
//
// It is a constant and not a setting: pull is anonymous, so a registry reachable
// off-host is an unauthenticated read of every image the cluster runs, and push
// is plain HTTP, so a credential presented to a non-loopback listener crosses the
// wire in the clear. Both stop being true the moment the bind leaves loopback,
// which is why New refuses one rather than documenting the hazard.
const LoopbackAddress = "127.0.0.1"

// Bring-up and teardown timings, matching the control plane's own child-process
// conventions (pkg/executor): a bounded wait for the listener, then a SIGTERM
// with a grace period before SIGKILL.
const (
	readyTimeout = 60 * time.Second
	readyPoll    = 200 * time.Millisecond
	// readyProbeTimeout bounds one /v2/ readiness probe.
	readyProbeTimeout = time.Second
	drainGrace        = 5 * time.Second
	// startAttempts bounds the retry. The registry is an ancillary service: a
	// transient failure deserves another try, and a persistent one deserves a
	// logged refusal rather than an unbounded retry loop holding a boot open.
	startAttempts = 3
	retryDelay    = 2 * time.Second
)

// The refusals a caller distinguishes. They are sentinels because "you asked for
// a bind this service will never do" and "something else already holds the port"
// call for opposite responses.
var (
	// ErrNonLoopbackBind: the configured bind address is not a loopback address.
	ErrNonLoopbackBind = errors.New("the ingest registry binds loopback only")
	// ErrPortHeld: the configured port is already held by another process.
	ErrPortHeld = errors.New("registry port already held")
	// ErrExecutableMoved: this binary no longer resolves to the path recorded when
	// the daemon started, so the spawn would run something the release path did
	// not verify.
	ErrExecutableMoved = errors.New("this binary is not the one the daemon started from")
)

// Config configures a Service.
type Config struct {
	// WorkDir is the control-plane work dir. Every registry path derives from it
	// (StateDir, ConfigPath, HTPasswdPath, CredentialPath, LogPath).
	WorkDir string
	// BinDir is where an earlier release staged its zot binary, which the orphan
	// reclaim still recognises. Empty derives <WorkDir>/bin.
	BinDir string
	// Port is the loopback TCP port to serve on. Required; there is no default
	// here on purpose, because "the registry is enabled" is the caller's decision
	// and a defaulted port would make it this package's.
	Port int
	// BindAddress is the address to bind. Empty means LoopbackAddress; anything
	// that is not a loopback address is refused by New.
	BindAddress string
	// DataVolume is the mount point of the data volume the work dir is on, or
	// empty when the install has none. The child refuses to start when the store
	// root is not on it.
	DataVolume string
	// Executable resolves the running binary; nil is os.Executable through
	// symlinks. New records its answer, and every spawn compares against that.
	Executable func() (string, error)
	// Logger receives bring-up and teardown events. Empty means slog.Default.
	Logger *slog.Logger
	// Quota is the byte quota per artifactType the server enforces at manifest
	// PUT (--registry-quota), rendered into the serve config. New refuses one
	// that is not a media type mapped to a positive count.
	Quota map[string]int64
}

// Service is the node-local OCI ingest registry: a `k3sm registry serve` child
// process on loopback, with its state, config and per-boot push credential under
// the work dir.
//
// The zero value is not usable — construct one with New, which is where the
// loopback-only bind is enforced.
type Service struct {
	cfg Config
	// exe and exeErr are Config.Executable's answer at New: the binary the
	// release path verified before this daemon started.
	exe    string
	exeErr error
	// geteuid is the process's effective uid (a seam for tests).
	geteuid func() int
	// lookupProc re-reads one process before each reclaim signal (a seam for
	// tests).
	lookupProc func(pid int) (procEntry, bool)

	// mu guards every field below it. It is held across the process-state
	// mutations (start, stop) and released before any wait, so a Shutdown racing
	// a Start observes a consistent view without either blocking the other for
	// the length of a bring-up.
	mu     sync.Mutex
	cmd    *exec.Cmd
	log    *os.File
	exited chan struct{}
	// reclaimedPID is the orphaned child the current Start reclaimed, or 0. It
	// is reset at the top of every Start and decides whether the serving
	// record says StateServing or StateReclaimed.
	reclaimedPID int
	// gateCred is the push gate's credential for the running child, minted
	// with the htpasswd file it was written into and never written in
	// plaintext. Zero until a bring-up attempt has provisioned.
	gateCred Credential
}

// New validates cfg and returns a Service.
//
// It REFUSES a non-loopback bind address with ErrNonLoopbackBind. That refusal is
// the enforcement point for the posture LoopbackAddress documents: anonymous pull
// plus plaintext push is safe exactly because nothing off this host can reach the
// listener, and a configuration that could relax it would make the safety a
// convention instead of a property.
func New(cfg Config) (*Service, error) {
	if cfg.WorkDir == "" {
		return nil, errors.New("registry: work dir is required")
	}
	if cfg.BindAddress == "" {
		cfg.BindAddress = LoopbackAddress
	}
	if err := validateBind(cfg.BindAddress, cfg.Port); err != nil {
		return nil, err
	}
	if err := validQuotas(cfg.Quota); err != nil {
		return nil, fmt.Errorf("registry: %w", err)
	}
	cfg.Quota = maps.Clone(cfg.Quota)
	if cfg.BinDir == "" {
		cfg.BinDir = filepath.Join(cfg.WorkDir, "bin")
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.Executable == nil {
		cfg.Executable = resolvedExecutable
	}
	exe, exeErr := cfg.Executable()
	return &Service{cfg: cfg, exe: exe, exeErr: exeErr, geteuid: os.Geteuid, lookupProc: lookupOwnProcess}, nil
}

// resolvedExecutable is os.Executable through symlinks. On Darwin os.Executable
// reports the path as invoked, which for an install is the /usr/local/bin link.
func resolvedExecutable() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	return filepath.EvalSymlinks(exe)
}

// validateBind rejects any bind that is not a loopback address, and any port
// outside the usable range. It is shared by New and validateForServing so the
// address the server binds cannot differ from the one the service claims to have
// validated.
func validateBind(address string, port int) error {
	addr, err := netip.ParseAddr(strings.Trim(address, "[]"))
	if err != nil {
		return fmt.Errorf("%w: %q is not an IP address", ErrNonLoopbackBind, address)
	}
	if !addr.IsLoopback() {
		return fmt.Errorf("%w: %s is reachable off this host, and the registry serves anonymous pulls over plain HTTP", ErrNonLoopbackBind, address)
	}
	if port <= 0 || port > 65535 {
		return fmt.Errorf("registry port %d out of range 1-65535", port)
	}
	return nil
}

// Addr returns the host:port the registry serves on. It is derived from the
// validated configuration, so it is the same string before and after a start.
func (s *Service) Addr() string {
	return net.JoinHostPort(s.cfg.BindAddress, strconv.Itoa(s.cfg.Port))
}

// GateCredential returns the credential the push gate forwards an authorized
// write with: the push gate's registry user, valid for the child this Service
// last provisioned. It is held in memory only. Zero before a Start.
func (s *Service) GateCredential() Credential {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.gateCred
}

// Port returns the port the registry serves on — what the KEP-1755 ConfigMap and
// every "localhost:<port>" reference are built from.
func (s *Service) Port() int { return s.cfg.Port }

// Start provisions the registry's state and brings the child up, retrying a
// bounded number of times.
//
// It NEVER kills the control plane: the caller logs a returned error and carries
// on, because a cluster without an ingest registry is a cluster that cannot
// ingest images, while a cluster that refused to boot over one is a cluster that
// does nothing at all. The bounded retry is here rather than at the caller so the
// backoff and the give-up point are the same in every posture.
func (s *Service) Start(ctx context.Context) error {
	s.mu.Lock()
	s.reclaimedPID = 0
	s.mu.Unlock()
	// A root daemon is not retried: the child refuses root, and the state a root
	// daemon writes is root's own, which a child dropped to the service user
	// could not open. An installed server runs as the service user.
	if s.geteuid() == 0 {
		err := fmt.Errorf("%w: a server running as root has no ingest registry", ErrServeAsRoot)
		s.record(StateDisabled, err.Error(), 0)
		return err
	}
	var err error
	for attempt := 1; attempt <= startAttempts; attempt++ {
		err = s.startOnce(ctx)
		if err == nil {
			s.cfg.Logger.Info("ingest registry serving",
				"addr", s.Addr(), "storage", StateDir(s.cfg.WorkDir), "credential", CredentialPath(s.cfg.WorkDir))
			s.mu.Lock()
			reclaimed := s.reclaimedPID
			s.mu.Unlock()
			if reclaimed != 0 {
				s.record(StateReclaimed, "", reclaimed)
			} else {
				s.record(StateServing, "", 0)
			}
			return nil
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if attempt < startAttempts {
			s.cfg.Logger.Warn("ingest registry did not come up; retrying",
				"attempt", attempt, "of", startAttempts, "err", err)
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(retryDelay):
			}
		}
	}
	err = fmt.Errorf("bring up the ingest registry on %s after %d attempts: %w", s.Addr(), startAttempts, err)
	s.mu.Lock()
	reclaimed := s.reclaimedPID
	s.mu.Unlock()
	s.record(StateDisabled, err.Error(), reclaimed)
	return err
}

// startOnce is one bring-up attempt: write the state, preflight the port, spawn,
// and wait for the registry to answer.
func (s *Service) startOnce(ctx context.Context) error {
	if err := s.provision(); err != nil {
		return err
	}
	// Fail closed BEFORE the spawn if the port is already held: the readiness wait
	// below would be satisfied by the incumbent's listener, so a child that lost
	// its bind would leave the registry reporting itself up while every push went
	// to somebody else's registry. The one holder that is reclaimed first is a
	// previous server's orphaned child (orphan.go), which nothing else ever stops.
	if err := s.claimPort(ctx); err != nil {
		return err
	}
	c, err := s.spawn()
	if err != nil {
		return err
	}
	if err := s.await(ctx, c); err != nil {
		s.stop(context.WithoutCancel(ctx))
		return err
	}
	return nil
}

// provision creates the state dir and writes the per-boot credential and the
// rendered config. It runs on every attempt, which is what makes an attempt
// self-contained: a retry after a half-written state dir rewrites all of it.
func (s *Service) provision() error {
	// 0700: the directory holds the plaintext push credential and the bcrypt file
	// beside the blob store, and no other user on this Mac has business in it.
	// openStateDir refuses a symlinked or foreign directory and narrows a wider
	// mode of this user's own, which a bare MkdirAll would leave as it found it.
	d, err := openStateDir(StateDir(s.cfg.WorkDir))
	if err != nil {
		return err
	}
	_ = d.Close() // read-only directory handle; the checks are done, nothing to flush
	addr := net.JoinHostPort(s.cfg.BindAddress, strconv.Itoa(s.cfg.Port))
	cred, err := generateCredential(addr)
	if err != nil {
		return err
	}
	gate, err := generateGateCredential(addr)
	if err != nil {
		return err
	}
	if err := WriteCredential(s.cfg.WorkDir, cred, gate); err != nil {
		return err
	}
	s.mu.Lock()
	s.gateCred = gate
	s.mu.Unlock()
	// The k3sm registry server authenticates against the serve config, which
	// carries the two principals' secret hashes; it is rewritten with the
	// credentials on every attempt so the two never disagree.
	serve, err := renderServeConfig(cred, gate, ServeConfig{
		Listen:     addr,
		DataVolume: s.cfg.DataVolume,
		UID:        s.geteuid(),
		GID:        os.Getegid(),
		Quota:      s.cfg.Quota,
	})
	if err != nil {
		return err
	}
	return writeServeConfig(s.cfg.WorkDir, serve)
}

// preflightPort reports ErrPortHeld when something already holds the bind. The
// probe is a real net.Listen on the exact address the child will bind — nothing
// weaker distinguishes "free" from "free for somebody else", and the listener is
// closed immediately, so the window between the probe and the child's own bind is
// the spawn itself.
func preflightPort(address string, port int) error {
	addr := net.JoinHostPort(address, strconv.Itoa(port))
	ln, err := net.Listen("tcp", addr)
	if err == nil {
		return ln.Close()
	}
	return fmt.Errorf("%w: %s is already in use, so the registry would serve nothing while something else answered on its port (probe: %v)",
		ErrPortHeld, addr, err)
}

// childCommand builds the child: exactly <exe> registry serve --config
// <work-dir>/registry-state/serve.json, with the executable resolved again and
// compared with the one New recorded, an empty environment, and no descriptor
// beyond stdio (exec.Cmd passes only what ExtraFiles names).
func (s *Service) childCommand() (*exec.Cmd, error) {
	if s.exeErr != nil {
		return nil, fmt.Errorf("locate this binary: %w", s.exeErr)
	}
	now, err := s.cfg.Executable()
	if err != nil {
		return nil, fmt.Errorf("locate this binary: %w", err)
	}
	if now != s.exe {
		return nil, fmt.Errorf("%w: %s at start, %s now", ErrExecutableMoved, s.exe, now)
	}
	argv := s.childArgv()
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Env = []string{}
	// Its own process group, so teardown signals the child and anything it started
	// rather than this process's whole group.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	return cmd, nil
}

// childArgv is the child's exact argument vector, which the reclaim also matches.
func (s *Service) childArgv() []string {
	return []string{s.exe, "registry", "serve", "--config", ServeConfigPath(s.cfg.WorkDir)}
}

// spawn starts the child in its own process group with its output redirected to
// the 0600 registry log, and starts the single reaper goroutine that closes the
// exited channel when the child dies. The reaper's lifetime is the child's; it
// parks in wait4 and ends exactly when the child does.
//
// The log is opened O_APPEND because the child opens it too, for its slog
// records; its own stderr keeps the refusals it makes before that open and any
// runtime crash. Each spawn truncates it, as a bound on its size.
//
// The child is deliberately NOT attached to a context (exec.Command, not
// CommandContext): its lifetime is owned by Shutdown, which tears it down in the
// signal order a registry holding a port needs, and a context kill would race
// that with a bare SIGKILL and leave the log file open.
func (s *Service) spawn() (chan struct{}, error) {
	cmd, err := s.childCommand()
	if err != nil {
		return nil, err
	}
	lf, err := openRegistryLog(s.cfg.WorkDir, os.O_TRUNC)
	if err != nil {
		return nil, fmt.Errorf("create the registry log: %w", err)
	}
	cmd.Stdout, cmd.Stderr = lf, lf
	if err := cmd.Start(); err != nil {
		_ = lf.Close()
		return nil, fmt.Errorf("start the registry: %w", err)
	}
	exited := make(chan struct{})
	go func() {
		_ = cmd.Wait()
		close(exited)
	}()

	s.mu.Lock()
	s.cmd, s.log, s.exited = cmd, lf, exited
	s.mu.Unlock()

	s.cfg.Logger.Info("started the ingest registry child",
		"pid", cmd.Process.Pid, "exe", s.exe, "log", LogPath(s.cfg.WorkDir))
	return exited, nil
}

// registryReady reports whether the registry at addr answers GET /v2/ with 200.
// A connect alone says nothing: anything holding the port accepts one. It reads
// no proxy setting, since addr is loopback, and follows no redirect, so it opens
// no connection but the one to addr.
func registryReady(ctx context.Context, addr string) error {
	ctx, cancel := context.WithTimeout(ctx, readyProbeTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+addr+"/v2/", nil)
	if err != nil {
		return err
	}
	client := http.Client{
		Transport:     &http.Transport{DisableKeepAlives: true},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET /v2/: %s", resp.Status)
	}
	return nil
}

// await blocks until the child answers /v2/ with 200, the child exits, the
// deadline passes, or ctx is cancelled. A closed exited channel WINS over a
// concurrent answer: a dead child is never "serving", and the incumbent that
// would answer instead is exactly the confusion preflightPort exists to stop.
func (s *Service) await(ctx context.Context, exited <-chan struct{}) error {
	addr := net.JoinHostPort(s.cfg.BindAddress, strconv.Itoa(s.cfg.Port))
	deadline := time.Now().Add(readyTimeout)
	for {
		select {
		case <-exited:
			return fmt.Errorf("the registry exited during bring-up: %s", s.logTail())
		default:
		}
		err := registryReady(ctx, addr)
		if err == nil {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("the registry was not serving on %s within %s: %w: %s", addr, readyTimeout, err, s.logTail())
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-exited:
			return fmt.Errorf("the registry exited during bring-up: %s", s.logTail())
		case <-time.After(readyPoll):
		}
	}
}

// logTailLines is how much of the child's log a bring-up failure carries. Enough
// to show the child's own refusal, short enough to stay a log line.
const logTailLines = 20

// logTail returns the last logTailLines lines of the child's log, best-effort: an
// unreadable log yields a placeholder so the caller's error stays actionable.
func (s *Service) logTail() string {
	b, err := os.ReadFile(LogPath(s.cfg.WorkDir))
	if err != nil {
		return fmt.Sprintf("<unreadable registry log: %v>", err)
	}
	lines := strings.Split(strings.TrimRight(string(b), "\n"), "\n")
	if len(lines) > logTailLines {
		lines = lines[len(lines)-logTailLines:]
	}
	return strings.Join(lines, "\n")
}

// Shutdown SIGTERMs the child's process group, waits drainGrace for the reaper to
// observe the exit, then SIGKILLs if it has not, and closes the log. It is
// idempotent and safe on a service that never started. Stopping a running child
// records StateStopped.
func (s *Service) Shutdown(ctx context.Context) error {
	if s.stop(ctx) {
		s.record(StateStopped, "", 0)
	}
	return nil
}

// stop is Shutdown without the state record, which is also how a failed
// bring-up attempt tears its own child down: that child never served, and the
// attempt's outcome is Start's to record. It reports whether a child was
// running.
func (s *Service) stop(ctx context.Context) bool {
	s.mu.Lock()
	cmd, lf, exited := s.cmd, s.log, s.exited
	s.cmd, s.log, s.exited = nil, nil, nil
	s.mu.Unlock()

	if cmd == nil || cmd.Process == nil {
		return false
	}
	pid := cmd.Process.Pid
	_ = syscall.Kill(-pid, syscall.SIGTERM)
	select {
	case <-exited:
	case <-ctx.Done():
		// The caller's shutdown budget is spent. Kill rather than leak: the child
		// holds the registry port, and a survivor would refuse the next boot's bind.
		_ = syscall.Kill(-pid, syscall.SIGKILL)
		<-exited
	case <-time.After(drainGrace):
		_ = syscall.Kill(-pid, syscall.SIGKILL)
		<-exited
	}
	if lf != nil {
		_ = lf.Close()
	}
	s.cfg.Logger.Info("stopped the ingest registry child", "pid", pid)
	return true
}

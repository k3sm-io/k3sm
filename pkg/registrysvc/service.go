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
	"net"
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
	drainGrace   = 5 * time.Second
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
)

// Config configures a Service.
type Config struct {
	// WorkDir is the control-plane work dir. Every registry path derives from it
	// (StateDir, ConfigPath, HTPasswdPath, CredentialPath, LogPath).
	WorkDir string
	// BinDir is where the zot binary is staged. Empty derives <WorkDir>/bin, the
	// same directory the control-plane binaries live in.
	BinDir string
	// PayloadBinDir is a packaged install's staged payload directory. Empty means
	// none is staged, and the binary is built on demand.
	PayloadBinDir string
	// Port is the loopback TCP port to serve on. Required; there is no default
	// here on purpose, because "the registry is enabled" is the caller's decision
	// and a defaulted port would make it this package's.
	Port int
	// BindAddress is the address to bind. Empty means LoopbackAddress; anything
	// that is not a loopback address is refused by New.
	BindAddress string
	// ZotVersion is the zot module version to stage. Empty means DefaultZotVersion.
	ZotVersion string
	// Logger receives bring-up and teardown events. Empty means slog.Default.
	Logger *slog.Logger
}

// Service is the node-local OCI ingest registry: a pinned zot child process on
// loopback, with its state, config and per-boot push credential under the work
// dir.
//
// The zero value is not usable — construct one with New, which is where the
// loopback-only bind is enforced.
type Service struct {
	cfg Config

	// mu guards every field below it. It is held across the process-state
	// mutations (start, stop) and released before any wait, so a Shutdown racing
	// a Start observes a consistent view without either blocking the other for
	// the length of a bring-up.
	mu     sync.Mutex
	cmd    *exec.Cmd
	log    *os.File
	exited chan struct{}
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
	if cfg.BinDir == "" {
		cfg.BinDir = filepath.Join(cfg.WorkDir, "bin")
	}
	if cfg.ZotVersion == "" {
		cfg.ZotVersion = DefaultZotVersion
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	return &Service{cfg: cfg}, nil
}

// validateBind rejects any bind that is not a loopback address, and any port
// outside the usable range. It is shared by New and renderConfig so the address
// written into the child's config cannot differ from the one the service claims
// to have validated.
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
	var err error
	for attempt := 1; attempt <= startAttempts; attempt++ {
		err = s.startOnce(ctx)
		if err == nil {
			s.cfg.Logger.Info("ingest registry serving",
				"addr", s.Addr(), "storage", StateDir(s.cfg.WorkDir), "credential", CredentialPath(s.cfg.WorkDir))
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
	return fmt.Errorf("bring up the ingest registry on %s after %d attempts: %w", s.Addr(), startAttempts, err)
}

// startOnce is one bring-up attempt: stage the binary, write the state, preflight
// the port, spawn, and wait for the listener.
func (s *Service) startOnce(ctx context.Context) error {
	if err := EnsureZot(ctx, s.cfg.BinDir, s.cfg.PayloadBinDir, s.cfg.ZotVersion); err != nil {
		return err
	}
	if err := s.provision(); err != nil {
		return err
	}
	// Fail closed BEFORE the spawn if the port is already held: the readiness wait
	// below would be satisfied by the incumbent's listener, so a child that lost
	// its bind would leave the registry reporting itself up while every push went
	// to somebody else's registry.
	if err := preflightPort(s.cfg.BindAddress, s.cfg.Port); err != nil {
		return err
	}
	c, err := s.spawn()
	if err != nil {
		return err
	}
	if err := s.await(ctx, c); err != nil {
		s.Shutdown(context.WithoutCancel(ctx))
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
	if err := os.MkdirAll(StateDir(s.cfg.WorkDir), 0o700); err != nil {
		return fmt.Errorf("create the registry state dir: %w", err)
	}
	cred, err := generateCredential(net.JoinHostPort(s.cfg.BindAddress, strconv.Itoa(s.cfg.Port)))
	if err != nil {
		return err
	}
	if err := WriteCredential(s.cfg.WorkDir, cred); err != nil {
		return err
	}
	body, err := renderConfig(s.cfg.WorkDir, s.cfg.BindAddress, s.cfg.Port)
	if err != nil {
		return err
	}
	// 0600 like the credential: the config names the htpasswd path and the storage
	// root, which is inventory nothing else on the host needs.
	if err := writeSecretFile(ConfigPath(s.cfg.WorkDir), body); err != nil {
		return fmt.Errorf("write the registry config: %w", err)
	}
	return nil
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

// spawn starts the zot child in its own process group with its output redirected
// to the 0600 registry log, and starts the single reaper goroutine that closes
// the exited channel when the child dies. The reaper's lifetime is the child's;
// it parks in wait4 and ends exactly when the child does.
//
// The child is deliberately NOT attached to a context (exec.Command, not
// CommandContext): its lifetime is owned by Shutdown, which tears it down in the
// signal order a registry holding a port needs, and a context kill would race
// that with a bare SIGKILL and leave the log file open.
func (s *Service) spawn() (chan struct{}, error) {
	lf, err := os.OpenFile(LogPath(s.cfg.WorkDir), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return nil, fmt.Errorf("create the registry log: %w", err)
	}
	//nolint:gosec // the binary is the one this package staged and marked, at a path it owns.
	cmd := exec.Command(ZotPath(s.cfg.BinDir), "serve", ConfigPath(s.cfg.WorkDir))
	cmd.Stdout, cmd.Stderr = lf, lf
	// Its own process group, so teardown signals the child and anything it started
	// rather than this process's whole group.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
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
		"pid", cmd.Process.Pid, "version", s.cfg.ZotVersion, "log", LogPath(s.cfg.WorkDir))
	return exited, nil
}

// await blocks until the child's listener accepts a connection, the child exits,
// the deadline passes, or ctx is cancelled. A closed exited channel WINS over a
// concurrently-ready port: a dead child is never "serving", and the incumbent
// that would answer instead is exactly the confusion preflightPort exists to stop.
func (s *Service) await(ctx context.Context, exited <-chan struct{}) error {
	addr := net.JoinHostPort(s.cfg.BindAddress, strconv.Itoa(s.cfg.Port))
	deadline := time.Now().Add(readyTimeout)
	dialer := &net.Dialer{Timeout: time.Second}
	for {
		select {
		case <-exited:
			return fmt.Errorf("the registry exited during bring-up: %s", s.logTail())
		default:
		}
		conn, err := dialer.DialContext(ctx, "tcp", addr)
		if err == nil {
			_ = conn.Close()
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("the registry was not serving on %s within %s: %s", addr, readyTimeout, s.logTail())
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
// to show zot's own refusal (a bad config names the offending key), short enough
// to stay a log line.
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
// idempotent and safe on a service that never started.
func (s *Service) Shutdown(ctx context.Context) error {
	s.mu.Lock()
	cmd, lf, exited := s.cmd, s.log, s.exited
	s.cmd, s.log, s.exited = nil, nil, nil
	s.mu.Unlock()

	if cmd == nil || cmd.Process == nil {
		return nil
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
	return nil
}

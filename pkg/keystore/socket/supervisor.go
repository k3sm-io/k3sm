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

package socket

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"runtime/debug"
	"sync"
	"time"
)

// The supervisor's timing (docs/design/keystore.md, "Lifecycle").
const (
	// MinBackoff is the first wait after a listener failure or a failed
	// start check; each further one doubles it, up to MaxBackoff.
	MinBackoff = time.Second
	// MaxBackoff caps the wait between retries.
	MaxBackoff = 5 * time.Minute
	// HealthyPeriod is how long the listener must serve before a failure
	// for the backoff to start again from MinBackoff.
	HealthyPeriod = time.Minute
	// MaintenancePoll is how often the supervisor looks for the
	// maintenance marker: while serving, to stop when it appears, and
	// while it stands, to start again once it is gone. A client that
	// connects meanwhile waits in the socket's backlog.
	MaintenancePoll = 2 * time.Second
	// ReopenRetries is how many times in a row a failed log reopen is
	// retried at MaintenancePoll, so the listener is back within a poll of
	// a maintenance verb's end, before the doubling backoff takes over.
	ReopenRetries = 15
	// ServerPoll is how often a serving listener counts the cluster's
	// servers again: a second server stops it ("Single-server clusters
	// only"). Each count is bounded by the count's own timeout and runs in
	// its own poller, so a slow apiserver never delays the marker poll.
	ServerPoll = 30 * time.Second
	// ServerPollErrors is how many failed serving counts in a row stop the
	// listener, as a count that cannot be read keeps it from starting.
	ServerPollErrors = 3
)

// OffReason says why the user scope's listener is not serving. The set is
// closed; doctor shows it as "keystore user scope: off (<reason>)".
type OffReason string

// The reasons the listener is off.
const (
	OffNotInstalledServer   OffReason = "user scope needs the installed server"
	OffServiceUIDLoginRange OffReason = "the service uid is in the login range"
	OffMaintenance          OffReason = "a maintenance verb is running"
	OffMaintenanceUnknown   OffReason = "the maintenance marker cannot be read"
	OffIgnoresOwnership     OffReason = "the data root is mounted ignoring ownership"
	OffMountUnknown         OffReason = "the data root's mount flags cannot be read"
	OffInstall              OffReason = "the socket directory or an append-only log is missing, wrong or unflagged"
	OffLogsUnavailable      OffReason = "the append-only logs cannot be opened (logs-unavailable)"
	OffServers              OffReason = "more than one server registered"
	OffServersUnknown       OffReason = "the server count is unknown"
	OffListenerUnavailable  OffReason = "the listening socket is unavailable"
	OffListenerFailed       OffReason = "the listener failed"
	OffSandboxCheckUnusable OffReason = "the peer sandbox check is unusable (sandbox-check-unusable)"
	OffUserScopeStart       OffReason = "the user scope's start step failed"
)

// The supervisor's log text: every off line starts with offMsg, and the
// install line names the remedy.
const (
	offMsg        = "keystore user scope is off"
	installRemedy = "run `sudo k3sm install`"
)

// Phase is where the supervisor is.
type Phase string

// The phases.
const (
	PhaseStarting   Phase = "starting"    // Run has not finished its first start check
	PhaseServing    Phase = "serving"     // the listener accepts
	PhaseOff        Phase = "off"         // a start check failed; Reason says which
	PhaseBackingOff Phase = "backing-off" // the listener failed; it restarts at Until
	PhaseStopped    Phase = "stopped"     // Run has returned
)

// State is the supervisor's state for doctor. Reason is set when off or
// backing off, Detail carries the error behind it if there was one, and
// Until is when the next start is tried.
type State struct {
	Phase  Phase
	Reason OffReason
	Detail string
	Until  time.Time
}

// ListenerSource returns the listening socket to serve. The supervisor
// calls it before every start, the first and each restart, and never binds,
// unlinks or activates a socket itself. A source that returns the listener
// it returned before has it reused: between runs the supervisor stops
// accepting on it by expiring its deadline (SetDeadline, which a
// *net.UnixListener has), so the descriptor stays open and bound, and
// clears the deadline before serving it again. That is the activated form:
// launchd's descriptor is handed back every time. A listener without
// SetDeadline is closed when its run ends, so its source must return a new
// one. The supervisor closes a listener when its source returns a different
// one, and the last one when Run returns.
type ListenerSource func(ctx context.Context) (net.Listener, error)

// SupervisorConfig is what a Supervisor needs. Every func and interface is
// required, and ServiceUID must not be 0.
type SupervisorConfig struct {
	// Listen supplies the listening socket (see ListenerSource).
	Listen ListenerSource
	// EUID returns the process's effective uid; production passes
	// ProcessEUID.
	EUID func() int
	// ServiceUID is the service user's uid: the listener starts only when
	// EUID returns it, and refuses it as a peer.
	ServiceUID uint32
	// IgnoresOwnership reports whether the data root's file system is
	// mounted with MNT_IGNORE_OWNERSHIP; production opens the data root
	// afresh for each start-check pass and reads its descriptor's flags.
	IgnoresOwnership func() (bool, error)
	// EndPass, when set, ends one start-check pass: it runs once Check
	// returns, whatever the outcome, and production closes the pass's
	// data-root descriptor in it.
	EndPass func()
	// CheckInstall returns an error when the socket directory or either
	// append-only log is absent, wrong or unflagged.
	CheckInstall func(ctx context.Context) error
	// ServerCount returns how many servers the cluster has registered.
	ServerCount func(ctx context.Context) (int, error)
	// MaintenanceMarked reports whether the maintenance marker stands. It
	// only reads: the supervisor polls it while serving.
	MaintenanceMarked func() (bool, error)
	// OpenLogs reopens the server's audit and floor append descriptors and
	// recounts what is charged from the new files (Preconditions.OpenLogs);
	// production passes (*keystore.ServerLogs).Reopen.
	OpenLogs func(ctx context.Context) error
	// SandboxCheck is Preconditions.SandboxCheck; production passes
	// SandboxSelfCheck.
	SandboxCheck func() error
	// StartScopes is Preconditions.StartScopes; production runs the
	// store's start step (keystore.FileStore.StartUserScopes) in it.
	// Optional.
	StartScopes func(ctx context.Context) error
	// Creds, Sandbox, Audit and Handler are given to each run's Listener.
	Creds   PeerCredSource
	Sandbox PeerSandboxSource
	Audit   RefusalAuditor
	Handler *Handler
	// Clock times the backoff, the marker polls and the Listener's.
	Clock Clock
	// Log receives the supervisor's lines, and NewSupervisor gives it to
	// Handler for the store errors that are damage (logStoreError). Handler
	// is the supervisor's from then on: NewSupervisor refuses a Handler
	// another supervisor already owns.
	Log *slog.Logger
}

// Supervisor owns the user socket's listener: it runs the start checks,
// serves a Listener on the source's socket in a goroutine that recovers a
// panic, restarts it with backoff after a panic or an accept error, and
// stops it while the maintenance marker stands. It never ends the process.
type Supervisor struct {
	cfg SupervisorConfig

	mu    sync.Mutex // guards state
	state State
}

// NewSupervisor returns a Supervisor over cfg, refusing a missing
// dependency.
func NewSupervisor(cfg SupervisorConfig) (*Supervisor, error) {
	var missing string
	switch {
	case cfg.Listen == nil:
		missing = "listener source"
	case cfg.EUID == nil:
		missing = "euid source"
	case cfg.ServiceUID == 0:
		return nil, errors.New("keystore socket: the service uid is 0")
	case cfg.IgnoresOwnership == nil:
		missing = "mount-flag check"
	case cfg.CheckInstall == nil:
		missing = "install check"
	case cfg.ServerCount == nil:
		missing = "server count"
	case cfg.MaintenanceMarked == nil:
		missing = "maintenance marker check"
	case cfg.OpenLogs == nil:
		missing = "log reopen"
	case cfg.SandboxCheck == nil:
		missing = "sandbox self-check"
	case cfg.Creds == nil:
		missing = "peer-credential source"
	case cfg.Sandbox == nil:
		missing = "peer-sandbox source"
	case cfg.Audit == nil:
		missing = "refusal auditor"
	case cfg.Handler == nil:
		missing = "handler"
	case cfg.Clock == nil:
		missing = "clock"
	case cfg.Log == nil:
		missing = "logger"
	}
	if missing != "" {
		return nil, fmt.Errorf("keystore socket: nil %s", missing)
	}
	// The supervisor owns its handler: the handler's damage lines go where
	// the supervisor's lines go, the server's log, set here, before Run
	// starts anything that serves, so no goroutine reads log while it is
	// set. A handler is given to one supervisor only, so no other owner's
	// logger is replaced under it.
	if !cfg.Handler.supervised.CompareAndSwap(false, true) {
		return nil, errors.New("keystore socket: the handler is already another supervisor's")
	}
	cfg.Handler.log = cfg.Log
	return &Supervisor{cfg: cfg, state: State{Phase: PhaseStarting}}, nil
}

// State returns the supervisor's current state. It is safe for concurrent
// use.
func (s *Supervisor) State() State {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.state
}

func (s *Supervisor) set(st State) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.state = st
}

// Run supervises the listener until ctx is done, then cuts its connections,
// closes the listening socket and returns. It is called once.
func (s *Supervisor) Run(ctx context.Context) {
	var cur net.Listener
	defer func() {
		if cur != nil {
			_ = cur.Close() // the server is stopping: nothing is left to serve on it
		}
		s.set(State{Phase: PhaseStopped})
	}()
	// checkBackoff spaces failed start checks and starts again from
	// MinBackoff whenever every check passes; runBackoff spaces listener
	// failures and starts again only after a run served HealthyPeriod (or
	// stopped for the marker), so a listener that fails at once after
	// every passing check still backs off.
	checkBackoff, runBackoff := MinBackoff, MinBackoff
	reopenTries := 0
	var last OffReason
	for ctx.Err() == nil {
		reason, detail := s.check(ctx)
		if reason != OffLogsUnavailable {
			reopenTries = 0
		}
		if reason != "" {
			wait := checkBackoff
			switch {
			case reason == OffMaintenance:
				// The marker is waited out, not backed off from, so the
				// listener is back within a poll of the verb's end.
				wait = MaintenancePoll
			case reason == OffLogsUnavailable && reopenTries < ReopenRetries:
				// A reopen right after the marker clears can meet the verb's
				// last step; it is retried at the marker's pace for a while.
				reopenTries++
				wait = MaintenancePoll
			default:
				checkBackoff = nextBackoff(checkBackoff)
			}
			s.off(reason, detail, last, wait)
			last = reason
			if !s.wait(ctx, wait) {
				return
			}
			continue
		}
		checkBackoff = MinBackoff
		last = ""
		ln, err := guard(func() (net.Listener, error) { return s.cfg.Listen(ctx) })
		if err == nil && ln == nil {
			err = errors.New("the listener source returned no socket")
		}
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			if !s.backOff(ctx, OffListenerUnavailable, err, &runBackoff) {
				return
			}
			continue
		}
		if cur != nil && cur != ln {
			_ = cur.Close() // replaced by the source: never served again
		}
		cur = ln
		started := s.cfg.Clock.Now()
		end, stopped, err := s.serve(ctx, ln)
		if _, pausable := ln.(deadliner); !pausable {
			_ = ln.Close() // it cannot be paused, so its run ends it; Serve may have closed it already
			cur = nil
		}
		switch end {
		case endDone:
			return
		case endMarker:
			runBackoff = MinBackoff
		case endServers:
			// Not a failure of the listener: the start checks decide, after
			// the start-check backoff, whether it may serve again.
			runBackoff = MinBackoff
			wait := checkBackoff
			checkBackoff = nextBackoff(checkBackoff)
			s.off(stopped, err.Error(), last, wait)
			last = stopped
			if !s.wait(ctx, wait) {
				return
			}
		case endFailed:
			if s.cfg.Clock.Now().Sub(started) >= HealthyPeriod {
				runBackoff = MinBackoff
			}
			if !s.backOff(ctx, OffListenerFailed, err, &runBackoff) {
				return
			}
		}
	}
}

// check runs the start checks over the supervisor's config.
func (s *Supervisor) check(ctx context.Context) (OffReason, string) {
	return Preconditions{
		EUID:              s.cfg.EUID,
		ServiceUID:        s.cfg.ServiceUID,
		MaintenanceMarked: s.cfg.MaintenanceMarked,
		OpenLogs:          s.cfg.OpenLogs,
		IgnoresOwnership:  s.cfg.IgnoresOwnership,
		CheckInstall:      s.cfg.CheckInstall,
		ServerCount:       s.cfg.ServerCount,
		SandboxCheck:      s.cfg.SandboxCheck,
		StartScopes:       s.cfg.StartScopes,
		EndPass:           s.cfg.EndPass,
	}.Check(ctx)
}

// Preconditions are the user scope's start checks, the ones the Supervisor
// runs before each start and doctor re-runs in its own process, so the two
// cannot disagree about why the listener is off. Every func is required.
type Preconditions struct {
	// EUID returns the effective uid of the process that would listen.
	EUID func() int
	// ServiceUID is the service user's uid.
	ServiceUID uint32
	// MaintenanceMarked reports whether the maintenance marker stands,
	// reading it only.
	MaintenanceMarked func() (bool, error)
	// OpenLogs is the step after the marker: the supervisor reopens both
	// append-only logs on it, so the listener starts against the files as
	// they are now (after maintenance swapped them, too); doctor judges
	// both logs read-only, holding and writing nothing. An error keeps the
	// listener off with OffLogsUnavailable.
	OpenLogs func(ctx context.Context) error
	// IgnoresOwnership reports whether the data root is mounted with
	// MNT_IGNORE_OWNERSHIP.
	IgnoresOwnership func() (bool, error)
	// CheckInstall returns an error when the socket directory or either
	// append-only log is absent, wrong or unflagged.
	CheckInstall func(ctx context.Context) error
	// ServerCount returns how many servers the cluster has registered.
	ServerCount func(ctx context.Context) (int, error)
	// SandboxCheck is the start-time control on the peer-sandbox check;
	// production passes SandboxSelfCheck. An error keeps the listener off
	// with OffSandboxCheckUnusable, and so does a nil one. It runs before
	// the server count.
	SandboxCheck func() error
	// StartScopes is optional and runs last, once every other check has
	// passed: the supervisor runs the store's start step in it (the log
	// bounds check, then the delivery catch-up), so the listener never
	// serves a store whose user scope did not start; doctor runs the
	// step's read-only half, the log bounds check. An error keeps the
	// listener off with OffUserScopeStart and the store's reason.
	StartScopes func(ctx context.Context) error
	// EndPass is optional: when set, Check calls it once it returns, so a
	// descriptor the pass opened (the data root, opened afresh by
	// IgnoresOwnership) is closed when the pass ends.
	EndPass func()
}

// Check runs the start checks in the design's order (the effective uid, the
// mount flags, the installed files, the maintenance marker, the log reopen,
// the sandbox self-check, a server count of exactly one, the user scope's
// start step) and returns the
// first reason the listener may not start, with its error's text, or ""
// when every check passes. Nothing is opened on the data root before its
// mount flags and the installed files are vetted, so an install that
// predates the logs is reported as the install reason, naming its remedy.
//
// A check that panics is recovered and fails as that check: its reason,
// with the panic as its detail.
func (p Preconditions) Check(ctx context.Context) (OffReason, string) {
	if p.EndPass != nil {
		defer func() { _, _ = guard(func() (struct{}, error) { p.EndPass(); return struct{}{}, nil }) }()
	}
	euid, err := guard(func() (int, error) { return p.EUID(), nil })
	if err != nil {
		return OffNotInstalledServer, err.Error()
	}
	if euid < 0 || uint64(euid) != uint64(p.ServiceUID) {
		return OffNotInstalledServer, fmt.Sprintf("effective uid %d is not the service uid %d", euid, p.ServiceUID)
	}
	// The service uid is a system account: refused as a peer before the
	// login range is judged, it must lie below the range, or a login user
	// sharing it would be refused as the service uid and a refusal under
	// it would be charged as a login line's.
	if p.ServiceUID >= MinPeerUID {
		return OffServiceUIDLoginRange, fmt.Sprintf("the service uid %d is not below %d", p.ServiceUID, MinPeerUID)
	}
	if ignores, err := guard(p.IgnoresOwnership); err != nil {
		return OffMountUnknown, err.Error()
	} else if ignores {
		return OffIgnoresOwnership, "MNT_IGNORE_OWNERSHIP is set"
	}
	if _, err := guard(func() (struct{}, error) { return struct{}{}, p.CheckInstall(ctx) }); err != nil {
		return OffInstall, err.Error()
	}
	if marked, err := guard(p.MaintenanceMarked); err != nil {
		return OffMaintenanceUnknown, err.Error()
	} else if marked {
		return OffMaintenance, ""
	}
	if _, err := guard(func() (struct{}, error) { return struct{}{}, p.OpenLogs(ctx) }); err != nil {
		return OffLogsUnavailable, err.Error()
	}
	if p.SandboxCheck == nil {
		return OffSandboxCheckUnusable, "no sandbox self-check"
	}
	if _, err := guard(func() (struct{}, error) { return struct{}{}, p.SandboxCheck() }); err != nil {
		return OffSandboxCheckUnusable, err.Error()
	}
	n, err := guard(func() (int, error) { return p.ServerCount(ctx) })
	switch {
	case err != nil:
		return OffServersUnknown, err.Error()
	case n > 1:
		return OffServers, fmt.Sprintf("%d servers registered", n)
	case n < 1:
		return OffServersUnknown, fmt.Sprintf("%d servers registered", n)
	}
	if p.StartScopes != nil {
		if _, err := guard(func() (struct{}, error) { return struct{}{}, p.StartScopes(ctx) }); err != nil {
			return OffUserScopeStart, err.Error()
		}
	}
	return "", ""
}

// errPanicked is an injected step that panicked; the supervisor treats it
// as that step failing.
var errPanicked = errors.New("keystore socket: recovered a panic")

// guard calls f, turning a panic in it into an error wrapping errPanicked
// that names the panic. The supervisor logs it with the step's off or
// backoff line; the stack is not kept, so a doctor detail stays one line.
func guard[T any](f func() (T, error)) (v T, err error) {
	defer func() {
		if r := recover(); r != nil {
			var zero T
			v, err = zero, fmt.Errorf("%w: %v", errPanicked, r)
		}
	}()
	return f()
}

// Remedy is the command the server log and doctor name for r, or "" when
// no command puts it right: only a missing, wrong or unflagged installed
// file names `sudo k3sm install`.
func (r OffReason) Remedy() string {
	if r == OffInstall {
		return installRemedy
	}
	return ""
}

// off records a failed start check and logs it: the install Warn on every
// retry, the marker once when it first stands, a server that is not the
// installed one (a rootless server, a permanent state) once at Info until
// it changes, every other reason each time at Warn.
func (s *Supervisor) off(reason OffReason, detail string, last OffReason, wait time.Duration) {
	s.set(State{Phase: PhaseOff, Reason: reason, Detail: detail, Until: s.cfg.Clock.Now().Add(wait)})
	switch reason {
	case OffMaintenance:
		if last != OffMaintenance {
			s.cfg.Log.Info(offMsg+": the listener is down while the maintenance marker stands", "reason", string(reason))
		}
	case OffNotInstalledServer:
		if last != OffNotInstalledServer {
			s.cfg.Log.Info(offMsg, "reason", string(reason), "err", detail)
		}
	case OffInstall:
		s.cfg.Log.Warn(offMsg+"; "+reason.Remedy(), "reason", string(reason), "err", detail, "retry", wait)
	default:
		s.cfg.Log.Warn(offMsg, "reason", string(reason), "err", detail, "retry", wait)
	}
}

// backOff records and logs a listener failure and waits out the backoff,
// doubling it. It reports false when ctx ended the wait.
func (s *Supervisor) backOff(ctx context.Context, reason OffReason, err error, backoff *time.Duration) bool {
	wait := *backoff
	*backoff = nextBackoff(wait)
	detail := ""
	if err != nil {
		detail = err.Error()
	}
	s.set(State{Phase: PhaseBackingOff, Reason: reason, Detail: detail, Until: s.cfg.Clock.Now().Add(wait)})
	s.cfg.Log.Error("keystore socket: listener down, restarting", "reason", string(reason), "err", detail, "retry", wait)
	return s.wait(ctx, wait)
}

// wait waits d on the clock, reporting false when ctx ends it first.
func (s *Supervisor) wait(ctx context.Context, d time.Duration) bool {
	tick, stop := s.cfg.Clock.After(d)
	defer stop()
	select {
	case <-ctx.Done():
		return false
	case <-tick:
		return true
	}
}

// nextBackoff doubles d up to MaxBackoff.
func nextBackoff(d time.Duration) time.Duration {
	return min(2*d, MaxBackoff)
}

// How a run ended.
type runEnd int

const (
	endDone    runEnd = iota // ctx is done
	endMarker                // the maintenance marker stands, or cannot be read
	endServers               // a serving count found a second server, or failed ServerPollErrors times
	endFailed                // a panic, an accept error or a failed restart
)

// serverCount is one serving count's result.
type serverCount struct {
	n   int
	err error
}

// pollServers counts the servers every ServerPoll until ctx is done,
// sending each result on out. It is serve's poller: serve cancels ctx and
// waits for it before returning.
func (s *Supervisor) pollServers(ctx context.Context, out chan<- serverCount) {
	for {
		tick, stop := s.cfg.Clock.After(ServerPoll)
		select {
		case <-ctx.Done():
			stop()
			return
		case <-tick:
		}
		n, err := guard(func() (int, error) { return s.cfg.ServerCount(ctx) })
		select {
		case out <- serverCount{n: n, err: err}:
		case <-ctx.Done():
			return
		}
	}
}

// deadliner is a listening socket whose Accept can be stopped without
// closing it.
type deadliner interface {
	SetDeadline(t time.Time) error
}

// pauseOnClose is the Listener's view of a reusable socket: the Listener
// closes its socket to end Accept, and this ends Accept by expiring the
// deadline instead, leaving the descriptor open and bound.
type pauseOnClose struct {
	net.Listener
	d deadliner
}

// Close implements net.Listener.
func (p pauseOnClose) Close() error { return p.d.SetDeadline(time.Unix(1, 0)) }

// serve runs one Listener on ln until ctx is done, the Listener panics or
// fails to accept, the maintenance marker is seen, or a serving count finds
// a second server or fails ServerPollErrors times in a row (endServers,
// with the off reason). Its connections are cut before it returns.
func (s *Supervisor) serve(ctx context.Context, ln net.Listener) (runEnd, OffReason, error) {
	served := ln
	if d, ok := ln.(deadliner); ok {
		if err := d.SetDeadline(time.Time{}); err != nil {
			return endFailed, "", fmt.Errorf("clear the listener's deadline: %w", err)
		}
		served = pauseOnClose{Listener: ln, d: d}
	}
	l, err := NewListener(served, s.cfg.Creds, s.cfg.Sandbox, s.cfg.ServiceUID, s.cfg.Clock, s.cfg.Audit, s.cfg.Handler)
	if err != nil {
		return endFailed, "", err
	}
	l.log = s.cfg.Log
	runCtx, cut := context.WithCancel(ctx)
	defer cut()
	done := make(chan error, 1)
	go func() {
		defer func() {
			if v := recover(); v != nil {
				s.cfg.Log.Error("keystore socket: listener panicked", "panic", fmt.Sprint(v), "stack", string(debug.Stack()))
				done <- fmt.Errorf("listener panic: %v", v)
			}
		}()
		done <- l.Serve(runCtx)
	}()
	counts := make(chan serverCount)
	var poller sync.WaitGroup
	poller.Go(func() { s.pollServers(runCtx, counts) })
	defer func() {
		cut()
		poller.Wait()
	}()
	s.set(State{Phase: PhaseServing})
	s.cfg.Log.Info("keystore socket: listener serving")
	countErrs := 0
	tick, stop := s.cfg.Clock.After(MaintenancePoll)
	defer func() { stop() }()
	for {
		select {
		case err := <-done:
			if ctx.Err() != nil {
				return endDone, "", nil
			}
			if err == nil {
				err = errors.New("the listener returned")
			}
			return endFailed, "", err
		case <-ctx.Done():
			cut()
			<-done
			return endDone, "", nil
		case c := <-counts:
			var reason OffReason
			var why error
			switch {
			case c.err == nil && c.n == 1:
				countErrs = 0
				continue
			case c.err == nil && c.n > 1:
				reason, why = OffServers, fmt.Errorf("%d servers registered", c.n)
			default:
				if countErrs++; countErrs < ServerPollErrors {
					continue
				}
				why = c.err
				if why == nil {
					why = fmt.Errorf("%d servers registered", c.n)
				}
				reason, why = OffServersUnknown, fmt.Errorf("%d serving counts in a row failed: %w", countErrs, why)
			}
			cut()
			<-done
			s.cfg.Log.Warn("keystore socket: listener stopped by the server count", "reason", string(reason), "err", why.Error())
			return endServers, reason, why
		case <-tick:
		}
		marked, err := guard(s.cfg.MaintenanceMarked)
		if err == nil && !marked {
			tick, stop = s.cfg.Clock.After(MaintenancePoll)
			continue
		}
		// Fail closed: an unreadable marker stops the listener too, and the
		// start check reports why.
		cut()
		<-done
		s.cfg.Log.Info("keystore socket: listener stopped for the maintenance marker")
		return endMarker, "", nil
	}
}

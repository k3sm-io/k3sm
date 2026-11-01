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

package api

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"runtime/debug"
	"time"

	"github.com/gorilla/mux"
	"golang.org/x/sys/unix"

	"k3sm.io/k3sm/pkg/ociregistry/ref"
	"k3sm.io/k3sm/pkg/ociregistry/store"
)

// Defaults for the Config limits.
const (
	// DefaultMaxSessions is the most upload sessions in use at once.
	DefaultMaxSessions = 64
	// DefaultMinFreeSpace is the free space below which new uploads are
	// refused with 507.
	DefaultMinFreeSpace = 2 << 30
	// DefaultSessionIdle is how long a session the server tracks may sit
	// unused before it stops counting against MaxSessions; it matches the
	// garbage collector's grace for idle uploads.
	DefaultSessionIdle = time.Hour
	// DefaultBodyIdle is the longest a request body may go without a byte.
	DefaultBodyIdle = 2 * time.Minute
	// DefaultBodyWindow and DefaultBodyMinBytes are the minimum progress of a
	// request body: at least DefaultBodyMinBytes in every DefaultBodyWindow
	// until it ends (about 4 KiB/s).
	DefaultBodyWindow   = time.Minute
	DefaultBodyMinBytes = 256 << 10
	// DefaultUploadTimeout bounds the whole of one request that carries a
	// body (an upload chunk, a monolithic upload, a manifest PUT).
	DefaultUploadTimeout = 2 * time.Hour
	// DefaultMaxUploadSize is the most bytes one upload session may hold.
	DefaultMaxUploadSize = 16 << 30
	// DefaultResponseTimeout is the time any response has to be written,
	// before the time a blob's size adds at DefaultMinWriteRate.
	DefaultResponseTimeout = 2 * time.Minute
	// DefaultMinWriteRate is the slowest rate, in bytes per second, a blob
	// GET is given time for.
	DefaultMinWriteRate = 512 << 10
	// spaceCheckEvery is how many body bytes an upload streams between two
	// free-space checks.
	spaceCheckEvery = 64 << 20
	// ReadHeaderTimeout bounds reading a request's headers.
	ReadHeaderTimeout = 30 * time.Second
	// maxHeaderBytes bounds a request's headers.
	maxHeaderBytes = 64 << 10
)

// Verb is the kind of access a request needs.
type Verb int

// The verbs.
const (
	// VerbRead is a GET or HEAD.
	VerbRead Verb = iota
	// VerbWrite is an upload, a mount or a manifest PUT.
	VerbWrite
	// VerbDelete is a manifest or tag DELETE, or an upload cancel.
	VerbDelete
)

// String names the verb.
func (v Verb) String() string {
	switch v {
	case VerbRead:
		return "read"
	case VerbWrite:
		return "write"
	case VerbDelete:
		return "delete"
	}
	return fmt.Sprintf("verb(%d)", int(v))
}

// Errors an Authorizer returns.
var (
	// ErrUnauthenticated is a request that needs credentials and has none
	// (401 with a Basic challenge).
	ErrUnauthenticated = errors.New("authentication required")
	// ErrDenied is a principal without the permission (403 DENIED).
	ErrDenied = errors.New("access denied")
	// ErrRateLimited is a source over its failure budget (429).
	ErrRateLimited = errors.New("rate limited")
)

// Authorizer decides whether r may do verb on repository n. n is the zero
// Name for the version check and the catalog itself. Any error refuses the
// request; ErrUnauthenticated, ErrDenied and ErrRateLimited choose the answer,
// and any other error is a 500.
type Authorizer func(r *http.Request, verb Verb, n ref.Name) error

// AllowAll is an Authorizer that allows every request. A server has no
// default access model, so a caller that wants an open registry says so by
// passing it.
func AllowAll(*http.Request, Verb, ref.Name) error { return nil }

// Config configures a Server. Store and Authorize are required; every other
// field has a default.
type Config struct {
	// Store is the on-disk store the server serves.
	Store *store.Store
	// Logger receives the server's records; nil discards them.
	Logger *slog.Logger
	// Authorize is asked before every request is served. It is required: New
	// refuses a nil Authorizer rather than allow everything (AllowAll does
	// that on purpose).
	Authorize Authorizer
	// FreeSpace reports the free bytes of the store volume; nil asks statfs
	// about the store root.
	FreeSpace func() (uint64, error)
	// MinFreeSpace is the free space below which new uploads get 507
	// (DefaultMinFreeSpace when zero).
	MinFreeSpace uint64
	// MaxSessions is the most upload sessions in use at once
	// (DefaultMaxSessions when zero).
	MaxSessions int
	// SessionIdle is how long a session may go unused before it stops
	// counting against MaxSessions (DefaultSessionIdle when zero).
	SessionIdle time.Duration
	// BodyIdle is the longest a request body may go without a byte
	// (DefaultBodyIdle when zero).
	BodyIdle time.Duration
	// BodyWindow and BodyMinBytes are the minimum progress of a request
	// body: at least BodyMinBytes in every BodyWindow, or the request fails
	// with 408 (DefaultBodyWindow and DefaultBodyMinBytes when zero).
	BodyWindow   time.Duration
	BodyMinBytes int64
	// UploadTimeout bounds the whole of a request that carries a body
	// (DefaultUploadTimeout when zero).
	UploadTimeout time.Duration
	// MaxUploadSize is the most bytes one upload session may hold; a chunk
	// that would pass it is refused with 413 and leaves the session as it was
	// (DefaultMaxUploadSize when zero).
	MaxUploadSize int64
	// ResponseTimeout is the time a response has to be written, and
	// MinWriteRate the slowest rate a blob GET is given time for on top of it
	// (DefaultResponseTimeout and DefaultMinWriteRate when zero). The write
	// deadline is set per request, so a large blob GET is never cut by a
	// server-wide timeout.
	ResponseTimeout time.Duration
	MinWriteRate    int64
	// Now is the clock (time.Now when nil).
	Now func() time.Time
}

// Server serves the distribution API. It is an http.Handler and is safe for
// concurrent use.
type Server struct {
	st            *store.Store
	log           *slog.Logger
	authorize     Authorizer
	freeSpace     func() (uint64, error)
	minFree       uint64
	bodyIdle      time.Duration
	bodyWindow    time.Duration
	bodyMinBytes  int64
	uploadTimeout time.Duration
	maxUpload     int64
	respTimeout   time.Duration
	minWriteRate  int64
	spaceEvery    int64
	now           func() time.Time
	sessions      *sessions
	router        *mux.Router
	// setWriteDeadline sets a response's write deadline (a seam for tests;
	// the default goes through http.ResponseController).
	setWriteDeadline func(w http.ResponseWriter, t time.Time)
	// manifestChecked, when set, runs between a manifest PUT's first blob
	// check and the index write (a seam for tests that race a sweep).
	manifestChecked func()
	// manifestRead, when set, runs between a manifest HEAD's read and its
	// touch (a seam for tests that reap the manifest in between).
	manifestRead func()
	// sessionAdmitted and chunkAppending, when set, run after a new session's
	// slot is reserved and before a chunk is appended (seams for tests that
	// make those steps panic).
	sessionAdmitted func()
	chunkAppending  func()
}

// New returns a Server over cfg.Store. It logs the effective RLIMIT_NOFILE,
// since every request holds descriptors only while it runs.
func New(cfg Config) (*Server, error) {
	if cfg.Store == nil {
		return nil, errors.New("registry api: no store")
	}
	if cfg.Authorize == nil {
		return nil, errors.New("registry api: no authorizer (pass AllowAll for an open registry)")
	}
	s := &Server{
		st:            cfg.Store,
		log:           logger(cfg.Logger),
		authorize:     cfg.Authorize,
		freeSpace:     cfg.FreeSpace,
		minFree:       cfg.MinFreeSpace,
		bodyIdle:      positive(cfg.BodyIdle, DefaultBodyIdle),
		bodyWindow:    positive(cfg.BodyWindow, DefaultBodyWindow),
		bodyMinBytes:  positive(cfg.BodyMinBytes, DefaultBodyMinBytes),
		uploadTimeout: positive(cfg.UploadTimeout, DefaultUploadTimeout),
		maxUpload:     positive(cfg.MaxUploadSize, DefaultMaxUploadSize),
		respTimeout:   positive(cfg.ResponseTimeout, DefaultResponseTimeout),
		minWriteRate:  positive(cfg.MinWriteRate, DefaultMinWriteRate),
		spaceEvery:    spaceCheckEvery,
		setWriteDeadline: func(w http.ResponseWriter, t time.Time) {
			_ = http.NewResponseController(w).SetWriteDeadline(t) // ErrNotSupported off a real connection
		},
	}
	if s.freeSpace == nil {
		root := cfg.Store.Root()
		s.freeSpace = func() (uint64, error) { return statfsFree(root) }
	}
	if s.minFree == 0 {
		s.minFree = DefaultMinFreeSpace
	}
	maxSessions, idle, now := cfg.MaxSessions, cfg.SessionIdle, cfg.Now
	if maxSessions <= 0 {
		maxSessions = DefaultMaxSessions
	}
	if idle <= 0 {
		idle = DefaultSessionIdle
	}
	if now == nil {
		now = time.Now
	}
	s.now = now
	s.sessions = newSessions(maxSessions, idle, now)
	var rl unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_NOFILE, &rl); err == nil {
		s.log.Info("registry api ready", "root", cfg.Store.Root(), "rlimit_nofile", rl.Cur, "max_sessions", maxSessions)
	}
	s.router = s.routes()
	return s, nil
}

// positive returns v, or def when v is not positive.
func positive[T int64 | time.Duration](v, def T) T {
	if v <= 0 {
		return def
	}
	return v
}

// statfsFree returns the bytes available to an unprivileged writer on the
// volume holding p.
func statfsFree(p string) (uint64, error) {
	var st unix.Statfs_t
	if err := unix.Statfs(p, &st); err != nil {
		return 0, fmt.Errorf("statfs %s: %w", p, err)
	}
	return st.Bavail * uint64(st.Bsize), nil
}

// HTTPServer returns an http.Server for s on addr: a 30 s header read
// timeout and no overall read or write timeout (request bodies have the
// progress bound instead, and each response gets its own write deadline),
// bounded headers, and errors logged through the server's logger.
func (s *Server) HTTPServer(addr string) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           s,
		ReadHeaderTimeout: ReadHeaderTimeout,
		IdleTimeout:       2 * time.Minute,
		MaxHeaderBytes:    maxHeaderBytes,
		ErrorLog:          slog.NewLogLogger(s.log.Handler(), slog.LevelWarn),
	}
}

// ServeHTTP serves one request, recovering from a panic in any handler. It
// sets the response's write deadline: ResponseTimeout, after UploadTimeout for
// a request that carries a body; a blob GET moves it out by the blob's size.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	window := s.respTimeout
	switch r.Method {
	case http.MethodPost, http.MethodPut, http.MethodPatch:
		window += s.uploadTimeout
	}
	s.setWriteDeadline(w, s.now().Add(window))
	w.Header().Set("X-Content-Type-Options", "nosniff")
	defer func() {
		v := recover()
		if v == nil {
			return
		}
		if v == http.ErrAbortHandler {
			panic(v)
		}
		s.log.Error("registry handler panicked", "method", r.Method, "path", r.URL.Path, "panic", fmt.Sprint(v), "stack", string(debug.Stack()))
		s.writeError(w, r, errorf(http.StatusInternalServerError, codeUnavailable, "internal error"))
	}()
	s.router.ServeHTTP(w, r)
}

// routes is the route table. A repository name spans path segments; each
// handler validates it (and every other path or query value) through ref.
func (s *Server) routes() *mux.Router {
	r := mux.NewRouter()
	// A path is never cleaned or redirected: a name with an empty or dot
	// segment is refused by the validator instead.
	r.SkipClean(true)
	const name = "/v2/{name:.+}"
	r.HandleFunc("/v2/", s.version).Methods(http.MethodGet, http.MethodHead)
	r.HandleFunc("/v2", s.version).Methods(http.MethodGet, http.MethodHead)
	r.HandleFunc("/v2/_catalog", s.catalog).Methods(http.MethodGet)
	r.HandleFunc(name+"/tags/list", s.withName(s.tags)).Methods(http.MethodGet)
	r.HandleFunc(name+"/manifests/{reference:[^/]+}", s.withName(s.getManifest)).Methods(http.MethodGet, http.MethodHead)
	r.HandleFunc(name+"/manifests/{reference:[^/]+}", s.withName(s.putManifest)).Methods(http.MethodPut)
	r.HandleFunc(name+"/manifests/{reference:[^/]+}", s.withName(s.deleteManifest)).Methods(http.MethodDelete)
	r.HandleFunc(name+"/blobs/uploads/", s.withName(s.startUpload)).Methods(http.MethodPost)
	r.HandleFunc(name+"/blobs/uploads", s.withName(s.startUpload)).Methods(http.MethodPost)
	r.HandleFunc(name+"/blobs/uploads/{uuid:[^/]+}", s.withName(s.uploadStatus)).Methods(http.MethodGet)
	r.HandleFunc(name+"/blobs/uploads/{uuid:[^/]+}", s.withName(s.patchUpload)).Methods(http.MethodPatch)
	r.HandleFunc(name+"/blobs/uploads/{uuid:[^/]+}", s.withName(s.finishUpload)).Methods(http.MethodPut)
	r.HandleFunc(name+"/blobs/uploads/{uuid:[^/]+}", s.withName(s.cancelUpload)).Methods(http.MethodDelete)
	r.HandleFunc(name+"/blobs/{digest:[^/]+}", s.withName(s.getBlob)).Methods(http.MethodGet, http.MethodHead)
	r.HandleFunc(name+"/blobs/{digest:[^/]+}", s.withName(s.deleteBlob)).Methods(http.MethodDelete)
	r.HandleFunc(name+"/referrers/{digest:[^/]+}", s.withName(s.referrers)).Methods(http.MethodGet)
	r.NotFoundHandler = http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		s.writeError(w, req, errorf(http.StatusNotFound, codeUnsupported, "no such endpoint"))
	})
	r.MethodNotAllowedHandler = http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		s.writeError(w, req, errorf(http.StatusMethodNotAllowed, codeUnsupported, "method not allowed"))
	})
	return r
}

// nameHandler is a handler for a route under a repository name, given the
// validated name.
type nameHandler func(w http.ResponseWriter, r *http.Request, n ref.Name)

// withName validates the route's repository name before calling h.
func (s *Server) withName(h nameHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		n, err := ref.ParseName(mux.Vars(r)["name"])
		if err != nil {
			s.fail(w, r, err)
			return
		}
		h(w, r, n)
	}
}

// allow asks the Authorizer, answering the refusal itself; it reports whether
// the request may proceed.
func (s *Server) allow(w http.ResponseWriter, r *http.Request, verb Verb, n ref.Name) bool {
	err := s.authorize(r, verb, n)
	if err == nil {
		return true
	}
	if !errors.Is(err, ErrUnauthenticated) && !errors.Is(err, ErrDenied) && !errors.Is(err, ErrRateLimited) {
		err = fmt.Errorf("authorize %s on %q: %w", verb, n.String(), err)
	}
	s.fail(w, r, err)
	return false
}

// version answers the API version check.
func (s *Server) version(w http.ResponseWriter, r *http.Request) {
	if !s.allow(w, r, VerbRead, ref.Name{}) {
		return
	}
	w.Header().Set("Docker-Distribution-API-Version", "registry/2.0")
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if r.Method != http.MethodHead {
		_, _ = io.WriteString(w, "{}")
	}
}

// Errors a request body fails with.
var (
	// errBodyTooSlow is a body that went BodyIdle without a byte, or a
	// BodyWindow with fewer than BodyMinBytes.
	errBodyTooSlow = errors.New("request body too slow")
	// errRequestTooLong is a body still arriving after UploadTimeout.
	errRequestTooLong = errors.New("request took too long")
)

// progressBody wraps a request body so that it must keep making progress: no
// read may wait longer than idle, every window must bring at least minBytes,
// and nothing is read after deadline. The connection's read deadline is moved
// to the earliest of those bounds before each read, so a stalled peer is cut
// by the kernel rather than waited on; where it cannot be set (an in-process
// transport) the checks between reads still hold. It is used by one goroutine.
type progressBody struct {
	rc       *http.ResponseController
	body     io.Reader
	now      func() time.Time
	idle     time.Duration
	window   time.Duration
	minBytes int64
	deadline time.Time

	winStart time.Time
	winBytes int64
}

func (b *progressBody) Read(p []byte) (int, error) {
	t := b.now()
	if !t.Before(b.deadline) {
		return 0, errRequestTooLong
	}
	if t.Sub(b.winStart) >= b.window {
		if b.winBytes < b.minBytes {
			return 0, errBodyTooSlow
		}
		b.winStart, b.winBytes = t, 0
	}
	dl := t.Add(b.idle)
	if end := b.winStart.Add(b.window); b.winBytes < b.minBytes && end.Before(dl) {
		dl = end
	}
	if b.deadline.Before(dl) {
		dl = b.deadline
	}
	_ = b.rc.SetReadDeadline(dl) // ErrNotSupported off a real connection
	n, err := b.body.Read(p)
	b.winBytes += int64(n)
	if errors.Is(err, os.ErrDeadlineExceeded) {
		err = errBodyTooSlow
	}
	return n, err
}

// body returns r's body under the progress bounds, with UploadTimeout from
// now as its deadline.
func (s *Server) body(w http.ResponseWriter, r *http.Request) io.Reader {
	t := s.now()
	return &progressBody{
		rc: http.NewResponseController(w), body: r.Body, now: s.now,
		idle: s.bodyIdle, window: s.bodyWindow, minBytes: s.bodyMinBytes,
		deadline: t.Add(s.uploadTimeout), winStart: t,
	}
}

// writeWindow is the time a response of size bytes is given: ResponseTimeout
// plus size at MinWriteRate.
func (s *Server) writeWindow(size int64) time.Duration {
	const most = 30 * 24 * time.Hour
	secs := size / s.minWriteRate
	if secs >= int64(most/time.Second) {
		return most
	}
	return s.respTimeout + time.Duration(secs)*time.Second + time.Duration(size%s.minWriteRate)*time.Second/time.Duration(s.minWriteRate)
}

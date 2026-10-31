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

// Config configures a Server. Store is required; every other field has a
// default.
type Config struct {
	// Store is the on-disk store the server serves.
	Store *store.Store
	// Logger receives the server's records; nil discards them.
	Logger *slog.Logger
	// Authorize, when set, is asked before every request is served. Nil
	// allows everything (the access model is the caller's).
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
	// Now is the clock (time.Now when nil).
	Now func() time.Time
}

// Server serves the distribution API. It is an http.Handler and is safe for
// concurrent use.
type Server struct {
	st        *store.Store
	log       *slog.Logger
	authorize Authorizer
	freeSpace func() (uint64, error)
	minFree   uint64
	bodyIdle  time.Duration
	sessions  *sessions
	router    *mux.Router
	// manifestChecked, when set, runs between a manifest PUT's first blob
	// check and the index write (a seam for tests that race a sweep).
	manifestChecked func()
}

// New returns a Server over cfg.Store. It logs the effective RLIMIT_NOFILE,
// since every request holds descriptors only while it runs.
func New(cfg Config) (*Server, error) {
	if cfg.Store == nil {
		return nil, errors.New("registry api: no store")
	}
	s := &Server{
		st:        cfg.Store,
		log:       logger(cfg.Logger),
		authorize: cfg.Authorize,
		freeSpace: cfg.FreeSpace,
		minFree:   cfg.MinFreeSpace,
		bodyIdle:  cfg.BodyIdle,
	}
	if s.freeSpace == nil {
		root := cfg.Store.Root()
		s.freeSpace = func() (uint64, error) { return statfsFree(root) }
	}
	if s.minFree == 0 {
		s.minFree = DefaultMinFreeSpace
	}
	if s.bodyIdle <= 0 {
		s.bodyIdle = DefaultBodyIdle
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
	s.sessions = newSessions(maxSessions, idle, now)
	var rl unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_NOFILE, &rl); err == nil {
		s.log.Info("registry api ready", "root", cfg.Store.Root(), "rlimit_nofile", rl.Cur, "max_sessions", maxSessions)
	}
	s.router = s.routes()
	return s, nil
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
// timeout and no overall body timeout (request bodies have the per-read idle
// bound instead), bounded headers, and errors logged through the server's
// logger.
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

// ServeHTTP serves one request, recovering from a panic in any handler.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
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
	if s.authorize == nil {
		return true
	}
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

// idleBody wraps a request body so that each read must make progress within
// the idle bound: the connection's read deadline moves forward on every read.
// Where the deadline cannot be set (an in-process transport) it is a no-op.
type idleBody struct {
	rc   *http.ResponseController
	body io.Reader
	idle time.Duration
}

func (b idleBody) Read(p []byte) (int, error) {
	_ = b.rc.SetReadDeadline(time.Now().Add(b.idle)) // ErrNotSupported off a real connection
	return b.body.Read(p)
}

func (s *Server) body(w http.ResponseWriter, r *http.Request) io.Reader {
	return idleBody{rc: http.NewResponseController(w), body: r.Body, idle: s.bodyIdle}
}

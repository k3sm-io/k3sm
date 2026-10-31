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
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"os"

	"k3sm.io/k3sm/pkg/ociregistry/ref"
	"k3sm.io/k3sm/pkg/ociregistry/store"
)

// Error codes of the distribution specification.
const (
	codeBlobUnknown         = "BLOB_UNKNOWN"
	codeBlobUploadInvalid   = "BLOB_UPLOAD_INVALID"
	codeBlobUploadUnknown   = "BLOB_UPLOAD_UNKNOWN"
	codeDigestInvalid       = "DIGEST_INVALID"
	codeManifestBlobUnknown = "MANIFEST_BLOB_UNKNOWN"
	codeManifestInvalid     = "MANIFEST_INVALID"
	codeManifestUnknown     = "MANIFEST_UNKNOWN"
	codeNameInvalid         = "NAME_INVALID"
	codeNameUnknown         = "NAME_UNKNOWN"
	codeSizeInvalid         = "SIZE_INVALID"
	codeUnauthorized        = "UNAUTHORIZED"
	codeDenied              = "DENIED"
	codeUnsupported         = "UNSUPPORTED"
	codeTooManyRequests     = "TOOMANYREQUESTS"
	codePaginationInvalid   = "PAGINATION_NUMBER_INVALID"
	codeUnavailable         = "UNAVAILABLE"
)

// apiError is an error answered with the specification's JSON error body.
type apiError struct {
	status int
	code   string
	msg    string
	detail map[string]string
	// cause is logged, never sent.
	cause error
}

func (e *apiError) Error() string { return e.code + ": " + e.msg }

func errorf(status int, code, msg string) *apiError {
	return &apiError{status: status, code: code, msg: msg}
}

type errorBody struct {
	Errors []errorEntry `json:"errors"`
}

type errorEntry struct {
	Code    string            `json:"code"`
	Message string            `json:"message"`
	Detail  map[string]string `json:"detail,omitempty"`
}

// writeError answers e. A HEAD gets the status and headers only.
func (s *Server) writeError(w http.ResponseWriter, r *http.Request, e *apiError) {
	if e.status >= 500 {
		s.log.Error("registry request failed", "method", r.Method, "path", r.URL.Path, "status", e.status, "code", e.code, "err", e.cause)
	} else {
		s.log.Debug("registry request refused", "method", r.Method, "path", r.URL.Path, "status", e.status, "code", e.code, "err", e.cause)
	}
	if e.status == http.StatusUnauthorized {
		w.Header().Set("WWW-Authenticate", `Basic realm="k3sm registry"`)
	}
	b, _ := json.Marshal(errorBody{Errors: []errorEntry{{Code: e.code, Message: e.msg, Detail: e.detail}}}) // a struct of strings always encodes
	w.Header().Set("Content-Type", "application/json")
	w.Header().Del("Content-Length")
	w.WriteHeader(e.status)
	if r.Method != http.MethodHead {
		_, _ = w.Write(b) // the client went away; nothing else to tell it
	}
}

// classify maps an error from ref, the store or the authorizer to the answer
// a client gets. An unrecognised error is a 500 whose detail is only logged.
func classify(err error) *apiError {
	var ae *apiError
	if errors.As(err, &ae) {
		return ae
	}
	e := func(status int, code, msg string) *apiError {
		return &apiError{status: status, code: code, msg: msg, cause: err}
	}
	switch {
	case errors.Is(err, ref.ErrInvalidName), errors.Is(err, ref.ErrReservedName):
		return e(http.StatusBadRequest, codeNameInvalid, "invalid repository name")
	case errors.Is(err, ref.ErrInvalidDigest):
		return e(http.StatusBadRequest, codeDigestInvalid, "invalid digest")
	case errors.Is(err, ref.ErrInvalidTag):
		return e(http.StatusBadRequest, codeManifestInvalid, "invalid tag")
	case errors.Is(err, ref.ErrInvalidUploadID), errors.Is(err, store.ErrUploadUnknown):
		return e(http.StatusNotFound, codeBlobUploadUnknown, "blob upload unknown")
	case errors.Is(err, store.ErrRepositoryUnknown):
		return e(http.StatusNotFound, codeNameUnknown, "repository name not known to registry")
	case errors.Is(err, store.ErrManifestUnknown):
		return e(http.StatusNotFound, codeManifestUnknown, "manifest unknown")
	case errors.Is(err, store.ErrBlobUnknown):
		return e(http.StatusNotFound, codeBlobUnknown, "blob unknown to registry")
	case errors.Is(err, store.ErrDigestMismatch):
		return e(http.StatusBadRequest, codeDigestInvalid, "provided digest did not match uploaded content")
	case errors.Is(err, store.ErrOffsetMismatch):
		return e(http.StatusRequestedRangeNotSatisfiable, codeBlobUploadInvalid, "chunk does not start at the session offset")
	case errors.Is(err, ErrUnauthenticated):
		return e(http.StatusUnauthorized, codeUnauthorized, "authentication required")
	case errors.Is(err, ErrDenied):
		return e(http.StatusForbidden, codeDenied, "requested access to the resource is denied")
	case errors.Is(err, ErrRateLimited):
		return e(http.StatusTooManyRequests, codeTooManyRequests, "too many requests")
	case errors.Is(err, store.ErrUploadTooLarge):
		return e(http.StatusRequestEntityTooLarge, codeSizeInvalid, "the upload is larger than the registry accepts")
	case errors.Is(err, errInsufficientSpace):
		return e(http.StatusInsufficientStorage, codeSizeInvalid, "the registry volume is low on space")
	case errors.Is(err, errBodyTooSlow), errors.Is(err, errRequestTooLong):
		return e(http.StatusRequestTimeout, codeBlobUploadInvalid, "the request body did not arrive in time")
	case errors.Is(err, errTooManySessions):
		return e(http.StatusServiceUnavailable, codeUnavailable, "too many upload sessions in progress")
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded), errors.Is(err, os.ErrDeadlineExceeded):
		return e(http.StatusServiceUnavailable, codeUnavailable, "request did not complete")
	default:
		return e(http.StatusInternalServerError, codeUnavailable, "internal error")
	}
}

// fail answers err through classify.
func (s *Server) fail(w http.ResponseWriter, r *http.Request, err error) {
	s.writeError(w, r, classify(err))
}

// logger returns l, or a logger that discards when l is nil.
func logger(l *slog.Logger) *slog.Logger {
	if l != nil {
		return l
	}
	return slog.New(slog.DiscardHandler)
}

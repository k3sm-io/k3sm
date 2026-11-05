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
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/gorilla/mux"
	"github.com/opencontainers/go-digest"

	"k3sm.io/k3sm/pkg/ociregistry/ref"
	"k3sm.io/k3sm/pkg/ociregistry/store"
)

// getBlob serves a blob GET or HEAD through http.ServeContent: Range, 206,
// 416 and Accept-Ranges are the standard library's.
func (s *Server) getBlob(w http.ResponseWriter, r *http.Request, n ref.Name) {
	d, err := ref.ParseDigest(mux.Vars(r)["digest"])
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if !s.allow(w, r, VerbRead, n) {
		return
	}
	f, err := s.st.OpenBlob(n, d)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		s.fail(w, r, err)
		return
	}
	// A HEAD is how a pushing client decides to skip an upload, so it
	// restarts the blob's GC grace: the manifest PUT that follows finds the
	// blob still there. The write is bounded (headTouch): never while half
	// the grace is left, and a failed touch is logged, not answered. If GC
	// reaped the blob after the open above, the touch finds it gone and the
	// HEAD answers 404. A GET (a pull) writes nothing.
	if r.Method == http.MethodHead && !s.graceFresh(fi.ModTime()) {
		if err := s.headTouch(r.Context(), n, d); err != nil {
			s.fail(w, r, err)
			return
		}
	}
	end := s.now().Add(s.writeWindow(fi.Size()))
	s.setWriteDeadline(w, end)
	h := w.Header()
	h.Set("Docker-Content-Digest", d.String())
	h.Set("Content-Type", "application/octet-stream")
	h.Set("ETag", `"`+d.String()+`"`)
	http.ServeContent(s.floored(w, r, fi.Size(), end), r, "", time.Time{}, f)
}

// graceFresh reports whether an object last touched at mtime has more than
// half the GC grace left, so a HEAD leaves it alone and takes no lock.
func (s *Server) graceFresh(mtime time.Time) bool {
	return s.now().Sub(mtime) < s.gcGrace/2
}

// blobModTime returns the mtime of blob d in n.
func (s *Server) blobModTime(n ref.Name, d digest.Digest) (time.Time, error) {
	f, err := s.st.OpenBlob(n, d)
	if err != nil {
		return time.Time{}, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return time.Time{}, err
	}
	return fi.ModTime(), nil
}

// headTouch restarts blob d's GC grace in n for a HEAD. A blob GC removed
// since the HEAD read it is ErrBlobUnknown, which the HEAD answers with 404;
// any other failure (a read-only or degraded store, a client gone while it
// waited for the lock) is logged and the HEAD is answered as if the touch
// were made: the touch only protects a push that may follow, and the read
// itself succeeded. After such a failure the object is not touched again, and
// its lock not taken, for half the grace, and the failure is logged once for
// that window rather than once per HEAD.
func (s *Server) headTouch(ctx context.Context, n ref.Name, d digest.Digest) error {
	k := touchKey{repo: n.String(), digest: d}
	if s.touchFails.suppressed(k, s.now()) {
		return nil
	}
	err := s.st.TouchBlob(ctx, n, d)
	if err == nil || errors.Is(err, store.ErrBlobUnknown) {
		return err
	}
	s.touchFails.add(k, s.now().Add(s.gcGrace/2))
	s.log.Warn("registry head: grace touch failed, answering the HEAD; no touch of this object for half the grace",
		"repository", n.String(), "digest", d.String(), "suppress_for", s.gcGrace/2, "err", err)
	return nil
}

// deleteBlob refuses: blobs leave the store through garbage collection only,
// which is the one place that knows whether a manifest still names them.
func (s *Server) deleteBlob(w http.ResponseWriter, r *http.Request, n ref.Name) {
	if !s.allow(w, r, VerbDelete, n) {
		return
	}
	if _, err := ref.ParseDigest(mux.Vars(r)["digest"]); err != nil {
		s.fail(w, r, err)
		return
	}
	s.writeError(w, r, errorf(http.StatusMethodNotAllowed, codeUnsupported, "blobs are removed by garbage collection"))
}

// sessionKey is the session table key of upload id in n.
func sessionKey(n ref.Name, id string) string { return n.String() + "\x00" + id }

// uploadHeaders sets the headers every upload session answer carries.
func uploadHeaders(w http.ResponseWriter, n ref.Name, id string, size int64) {
	h := w.Header()
	h.Set("Location", "/v2/"+n.String()+"/blobs/uploads/"+id)
	h.Set("Range", formatRange(size))
	h.Set("Blob-Upload-UUID", id)
	h.Set("Docker-Upload-UUID", id)
	h.Set("Content-Length", "0")
}

// blobCreated answers 201 for blob d of n.
func blobCreated(w http.ResponseWriter, n ref.Name, d digest.Digest) {
	h := w.Header()
	h.Set("Location", "/v2/"+n.String()+"/blobs/"+d.String())
	h.Set("Docker-Content-Digest", d.String())
	h.Set("Content-Length", "0")
	w.WriteHeader(http.StatusCreated)
}

// one returns the single value of query key, "" when absent, and an error when
// it is repeated.
func one(r *http.Request, key string) (string, bool, error) {
	v, ok := r.URL.Query()[key]
	switch {
	case !ok:
		return "", false, nil
	case len(v) != 1:
		return "", true, errorf(http.StatusBadRequest, codeBlobUploadInvalid, "query parameter "+key+" given more than once")
	}
	return v[0], true, nil
}

// startUpload is POST .../blobs/uploads/: a mount (?mount=&from=), a
// monolithic upload (?digest=), or a new session.
func (s *Server) startUpload(w http.ResponseWriter, r *http.Request, n ref.Name) {
	if !s.allow(w, r, VerbWrite, n) {
		return
	}
	mount, hasMount, err := one(r, "mount")
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if hasMount {
		if done := s.mount(w, r, n, mount); done {
			return
		}
	}
	dg, hasDigest, err := one(r, "digest")
	if err != nil {
		s.fail(w, r, err)
		return
	}
	var need int64
	if hasDigest {
		need = r.ContentLength
	}
	if err := s.roomFor(need); err != nil {
		s.fail(w, r, err)
		return
	}
	if hasDigest {
		s.monolithic(w, r, n, dg)
		return
	}
	id, err := s.newSession(r, n)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	uploadHeaders(w, n, id, 0)
	w.WriteHeader(http.StatusAccepted)
}

// mount tries a cross-repository mount of digest from the repository named by
// from, and reports whether it answered the request. A mount honours from and
// nothing else: without it, or when from does not hold the blob, or the link
// would cross volumes, the request falls through to a new session (202), as
// the specification allows. The source must be readable by the caller. A
// mounted blob is trusted as it stands: the store verified it against its
// digest when it was committed and never writes a blob file in place.
func (s *Server) mount(w http.ResponseWriter, r *http.Request, n ref.Name, mount string) bool {
	d, err := ref.ParseDigest(mount)
	if err != nil {
		s.fail(w, r, err)
		return true
	}
	fromS, hasFrom, err := one(r, "from")
	if err != nil {
		s.fail(w, r, err)
		return true
	}
	if !hasFrom {
		return false
	}
	from, err := ref.ParseName(fromS)
	if err != nil {
		s.fail(w, r, err)
		return true
	}
	if !s.allow(w, r, VerbRead, from) {
		return true
	}
	err = s.st.MountBlob(r.Context(), n, from, d)
	if errors.Is(err, store.ErrMountUnavailable) {
		s.log.Debug("registry mount fell back to an upload", "repository", n.String(), "from", from.String(), "digest", d.String(), "err", err)
		return false
	}
	if err != nil {
		s.fail(w, r, err)
		return true
	}
	s.log.Info("registry blob mounted", "repository", n.String(), "from", from.String(), "digest", d.String())
	blobCreated(w, n, d)
	return true
}

// errInsufficientSpace is an upload refused because the store volume is, or
// would become, shorter of space than MinFreeSpace.
var errInsufficientSpace = errors.New("insufficient free space")

// roomFor refuses an upload of need bytes (0 or less when the length is not
// known) unless the store volume keeps MinFreeSpace free after it and after
// what the bodies in flight have reserved. It reserves nothing: claim does,
// when a body starts to arrive. The answer never says how much space there is.
func (s *Server) roomFor(need int64) error {
	s.spaceMu.Lock()
	defer s.spaceMu.Unlock()
	return s.roomLocked(max(need, 0))
}

// roomLocked is roomFor with spaceMu held.
func (s *Server) roomLocked(need int64) error {
	free, err := s.freeSpace()
	if err != nil {
		return fmt.Errorf("%w: %w", errInsufficientSpace, err)
	}
	if free < s.minFree || uint64(s.spaceHeld+need) > free-s.minFree {
		return fmt.Errorf("%w: %d bytes free, %d kept, %d held, %d asked", errInsufficientSpace, free, s.minFree, s.spaceHeld, need)
	}
	return nil
}

// claim reserves need bytes for a body in flight, refusing as roomFor does.
// A claim of 0 only checks that what is already reserved still fits.
func (s *Server) claim(need int64) error {
	s.spaceMu.Lock()
	defer s.spaceMu.Unlock()
	if err := s.roomLocked(need); err != nil {
		return err
	}
	s.spaceHeld += need
	return nil
}

// unclaim gives back n reserved bytes.
func (s *Server) unclaim(n int64) {
	s.spaceMu.Lock()
	s.spaceHeld -= n
	s.spaceMu.Unlock()
}

// tooLarge refuses a body whose known length alone passes MaxUploadSize.
func (s *Server) tooLarge(r *http.Request) error {
	if r.ContentLength > s.maxUpload {
		return fmt.Errorf("%w: a %d-byte body", store.ErrUploadTooLarge, r.ContentLength)
	}
	return nil
}

// spaceReader holds a body's share of the store volume while it streams, so
// that bodies in flight are checked in aggregate: free space alone says nothing
// about bytes another body has yet to deliver. Its first read reserves a known
// length whole, or every bytes of an unknown one, and takes the next every
// bytes when that runs out; a known length is checked again each every bytes.
// A read gives back what the read before it delivered, since the store has
// written those bytes and statfs now counts them. The reservation starts at the
// first read, so a request waiting for its session's lock holds none. The
// caller calls done when the body is finished with. It is used by one goroutine.
type spaceReader struct {
	r     io.Reader
	s     *Server
	every int64
	// left is what a known length has yet to bring; negative when unknown.
	left    int64
	held    int64
	since   int64
	last    int64
	started bool
}

func (sr *spaceReader) Read(p []byte) (int, error) {
	if give := min(sr.last, sr.held); give > 0 {
		sr.s.unclaim(give)
		sr.held -= give
	}
	sr.last = 0
	need, check := int64(0), false
	switch {
	case !sr.started:
		sr.started = true
		need, check = sr.left, true
		if need < 0 {
			need = sr.every
		}
	case sr.left == 0:
		// The promised bytes are in; this read only finds the end.
	case sr.held <= 0:
		need, check = sr.every, true
	case sr.since >= sr.every:
		check = true
	}
	if check {
		if err := sr.s.claim(need); err != nil {
			return 0, err
		}
		sr.held += need
		sr.since = 0
	}
	n, err := sr.r.Read(p)
	sr.since += int64(n)
	sr.last = int64(n)
	if sr.left > 0 {
		sr.left = max(sr.left-int64(n), 0)
	}
	return n, err
}

// done gives back whatever is still reserved.
func (sr *spaceReader) done() {
	if sr.held > 0 {
		sr.s.unclaim(sr.held)
	}
	sr.held, sr.last = 0, 0
}

// newSession admits and creates a session, returning its id.
func (s *Server) newSession(r *http.Request, n ref.Name) (string, error) {
	id, _, release, err := s.admitSession(r, n)
	if err != nil {
		return "", err
	}
	release()
	return id, nil
}

// admitSession reserves a slot in the session table, creates the session on
// disk and returns its id with the table entry still held. The slot is taken
// before the file exists, so the cap holds while the store creates it; it is
// given back on every other way out, a panic included.
func (s *Server) admitSession(r *http.Request, n ref.Name) (string, *session, func(), error) {
	owner := ""
	if s.principal != nil {
		owner = s.principal(r)
	}
	e, release, err := s.sessions.admit(owner)
	if err != nil {
		return "", nil, nil, err
	}
	bound := false
	defer func() {
		if !bound {
			release()
			s.sessions.abandon(e)
		}
	}()
	if s.sessionAdmitted != nil {
		s.sessionAdmitted()
	}
	id, err := s.st.NewUpload(r.Context(), n)
	if err != nil {
		return "", nil, nil, err
	}
	s.sessions.bind(sessionKey(n, id), e)
	bound = true
	return id, e, release, nil
}

// monolithic is POST ?digest=: the whole blob in one request with a known
// length, hashed while it streams.
func (s *Server) monolithic(w http.ResponseWriter, r *http.Request, n ref.Name, dg string) {
	d, err := ref.ParseDigest(dg)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if r.ContentLength < 0 {
		s.writeError(w, r, errorf(http.StatusBadRequest, codeBlobUploadInvalid, "a monolithic upload needs a Content-Length"))
		return
	}
	if err := s.tooLarge(r); err != nil {
		s.fail(w, r, err)
		return
	}
	id, e, release, err := s.admitSession(r, n)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	key := sessionKey(n, id)
	// The entry is released, and the session removed unless it was
	// committed, on every way out, a panic included. The cancel outlives a
	// client that went away.
	pushed := false
	defer func() {
		release()
		if !pushed {
			_ = s.st.CancelUpload(context.WithoutCancel(r.Context()), n, id) // best effort; GC reaps an idle session
		}
		s.sessions.forget(key)
	}()
	_, err = s.appendChunk(r, w, n, id, e, 0)
	if err == nil {
		err = s.commit(r, n, id, e, d)
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	pushed = true
	w.Header().Set("Blob-Upload-UUID", id)
	w.Header().Set("Docker-Upload-UUID", id)
	s.log.Info("registry blob pushed", "repository", n.String(), "digest", d.String())
	blobCreated(w, n, d)
}

// uploadID validates the route's session id.
func uploadID(r *http.Request) (string, error) {
	return ref.ParseUploadID(mux.Vars(r)["uuid"])
}

// uploadStatus is GET on a session: 204 with its Range.
func (s *Server) uploadStatus(w http.ResponseWriter, r *http.Request, n ref.Name) {
	id, err := uploadID(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if !s.allow(w, r, VerbRead, n) {
		return
	}
	size, err := s.st.UploadSize(r.Context(), n, id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	uploadHeaders(w, n, id, size)
	w.WriteHeader(http.StatusNoContent)
}

// chunkOffset reads a request's Content-Range: -1 (append wherever the session
// ends) when there is none, else the chunk's start, after checking that the
// range's length is the body's.
func chunkOffset(r *http.Request) (int64, error) {
	cr := r.Header.Get("Content-Range")
	if cr == "" {
		return -1, nil
	}
	start, end, err := parseChunkRange(cr)
	if err != nil {
		return 0, &apiError{status: http.StatusBadRequest, code: codeBlobUploadInvalid, msg: "malformed Content-Range", cause: err}
	}
	if r.ContentLength < 0 {
		return 0, errorf(http.StatusBadRequest, codeBlobUploadInvalid, "a Content-Range chunk needs a Content-Length")
	}
	if end-start+1 != r.ContentLength {
		return 0, errorf(http.StatusRequestedRangeNotSatisfiable, codeBlobUploadInvalid, "Content-Range length does not match Content-Length")
	}
	return start, nil
}

// appendChunk appends the request body to session id at offset (-1: at its
// end), hashing it as it streams when the session's hash is still known.
// The caller holds e.
// The session may not grow past MaxUploadSize, and the body holds its share of
// the volume while it streams (spaceReader).
func (s *Server) appendChunk(r *http.Request, w http.ResponseWriter, n ref.Name, id string, e *session, offset int64) (int64, error) {
	if s.chunkAppending != nil {
		s.chunkAppending()
	}
	body := &spaceReader{r: s.body(w, r), s: s, every: s.spaceEvery, left: r.ContentLength}
	defer body.done()
	tee := e.hash.writer()
	newLen, err := s.st.AppendUploadLimit(r.Context(), n, id, offset, s.maxUpload, io.TeeReader(body, tee))
	e.hash.settle(newLen, err)
	if err != nil && errors.Is(err, store.ErrOffsetMismatch) {
		uploadHeaders(w, n, id, newLen)
	}
	return newLen, err
}

// settle records the outcome of a store operation on an acquired entry: a
// success confirms the session; an error drops the entry when the session is
// unknown or invalid, or was never confirmed, so a made-up id leaves nothing
// in the table.
func (s *Server) settle(key string, e *session, err error) {
	if err == nil {
		s.sessions.confirm(e)
		return
	}
	if errors.Is(err, store.ErrUploadUnknown) || errors.Is(err, ref.ErrInvalidUploadID) || !s.sessions.isConfirmed(e) {
		s.sessions.drop(key, e)
	}
}

// commit finishes session id as blob d: with the streamed hash when it covers
// the session and matches, else by hashing the file again. The caller holds e.
func (s *Server) commit(r *http.Request, n ref.Name, id string, e *session, d digest.Digest) error {
	if s.uploadCommitting != nil {
		defer s.uploadCommitting()
	}
	if sum, size, ok := e.hash.sum(d.Algorithm()); ok && sum == d {
		return s.st.CommitHashedUpload(r.Context(), n, id, d, size)
	}
	return s.st.CommitUpload(r.Context(), n, id, d)
}

// patchUpload is PATCH on a session: a chunk, at the Content-Range start when
// both Content-Range and Content-Length are sent, else appended.
func (s *Server) patchUpload(w http.ResponseWriter, r *http.Request, n ref.Name) {
	id, err := uploadID(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if !s.allow(w, r, VerbWrite, n) {
		return
	}
	offset, err := chunkOffset(r)
	if err == nil {
		err = s.tooLarge(r)
	}
	if err == nil {
		err = s.roomFor(r.ContentLength)
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	key := sessionKey(n, id)
	e, release := s.sessions.acquire(key)
	defer release()
	newLen, err := s.appendChunk(r, w, n, id, e, offset)
	s.settle(key, e, err)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	uploadHeaders(w, n, id, newLen)
	w.WriteHeader(http.StatusAccepted)
}

// finishUpload is PUT on a session with ?digest=: an optional final chunk,
// then the commit.
func (s *Server) finishUpload(w http.ResponseWriter, r *http.Request, n ref.Name) {
	id, err := uploadID(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if !s.allow(w, r, VerbWrite, n) {
		return
	}
	dg, ok, err := one(r, "digest")
	if err == nil && !ok {
		err = errorf(http.StatusBadRequest, codeDigestInvalid, "digest query parameter missing")
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	d, err := ref.ParseDigest(dg)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	offset, err := chunkOffset(r)
	chunk := offset >= 0 || r.ContentLength != 0
	if err == nil && chunk {
		err = s.tooLarge(r)
		if err == nil {
			err = s.roomFor(r.ContentLength)
		}
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	key := sessionKey(n, id)
	e, release := s.sessions.acquire(key)
	// A commit that panics may have committed, and either way its entry
	// would hold a slot until SessionIdle, so it leaves the table too. Losing
	// the entry of a session that survived costs a re-hash at its commit.
	committing := false
	defer func() {
		release()
		if committing {
			s.sessions.forget(key)
		}
	}()
	if chunk {
		_, err := s.appendChunk(r, w, n, id, e, offset)
		s.settle(key, e, err)
		if err != nil {
			s.fail(w, r, err)
			return
		}
	}
	committing = true
	err = s.commit(r, n, id, e, d)
	committing = false
	if err != nil {
		s.settle(key, e, err)
		s.fail(w, r, err)
		return
	}
	s.sessions.forget(key)
	s.log.Info("registry blob pushed", "repository", n.String(), "digest", d.String())
	blobCreated(w, n, d)
}

// cancelUpload is DELETE on a session. It needs the delete permission.
func (s *Server) cancelUpload(w http.ResponseWriter, r *http.Request, n ref.Name) {
	id, err := uploadID(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if !s.allow(w, r, VerbDelete, n) {
		return
	}
	key := sessionKey(n, id)
	e, release := s.sessions.acquire(key)
	defer func() {
		release()
		s.sessions.drop(key, e)
	}()
	err = s.st.CancelUpload(r.Context(), n, id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

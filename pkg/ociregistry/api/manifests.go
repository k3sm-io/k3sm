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
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"strconv"
	"strings"

	"github.com/gorilla/mux"
	"github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"

	"k3sm.io/k3sm/pkg/ociregistry/ref"
	"k3sm.io/k3sm/pkg/ociregistry/store"
)

// Manifest media types the server accepts at PUT.
const (
	mediaTypeDockerManifest     = "application/vnd.docker.distribution.manifest.v2+json"
	mediaTypeDockerManifestList = "application/vnd.docker.distribution.manifest.list.v2+json"
	mediaTypeDockerForeignLayer = "application/vnd.docker.image.rootfs.foreign.diff.tar.gzip"
	// The OCI non-distributable layer types, deprecated in image-spec 1.1
	// but still pushed, and still exempt from the presence check.
	mediaTypeNonDistributable     = "application/vnd.oci.image.layer.nondistributable.v1.tar"
	mediaTypeNonDistributableGzip = "application/vnd.oci.image.layer.nondistributable.v1.tar+gzip"
	mediaTypeNonDistributableZstd = "application/vnd.oci.image.layer.nondistributable.v1.tar+zstd"
	// maxQueryTags is the most ?tag= values one PUT may carry.
	maxQueryTags = 46
)

var manifestTypes = map[string]bool{
	ispec.MediaTypeImageManifest: true,
	ispec.MediaTypeImageIndex:    true,
	mediaTypeDockerManifest:      true,
	mediaTypeDockerManifestList:  true,
}

func isIndexType(mt string) bool {
	return mt == ispec.MediaTypeImageIndex || mt == mediaTypeDockerManifestList
}

var nonDistributable = map[string]bool{
	mediaTypeDockerForeignLayer:   true,
	mediaTypeNonDistributable:     true,
	mediaTypeNonDistributableGzip: true,
	mediaTypeNonDistributableZstd: true,
}

// parseReference validates the route's manifest reference.
func parseReference(r *http.Request) (ref.Reference, error) {
	rf, err := ref.ParseReference(mux.Vars(r)["reference"])
	if err != nil {
		return ref.Reference{}, err
	}
	return rf, nil
}

// getManifest serves a manifest GET or HEAD. Accept is ignored: the answer is
// the manifest as pushed, with its pushed media type.
//
// A reference outside the tag grammar names no manifest a push could have
// stored, so a read of one is answered 404 MANIFEST_UNKNOWN, as the OCI
// distribution-spec conformance suite requires and the registry this replaces
// answers. It is still refused before the store is touched, and a malformed
// digest stays 400 DIGEST_INVALID. Authorization comes first, so a caller
// who may not read the repository learns nothing about the reference.
func (s *Server) getManifest(w http.ResponseWriter, r *http.Request, n ref.Name) {
	if !s.allow(w, r, VerbRead, n) {
		return
	}
	rf, err := parseReference(r)
	if errors.Is(err, ref.ErrInvalidTag) {
		err = &apiError{status: http.StatusNotFound, code: codeManifestUnknown, msg: "manifest unknown", cause: err}
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	desc, body, err := s.st.Manifest(n, rf)
	// A HEAD by digest is how a pushing client decides to skip a child
	// manifest's push before it PUTs the index naming it, so it restarts the
	// manifest's GC grace, exactly as a blob HEAD does: an untagged child past
	// the grace is not reaped before the index PUT. If GC reaped it after the
	// read above, the touch finds it gone and the HEAD answers 404. A HEAD by
	// tag writes nothing: a tagged row is kept at any age, and the index names
	// its children by digest. A GET (a pull) writes nothing either.
	if err == nil && r.Method == http.MethodHead && rf.Digest != "" {
		err = s.st.TouchBlob(r.Context(), n, desc.Digest)
	}
	if errors.Is(err, store.ErrBlobUnknown) {
		err = fmt.Errorf("%w: %w", store.ErrManifestUnknown, err)
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	h := w.Header()
	h.Set("Content-Type", desc.MediaType)
	h.Set("Docker-Content-Digest", desc.Digest.String())
	h.Set("Content-Length", strconv.Itoa(len(body)))
	h.Set("ETag", `"`+desc.Digest.String()+`"`)
	w.WriteHeader(http.StatusOK)
	if r.Method != http.MethodHead {
		_, _ = w.Write(body) // the client went away
	}
}

// manifestInvalid is a 400 MANIFEST_INVALID.
func manifestInvalid(format string, a ...any) *apiError {
	return errorf(http.StatusBadRequest, codeManifestInvalid, fmt.Sprintf(format, a...))
}

// descriptorDigest validates a descriptor a manifest names.
func descriptorDigest(what string, d ispec.Descriptor) (digest.Digest, error) {
	if _, err := ref.ParseDigest(d.Digest.String()); err != nil {
		return "", manifestInvalid("%s digest %q is invalid", what, d.Digest)
	}
	if d.Size < 0 {
		return "", manifestInvalid("%s %s has a negative size", what, d.Digest)
	}
	return d.Digest, nil
}

// checkedManifest is what a PUT needs from a validated body.
type checkedManifest struct {
	// needs are the blobs that must already be in the repository.
	needs []digest.Digest
	// subject is the subject's digest, when the manifest has one.
	subject digest.Digest
}

// checkManifest validates body as a manifest of media type mt, following the
// accept and reject rules of the registry this replaces:
//   - schemaVersion is 2, and a mediaType field, when present, is mt;
//   - every descriptor carries a valid digest and a non-negative size;
//   - a Docker v2 manifest needs its config and every layer present;
//   - an OCI manifest needs its config and layers present when the config is
//     an OCI image config or the empty descriptor, except non-distributable
//     layers; with any other config type nothing is required;
//   - an index or manifest list requires nothing: children need not exist.
func checkManifest(mt string, body []byte) (checkedManifest, error) {
	var out checkedManifest
	if isIndexType(mt) {
		var idx ispec.Index
		if err := json.Unmarshal(body, &idx); err != nil {
			return out, manifestInvalid("index does not parse: %v", err)
		}
		if idx.SchemaVersion != 2 {
			return out, manifestInvalid("schemaVersion %d, want 2", idx.SchemaVersion)
		}
		if idx.MediaType != "" && idx.MediaType != mt {
			return out, manifestInvalid("mediaType %q is not the Content-Type %q", idx.MediaType, mt)
		}
		for _, m := range idx.Manifests {
			if _, err := descriptorDigest("child", m); err != nil {
				return out, err
			}
		}
		return out, subjectOf(idx.Subject, &out)
	}
	var m ispec.Manifest
	if err := json.Unmarshal(body, &m); err != nil {
		return out, manifestInvalid("manifest does not parse: %v", err)
	}
	if m.SchemaVersion != 2 {
		return out, manifestInvalid("schemaVersion %d, want 2", m.SchemaVersion)
	}
	if m.MediaType != "" && m.MediaType != mt {
		return out, manifestInvalid("mediaType %q is not the Content-Type %q", m.MediaType, mt)
	}
	cfg, err := descriptorDigest("config", m.Config)
	if err != nil {
		return out, err
	}
	layers := make([]digest.Digest, 0, len(m.Layers))
	for _, l := range m.Layers {
		d, err := descriptorDigest("layer", l)
		if err != nil {
			return out, err
		}
		if mt == mediaTypeDockerManifest || !nonDistributable[l.MediaType] {
			layers = append(layers, d)
		}
	}
	switch {
	case mt == mediaTypeDockerManifest:
		out.needs = append([]digest.Digest{cfg}, layers...)
	case m.Config.MediaType == ispec.MediaTypeImageConfig || m.Config.MediaType == ispec.MediaTypeEmptyJSON:
		out.needs = append([]digest.Digest{cfg}, layers...)
	}
	return out, subjectOf(m.Subject, &out)
}

func subjectOf(sub *ispec.Descriptor, out *checkedManifest) error {
	if sub == nil {
		return nil
	}
	d, err := descriptorDigest("subject", *sub)
	if err != nil {
		return err
	}
	out.subject = d
	return nil
}

// putManifest is a manifest PUT by tag or by digest, with ?tag= values for a
// digest PUT.
func (s *Server) putManifest(w http.ResponseWriter, r *http.Request, n ref.Name) {
	if !s.allow(w, r, VerbWrite, n) {
		return
	}
	rf, err := parseReference(r)
	if err != nil {
		if errors.Is(err, ref.ErrInvalidTag) {
			err = manifestInvalid("invalid tag")
		}
		s.fail(w, r, err)
		return
	}
	tags := r.URL.Query()["tag"]
	if len(tags) > 0 && rf.Digest == "" {
		s.writeError(w, r, manifestInvalid("tag query parameters need a digest reference"))
		return
	}
	if len(tags) > maxQueryTags {
		s.writeError(w, r, errorf(http.StatusRequestURITooLong, codeManifestInvalid, "too many tag query parameters"))
		return
	}
	for _, t := range tags {
		if _, err := ref.ParseTag(t); err != nil {
			s.writeError(w, r, manifestInvalid("invalid tag %q", t))
			return
		}
	}
	mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || !manifestTypes[mt] {
		s.writeError(w, r, errorf(http.StatusUnsupportedMediaType, codeManifestInvalid, "unsupported manifest media type"))
		return
	}
	if r.ContentLength > store.MaxManifestSize {
		s.writeError(w, r, errorf(http.StatusRequestEntityTooLarge, codeManifestInvalid, "manifest larger than 4 MiB"))
		return
	}
	body, err := io.ReadAll(io.LimitReader(s.body(w, r), store.MaxManifestSize+1))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if len(body) > store.MaxManifestSize {
		s.writeError(w, r, errorf(http.StatusRequestEntityTooLarge, codeManifestInvalid, "manifest larger than 4 MiB"))
		return
	}
	if rf.Digest != "" && rf.Digest.Algorithm().FromBytes(body) != rf.Digest {
		s.writeError(w, r, manifestInvalid("manifest body does not hash to %s", rf.Digest))
		return
	}
	checked, err := checkManifest(mt, body)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	// The blobs are checked under the repository lock, just before the
	// index is written, so a garbage-collection sweep (which deletes under
	// the same lock) cannot remove one between the check and the write.
	needs := func() error { return s.blobsPresent(n, checked.needs) }
	if err := needs(); err != nil {
		s.fail(w, r, err)
		return
	}
	if s.manifestChecked != nil {
		s.manifestChecked()
	}
	desc, err := s.st.PutManifestChecked(r.Context(), n, rf, mt, body, needs)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	for _, t := range tags {
		if _, err := s.st.PutManifestChecked(r.Context(), n, ref.Reference{Tag: t}, mt, body, needs); err != nil {
			s.fail(w, r, err)
			return
		}
		w.Header().Add("OCI-Tag", t)
	}
	s.log.Info("registry manifest pushed", "repository", n.String(), "reference", rf.String(), "digest", desc.Digest.String(), "media_type", mt)
	h := w.Header()
	h.Set("Location", "/v2/"+n.String()+"/manifests/"+desc.Digest.String())
	h.Set("Docker-Content-Digest", desc.Digest.String())
	if checked.subject != "" {
		h.Set("OCI-Subject", checked.subject.String())
	}
	h.Set("Content-Length", "0")
	w.WriteHeader(http.StatusCreated)
}

// blobsPresent fails with MANIFEST_BLOB_UNKNOWN, naming the first missing
// digest, unless n holds every blob in needs.
func (s *Server) blobsPresent(n ref.Name, needs []digest.Digest) error {
	for _, d := range needs {
		if _, err := s.st.StatBlob(n, d); err != nil {
			if errors.Is(err, store.ErrBlobUnknown) {
				e := errorf(http.StatusBadRequest, codeManifestBlobUnknown, "blob unknown to registry")
				e.detail = map[string]string{"digest": d.String()}
				return e
			}
			return err
		}
	}
	return nil
}

// errNamedByIndex is a digest DELETE of a manifest an index in the repository
// still names.
var errNamedByIndex = errorf(http.StatusMethodNotAllowed, codeDenied, "the manifest is named by an index in the repository")

// errPreconditionFailed is a DELETE whose If-Match names no state the
// repository is in.
var errPreconditionFailed = errorf(http.StatusPreconditionFailed, codeDenied, "the repository changed since the state the request names")

// deleteManifest is a manifest DELETE: by tag, only that tag's row; by digest,
// every row of the digest, refused while an index in the repository names it.
//
// A DELETE carrying If-Match is conditional on the repository's state: the
// entity tag is store.IndexState of its index.json rows, compared under the
// repository lock that the delete itself holds, so no write lands between the
// comparison and the delete. A state that no longer holds is a 412 and deletes
// nothing. A request without If-Match is unconditional. Presence is any
// If-Match field line, so a request whose If-Match lines are empty or hold no
// well-formed tag is a 412, never unconditional (RFC 9110 section 13.1.1).
func (s *Server) deleteManifest(w http.ResponseWriter, r *http.Request, n ref.Name) {
	if !s.allow(w, r, VerbDelete, n) {
		return
	}
	rf, err := parseReference(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	ifMatch := r.Header.Values("If-Match")
	conditional := len(ifMatch) > 0
	precondition := func(rows []ispec.Descriptor) error {
		if !conditional {
			return nil
		}
		state, err := store.IndexState(rows)
		if err != nil {
			return err
		}
		if !matchesEntityTag(ifMatch, state) {
			return errPreconditionFailed
		}
		return nil
	}
	if rf.Tag != "" {
		err = s.st.DeleteTagChecked(r.Context(), n, rf.Tag, precondition)
	} else {
		err = s.st.DeleteDigestChecked(r.Context(), n, rf.Digest, func(rows []ispec.Descriptor) error {
			if err := precondition(rows); err != nil {
				return err
			}
			return s.notNamedByIndex(n, rows, rf.Digest)
		})
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.log.Info("registry manifest deleted", "repository", n.String(), "reference", rf.String())
	w.WriteHeader(http.StatusAccepted)
}

// matchesEntityTag reports whether the If-Match field values match state:
// "*" matches any current state, and a quoted strong entity tag matches when
// its value is state (RFC 9110 section 13.1.1, strong comparison). The values
// are one comma-separated list across every field line, and a quoted tag is
// read to its closing quote, so a comma inside it does not split it. A weak
// tag never matches. A field that is empty, or holds any member that is not
// "*" or an entity tag, matches nothing, so a malformed condition fails
// rather than deletes.
func matchesEntityTag(values []string, state string) bool {
	matched, members := false, 0
	for _, v := range values {
		for i := 0; i < len(v); {
			switch c := v[i]; {
			case c == ' ' || c == '\t' || c == ',':
				i++
				continue
			case c == '*':
				i++
				matched = true
			case c == '"' || strings.HasPrefix(v[i:], `W/"`):
				weak := c == 'W'
				if weak {
					i += 2
				}
				end := strings.IndexByte(v[i+1:], '"')
				if end < 0 {
					return false
				}
				tag := v[i+1 : i+1+end]
				i += end + 2
				if !weak && tag == state {
					matched = true
				}
			default:
				return false
			}
			members++
			// A member ends at whitespace, a comma or the end of the line.
			if i < len(v) && v[i] != ' ' && v[i] != '\t' && v[i] != ',' {
				return false
			}
		}
	}
	return members > 0 && matched
}

// notNamedByIndex fails when an index row of rows, other than d itself, lists
// d among its manifests. An index body that cannot be read refuses the delete
// (fail closed).
func (s *Server) notNamedByIndex(n ref.Name, rows []ispec.Descriptor, d digest.Digest) error {
	seen := map[digest.Digest]bool{}
	for _, row := range rows {
		if !isIndexType(row.MediaType) || row.Digest == d || seen[row.Digest] {
			continue
		}
		seen[row.Digest] = true
		body, err := s.readManifestBlob(n, row)
		if err != nil {
			return fmt.Errorf("read index %s: %w", row.Digest, err)
		}
		var idx ispec.Index
		if err := json.Unmarshal(body, &idx); err != nil {
			return fmt.Errorf("parse index %s: %w", row.Digest, err)
		}
		for _, c := range idx.Manifests {
			if c.Digest == d {
				return errNamedByIndex
			}
		}
	}
	return nil
}

// readManifestBlob reads the body a row names, bounded and checked against the
// row's digest.
func (s *Server) readManifestBlob(n ref.Name, row ispec.Descriptor) ([]byte, error) {
	if row.Size < 0 || row.Size > store.MaxManifestSize {
		return nil, fmt.Errorf("manifest %s: size %d out of bounds", row.Digest, row.Size)
	}
	f, err := s.st.OpenBlob(n, row.Digest)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, row.Size+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) != row.Size || row.Digest.Algorithm().FromBytes(b) != row.Digest {
		return nil, fmt.Errorf("%w: manifest %s", store.ErrDigestMismatch, row.Digest)
	}
	return b, nil
}

// compactJSON encodes v without HTML escaping or a trailing newline.
func compactJSON(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

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
	"net/url"
	"path"
	"strings"
)

// The push gate's request classifier: which requests are anonymous reads that
// pass through untouched, which are the handful of write shapes an in-pod push
// is made of, and which are refused before anything is forwarded.
//
// It is PURE and FAIL-CLOSED. A write is forwarded with the gate's own registry
// credential attached, so the repository a write is authorized for must be the
// repository zot then acts on. The parser therefore refuses every spelling that
// could be read two ways: a percent escape, a backslash, an empty or dot
// segment, a NUL or control byte, an uppercase letter outside a tag, and a
// repository component that is one of the route words. What it accepts, it
// forwards byte for byte as the path it parsed.

// gateOp is what the gate does with one request.
type gateOp uint8

const (
	// opInvalid is a malformed write (or a malformed request on an upload
	// path): 400, never forwarded.
	opInvalid gateOp = iota
	// opRefused is a method or write shape the gate never forwards, DELETE and
	// zot's extension endpoints among them: 405.
	opRefused
	// opRead is an anonymous read (GET or HEAD off an upload path), forwarded
	// as received with no credential.
	opRead
	// opUploadStart is POST /v2/<name>/blobs/uploads/.
	opUploadStart
	// opUploadChunk is PATCH /v2/<name>/blobs/uploads/<id>.
	opUploadChunk
	// opUploadFinish is PUT /v2/<name>/blobs/uploads/<id>.
	opUploadFinish
	// opUploadStatus is GET or HEAD /v2/<name>/blobs/uploads/<id>. It reads an
	// upload session, which only its writer has any business doing, so it is
	// authorized as a write.
	opUploadStatus
	// opManifestPut is PUT /v2/<name>/manifests/<reference>.
	opManifestPut
)

// String names the operation for the audit line.
func (o gateOp) String() string {
	switch o {
	case opRead:
		return "read"
	case opRefused:
		return "refused"
	case opUploadStart:
		return "blob-upload-start"
	case opUploadChunk:
		return "blob-upload-chunk"
	case opUploadFinish:
		return "blob-upload-finish"
	case opUploadStatus:
		return "blob-upload-status"
	case opManifestPut:
		return "manifest-put"
	default:
		return "invalid"
	}
}

// isWrite reports whether op must be authenticated and authorized.
func (o gateOp) isWrite() bool { return o >= opUploadStart }

// gateRoute is classify's answer.
type gateRoute struct {
	op gateOp
	// repo is the repository a write acts on.
	repo string
	// from is a cross-repository mount's source repository, or "".
	from string
	// path and query are what a write is forwarded with: exactly the path that
	// was parsed and the allowlisted query, re-encoded.
	path, query string
}

// Limits from the distribution specification: a repository name is at most 255
// characters, a tag at most 128.
const (
	maxRepoNameLen = 255
	maxTagLen      = 128
	maxUploadIDLen = 128
	maxStateLen    = 4096
)

// routeWords are the path segments the registry's router splits a request on.
// A repository component spelled as one could be split two ways, so a write
// naming one is refused.
var routeWords = map[string]bool{"blobs": true, "manifests": true, "uploads": true}

// classify decides what the gate does with a request, from its method, the
// path exactly as it appeared on the request line, and the raw query.
func classify(method, rawPath, rawQuery string) gateRoute {
	switch method {
	case "GET", "HEAD":
		if !onUploadPath(rawPath) {
			return gateRoute{op: opRead}
		}
		// Anything that might reach an upload session and does not parse as
		// one is malformed, never an anonymous read.
		if r := classifyWrite(opUploadStatus, rawPath, rawQuery); r.op != opRefused {
			return r
		}
		return gateRoute{op: opInvalid}
	case "POST":
		return classifyWrite(opUploadStart, rawPath, rawQuery)
	case "PATCH":
		return classifyWrite(opUploadChunk, rawPath, rawQuery)
	case "PUT":
		// A PUT is either an upload's completion or a manifest; the path says
		// which, and anything else is refused below.
		if r := classifyWrite(opUploadFinish, rawPath, rawQuery); r.op != opRefused {
			return r
		}
		return classifyWrite(opManifestPut, rawPath, rawQuery)
	default:
		// DELETE above all: a pod never deletes. Every other method is not
		// part of a push.
		return gateRoute{op: opRefused}
	}
}

// onUploadPath reports whether a read-method path could reach an upload
// session under ANY reading of it: decoded, with backslashes as slashes, case
// folded, and with dot segments and repeated slashes resolved. A read that
// might be an upload is authorized as one, so the lenient answer here is the
// safe one.
func onUploadPath(rawPath string) bool {
	decoded, err := url.PathUnescape(rawPath)
	if err != nil {
		return true // unparseable: let the strict parser refuse it
	}
	for _, p := range []string{rawPath, decoded} {
		p = strings.ToLower(strings.ReplaceAll(p, "\\", "/"))
		for _, candidate := range []string{p, path.Clean("/" + p)} {
			prev := ""
			for _, seg := range strings.Split(candidate, "/") {
				if seg == "" || seg == "." {
					continue
				}
				if prev == "blobs" && seg == "uploads" {
					return true
				}
				prev = seg
			}
		}
	}
	return false
}

// classifyWrite parses rawPath strictly as op's write shape.
func classifyWrite(op gateOp, rawPath, rawQuery string) gateRoute {
	rest, ok := strings.CutPrefix(rawPath, "/v2/")
	if !ok {
		return gateRoute{op: opRefused}
	}
	if !cleanPath(rawPath) {
		return gateRoute{op: opInvalid}
	}
	segs := strings.Split(rest, "/")
	n := len(segs)
	var name []string
	switch op {
	case opUploadStart:
		// /v2/<name>/blobs/uploads/ — the trailing slash is the empty last
		// segment, and the only empty segment cleanPath lets through.
		if n < 4 || segs[n-1] != "" || segs[n-2] != "uploads" || segs[n-3] != "blobs" {
			return gateRoute{op: opRefused}
		}
		name = segs[:n-3]
	case opUploadChunk, opUploadFinish, opUploadStatus:
		if n < 4 || segs[n-2] != "uploads" || segs[n-3] != "blobs" {
			return gateRoute{op: opRefused}
		}
		if !validUploadID(segs[n-1]) {
			return gateRoute{op: opInvalid}
		}
		name = segs[:n-3]
	case opManifestPut:
		if n < 3 || segs[n-2] != "manifests" {
			return gateRoute{op: opRefused}
		}
		if !validReference(segs[n-1]) {
			return gateRoute{op: opInvalid}
		}
		name = segs[:n-2]
	default:
		return gateRoute{op: opRefused}
	}
	repo := strings.Join(name, "/")
	if !validRepoName(repo) {
		return gateRoute{op: opInvalid}
	}
	route := gateRoute{op: op, repo: repo, path: rawPath}
	q, from, ok := parseWriteQuery(op, rawQuery)
	if !ok {
		return gateRoute{op: opInvalid}
	}
	route.query, route.from = q, from
	return route
}

// cleanPath reports whether p carries none of the spellings that can be read
// two ways: an escape, a backslash, a NUL, a control or non-ASCII byte, an
// empty segment other than the trailing one, or a dot segment.
func cleanPath(p string) bool {
	for i := 0; i < len(p); i++ {
		c := p[i]
		if c <= 0x20 || c >= 0x7f || c == '%' || c == '\\' {
			return false
		}
	}
	segs := strings.Split(strings.TrimPrefix(p, "/"), "/")
	for i, s := range segs {
		if s == "." || s == ".." {
			return false
		}
		if s == "" && i != len(segs)-1 {
			return false
		}
	}
	return true
}

// validRepoName checks a repository name against the distribution grammar
// (components of [a-z0-9] runs joined by '.', '_', '__' or runs of '-',
// separated by '/'), its length cap, and the route-word refusal.
func validRepoName(name string) bool {
	if name == "" || len(name) > maxRepoNameLen {
		return false
	}
	for _, comp := range strings.Split(name, "/") {
		if !validRepoComponent(comp) || routeWords[comp] {
			return false
		}
	}
	return true
}

// validRepoComponent matches [a-z0-9]+(?:(?:\.|_|__|-+)[a-z0-9]+)*.
func validRepoComponent(c string) bool {
	if c == "" {
		return false
	}
	i := 0
	alnumRun := func() bool {
		start := i
		for i < len(c) && isLowerAlnum(c[i]) {
			i++
		}
		return i > start
	}
	if !alnumRun() {
		return false
	}
	for i < len(c) {
		switch {
		case c[i] == '.':
			i++
		case c[i] == '_':
			i++
			if i < len(c) && c[i] == '_' {
				i++
			}
		case c[i] == '-':
			for i < len(c) && c[i] == '-' {
				i++
			}
		default:
			return false
		}
		if !alnumRun() {
			return false
		}
	}
	return true
}

func isLowerAlnum(b byte) bool { return (b >= 'a' && b <= 'z') || (b >= '0' && b <= '9') }

// validReference accepts a tag ([A-Za-z0-9_][A-Za-z0-9._-]{0,127}, the one
// place the specification allows uppercase) or a digest.
func validReference(ref string) bool {
	if strings.Contains(ref, ":") {
		return validDigest(ref)
	}
	if ref == "" || len(ref) > maxTagLen {
		return false
	}
	for i := 0; i < len(ref); i++ {
		b := ref[i]
		ok := isLowerAlnum(b) || (b >= 'A' && b <= 'Z') || b == '_' || (i > 0 && (b == '.' || b == '-'))
		if !ok {
			return false
		}
	}
	return true
}

// validDigest accepts sha256:<64 hex> and sha512:<128 hex>, lowercase.
func validDigest(d string) bool {
	algo, hex, ok := strings.Cut(d, ":")
	if !ok {
		return false
	}
	want := map[string]int{"sha256": 64, "sha512": 128}[algo]
	if want == 0 || len(hex) != want {
		return false
	}
	for i := 0; i < len(hex); i++ {
		if !((hex[i] >= '0' && hex[i] <= '9') || (hex[i] >= 'a' && hex[i] <= 'f')) {
			return false
		}
	}
	return true
}

// validUploadID accepts an upload session id: the registry mints a lowercase
// UUID, so a lowercase alphanumeric-and-dash token of bounded length is the
// whole grammar.
func validUploadID(id string) bool {
	if id == "" || len(id) > maxUploadIDLen {
		return false
	}
	for i := 0; i < len(id); i++ {
		if !(isLowerAlnum(id[i]) || id[i] == '-' || id[i] == '_') {
			return false
		}
	}
	return true
}

// validState accepts the opaque upload state some clients echo back: base64
// characters of bounded length.
func validState(s string) bool {
	if s == "" || len(s) > maxStateLen {
		return false
	}
	for i := 0; i < len(s); i++ {
		b := s[i]
		if !(isLowerAlnum(b) || (b >= 'A' && b <= 'Z') || b == '+' || b == '/' || b == '=' || b == '_' || b == '-' || b == '.') {
			return false
		}
	}
	return true
}

// parseWriteQuery parses rawQuery strictly against op's allowlist: every key
// known, none repeated, every value valid. It returns the query re-encoded and
// a mount's source repository.
func parseWriteQuery(op gateOp, rawQuery string) (query, from string, ok bool) {
	allowed := map[gateOp][]string{
		opUploadStart:  {"digest", "mount", "from"},
		opUploadChunk:  {"digest", "_state"},
		opUploadFinish: {"digest", "_state"},
		opUploadStatus: {"_state"},
		opManifestPut:  nil,
	}[op]
	vals := url.Values{}
	if rawQuery != "" {
		for _, part := range strings.Split(rawQuery, "&") {
			k, v, hasEq := strings.Cut(part, "=")
			if !hasEq || k == "" {
				return "", "", false
			}
			known := false
			for _, a := range allowed {
				known = known || a == k
			}
			if !known || vals.Has(k) {
				return "", "", false
			}
			dv, err := url.QueryUnescape(v)
			if err != nil {
				return "", "", false
			}
			valid := false
			switch k {
			case "digest", "mount":
				valid = validDigest(dv)
			case "from":
				valid = validRepoName(dv)
			case "_state":
				valid = validState(dv)
			}
			if !valid {
				return "", "", false
			}
			vals.Set(k, dv)
		}
	}
	// A mount names its source; a source without a mount is meaningless; and a
	// mount that is also a monolithic upload is two operations in one request.
	if vals.Has("mount") != vals.Has("from") || (vals.Has("mount") && vals.Has("digest")) {
		return "", "", false
	}
	return vals.Encode(), vals.Get("from"), true
}

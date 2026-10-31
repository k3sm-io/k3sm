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
	"net/http"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/remote/transport"
)

// ErrChangedSincePlan is a conditional DELETE the registry refused with 412:
// the repository's index is no longer in the state the delete named.
var ErrChangedSincePlan = errors.New("the repository changed since the re-check")

// DeleteManifest deletes the manifest ref names, conditional on its
// repository still being in state, the store.IndexState Recheck returned.
//
// The condition rides the DELETE as If-Match: "<state>", and the k3sm
// registry compares it with the repository's rows under the same lock the
// delete takes, so a push that lands after the re-check (a tag on the planned
// digest, a tagged index naming it, a tagged subject it refers to) makes the
// server refuse the delete with 412, reported as ErrChangedSincePlan, rather
// than drop the push's rows. An empty state sends no condition.
//
// A registry that does not implement If-Match on DELETE, zot among them,
// ignores the field and deletes unconditionally; for it the window between
// Recheck and this request stays open, as it was before.
//
// rt is the transport under go-containerregistry's own (nil uses
// remote.DefaultTransport).
func DeleteManifest(ctx context.Context, ref name.Digest, state string, auth authn.Authenticator, rt http.RoundTripper) error {
	if rt == nil {
		rt = remote.DefaultTransport
	}
	if state != "" {
		rt = ifMatchTransport{base: rt, etag: `"` + state + `"`}
	}
	err := remote.Delete(ref, remote.WithAuth(auth), remote.WithContext(ctx), remote.WithTransport(rt))
	var terr *transport.Error
	if errors.As(err, &terr) && terr.StatusCode == http.StatusPreconditionFailed {
		return fmt.Errorf("delete %s: %w", ref, ErrChangedSincePlan)
	}
	return err
}

// ifMatchTransport sets If-Match on every DELETE it carries. Only the DELETE
// is conditional; the ping and token requests before it go out unchanged.
type ifMatchTransport struct {
	base http.RoundTripper
	etag string
}

// RoundTrip sends req through base, with If-Match set when it is a DELETE.
func (t ifMatchTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.Method == http.MethodDelete {
		req = req.Clone(req.Context())
		req.Header.Set("If-Match", t.etag)
	}
	return t.base.RoundTrip(req)
}

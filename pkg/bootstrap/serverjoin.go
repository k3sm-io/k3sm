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

package bootstrap

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"

	"k3sm.io/k3sm/pkg/certs"
)

// ServerJoinOptions configures an HA control-plane server-join — the second server
// fetching + importing the identical-CA bundle from an existing server.
type ServerJoinOptions struct {
	// Server is the existing server's mesh-reachable bootstrap base URL
	// (https://<mesh-ip>:9345).
	Server string
	// Token is the K10<caHash>::server:<secret> server token: its CA hash PINS the
	// existing server's TLS chain, and its secret is the bundle's KDF passphrase.
	Token string
	// WorkDir is this joining server's work dir; the reconstructed CA PEMs missing
	// from its PKI dir are installed there.
	WorkDir string
	// HTTPClient overrides the default pinned-CA client (tests inject one). When nil,
	// the fetch builds a client that verifies the server's chain against the token's CA
	// hash (no insecure-skip).
	HTTPClient *http.Client
}

// FetchCABundle fetches the sealed CA bootstrap bundle from an existing server over a
// CA-hash-PINNED TLS connection (the same trust primitive as the worker join — NOT
// insecure-skip-tls-verify), authenticating with the server token as a bearer
// credential. A non-2xx status or an empty body is an error.
func FetchCABundle(ctx context.Context, serverURL, token string, client *http.Client) ([]byte, error) {
	tok, err := ParseServerToken(token)
	if err != nil {
		return nil, err
	}
	if client == nil {
		client = PinnedClient(tok.CAHash)
	}
	url := strings.TrimRight(serverURL, "/") + BundlePath
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("build CA bundle request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch CA bundle %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("CA bundle fetch rejected (%s): %s", resp.Status, strings.TrimSpace(string(msg)))
	}
	sealed, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("read CA bundle: %w", err)
	}
	if len(sealed) == 0 {
		return nil, fmt.Errorf("CA bundle fetch returned an empty bundle")
	}
	return sealed, nil
}

// ImportCABundle is the FAIL-CLOSED HA server-join import: fetch the sealed bundle,
// decrypt + authenticate it with the server token's secret (the KDF passphrase), decode
// the five CA keypairs (cluster, signing, etcd server, etcd peer, request-header) — a
// schema-2 bundle, which lacks the request-header CA, is ErrBundlePredatesRequestHeaderCA
// with nothing written — and reconcile them
// into the work dir's PKI dir (certs.ReconcileImportedHierarchy) — so a subsequent
// certs.EnsureHierarchy / certs.EnsureEtcdCAs LOADS the IDENTICAL CAs instead of
// minting fresh, divergent ones. Only CAs absent from disk are installed; a CA already
// present is never replaced, and one whose pin differs from the bundle's fails the
// whole import with certs.ErrHierarchyDiverged. A fetch, GCM tag/decrypt or decode
// failure, or a divergence, leaves NO CA material written (nothing is written before a
// successful unseal + decode + pin check). The caller MUST treat an error as fatal and
// NEVER fall through to minting a self-signed divergent CA — that would split cluster
// trust.
func ImportCABundle(ctx context.Context, opts ServerJoinOptions) error {
	tok, err := ParseServerToken(opts.Token)
	if err != nil {
		return err
	}
	sealed, err := FetchCABundle(ctx, opts.Server, opts.Token, opts.HTTPClient)
	if err != nil {
		return err
	}
	plaintext, err := OpenBundle(tok.Secret, sealed)
	if err != nil {
		return err // ErrBundleOpen: wrong secret or tampered — fail closed, nothing written
	}
	var h certs.Hierarchy
	if err := h.Unmarshal(plaintext); err != nil {
		return fmt.Errorf("decode reconstructed CA hierarchy: %w", err)
	}
	// A schema-2 bundle decodes without the request-header CA: its server runs the
	// previous release. Refuse it by policy before any write, so the caller waits for
	// that server's upgrade instead of this server ever minting the CA itself.
	if missing := h.Missing(certs.PostureEtcd); len(missing) > 0 {
		if slices.Equal(missing, []certs.CAID{certs.CARequestHeader}) {
			return ErrBundlePredatesRequestHeaderCA
		}
		return fmt.Errorf("decode reconstructed CA hierarchy: the bundle lacks the %v CAs", missing)
	}
	if err := certs.ReconcileImportedHierarchy(opts.WorkDir, &h, certs.PostureEtcd); err != nil {
		return fmt.Errorf("reconcile reconstructed CA hierarchy: %w", err)
	}
	return nil
}

package bootstrap

import (
	"context"
	"fmt"
	"io"
	"net/http"
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
	// WorkDir is this joining server's work dir; the reconstructed CA PEMs are written
	// under its PKI dir.
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
// the four CA PEMs, and write them into the work dir's PKI dir — so a subsequent
// certs.EnsureHierarchy LOADS the IDENTICAL cluster + signing CAs instead of minting
// fresh, divergent ones. EVERY failure (fetch, GCM tag/decrypt, decode, write) returns
// an error and leaves NO CA material written (the bytes are written only after a
// successful unseal + decode). The caller MUST treat an error as fatal and NEVER fall
// through to minting a self-signed divergent CA — that would split cluster trust.
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
	if err := certs.WriteHierarchy(opts.WorkDir, &h); err != nil {
		return fmt.Errorf("write reconstructed CA hierarchy: %w", err)
	}
	return nil
}

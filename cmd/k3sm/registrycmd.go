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

package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"k3sm.io/k3sm/internal/atomicfile"
	"k3sm.io/k3sm/pkg/registrysvc"
)

// registryUsage is `k3sm registry`'s help.
const registryUsage = `Usage: k3sm registry <token|login> [flags]

Mint the cluster registry's push credential for any OCI tool. The credential
is a short-lived token for the k3sm-registry/builder ServiceAccount (audience
k3sm-registry), minted through your kubeconfig: you can push when your
kubeconfig may create that ServiceAccount's token (an admin kubeconfig can; an
admin can grant it to anyone by binding the k3sm:registry-builder-token
Role with a RoleBinding in k3sm-registry).

  token   print a token on stdout (--duration, default 1h; refused above the
          cluster's maximum). The same call as
          kubectl create token builder -n k3sm-registry --audience k3sm-registry
  login   write the token into your docker config ($DOCKER_CONFIG/config.json,
          else ~/.docker/config.json, mode 0600) for the address this Mac
          reaches the registry at (localhost:6451 on the server, the server's
          cluster address :6450 on a worker), and the cluster CA to
          certs.d/<host:port>/ca.crt beside it, so docker, buildx, crane and
          oras push with no k3sm in the loop (--duration as for token)

A worker writes no user kubeconfig. On one, first run
  k3sm kubeconfig --server https://<server>:6444 --certificate-authority <ca> --write
with the admin kubeconfig copied from the server.
`

// runRegistry dispatches `k3sm registry <verb>`.
func runRegistry(args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" || args[0] == "help" {
		fmt.Fprint(stdout, registryUsage)
		return nil
	}
	fs := flag.NewFlagSet("k3sm registry "+args[0], flag.ContinueOnError)
	fs.SetOutput(stderr)
	d := fs.Duration("duration", defaultBuilderTokenDuration, "how long the token is valid (minimum 10m)")
	switch args[0] {
	case "token", "login":
	default:
		return fmt.Errorf("unknown registry verb %q (want token or login)", args[0])
	}
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("registry %s takes no arguments, got %q", args[0], fs.Args())
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	api, err := clusterRegistryClient()
	if err != nil {
		return err
	}
	tok, err := mintBuilderToken(ctx, api.tokens, *d, time.Now)
	if err != nil {
		return err
	}
	if args[0] == "token" {
		_, err := fmt.Fprintln(stdout, tok.value)
		return err
	}
	host, err := loginAuthority(ctx, workDirFromEnv(), api.slices)
	if err != nil {
		return err
	}
	// Check the address before anything is written, so a refused address
	// leaves no token entry behind in the docker config.
	if err := validRegistryHost(host); err != nil {
		return err
	}
	if len(api.caPEM) == 0 {
		return fmt.Errorf("%w: the kubeconfig carries no cluster CA for %s", errNoNodeRegistry, host)
	}
	path := dockerConfigPath(os.Getenv("DOCKER_CONFIG"), homeDir())
	if err := writeDockerConfigEntry(path, host, builderTokenUser, tok.value); err != nil {
		return err
	}
	caPath, err := writeDockerCA(filepath.Dir(path), host, api.caPEM)
	if err != nil {
		return err
	}
	fmt.Fprintf(stdout, "logged in to %s in %s (the token expires %s; run k3sm registry login again after that)\n",
		host, path, tok.expires.Local().Format(time.RFC3339))
	fmt.Fprintf(stdout, "wrote the cluster CA for %s to %s\n", host, caPath)
	fmt.Fprintf(stdout, "push as %s/<repository>:<tag>; a Pod names it %s/<repository>:<tag>\n", host, registrysvc.FlatAuthority())
	return nil
}

// loginAuthority is the registry address a Mac tool reaches the push gate at:
// localhost:<gate port> on a server (the loopback gate), or the server's
// cluster address from the flat Service's endpoint on a worker.
func loginAuthority(ctx context.Context, workDir string, slices endpointSliceLister) (string, error) {
	if port := localGatePort(workDir); port > 0 {
		return net.JoinHostPort("localhost", strconv.Itoa(port)), nil
	}
	return clusterEndpointAuthority(ctx, slices)
}

// errBadRegistryHost reports a registry address that is not a literal
// host:port, refused before it becomes a directory name under certs.d.
var errBadRegistryHost = errors.New("the registry address is not a literal host:port")

// errSymlinkInCertsDir reports a symbolic link where writeDockerCA expects a
// directory: following it would write the CA wherever it points.
var errSymlinkInCertsDir = errors.New("a symbolic link stands where a certs.d directory belongs")

// writeDockerCA writes the cluster CA as certs.d/<host>/ca.crt under the docker
// config dir, where docker and buildx look for a registry's CA. The file is
// mode 0644 under a 0755 directory: a CA certificate is public. host must be a
// literal host:port, and no directory under certs.d is reached through a
// symbolic link.
func writeDockerCA(dockerDir, host string, caPEM []byte) (string, error) {
	if err := validRegistryHost(host); err != nil {
		return "", err
	}
	if err := os.MkdirAll(dockerDir, 0o700); err != nil {
		return "", fmt.Errorf("create %s: %w", dockerDir, err)
	}
	certsDir := filepath.Join(dockerDir, "certs.d")
	dir := filepath.Join(certsDir, host)
	for _, d := range []string{certsDir, dir} {
		if err := ensureRealDir(d, 0o755); err != nil {
			return "", err
		}
	}
	path := filepath.Join(dir, "ca.crt")
	if err := atomicfile.Replace(path, caPEM, 0o644); err != nil {
		return "", fmt.Errorf("write the cluster CA %s: %w", path, err)
	}
	return path, nil
}

// validRegistryHost accepts a literal host:port: an IP address or a DNS name,
// and a numeric port in 1-65535. A path separator, "..", or NUL is refused
// whatever else the string holds, since host becomes a directory name.
func validRegistryHost(host string) error {
	if host == "" || strings.ContainsAny(host, "/\\\x00") || strings.Contains(host, "..") {
		return fmt.Errorf("%w: %q", errBadRegistryHost, host)
	}
	h, port, err := net.SplitHostPort(host)
	if err != nil {
		return fmt.Errorf("%w: %q: %w", errBadRegistryHost, host, err)
	}
	if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 || strconv.Itoa(n) != port {
		return fmt.Errorf("%w: %q: the port is not a number in 1-65535", errBadRegistryHost, host)
	}
	if net.ParseIP(h) == nil && !validDNSName(h) {
		return fmt.Errorf("%w: %q: the host is neither an IP address nor a DNS name", errBadRegistryHost, host)
	}
	return nil
}

// validDNSName reports whether name is a DNS name: dot-separated labels of
// letters, digits and hyphens, each 1-63 bytes and not starting or ending with
// a hyphen, 253 bytes at most in all.
func validDNSName(name string) bool {
	if name == "" || len(name) > 253 {
		return false
	}
	for _, label := range strings.Split(name, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}

// ensureRealDir makes dir a real directory of the given mode without following
// a symbolic link: an existing symlink is refused, an existing directory has
// its mode set (the umask may have narrowed it, and the CA is meant to be
// readable), and a missing one is created. Anything else is refused.
func ensureRealDir(dir string, mode os.FileMode) error {
	fi, err := os.Lstat(dir)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		if err := os.Mkdir(dir, mode); err != nil {
			return fmt.Errorf("create %s: %w", dir, err)
		}
		// Mkdir fails on anything planted since the Lstat rather than
		// following it; look again at what was made before the Chmod.
		if fi, err = os.Lstat(dir); err != nil {
			return fmt.Errorf("inspect %s: %w", dir, err)
		}
	case err != nil:
		return fmt.Errorf("inspect %s: %w", dir, err)
	}
	if fi.Mode()&fs.ModeSymlink != 0 {
		return fmt.Errorf("%w: %s", errSymlinkInCertsDir, dir)
	}
	if !fi.IsDir() {
		return fmt.Errorf("%s is not a directory", dir)
	}
	if err := os.Chmod(dir, mode); err != nil {
		return fmt.Errorf("set the mode of %s: %w", dir, err)
	}
	return nil
}

// homeDir is the invoking user's home, or "" when it cannot be resolved.
func homeDir() string {
	h, _ := os.UserHomeDir()
	return h
}

// dockerConfigPath is the file docker reads its credentials from: config.json
// under $DOCKER_CONFIG when set, else under ~/.docker.
func dockerConfigPath(dockerConfigEnv, home string) string {
	if dockerConfigEnv != "" {
		return filepath.Join(dockerConfigEnv, "config.json")
	}
	return filepath.Join(home, ".docker", "config.json")
}

// errDockerCredentialStore reports a docker config whose credential store or
// helper, not its auths map, answers for the registry: an entry written to auths
// would be ignored, so login refuses instead of reporting a login that is not.
var errDockerCredentialStore = errors.New("this docker config keeps credentials in a credential store")

// writeDockerConfigEntry sets auths[host] in the docker config at path to a
// Basic credential of user and secret, keeping every other key the file holds,
// and writes it atomically with mode 0600. A missing file is created.
func writeDockerConfigEntry(path, host, user, secret string) error {
	doc := map[string]json.RawMessage{}
	raw, err := os.ReadFile(path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
	case err != nil:
		return fmt.Errorf("read docker config %s: %w", path, err)
	default:
		if err := json.Unmarshal(raw, &doc); err != nil {
			return fmt.Errorf("docker config %s is not a JSON object: %w", path, err)
		}
	}
	var helpers map[string]string
	if h, ok := doc["credHelpers"]; ok {
		_ = json.Unmarshal(h, &helpers) // a malformed value is docker's to report
	}
	var store string
	if s, ok := doc["credsStore"]; ok {
		_ = json.Unmarshal(s, &store)
	}
	if helpers[host] != "" || store != "" {
		return fmt.Errorf("%w (%s); log in through it instead: k3sm registry token | docker login %s -u %s --password-stdin",
			errDockerCredentialStore, path, host, user)
	}
	auths := map[string]json.RawMessage{}
	if a, ok := doc["auths"]; ok {
		if err := json.Unmarshal(a, &auths); err != nil {
			return fmt.Errorf("docker config %s: auths is not an object: %w", path, err)
		}
	}
	entry, err := json.Marshal(map[string]string{"auth": base64.StdEncoding.EncodeToString([]byte(user + ":" + secret))})
	if err != nil {
		return fmt.Errorf("encode the docker config entry: %w", err)
	}
	auths[host] = entry
	if doc["auths"], err = json.Marshal(auths); err != nil {
		return fmt.Errorf("encode the docker config auths: %w", err)
	}
	out, err := json.MarshalIndent(doc, "", "\t")
	if err != nil {
		return fmt.Errorf("encode docker config %s: %w", path, err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create %s: %w", filepath.Dir(path), err)
	}
	if err := atomicfile.Replace(path, append(out, '\n'), 0o600); err != nil {
		return fmt.Errorf("write docker config %s: %w", path, err)
	}
	return nil
}

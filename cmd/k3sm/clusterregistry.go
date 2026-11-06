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
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	stdmaps "maps"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	discoveryv1 "k8s.io/api/discovery/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"

	"k3sm.io/darwin-net/pkg/tcpseg"
	"k3sm.io/k3sm/pkg/executor"
	"k3sm.io/k3sm/pkg/install"
	"k3sm.io/k3sm/pkg/registrysvc"
)

// THE CLUSTER REGISTRY FROM THIS MAC. Every write k3sm makes to the cluster
// registry (build, load, import, push) goes through the push gate with a
// builder token minted through the caller's kubeconfig, on every Mac:
//
//   - on a server, to the loopback gate on 127.0.0.1 at the port its state
//     record names (registrysvc.GatePort, 6451 by default);
//   - on a worker, to the server's cluster address, the endpoint of the flat
//     registry-k3sm Service's EndpointSlice.
//
// Either way the connection is HTTPS, verified against the cluster CA from the
// kubeconfig with the name registry-k3sm, which both gates' certificates carry.
// The registry's per-boot credential is not used: it stays the gate's own
// upstream credential to the registry.

// defaultGatePort is the loopback gate's port on a server started with the
// default --registry-port.
var defaultGatePort = registrysvc.GatePort(executor.DefaultRegistryPort)

// pushTokenDuration is the lifetime of the builder token a push mints.
const pushTokenDuration = defaultBuilderTokenDuration

// endpointSliceGetter is the slice of the API the worker path reads the flat
// Service's endpoint through: a get of the one EndpointSlice by name, which is
// all the k3sm:registry-builder-token Role grants (it has no list).
type endpointSliceGetter interface {
	Get(ctx context.Context, name string, opts metav1.GetOptions) (*discoveryv1.EndpointSlice, error)
}

// clusterRegistryAPI is what the caller's kubeconfig gives the cluster-registry
// path: the builder token endpoint, the flat Service's EndpointSlices, and the
// cluster CA the registry's certificates are verified against.
type clusterRegistryAPI struct {
	tokens serviceAccountTokens
	slices endpointSliceGetter
	caPEM  []byte
	// nodeHint, when set, says the kubeconfig is this worker's node credential
	// and what to do about a refused token (nodeCredentialHint).
	nodeHint string
}

// mintToken mints a builder token, and a refusal says what to do when the
// identity asking is a node's.
func (a clusterRegistryAPI) mintToken(ctx context.Context, d time.Duration, now func() time.Time) (builderToken, error) {
	tok, err := mintBuilderToken(ctx, a.tokens, d, now)
	if a.nodeHint != "" && errors.Is(err, errBuilderTokenRefused) {
		return builderToken{}, fmt.Errorf("%w; %s", err, a.nodeHint)
	}
	return tok, err
}

// clusterRegistryClient resolves the caller's kubeconfig the way `k3sm kubectl`
// and the builder verbs do, except for a worker under sudo (registryClients). It
// is a variable so a test points it at a fake.
var clusterRegistryClient = func() (clusterRegistryAPI, error) {
	in := builderKubeInputs(builderOptions{workDir: workDirFromEnv(), workDirExplicit: os.Getenv("K3SM_WORK_DIR") != ""})
	return clusterRegistryAPIFrom(in, topSudoInputsFromEnv())
}

// clusterRegistryAPIFrom is clusterRegistryClient over injected inputs.
func clusterRegistryAPIFrom(in kubectlInputs, sudo topSudoInputs) (clusterRegistryAPI, error) {
	restCfg, cs, nodeHint, err := registryClients(in, sudo)
	if err != nil {
		remedy := builderTokenRemedy
		if in.role == install.RoleAgent {
			remedy = workerMintRemedy
		}
		return clusterRegistryAPI{}, fmt.Errorf("%w (%v); %s", errNoUserKubeconfig, err, remedy)
	}
	ca := restCfg.CAData
	if len(ca) == 0 && restCfg.CAFile != "" {
		if ca, err = os.ReadFile(restCfg.CAFile); err != nil {
			return clusterRegistryAPI{}, fmt.Errorf("read the cluster CA %s named by the kubeconfig: %w", restCfg.CAFile, err)
		}
	}
	return clusterRegistryAPI{
		tokens:   cs.CoreV1().ServiceAccounts(registrysvc.BuilderNamespace),
		slices:   cs.DiscoveryV1().EndpointSlices(registrysvc.FlatServiceNamespace),
		caPEM:    ca,
		nodeHint: nodeHint,
	}, nil
}

// workerMintRemedy is the fix for a worker with no kubeconfig to mint a registry
// push token with. A worker writes no user kubeconfig, so the copy is saved by hand,
// where registryClients reads it under sudo: `image migrate`, `push` and `load` need
// root or the service user, and $KUBECONFIG is ignored under sudo.
const workerMintRemedy = "run `k3sm kubeconfig > k3sm.yaml` on the server, save the copied admin kubeconfig as `~/.kube/config`, owned by you and not group- or world-writable, and run with sudo; or have an admin bind the k3sm:registry-builder-token Role to you with a RoleBinding in " + registrysvc.BuilderNamespace

// registryClients picks the kubeconfig a builder token is minted through.
//
// Everywhere but a worker under sudo it is the builder verbs' choice. Under sudo
// a worker's order is K3SM_WORK_DIR, then the account's own kubeconfig, but the
// account has two owners: root's own comes first, then the invoking user's. That
// user's file is read only through topSudoInputs.userKubeconfig, with its checks
// on ownership and credentials, and $HOME is not consulted at all, because sudo
// may have kept the invoker's and that would read the same file without those
// checks. $KUBECONFIG is dropped for the same reason: under sudo it may name a
// file root has not checked, and the invoker's own file is already read through
// the checked path. That file also picks where root pushes, so checkSudoUserCluster
// holds it to the cluster this node joined.
//
// With neither, the run stops: root never falls back to the node credential, under
// sudo or not (workerMintRefusal). The service user reads its own node credential
// and gets nodeHint for the refusal that follows.
func registryClients(in kubectlInputs, sudo topSudoInputs) (*rest.Config, kubernetes.Interface, string, error) {
	in.asRoot = sudo.euid == 0
	worker := in.role == install.RoleAgent && in.workDirOverride == ""
	if worker && sudo.underSudo() {
		if in.kubeconfigEnv != "" && sudo.warn != nil {
			fmt.Fprintf(sudo.warn, "k3sm: ignoring $KUBECONFIG under sudo on this worker: reading %s's ~/.kube/config instead, after checking its owner, mode and cluster\n", sudo.sudoUser)
		}
		node := in.nodeKubeconfig
		in.kubeconfigEnv = ""
		in.home = sudo.rootHome()
		in.nodeKubeconfig = ""
		if _, err := resolveKubectlConfig(in); err == nil {
			restCfg, cs, err := builderClients(in)
			return restCfg, cs, "", err
		}
		cfg, path, err := sudo.userKubeconfig()
		if err == nil {
			err = checkSudoUserCluster(cfg, path, sudo)
		}
		if err != nil {
			if errors.Is(err, errSudoKubeconfigRefused) && sudo.warn != nil {
				fmt.Fprintf(sudo.warn, "k3sm: %v\n", err)
			}
			return nil, nil, "", fmt.Errorf("%w; and root does not use the node credential %s, which is a node identity and may not mint a registry push token", err, node)
		}
		restCfg, cs, err := sudoUserClients(cfg, sudo.contextName)
		return restCfg, cs, "", err
	}
	if worker {
		if err := workerMintRefusal(in); err != nil {
			return nil, nil, "", err
		}
	}
	restCfg, cs, err := builderClients(in)
	if err != nil {
		return nil, nil, "", err
	}
	hint := ""
	if chosen, err := builderKubeconfig(in); worker && err == nil && in.nodeKubeconfig != "" && chosen.kubeconfig == in.nodeKubeconfig {
		hint = nodeCredentialHint(in.nodeKubeconfig)
	}
	return restCfg, cs, hint, nil
}

// workerMintRefusal says why this account has nothing to mint a push token with on
// a worker, or nil when it has. It stops before builderKubeconfig's refusals, whose
// fix is for the builder verbs; clusterRegistryAPIFrom adds workerMintRemedy.
func workerMintRefusal(in kubectlInputs) error {
	cfg, err := resolveKubectlConfig(in)
	if err != nil {
		return fmt.Errorf("%s does not exist and the node credential %s is not readable by this account", userKubeconfigNames(in), in.nodeKubeconfig)
	}
	if rootChoseNodeCredential(in, cfg) {
		return fmt.Errorf("%s does not exist and root does not use the node credential %s, which is a node identity and may not mint a registry push token", userKubeconfigNames(in), in.nodeKubeconfig)
	}
	return nil
}

// checkSudoUserCluster refuses a sudo user's kubeconfig that would have root talk
// to anything but the cluster this node joined. The file chooses the apiserver, and
// the apiserver's EndpointSlice chooses where root pushes, so its cluster must be
// reached over verified TLS and hold exactly the CA in this worker's root-only copy
// (agentClusterCA). The pin is the CA and not the address, because a person's file
// can legitimately use a different address from the node's. A copy that cannot be
// trusted leaves nothing to compare with, which is a refusal too, and the node
// credential is not used instead: a node identity may not mint a registry push
// token.
func checkSudoUserCluster(cfg *clientcmdapi.Config, path string, sudo topSudoInputs) error {
	name := cfg.Contexts[sudo.contextName].Cluster
	cluster := cfg.Clusters[name]
	refuse := func(format string, args ...any) error {
		return fmt.Errorf("%s's kubeconfig %s: cluster %q %s, %w", sudo.sudoUser, path, name, fmt.Sprintf(format, args...), errSudoKubeconfigRefused)
	}
	if cluster.InsecureSkipTLSVerify {
		return refuse("sets insecure-skip-tls-verify, and root does not reach a cluster unverified on a user's behalf")
	}
	if u, err := url.Parse(cluster.Server); err != nil || u.Scheme != "https" {
		return refuse("names the server %q, and root reaches a cluster only over https on a user's behalf", cluster.Server)
	}
	clusterCA, err := agentClusterCA(sudo.readFile)
	if err != nil {
		return refuse("cannot be checked, because %v; to fix this worker's copy, run %s", err, agentClusterCARemedy)
	}
	ca := pemCertificates(cluster.CertificateAuthorityData)
	if len(ca) == 0 {
		return refuse("carries no inline CA to compare with this worker's cluster CA %s", install.AgentClusterCAPath)
	}
	if !stdmaps.Equal(ca, clusterCA) {
		return refuse("holds a different CA from this worker's cluster CA %s, so it is not the cluster this node joined", install.AgentClusterCAPath)
	}
	return nil
}

// agentClusterCARemedy repairs the worker's root-only cluster CA copy. The removal
// comes first because an install keeps a copy that holds the CA it would write,
// whoever owns it, and the token because an install with none would take a missing
// copy from the node credential.
var agentClusterCARemedy = fmt.Sprintf("`sudo rm -f %s` and then `sudo k3sm install --agent --server <server> --token-file <file>`, with a fresh token from `k3sm token create` on the server",
	install.AgentClusterCAPath)

// agentClusterCA is the set of certificates in this worker's root-only copy of the
// cluster CA, which `k3sm install` writes pinned by the join token. The checks are
// on what was read: root must own it and nobody else may write to it.
func agentClusterCA(read func(path string) (sudoKubeconfigFile, error)) (map[string]struct{}, error) {
	path := install.AgentClusterCAPath
	f, err := read(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("this worker's cluster CA %s does not exist", path)
	}
	if err != nil {
		return nil, fmt.Errorf("this worker's cluster CA %s cannot be read: %w", path, err)
	}
	if problem := f.ownershipProblem(0, "root"); problem != "" {
		return nil, fmt.Errorf("this worker's cluster CA %s %s", path, problem)
	}
	ca := pemCertificates(f.data)
	if len(ca) == 0 {
		return nil, fmt.Errorf("this worker's cluster CA %s holds no certificate", path)
	}
	return ca, nil
}

// pemCertificates is the set of certificates in a PEM bundle, by DER, so two
// spellings of one CA compare equal and a bundle with one more does not. It reads
// the blocks x509.CertPool.AppendCertsFromPEM reads, which is what the bundle would
// be trusted for.
func pemCertificates(data []byte) map[string]struct{} {
	out := map[string]struct{}{}
	for {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			return out
		}
		if block.Type == "CERTIFICATE" && len(block.Headers) == 0 {
			out[string(block.Bytes)] = struct{}{}
		}
	}
}

// sudoUserClients builds the clients from the sudo user's checked kubeconfig.
func sudoUserClients(cfg *clientcmdapi.Config, contextName string) (*rest.Config, kubernetes.Interface, error) {
	restCfg, err := clientcmd.NewNonInteractiveClientConfig(*cfg, contextName, &clientcmd.ConfigOverrides{}, nil).ClientConfig()
	if err != nil {
		return nil, nil, fmt.Errorf("load the sudo user's kubeconfig context %q: %w", contextName, err)
	}
	cs, err := kubernetes.NewForConfig(restCfg)
	if err != nil {
		return nil, nil, fmt.Errorf("build kubernetes client: %w", err)
	}
	return restCfg, cs, nil
}

// nodeCredentialHint is what a refused token adds when the identity asking was
// this worker's node credential: the fix.
func nodeCredentialHint(path string) string {
	return fmt.Sprintf("this ran with the worker's node credential %s, which may not mint a registry push token and is not meant to; give your account a kubeconfig: %s", path, workerMintRemedy)
}

// gateEndpoint is where this Mac sends a write to the cluster registry, and
// with what. String never prints the token.
type gateEndpoint struct {
	// authority is the host:port this Mac dials.
	authority string
	// caPEM is the cluster CA the endpoint's certificate is verified against.
	caPEM []byte
	// token is the builder token every request carries.
	token builderToken
}

// resolveClusterRegistry finds the cluster registry from this Mac and mints a
// builder token for it. It is a variable so a test that is not about the
// resolution points it at a fixed endpoint.
var resolveClusterRegistry = resolveClusterRegistryLive

// resolveClusterRegistryLive is the production resolveClusterRegistry.
func resolveClusterRegistryLive(ctx context.Context, workDir string) (gateEndpoint, error) {
	api, err := clusterRegistryClient()
	if err != nil {
		return gateEndpoint{}, err
	}
	return clusterRegistryFrom(ctx, workDir, api, time.Now)
}

// clusterRegistryFrom is resolveClusterRegistry over an injected API.
func clusterRegistryFrom(ctx context.Context, workDir string, api clusterRegistryAPI, now func() time.Time) (gateEndpoint, error) {
	if len(api.caPEM) == 0 {
		return gateEndpoint{}, fmt.Errorf("%w: the kubeconfig carries no cluster CA to verify the registry against", errNoNodeRegistry)
	}
	authority, err := clusterRegistryAuthority(ctx, workDir, api.slices)
	if err != nil {
		return gateEndpoint{}, err
	}
	tok, err := api.mintToken(ctx, pushTokenDuration, now)
	if err != nil {
		return gateEndpoint{}, err
	}
	return gateEndpoint{authority: authority, caPEM: api.caPEM, token: tok}, nil
}

// clusterRegistryAuthority is the address this Mac reaches the push gate at:
// the loopback gate when this Mac's server serves one, else the flat
// Service's endpoint.
func clusterRegistryAuthority(ctx context.Context, workDir string, slices endpointSliceGetter) (string, error) {
	if port := localGatePort(workDir); port > 0 {
		return net.JoinHostPort(registrysvc.LoopbackAddress, strconv.Itoa(port)), nil
	}
	return clusterEndpointAuthority(ctx, slices)
}

// installedServerWorkDir is the installed server's work dir. An ordinary account's
// own work dir (<home>/server) holds no registry state, so localRegistryState also
// reads the record this server publishes beside it, in the world-readable status
// directory. A variable so a test points it at a fake install.
var installedServerWorkDir = executor.DefaultWorkDir

// localGatePort is the loopback gate's port this Mac's server recorded, or 0
// when this Mac serves none (a worker, or a server whose gate is off).
func localGatePort(workDir string) int {
	st, ok := localRegistryState(workDir)
	if !ok {
		return 0
	}
	if st.GatePort == 0 {
		slog.Debug("this Mac's registry records no loopback push gate", "workDir", workDir)
	}
	return st.GatePort
}

// localRegistryPort is the port this Mac's registry serves on its loopback
// listener, as its server recorded it, or 0 when this Mac serves none. An
// anonymous read goes there.
func localRegistryPort(workDir string) int {
	st, ok := localRegistryState(workDir)
	if !ok {
		return 0
	}
	return st.Port
}

// localRegistryState is the serving registry record of this Mac's server, and
// whether there is one.
//
// It reads workDir's record and, when workDir holds none, the installed
// server's: for an ordinary account workDir is <home>/server, where no server
// ever wrote, while the installed server publishes its record world-readably
// (registrysvc.ReadLocalState reads that copy before the 0600 original). Every
// way of finding none is logged at debug, so a fallback to the cluster address
// says why.
func localRegistryState(workDir string) (registrysvc.State, bool) {
	for _, dir := range localRegistryDirs(workDir) {
		if dir == "" {
			continue
		}
		st, err := registrysvc.ReadLocalState(dir)
		if errors.Is(err, fs.ErrNotExist) {
			slog.Debug("no registry state record; looking further for this Mac's registry", "workDir", dir)
			continue
		}
		if err != nil {
			slog.Debug("cannot read the registry state record, so this Mac's registry is not used",
				"workDir", dir, "published", registrysvc.PublishedStatePath(dir), "err", err)
			return registrysvc.State{}, false
		}
		if st.State != registrysvc.StateServing && st.State != registrysvc.StateReclaimed {
			slog.Debug("this Mac's registry is not serving, so it is not used", "workDir", dir, "state", st.State)
			return registrysvc.State{}, false
		}
		return st, true
	}
	slog.Debug("this Mac serves no registry; the push goes to the server's cluster address")
	return registrysvc.State{}, false
}

// localRegistryDirs is where this Mac's serving registry record may be. A worker
// serves no registry, so a record in the server work dir, or published beside it,
// is left over from an earlier server install: a "serving" one would send the
// push to a loopback gate nothing listens on, the same stale address as the work
// dir's kubeconfig. There only a work dir the caller named is read, by
// K3SM_WORK_DIR or by a --work-dir that is not this default.
func localRegistryDirs(workDir string) []string {
	if role, _ := installedNodeCredential(); role == install.RoleAgent {
		if !callerNamedWorkDir(workDir) {
			slog.Debug("this Mac is a worker; a registry record in the server work dir is not its own", "workDir", workDir)
			return nil
		}
		return []string{workDir}
	}
	dirs := []string{workDir}
	if workDir != installedServerWorkDir {
		dirs = append(dirs, installedServerWorkDir)
	}
	return dirs
}

// callerNamedWorkDir reports whether workDir is one the caller chose, by
// K3SM_WORK_DIR or by a --work-dir that is not this Mac's default server work dir.
// On a worker, anything else in a server work dir is left over from an earlier
// server install.
func callerNamedWorkDir(workDir string) bool {
	clean := filepath.Clean(workDir)
	return os.Getenv("K3SM_WORK_DIR") != "" || (clean != filepath.Clean(workDirFromEnv()) && clean != filepath.Clean(installedServerWorkDir))
}

// clusterEndpointAuthority reads the flat registry-k3sm Service's EndpointSlice,
// by name, and returns its ready endpoint as host:port: the server's cluster
// address and the relay's port. The server publishes exactly one slice for the
// Service, named after it, so a get by name finds it with no list right.
func clusterEndpointAuthority(ctx context.Context, slices endpointSliceGetter) (string, error) {
	s, err := slices.Get(ctx, registrysvc.FlatServiceName, metav1.GetOptions{})
	switch {
	case apierrors.IsForbidden(err):
		return "", fmt.Errorf("%w: this kubeconfig may not get the %s EndpointSlice in %s, which names the server's registry address",
			errNoNodeRegistry, registrysvc.FlatServiceName, registrysvc.FlatServiceNamespace)
	case apierrors.IsNotFound(err):
		return "", fmt.Errorf("%w: the cluster publishes no %s EndpointSlice in %s (the server's registry is off or down, or it has no mesh address a worker reaches)",
			errNoNodeRegistry, registrysvc.FlatServiceName, registrysvc.FlatServiceNamespace)
	case err != nil:
		return "", fmt.Errorf("find the cluster registry (the %s Service's endpoint): %w", registrysvc.FlatServiceName, err)
	}
	if port := slicePort(s.Ports); port != 0 {
		for _, ep := range s.Endpoints {
			if ep.Conditions.Ready != nil && !*ep.Conditions.Ready {
				continue
			}
			if len(ep.Addresses) == 0 {
				continue
			}
			return net.JoinHostPort(ep.Addresses[0], strconv.Itoa(port)), nil
		}
	}
	return "", fmt.Errorf("%w: the cluster publishes no ready endpoint for the %s Service (the server's registry is off or down, or it has no mesh address a worker reaches)",
		errNoNodeRegistry, registrysvc.FlatServiceName)
}

// slicePort is the registry port of an EndpointSlice: the one named
// registrysvc.ClusterServicePortName, or the only one.
func slicePort(ports []discoveryv1.EndpointPort) int {
	for _, p := range ports {
		if p.Port != nil && p.Name != nil && *p.Name == registrysvc.ClusterServicePortName {
			return int(*p.Port)
		}
	}
	if len(ports) == 1 && ports[0].Port != nil {
		return int(*ports[0].Port)
	}
	return 0
}

// errBadClusterCA reports a kubeconfig CA that holds no certificate.
var errBadClusterCA = errors.New("the kubeconfig's cluster CA holds no PEM certificate")

// gateDial replaces how a request to a push gate is dialed; tests serve the
// gate in process through it. nil is the segment-clamped TCP dial.
var gateDial func(ctx context.Context, network, addr string) (net.Conn, error)

// options are the go-containerregistry options a request to c carries: HTTPS
// verified against the cluster CA under the name registry-k3sm, and the
// builder token as the password of a Basic login.
func (c gateEndpoint) options(ctx context.Context) ([]remote.Option, error) {
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(c.caPEM) {
		return nil, errBadClusterCA
	}
	t := http.DefaultTransport.(*http.Transport).Clone()
	// Segment-clamped like every other dial this node makes toward the mesh
	// (tcpseg): on a worker the gate is the server's cluster address. The
	// timeouts are http.DefaultTransport's own dialer's.
	t.DialContext = (&tcpseg.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}).DialContext
	if gateDial != nil {
		t.DialContext = gateDial
	}
	t.TLSClientConfig = &tls.Config{
		MinVersion: tls.VersionTLS12,
		RootCAs:    pool,
		ServerName: registrysvc.FlatServiceName,
	}
	auth := authn.FromConfig(authn.AuthConfig{Username: builderTokenUser, Password: c.token.value})
	return []remote.Option{remote.WithContext(ctx), remote.WithTransport(boundRequests(t)), remote.WithAuth(auth)}, nil
}

// String names the endpoint and redacts the token.
func (c gateEndpoint) String() string { return c.authority + " (" + c.token.String() + ")" }

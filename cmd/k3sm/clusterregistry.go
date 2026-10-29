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
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	discoveryv1 "k8s.io/api/discovery/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"k3sm.io/darwin-net/pkg/tcpseg"
	"k3sm.io/k3sm/pkg/executor"
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
// upstream credential to zot.

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
}

// clusterRegistryClient resolves the caller's kubeconfig the way `k3sm kubectl`
// and the builder verbs do. It is a variable so a test points it at a fake.
var clusterRegistryClient = func() (clusterRegistryAPI, error) {
	in := builderKubeInputs(builderOptions{workDir: workDirFromEnv(), workDirExplicit: os.Getenv("K3SM_WORK_DIR") != ""})
	restCfg, cs, err := builderClients(in)
	if err != nil {
		return clusterRegistryAPI{}, fmt.Errorf("%w (%v); %s", errNoUserKubeconfig, err, builderTokenRemedy)
	}
	ca := restCfg.CAData
	if len(ca) == 0 && restCfg.CAFile != "" {
		if ca, err = os.ReadFile(restCfg.CAFile); err != nil {
			return clusterRegistryAPI{}, fmt.Errorf("read the cluster CA %s named by the kubeconfig: %w", restCfg.CAFile, err)
		}
	}
	return clusterRegistryAPI{
		tokens: cs.CoreV1().ServiceAccounts(registrysvc.BuilderNamespace),
		slices: cs.DiscoveryV1().EndpointSlices(registrysvc.FlatServiceNamespace),
		caPEM:  ca,
	}, nil
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
	tok, err := mintBuilderToken(ctx, api.tokens, pushTokenDuration, now)
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
	dirs := []string{workDir}
	if workDir != installedServerWorkDir {
		dirs = append(dirs, installedServerWorkDir)
	}
	for _, dir := range dirs {
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
	return []remote.Option{remote.WithContext(ctx), remote.WithTransport(dropMountOrigin{t}), remote.WithAuth(auth)}, nil
}

// dropMountOrigin removes the "origin" parameter go-containerregistry adds to a
// cross-repository mount request (POST .../blobs/uploads/?mount=&from=&origin=).
// It is not part of the distribution specification, and the push gate parses an
// upload's query against the specification's keys and refuses any other, so
// with it every mount would be refused and the blob re-sent in full. Without
// it the request is the specification's mount, which the gate authorizes on
// both repositories.
type dropMountOrigin struct{ next http.RoundTripper }

// RoundTrip sends r without an "origin" query parameter on a blob upload start.
func (d dropMountOrigin) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.Method != http.MethodPost || !strings.HasSuffix(r.URL.Path, "/blobs/uploads/") {
		return d.next.RoundTrip(r)
	}
	q := r.URL.Query()
	if !q.Has("origin") {
		return d.next.RoundTrip(r)
	}
	q.Del("origin")
	out := r.Clone(r.Context())
	out.URL.RawQuery = q.Encode()
	return d.next.RoundTrip(out)
}

// String names the endpoint and redacts the token.
func (c gateEndpoint) String() string { return c.authority + " (" + c.token.String() + ")" }

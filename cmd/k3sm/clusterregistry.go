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
	"net"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	discoveryv1 "k8s.io/api/discovery/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

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

// endpointSliceLister is the slice of the API the worker path reads the flat
// Service's endpoint through.
type endpointSliceLister interface {
	List(ctx context.Context, opts metav1.ListOptions) (*discoveryv1.EndpointSliceList, error)
}

// clusterRegistryAPI is what the caller's kubeconfig gives the cluster-registry
// path: the builder token endpoint, the flat Service's EndpointSlices, and the
// cluster CA the registry's certificates are verified against.
type clusterRegistryAPI struct {
	tokens serviceAccountTokens
	slices endpointSliceLister
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
func clusterRegistryAuthority(ctx context.Context, workDir string, slices endpointSliceLister) (string, error) {
	if port := localGatePort(workDir); port > 0 {
		return net.JoinHostPort(registrysvc.LoopbackAddress, strconv.Itoa(port)), nil
	}
	return clusterEndpointAuthority(ctx, slices)
}

// localGatePort is the loopback gate's port this Mac's server recorded, or 0
// when this Mac serves none (a worker, or a server whose gate is off).
func localGatePort(workDir string) int {
	if workDir == "" {
		return 0
	}
	st, err := registrysvc.ReadLocalState(workDir)
	if err != nil {
		return 0
	}
	if st.State != registrysvc.StateServing && st.State != registrysvc.StateReclaimed {
		return 0
	}
	return st.GatePort
}

// clusterEndpointAuthority reads the flat registry-k3sm Service's EndpointSlice
// and returns its ready endpoint as host:port: the server's cluster address
// and the relay's port.
func clusterEndpointAuthority(ctx context.Context, slices endpointSliceLister) (string, error) {
	list, err := slices.List(ctx, metav1.ListOptions{LabelSelector: discoveryv1.LabelServiceName + "=" + registrysvc.FlatServiceName})
	switch {
	case apierrors.IsForbidden(err):
		return "", fmt.Errorf("%w: this kubeconfig may not read the %s Service's EndpointSlices in %s, which name the server's registry address",
			errNoNodeRegistry, registrysvc.FlatServiceName, registrysvc.FlatServiceNamespace)
	case err != nil:
		return "", fmt.Errorf("find the cluster registry (the %s Service's endpoint): %w", registrysvc.FlatServiceName, err)
	}
	for _, s := range list.Items {
		port := slicePort(s.Ports)
		if port == 0 {
			continue
		}
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

// options are the go-containerregistry options a request to c carries: HTTPS
// verified against the cluster CA under the name registry-k3sm, and the
// builder token as the password of a Basic login.
func (c gateEndpoint) options(ctx context.Context) ([]remote.Option, error) {
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(c.caPEM) {
		return nil, errBadClusterCA
	}
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.TLSClientConfig = &tls.Config{
		MinVersion: tls.VersionTLS12,
		RootCAs:    pool,
		ServerName: registrysvc.FlatServiceName,
	}
	auth := authn.FromConfig(authn.AuthConfig{Username: builderTokenUser, Password: c.token.value})
	return []remote.Option{remote.WithContext(ctx), remote.WithTransport(t), remote.WithAuth(auth)}, nil
}

// String names the endpoint and redacts the token.
func (c gateEndpoint) String() string { return c.authority + " (" + c.token.String() + ")" }

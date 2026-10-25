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
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/google/go-containerregistry/pkg/v1/remote"

	"k3sm.io/k3sm/pkg/registrysvc"
)

// The cluster-registry verbs run by an ordinary account on the server: its own
// work dir holds no push credential, and the installed server's 0600 one is
// closed to it. Writes go through the push gate with the account's builder
// token, reads go anonymously to the registry's loopback listener, and untag,
// which the gate never forwards, names the root run that does it.

// asCredentiallessServer lays out the server an ordinary account sees: its own
// work dir (<home>/server) holds nothing, and the installed server's record,
// serving the registry on regPort with the push gate on gatePort, is readable
// while no push credential is. It returns the account's own work dir.
func asCredentiallessServer(t *testing.T, regPort, gatePort int) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("DOCKER_CONFIG", home)
	t.Setenv("K3SM_WORK_DIR", "")
	t.Setenv(registryTokenEnv, "")
	installed := filepath.Join(t.TempDir(), "server")
	if err := os.Mkdir(installed, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := registrysvc.WriteState(installed, registrysvc.State{
		State: registrysvc.StateServing, Port: regPort, Addr: "127.0.0.1:" + strconv.Itoa(regPort), GatePort: gatePort,
	}); err != nil {
		t.Fatal(err)
	}
	prev := installedServerWorkDir
	installedServerWorkDir = installed
	t.Cleanup(func() { installedServerWorkDir = prev })
	return filepath.Join(home, "server")
}

// gateTransport reaches the in-process gate as a test client.
func gateTransport(g gateRegistry) *http.Transport {
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(g.caPEM)
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = &tls.Config{RootCAs: pool, ServerName: "registry-k3sm"}
	tr.DialContext = g.dial
	return tr
}

// TestImageUntagUsesUserIdentity is the gate for the cluster-registry verbs run
// by an ordinary account on the server, which holds no readable push
// credential. `k3sm image tag` writes through the push gate with a builder
// token minted through the account's kubeconfig, as push and build --push do.
// `k3sm image untag` cannot: the gate never forwards a delete, so a builder
// token can never remove a tag, and untag refuses before any request with the
// root run that does it.
func TestImageUntagUsesUserIdentity(t *testing.T) {
	want := "Basic " + base64.StdEncoding.EncodeToString([]byte("builder:"+fakeBuilderTokenToken))

	t.Run("tag writes through the gate with the builder token", func(t *testing.T) {
		g := startGateRegistry(t)
		minted := clusterAPIFor(t, g)
		asCredentiallessServer(t, 16450, g.port)
		img, err := random.Image(64, 1)
		if err != nil {
			t.Fatal(err)
		}
		at := func(tag string) name.Tag {
			ref, err := name.NewTag("127.0.0.1:" + strconv.Itoa(g.port) + "/team/app:" + tag)
			if err != nil {
				t.Fatal(err)
			}
			return ref
		}
		tr := gateTransport(g)
		if err := remote.Write(at("v1"), img, remote.WithTransport(tr), remote.WithContext(t.Context())); err != nil {
			t.Fatalf("seed: %v", err)
		}
		seeded := len(g.probe.headers())

		out, err := runImageCmd(t, []string{"tag", "team/app:v1", "registry-k3sm:6450/team/app:stable"})
		if err != nil {
			t.Fatalf("tag as an ordinary account: %v\n%s", err, out)
		}
		if !strings.Contains(out, "tagged registry-k3sm:6450/team/app:stable") {
			t.Errorf("output = %q, want the flat name", out)
		}
		desc, err := remote.Head(at("stable"), remote.WithTransport(tr), remote.WithContext(t.Context()))
		if err != nil {
			t.Fatalf("head the new tag: %v", err)
		}
		if wd, _ := img.Digest(); desc.Digest != wd {
			t.Errorf("team/app:stable = %s, want %s", desc.Digest, wd)
		}
		if *minted != 1 {
			t.Errorf("builder tokens minted = %d, want 1", *minted)
		}
		sent := g.probe.headers()[seeded:]
		if !containsHeader(sent, want) {
			t.Errorf("tag never presented the builder token; headers = %q", sent)
		}
		for _, h := range sent {
			if h != "" && h != want {
				t.Errorf("tag presented a credential other than the builder token: %q", h)
			}
		}
	})

	t.Run("untag names the root run instead of reaching the gate", func(t *testing.T) {
		g := startGateRegistry(t)
		minted := clusterAPIFor(t, g)
		dir := asCredentiallessServer(t, 16450, g.port)
		_, err := runImageCmd(t, []string{"untag", "registry-k3sm:6450/team/app:v1"})
		if !errors.Is(err, errNoNodeRegistry) {
			t.Fatalf("untag = %v, want errNoNodeRegistry", err)
		}
		for _, s := range []string{"never forwards a delete", "sudo k3sm image --work-dir " + installedServerWorkDir + " untag", registrysvc.CredentialPath(dir)} {
			if !strings.Contains(err.Error(), s) {
				t.Errorf("untag err = %v, want it to name %q", err, s)
			}
		}
		if *minted != 0 || len(g.probe.headers()) != 0 {
			t.Errorf("untag reached the cluster: %d tokens minted, %d gate requests", *minted, len(g.probe.headers()))
		}
	})
}

// loopbackRegistry is an in-process registry standing in for the registry's own
// plain-HTTP loopback listener, served on an in-memory listener that gateDial
// routes localhost:port and 127.0.0.1:port to.
type loopbackRegistry struct {
	port  int
	probe *authProbe
	ln    *memListener
}

func (r loopbackRegistry) dial(ctx context.Context, _, addr string) (net.Conn, error) {
	if addr != r.ln.ap.String() && addr != "localhost:"+strconv.Itoa(r.port) {
		return nil, fmt.Errorf("dial tcp %s: connect: connection refused", addr)
	}
	client, server := net.Pipe()
	select {
	case r.ln.conns <- server:
		return client, nil
	case <-r.ln.closed:
		client.Close()
		server.Close()
		return nil, net.ErrClosed
	case <-ctx.Done():
		client.Close()
		server.Close()
		return nil, ctx.Err()
	}
}

func startLoopbackRegistry(t *testing.T, port int) loopbackRegistry {
	t.Helper()
	probe := &authProbe{inner: registry.New(registry.Logger(log.New(io.Discard, "", 0)))}
	ln := &memListener{
		ap:    netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(port)),
		conns: make(chan net.Conn), closed: make(chan struct{}),
	}
	srv := &http.Server{Handler: probe, ErrorLog: log.New(io.Discard, "", 0)}
	go func() { _ = srv.Serve(ln) }()
	r := loopbackRegistry{port: port, probe: probe, ln: ln}
	prev := gateDial
	gateDial = r.dial
	t.Cleanup(func() {
		gateDial = prev
		_ = srv.Close()
		_ = ln.Close()
	})
	return r
}

// TestImageInspectNeedsNoPushCredential pins that a read of the cluster
// registry needs neither the push credential nor a kubeconfig: an ordinary
// account on the server inspects an image anonymously at the registry's
// loopback listener, the port the server's published record names.
func TestImageInspectNeedsNoPushCredential(t *testing.T) {
	const port = 16452
	reg := startLoopbackRegistry(t, port)
	asCredentiallessServer(t, port, 16451)
	noAPI := 0
	prev := clusterRegistryClient
	clusterRegistryClient = func() (clusterRegistryAPI, error) {
		noAPI++
		return clusterRegistryAPI{}, errNoUserKubeconfig
	}
	t.Cleanup(func() { clusterRegistryClient = prev })

	img, err := random.Image(64, 1)
	if err != nil {
		t.Fatal(err)
	}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.DialContext = reg.dial
	seed, _ := name.NewTag("localhost:" + strconv.Itoa(port) + "/team/app:v1")
	if err := remote.Write(seed, img, remote.WithTransport(tr), remote.WithContext(t.Context())); err != nil {
		t.Fatalf("seed: %v", err)
	}
	digest, _ := img.Digest()
	seeded := len(reg.probe.headers())

	out, err := runImageCmd(t, []string{"inspect", "registry-k3sm:6450/team/app@" + digest.String()})
	if err != nil {
		t.Fatalf("inspect as an ordinary account: %v\n%s", err, out)
	}
	if !strings.Contains(out, digest.String()) {
		t.Errorf("inspect output does not name %s:\n%s", digest, out)
	}
	for _, h := range reg.probe.headers()[seeded:] {
		if h != "" {
			t.Errorf("inspect presented a credential %q; a read is anonymous", h)
		}
	}
	if noAPI != 0 {
		t.Errorf("inspect asked for a kubeconfig %d times; a read needs none", noAPI)
	}
}

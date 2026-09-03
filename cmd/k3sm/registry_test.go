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
	"errors"
	"flag"
	"log/slog"
	"strconv"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	"k3sm.io/k3sm/pkg/executor"
	"k3sm.io/k3sm/pkg/registrysvc"
)

// TestRegistryPortFlagDefaultsOff pins the shipped default. The registry stages
// and runs a pinned zot child — real disk, a real process, a real port — so a
// server that was never asked for one must not acquire it. A default that drifted
// to "on" would be invisible until a second server on the same Mac failed a bind.
func TestRegistryPortFlagDefaultsOff(t *testing.T) {
	fs := flag.NewFlagSet("server", flag.ContinueOnError)
	var opts serverOptions
	_ = registerServerFlags(fs, &opts)

	f := fs.Lookup("registry-port")
	if f == nil {
		t.Fatal("--registry-port is not registered")
	}
	if f.DefValue != "0" {
		t.Errorf("--registry-port default = %q, want \"0\" (disabled)", f.DefValue)
	}
	if !strings.Contains(f.Usage, "0 disables") {
		t.Errorf("--registry-port usage %q does not say that 0 disables it", f.Usage)
	}
	// The suggested port is named in the help so an operator who wants the
	// registry does not have to go read a constant to find a port that is clear of
	// every other listener this process owns.
	if !strings.Contains(f.Usage, strconv.Itoa(executor.DefaultRegistryPort)) {
		t.Errorf("--registry-port usage %q does not name DefaultRegistryPort", f.Usage)
	}
	if err := fs.Parse(nil); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if opts.registryPort != 0 {
		t.Errorf("registryPort = %d after parsing no args, want 0", opts.registryPort)
	}
}

// TestRegistryPortFlagParses pins that an operator-supplied port actually reaches
// the option — the defect class where a flag is registered, parsed, and then
// silently replaced by a default on the way to the thing that binds.
func TestRegistryPortFlagParses(t *testing.T) {
	fs := flag.NewFlagSet("server", flag.ContinueOnError)
	var opts serverOptions
	_ = registerServerFlags(fs, &opts)
	if err := fs.Parse([]string{"--registry-port", "14507"}); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if opts.registryPort != 14507 {
		t.Fatalf("registryPort = %d, want 14507", opts.registryPort)
	}
}

// TestRegistryConfig pins the flag-to-config mapping, including the payload dir
// that lets a packaged install seed the zot binary instead of building it — a
// launchd daemon has no Go toolchain, so losing that field would turn every
// packaged boot into a failed registry.
func TestRegistryConfig(t *testing.T) {
	opts := serverOptions{workDir: "/var/lib/k3sm/server", registryPort: 6450}
	cfg := registryConfig(opts, "/opt/k3sm/bin", slog.Default())
	if cfg.WorkDir != opts.workDir {
		t.Errorf("WorkDir = %q, want %q", cfg.WorkDir, opts.workDir)
	}
	if cfg.Port != opts.registryPort {
		t.Errorf("Port = %d, want %d", cfg.Port, opts.registryPort)
	}
	if cfg.PayloadBinDir != "/opt/k3sm/bin" {
		t.Errorf("PayloadBinDir = %q, want the staged payload dir", cfg.PayloadBinDir)
	}
	if cfg.BindAddress != "" {
		t.Errorf("BindAddress = %q, want empty so registrysvc's loopback default applies", cfg.BindAddress)
	}
	if cfg.Logger == nil {
		t.Error("Logger is nil")
	}
}

// TestStartIngestRegistry drives the wiring this file owns: start, publish, tear
// down — and, most importantly, the never-fatal contract on the failure path.
func TestStartIngestRegistry(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(discard{}, nil))

	t.Run("a healthy registry is published and torn down", func(t *testing.T) {
		svc := &fakeRegistry{addr: "127.0.0.1:6450"}
		cs := fake.NewSimpleClientset()
		stop := startIngestRegistry(t.Context(), ingestRegistry{
			svc: svc, port: 6450, nodeName: "mac-a",
			hostingCMs: cs.CoreV1().ConfigMaps(registrysvc.HostingNamespace),
			advertCMs:  cs.CoreV1().ConfigMaps(registrysvc.AdvertisementNamespace),
			logger:     logger,
		})
		if stop == nil {
			t.Fatal("startIngestRegistry returned a nil teardown; the caller defers it unconditionally")
		}
		if svc.starts != 1 {
			t.Fatalf("starts = %d, want 1", svc.starts)
		}
		cm, err := cs.CoreV1().ConfigMaps(registrysvc.HostingNamespace).
			Get(context.Background(), registrysvc.HostingConfigMapName, metav1.GetOptions{})
		if err != nil {
			t.Fatalf("the discovery ConfigMap was not published: %v", err)
		}
		if !strings.Contains(cm.Data[registrysvc.HostingDataKey], "localhost:6450") {
			t.Errorf("published document %q does not name the port", cm.Data[registrysvc.HostingDataKey])
		}
		stop()
		if svc.shutdowns != 1 {
			t.Errorf("shutdowns = %d after the teardown closure ran, want 1", svc.shutdowns)
		}
		if svc.shutdownAfterCancel {
			t.Error("Shutdown received an already-cancelled context; the child would be SIGKILLed mid-write instead of drained")
		}
	})

	t.Run("a registry that cannot start is not fatal and publishes nothing", func(t *testing.T) {
		svc := &fakeRegistry{startErr: errors.New("port held")}
		cs := fake.NewSimpleClientset()
		stop := startIngestRegistry(t.Context(), ingestRegistry{
			svc: svc, port: 6450, nodeName: "mac-a", meshIP: "100.64.1.1",
			hostingCMs: cs.CoreV1().ConfigMaps(registrysvc.HostingNamespace),
			advertCMs:  cs.CoreV1().ConfigMaps(registrysvc.AdvertisementNamespace),
			logger:     logger,
		})
		if stop == nil {
			t.Fatal("startIngestRegistry returned a nil teardown on the failure path")
		}
		if _, err := cs.CoreV1().ConfigMaps(registrysvc.HostingNamespace).
			Get(context.Background(), registrysvc.HostingConfigMapName, metav1.GetOptions{}); err == nil {
			t.Error("a registry that never started still published a discovery ConfigMap naming its port")
		}
		// Nor an advertisement: a peer that found one would wait out a dial to a
		// port nothing is listening on, on every pull that missed locally.
		if _, err := cs.CoreV1().ConfigMaps(registrysvc.AdvertisementNamespace).
			Get(context.Background(), registrysvc.AdvertisementName("mac-a"), metav1.GetOptions{}); err == nil {
			t.Error("a registry that never started still advertised itself to peers")
		}
		stop() // must not panic on a service that never started
		if svc.shutdowns != 0 {
			t.Errorf("shutdowns = %d, want 0 — nothing was started", svc.shutdowns)
		}
	})

	t.Run("a mesh node advertises itself and retracts on teardown", func(t *testing.T) {
		svc := &fakeRegistry{addr: "127.0.0.1:6450"}
		cs := fake.NewSimpleClientset()
		stop := startIngestRegistry(t.Context(), ingestRegistry{
			svc: svc, port: 6450, nodeName: "mac-a", meshIP: "100.64.1.1",
			hostingCMs: cs.CoreV1().ConfigMaps(registrysvc.HostingNamespace),
			advertCMs:  cs.CoreV1().ConfigMaps(registrysvc.AdvertisementNamespace),
			logger:     logger,
		})
		cm, err := cs.CoreV1().ConfigMaps(registrysvc.AdvertisementNamespace).
			Get(context.Background(), registrysvc.AdvertisementName("mac-a"), metav1.GetOptions{})
		if err != nil {
			t.Fatalf("this node published no advertisement, so no peer can pull from it: %v", err)
		}
		if got := cm.Data[registrysvc.AdvertisementMeshHostKey]; got != "100.64.1.1:6450" {
			t.Errorf("advertised %q, want the node's own mesh address and the registry port", got)
		}
		stop()
		// Retracted: a peer must stop being told to dial a registry that is going
		// away. Best effort, but the clean-shutdown path is the one that can.
		if _, err := cs.CoreV1().ConfigMaps(registrysvc.AdvertisementNamespace).
			Get(context.Background(), registrysvc.AdvertisementName("mac-a"), metav1.GetOptions{}); err == nil {
			t.Error("the advertisement survived a clean shutdown")
		}
	})

	t.Run("a single node advertises nothing", func(t *testing.T) {
		// No mesh address: there is no address a peer could dial, and an
		// advertisement naming one would be a lie a peer then dials.
		svc := &fakeRegistry{addr: "127.0.0.1:6450"}
		cs := fake.NewSimpleClientset()
		stop := startIngestRegistry(t.Context(), ingestRegistry{
			svc: svc, port: 6450, nodeName: "mac-a",
			hostingCMs: cs.CoreV1().ConfigMaps(registrysvc.HostingNamespace),
			advertCMs:  cs.CoreV1().ConfigMaps(registrysvc.AdvertisementNamespace),
			logger:     logger,
		})
		defer stop()
		list, err := cs.CoreV1().ConfigMaps(registrysvc.AdvertisementNamespace).
			List(context.Background(), metav1.ListOptions{})
		if err != nil {
			t.Fatalf("list: %v", err)
		}
		for _, cm := range list.Items {
			if strings.HasPrefix(cm.Name, registrysvc.AdvertisementPrefix) {
				t.Errorf("a node with no mesh address published %s", cm.Name)
			}
		}
	})

	t.Run("the discovery document and the advertisement land in different namespaces", func(t *testing.T) {
		// The separation is what earns the node identity's read grant its scope:
		// an informer needs list and watch, RBAC's resourceNames constrains
		// neither, so the namespace holding the advertisements IS the scope of
		// what a node may read (pkg/rbac). Publishing both into kube-public — as
		// this used to — would have made that grant read everything parked there.
		if registrysvc.AdvertisementNamespace == registrysvc.HostingNamespace {
			t.Fatalf("the advertisements share %q with the KEP-1755 document; the node read grant is no longer scoped to advertisements",
				registrysvc.HostingNamespace)
		}
		svc := &fakeRegistry{addr: "127.0.0.1:6450"}
		cs := fake.NewSimpleClientset()
		stop := startIngestRegistry(t.Context(), ingestRegistry{
			svc: svc, port: 6450, nodeName: "mac-a", meshIP: "100.64.1.1",
			hostingCMs: cs.CoreV1().ConfigMaps(registrysvc.HostingNamespace),
			advertCMs:  cs.CoreV1().ConfigMaps(registrysvc.AdvertisementNamespace),
			logger:     logger,
		})
		defer stop()

		// The KEP-1755 document stays in kube-public, which the KEP mandates.
		if _, err := cs.CoreV1().ConfigMaps(registrysvc.HostingNamespace).
			Get(context.Background(), registrysvc.HostingConfigMapName, metav1.GetOptions{}); err != nil {
			t.Errorf("the KEP-1755 document is not in %s: %v", registrysvc.HostingNamespace, err)
		}
		// …and no advertisement follows it there.
		hosting, err := cs.CoreV1().ConfigMaps(registrysvc.HostingNamespace).
			List(context.Background(), metav1.ListOptions{})
		if err != nil {
			t.Fatalf("list %s: %v", registrysvc.HostingNamespace, err)
		}
		for _, cm := range hosting.Items {
			if strings.HasPrefix(cm.Name, registrysvc.AdvertisementPrefix) {
				t.Errorf("advertisement %s was published into %s, outside the scoped namespace", cm.Name, registrysvc.HostingNamespace)
			}
		}
		if _, err := cs.CoreV1().ConfigMaps(registrysvc.AdvertisementNamespace).
			Get(context.Background(), registrysvc.AdvertisementName("mac-a"), metav1.GetOptions{}); err != nil {
			t.Errorf("the advertisement is not in %s: %v", registrysvc.AdvertisementNamespace, err)
		}
	})

	t.Run("a node with a relay address publishes its cluster Service", func(t *testing.T) {
		// The ONE cluster address a native Pod, a vm guest and the host all reach
		// this node's registry at. The endpoint is the relay's own address —
		// EndpointSlice validation refuses a loopback one, so the registry's
		// 127.0.0.1 listener can never be published here.
		svc := &fakeRegistry{addr: "127.0.0.1:6450"}
		cs := fake.NewSimpleClientset()
		stop := startIngestRegistry(t.Context(), ingestRegistry{
			svc: svc, port: 6450, nodeName: "mac-a", meshIP: "100.64.1.1",
			hostingCMs:    cs.CoreV1().ConfigMaps(registrysvc.HostingNamespace),
			advertCMs:     cs.CoreV1().ConfigMaps(registrysvc.AdvertisementNamespace),
			clusterSvcs:   cs.CoreV1().Services(registrysvc.AdvertisementNamespace),
			clusterSlices: cs.DiscoveryV1().EndpointSlices(registrysvc.AdvertisementNamespace),
			clusterDomain: "cluster.local",
			logger:        logger,
		})
		name := registrysvc.ClusterServiceName("mac-a")
		published, err := cs.CoreV1().Services(registrysvc.AdvertisementNamespace).
			Get(context.Background(), name, metav1.GetOptions{})
		if err != nil {
			t.Fatalf("no cluster Service was published: %v", err)
		}
		if published.Spec.Selector != nil {
			t.Errorf("the Service carries a selector %v; nothing schedules the registry", published.Spec.Selector)
		}
		es, err := cs.DiscoveryV1().EndpointSlices(registrysvc.AdvertisementNamespace).
			Get(context.Background(), name, metav1.GetOptions{})
		if err != nil {
			t.Fatalf("no EndpointSlice was published, so the Service has a VIP and no backend: %v", err)
		}
		if len(es.Endpoints) != 1 || len(es.Endpoints[0].Addresses) != 1 || es.Endpoints[0].Addresses[0] != "100.64.1.1" {
			t.Errorf("endpoints = %+v, want the node's relay address", es.Endpoints)
		}
		// The discovery document now names it, and only because it exists.
		cm, err := cs.CoreV1().ConfigMaps(registrysvc.HostingNamespace).
			Get(context.Background(), registrysvc.HostingConfigMapName, metav1.GetOptions{})
		if err != nil {
			t.Fatalf("the discovery ConfigMap was not published: %v", err)
		}
		want := registrysvc.ClusterServiceAuthority("mac-a", "cluster.local", 6450)
		if !strings.Contains(cm.Data[registrysvc.HostingDataKey], want) {
			t.Errorf("the discovery document %q does not carry hostFromClusterNetwork %q",
				cm.Data[registrysvc.HostingDataKey], want)
		}
		stop()
		if _, err := cs.DiscoveryV1().EndpointSlices(registrysvc.AdvertisementNamespace).
			Get(context.Background(), name, metav1.GetOptions{}); err == nil {
			t.Error("the EndpointSlice survived a clean shutdown")
		}
		if _, err := cs.CoreV1().Services(registrysvc.AdvertisementNamespace).
			Get(context.Background(), name, metav1.GetOptions{}); err == nil {
			t.Error("the cluster Service survived a clean shutdown")
		}
	})

	t.Run("a node with no relay address publishes no cluster Service and claims none", func(t *testing.T) {
		// No mesh address and no vm network: nothing off loopback answers, so a
		// hostFromClusterNetwork would name an address no caller could reach.
		svc := &fakeRegistry{addr: "127.0.0.1:6450"}
		cs := fake.NewSimpleClientset()
		stop := startIngestRegistry(t.Context(), ingestRegistry{
			svc: svc, port: 6450, nodeName: "mac-a",
			hostingCMs:    cs.CoreV1().ConfigMaps(registrysvc.HostingNamespace),
			advertCMs:     cs.CoreV1().ConfigMaps(registrysvc.AdvertisementNamespace),
			clusterSvcs:   cs.CoreV1().Services(registrysvc.AdvertisementNamespace),
			clusterSlices: cs.DiscoveryV1().EndpointSlices(registrysvc.AdvertisementNamespace),
			logger:        logger,
		})
		defer stop()
		if _, err := cs.CoreV1().Services(registrysvc.AdvertisementNamespace).
			Get(context.Background(), registrysvc.ClusterServiceName("mac-a"), metav1.GetOptions{}); err == nil {
			t.Error("a node with no relay address published a cluster Service nothing would answer")
		}
		cm, err := cs.CoreV1().ConfigMaps(registrysvc.HostingNamespace).
			Get(context.Background(), registrysvc.HostingConfigMapName, metav1.GetOptions{})
		if err != nil {
			t.Fatalf("the discovery ConfigMap was not published: %v", err)
		}
		if strings.Contains(cm.Data[registrysvc.HostingDataKey], "hostFromClusterNetwork:") {
			t.Errorf("the discovery document %q claims a cluster address on a node with no relay",
				cm.Data[registrysvc.HostingDataKey])
		}
	})

	t.Run("a failed publish leaves the registry serving", func(t *testing.T) {
		svc := &fakeRegistry{addr: "127.0.0.1:6450"}
		stop := startIngestRegistry(t.Context(), ingestRegistry{
			svc: svc, port: 6450, nodeName: "mac-a", meshIP: "100.64.1.1",
			hostingCMs: failingConfigMaps{}, advertCMs: failingConfigMaps{}, logger: logger,
		})
		if svc.starts != 1 {
			t.Fatalf("starts = %d, want 1", svc.starts)
		}
		stop()
		if svc.shutdowns != 1 {
			t.Errorf("shutdowns = %d, want 1 — a publish failure must not orphan the child", svc.shutdowns)
		}
	})
}

// fakeRegistry is the three-method registryService seam, counted rather than run.
type fakeRegistry struct {
	addr                string
	startErr            error
	starts, shutdowns   int
	shutdownAfterCancel bool
}

func (f *fakeRegistry) Start(context.Context) error {
	if f.startErr != nil {
		return f.startErr
	}
	f.starts++
	return nil
}

func (f *fakeRegistry) Addr() string { return f.addr }

func (f *fakeRegistry) Shutdown(ctx context.Context) error {
	// The teardown runs from a defer during shutdown, so it must NOT inherit the
	// cancelled bring-up context — a child killed instead of drained leaves its
	// blob store mid-write.
	f.shutdownAfterCancel = ctx.Err() != nil
	f.shutdowns++
	return nil
}

// failingConfigMaps refuses every read, standing in for an apiserver that has
// started draining while the registry is still coming up.
type failingConfigMaps struct{}

func (failingConfigMaps) Get(context.Context, string, metav1.GetOptions) (*corev1.ConfigMap, error) {
	return nil, errors.New("apiserver unavailable")
}

func (failingConfigMaps) Create(context.Context, *corev1.ConfigMap, metav1.CreateOptions) (*corev1.ConfigMap, error) {
	return nil, errors.New("apiserver unavailable")
}

func (failingConfigMaps) Update(context.Context, *corev1.ConfigMap, metav1.UpdateOptions) (*corev1.ConfigMap, error) {
	return nil, errors.New("apiserver unavailable")
}

func (failingConfigMaps) Delete(context.Context, string, metav1.DeleteOptions) error {
	return errors.New("apiserver unavailable")
}

// discard is an io.Writer that drops the test logger's output.
type discard struct{}

func (discard) Write(p []byte) (int, error) { return len(p), nil }

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

package provider

import (
	"context"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	testclock "k8s.io/utils/clock/testing"

	netv1 "k3sm.io/apis/net/v1"
	runtimev1 "k3sm.io/apis/runtime/v1"
	"k3sm.io/darwin-net/pkg/dns"
	"k3sm.io/darwin-net/pkg/podnet"
	"k3sm.io/runtimed/pkg/sandbox"
)

const (
	noneTestVIP    = "10.43.0.10"
	noneTestDomain = "cluster.local"
	noneTestNS     = "ns1"
)

// noneTestProvider is a runtimed-backed provider with the cluster DNS inputs set,
// so a leg that leaks the cluster base into a None pod has a VIP and a
// namespace-scoped search list to leak. network may be nil (--network none).
func noneTestProvider(t *testing.T, network PodNetwork) (*runtimedRuntime, *fakeRuntimeServer, *record.FakeRecorder) {
	t.Helper()
	f := newFakeRuntimeServer()
	rec := record.NewFakeRecorder(64)
	r := newRuntimedWith(f, RuntimedConfig{
		NodeName: "n",
		NodeIP:   "192.168.1.10",
		Root:     t.TempDir(), PodLogsDir: t.TempDir(),
		ResolverVIP:   noneTestVIP,
		ClusterDomain: noneTestDomain,
		Recorder:      rec,
		Network:       network,
	}, nil, nil)
	return r, f, rec
}

// nonePod is a pod in noneTestNS under policy with cfg as spec.dnsConfig, one init
// and one regular container.
func nonePod(name string, policy corev1.DNSPolicy, cfg *corev1.PodDNSConfig) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: noneTestNS, Name: name, UID: types.UID("uid-" + name)},
		Spec: corev1.PodSpec{
			DNSPolicy:      policy,
			DNSConfig:      cfg,
			InitContainers: []corev1.Container{{Name: "init0", Image: "registry/web:latest", Command: []string{"/init"}}},
			Containers:     []corev1.Container{{Name: "c0", Image: "registry/web:latest", Command: []string{"/web"}}},
		},
	}
}

// liveBox is the PodBox the runtime RECEIVED for pod: what runtimed would run,
// after buildBox resolved the env. nil when the create never reached the runtime.
func liveBox(f *fakeRuntimeServer, pod *corev1.Pod) *runtimev1.PodBox {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.created[string(pod.UID)]
}

// dnsEnvKeys returns the K3SM_DNS_* names in c's env, in env order.
func dnsEnvKeys(c *runtimev1.Container) []string {
	var out []string
	for _, e := range c.GetEnv() {
		if strings.HasPrefix(e.GetName(), "K3SM_DNS_") {
			out = append(out, e.GetName())
		}
	}
	return out
}

// TestToPodBoxDNSPolicyNoneInjectsCustomConfig pins B20b step 3 on the native
// path: a dnsPolicy None pod's own spec.dnsConfig reaches every container of the
// box the runtime receives as the shim's exclusive-mode env, Default still
// injects nothing, ClusterFirst is unchanged, a mixed v4/v6 list runs on the v4
// subset with a DNSConfigPartial Event, and an all-IPv6 list fails closed as a
// CreateContainerConfigError that never reaches the runtime.
//
// Non-vacuity: before the change None injected nothing (translate.go's
// clusterDNSPolicy gate), so leg (i) finds no K3SM_DNS_SERVERS, leg (iv) no
// env and no Event, and leg (v) a pod created and started on the host resolver.
func TestToPodBoxDNSPolicyNoneInjectsCustomConfig(t *testing.T) {
	ctx := context.Background()

	t.Run("(i) None injects its own nameservers, search and ndots into every container", func(t *testing.T) {
		r, f, _ := noneTestProvider(t, nil)
		pod := nonePod("none", corev1.DNSNone, &corev1.PodDNSConfig{
			Nameservers: []string{"1.1.1.1", "9.9.9.9"},
			Searches:    []string{"a.example"},
			Options: []corev1.PodDNSConfigOption{
				{Name: "ndots", Value: ptr("2")},
				{Name: "edns0"},
			},
		})
		if err := r.CreatePod(ctx, pod); err != nil {
			t.Fatalf("CreatePod: %v", err)
		}
		box := liveBox(f, pod)
		if box == nil {
			t.Fatal("the runtime received no box for the None pod")
		}
		cs := allContainers(box)
		if len(cs) != 2 {
			t.Fatalf("want 2 containers (1 init + 1 regular), got %d", len(cs))
		}
		for _, c := range cs {
			env := containerEnv(c)
			for _, kv := range []struct{ k, want string }{
				{dns.EnvDNSServers, "1.1.1.1 9.9.9.9"},
				{dns.EnvDNSExclusive, "1"},
				{dns.EnvDNSNdots, "2"},
				{dns.EnvDNSSearch, "a.example"},
			} {
				if got, ok := env[kv.k]; !ok || got != kv.want {
					t.Errorf("container %s: %s = %q (set %v), want %q", c.GetName(), kv.k, got, ok, kv.want)
				}
			}
			if v, ok := env[dns.EnvDNSServer]; ok {
				t.Errorf("container %s: %s=%q injected; a None pod must never get the ClusterFirst server key", c.GetName(), dns.EnvDNSServer, v)
			}
			if v, ok := env[dns.EnvDNSDomain]; ok {
				t.Errorf("container %s: %s=%q injected; None takes no cluster domain", c.GetName(), dns.EnvDNSDomain, v)
			}
			if strings.Contains(env[dns.EnvDNSSearch], noneTestDomain) {
				t.Errorf("container %s: search %q carries a cluster search domain", c.GetName(), env[dns.EnvDNSSearch])
			}
			if keys := dnsEnvKeys(c); !slices.IsSorted(keys) {
				t.Errorf("container %s: K3SM_DNS_* keys %v are not in sorted order", c.GetName(), keys)
			}
		}
	})

	t.Run("(ii) Default injects nothing", func(t *testing.T) {
		r, f, _ := noneTestProvider(t, nil)
		pod := nonePod("dflt", corev1.DNSDefault, &corev1.PodDNSConfig{
			Nameservers: []string{"1.1.1.1"},
			Searches:    []string{"a.example"},
		})
		if err := r.CreatePod(ctx, pod); err != nil {
			t.Fatalf("CreatePod: %v", err)
		}
		box := liveBox(f, pod)
		if box == nil {
			t.Fatal("the runtime received no box for the Default pod")
		}
		for _, c := range allContainers(box) {
			if keys := dnsEnvKeys(c); len(keys) != 0 {
				t.Errorf("container %s: Default pod got %v, want no K3SM_DNS_* env", c.GetName(), keys)
			}
		}
	})

	t.Run("(iii) ClusterFirst env unchanged", func(t *testing.T) {
		r, f, _ := noneTestProvider(t, nil)
		pod := nonePod("cf", corev1.DNSClusterFirst, nil)
		if err := r.CreatePod(ctx, pod); err != nil {
			t.Fatalf("CreatePod: %v", err)
		}
		box := liveBox(f, pod)
		if box == nil {
			t.Fatal("the runtime received no box for the ClusterFirst pod")
		}
		want := map[string]string{
			dns.EnvDNSDomain: noneTestDomain,
			dns.EnvDNSNdots:  "5",
			dns.EnvDNSSearch: "ns1.svc.cluster.local svc.cluster.local cluster.local",
			dns.EnvDNSServer: noneTestVIP,
		}
		for _, c := range allContainers(box) {
			env := containerEnv(c)
			got := map[string]string{}
			for _, k := range dnsEnvKeys(c) {
				got[k] = env[k]
			}
			if len(got) != len(want) {
				t.Errorf("container %s: K3SM_DNS_* = %v, want exactly %v", c.GetName(), got, want)
			}
			for k, v := range want {
				if got[k] != v {
					t.Errorf("container %s: %s = %q, want %q", c.GetName(), k, got[k], v)
				}
			}
		}
	})

	t.Run("(iv) mixed IPv4 and IPv6 injects the IPv4 subset and records DNSConfigPartial", func(t *testing.T) {
		r, f, rec := noneTestProvider(t, nil)
		pod := nonePod("mixed", corev1.DNSNone, &corev1.PodDNSConfig{
			Nameservers: []string{"2606:4700:4700::1111", "1.1.1.1"},
		})
		if err := r.CreatePod(ctx, pod); err != nil {
			t.Fatalf("CreatePod: %v", err)
		}
		box := liveBox(f, pod)
		if box == nil {
			t.Fatal("the runtime received no box for the mixed None pod")
		}
		for _, c := range allContainers(box) {
			if got := containerEnv(c)[dns.EnvDNSServers]; got != "1.1.1.1" {
				t.Errorf("container %s: %s = %q, want the IPv4 subset %q", c.GetName(), dns.EnvDNSServers, got, "1.1.1.1")
			}
		}
		events := recordedEvents(rec.Events)
		if !containsEvent(events, "Warning "+reasonDNSConfigPartial+" ") || !containsEvent(events, "2606:4700:4700::1111") {
			t.Errorf("events = %v, want a Warning %s Event naming the dropped 2606:4700:4700::1111", events, reasonDNSConfigPartial)
		}
	})

	t.Run("(v) all IPv6 fails closed as CreateContainerConfigError", func(t *testing.T) {
		g := newGuestDNSRecorder(t)
		r, f, rec := noneTestProvider(t, g)
		clk := testclock.NewFakeClock(time.Unix(10000, 0))
		r.clk = clk
		pod := nonePod("v6only", corev1.DNSNone, &corev1.PodDNSConfig{
			Nameservers: []string{"2606:4700:4700::1111", "2001:4860:4860::8888"},
		})
		pod.Spec.InitContainers = nil
		if err := r.CreatePod(ctx, pod); err != nil {
			t.Fatalf("CreatePod = %v, want the pod parked (an error lands it ProviderFailed)", err)
		}
		// Refused from the spec alone, before anything was allocated for it.
		if n := g.setupCount(); n != 0 {
			t.Errorf("pod network Setup calls = %d, want 0 (no /32 drawn for a refused pod)", n)
		}
		if ip, ok := g.ipam.allocations()[string(pod.UID)]; ok {
			t.Errorf("the refused pod holds address %s, want none", ip)
		}
		if box := liveBox(f, pod); box != nil {
			t.Fatalf("the runtime received a box for an all-IPv6 None pod; it must never start (env %v)", dnsEnvKeys(box.GetContainers()[0]))
		}
		f.mu.Lock()
		calls := f.createCalls
		f.mu.Unlock()
		if calls != 0 {
			t.Errorf("runtime CreatePod calls = %d, want 0", calls)
		}
		st, err := r.GetPodStatus(ctx, pod.Namespace, pod.Name)
		if err != nil {
			t.Fatalf("GetPodStatus: %v", err)
		}
		if st.Phase != corev1.PodPending {
			t.Errorf("phase = %s, want Pending", st.Phase)
		}
		w := waitingOf(st, "c0")
		if w == nil || w.Reason != reasonCreateContainerConfigError {
			t.Fatalf("c0 waiting = %+v, want Waiting{CreateContainerConfigError}", w)
		}
		if w.Message != msgDNSNoneIPv6Only {
			t.Errorf("c0 waiting message = %q, want %q", w.Message, msgDNSNoneIPv6Only)
		}
		// The cause cannot change (spec.dnsConfig is immutable), so resyncs neither
		// retry it nor repeat its Event: one Failed Warning, at the park.
		for range 3 {
			clk.Step(resyncInterval + time.Second)
			if _, err := r.GetPodStatus(ctx, pod.Namespace, pod.Name); err != nil {
				t.Fatalf("GetPodStatus after a resync: %v", err)
			}
		}
		events := recordedEvents(rec.Events)
		want := "Warning " + reasonFailed + " " + msgContainerConfigError(msgDNSNoneIPv6Only)
		if n := countEvents(events, want); n != 1 {
			t.Errorf("Failed Warning Events = %d, want exactly 1 (at the park, never per resync); events: %q", n, events)
		}
		if n := countEvents(events, " "+reasonPulling+" "); n != 0 {
			t.Errorf("Pulling Events = %d for a pod that is never retried; events: %q", n, events)
		}
		f.mu.Lock()
		calls = f.createCalls
		f.mu.Unlock()
		if calls != 0 {
			t.Errorf("runtime CreatePod calls after resyncs = %d, want 0", calls)
		}
	})

	t.Run("a None pod's bind discipline keeps the cluster Service CIDR", func(t *testing.T) {
		r, _, _ := noneTestProvider(t, nil)
		pod := nonePod("cidr", corev1.DNSNone, &corev1.PodDNSConfig{Nameservers: []string{"1.1.1.1"}})
		// A distinct /32, so the bind discipline applies; buildBox is the
		// production translation path.
		box, err := r.buildBox(ctx, pod, "100.64.0.7")
		if err != nil {
			t.Fatalf("buildBox: %v", err)
		}
		want := podnet.ClusterPodCIDR.String() + ",10.43.0.0/16"
		for _, c := range allContainers(box) {
			if got := containerEnv(c)[podnet.EnvClusterCIDRs]; got != want {
				t.Errorf("container %s: %s = %q, want %q (the Service CIDR from the node's DNS VIP, not the pod's resolver)", c.GetName(), podnet.EnvClusterCIDRs, got, want)
			}
		}
	})

	t.Run("DNSConfigPartial is recorded at create only", func(t *testing.T) {
		r, _, rec := noneTestProvider(t, nil)
		pod := nonePod("partial-once", corev1.DNSNone, &corev1.PodDNSConfig{
			Nameservers: []string{"2606:4700:4700::1111", "1.1.1.1"},
		})
		if err := r.CreatePod(ctx, pod); err != nil {
			t.Fatalf("CreatePod: %v", err)
		}
		// Every later translation (update, re-attach, parked retry) runs buildBox.
		for range 2 {
			if _, err := r.buildBox(ctx, pod, "100.64.0.7"); err != nil {
				t.Fatalf("buildBox: %v", err)
			}
		}
		events := recordedEvents(rec.Events)
		if n := countEvents(events, " "+reasonDNSConfigPartial+" "); n != 1 {
			t.Errorf("DNSConfigPartial Events = %d, want 1 (create only); events: %q", n, events)
		}
	})

	t.Run("ndots 0 is applied as 1 with a DNSConfigForming Event", func(t *testing.T) {
		r, f, rec := noneTestProvider(t, nil)
		pod := nonePod("ndots0", corev1.DNSNone, &corev1.PodDNSConfig{
			Nameservers: []string{"1.1.1.1"},
			Options:     []corev1.PodDNSConfigOption{{Name: "ndots", Value: ptr("0")}},
		})
		if err := r.CreatePod(ctx, pod); err != nil {
			t.Fatalf("CreatePod: %v", err)
		}
		box := liveBox(f, pod)
		if box == nil {
			t.Fatal("the runtime received no box")
		}
		if got := containerEnv(box.GetContainers()[0])[dns.EnvDNSNdots]; got != "1" {
			t.Errorf("%s = %q, want %q", dns.EnvDNSNdots, got, "1")
		}
		events := recordedEvents(rec.Events)
		if n := countEvents(events, "Warning "+reasonDNSConfigForming+" "+msgDNSNdotsZero); n != 1 {
			t.Errorf("DNSConfigForming ndots Events = %d, want 1; events: %q", n, events)
		}
	})

	t.Run("nameservers and search domains beyond the caps are dropped with DNSConfigForming", func(t *testing.T) {
		r, f, rec := noneTestProvider(t, nil)
		searches := []string{"s1.example", "s2.example", "s3.example", "s4.example", "s5.example",
			"s6.example", "s7.example", "s8.example", "s9.example", "s10.example"}
		pod := nonePod("caps", corev1.DNSNone, &corev1.PodDNSConfig{
			Nameservers: []string{"1.1.1.1", "8.8.8.8", "9.9.9.9", "8.8.4.4"},
			Searches:    searches,
		})
		if err := r.CreatePod(ctx, pod); err != nil {
			t.Fatalf("CreatePod: %v", err)
		}
		box := liveBox(f, pod)
		if box == nil {
			t.Fatal("the runtime received no box: a pod over the caps must run on the first entries")
		}
		env := containerEnv(box.GetContainers()[0])
		if got := env[dns.EnvDNSServers]; got != "1.1.1.1 8.8.8.8 9.9.9.9" {
			t.Errorf("%s = %q, want the first three", dns.EnvDNSServers, got)
		}
		if got := env[dns.EnvDNSSearch]; got != strings.Join(searches[:dns.MaxSearchDomains], " ") {
			t.Errorf("%s = %q, want the first %d", dns.EnvDNSSearch, got, dns.MaxSearchDomains)
		}
		events := recordedEvents(rec.Events)
		if n := countEvents(events, "Warning "+reasonDNSConfigForming+" "+msgDNSNameserversCapped([]string{"8.8.4.4"})); n != 1 {
			t.Errorf("nameserver DNSConfigForming Events = %d, want 1 naming 8.8.4.4; events: %q", n, events)
		}
		if n := countEvents(events, "Warning "+reasonDNSConfigForming+" "+msgDNSSearchesCapped([]string{"s9.example", "s10.example"})); n != 1 {
			t.Errorf("search DNSConfigForming Events = %d, want 1 naming s9.example s10.example; events: %q", n, events)
		}
	})

	t.Run("repeated nameservers are merged and the pod runs", func(t *testing.T) {
		r, f, rec := noneTestProvider(t, nil)
		pod := nonePod("dups", corev1.DNSNone, &corev1.PodDNSConfig{
			Nameservers: []string{"1.1.1.1", "1.1.1.1", "::ffff:1.1.1.1", "9.9.9.9"},
		})
		if err := r.CreatePod(ctx, pod); err != nil {
			t.Fatalf("CreatePod: %v", err)
		}
		box := liveBox(f, pod)
		if box == nil {
			t.Fatal("the runtime received no box: a pod with repeated nameservers must run")
		}
		if got := containerEnv(box.GetContainers()[0])[dns.EnvDNSServers]; got != "1.1.1.1 9.9.9.9" {
			t.Errorf("%s = %q, want %q (first seen order, repeats merged)", dns.EnvDNSServers, got, "1.1.1.1 9.9.9.9")
		}
		if n := countEvents(recordedEvents(rec.Events), " "+reasonDNSConfigForming+" "); n != 0 {
			t.Errorf("DNSConfigForming Events = %d, want 0: merging a repeat changes nothing", n)
		}
	})
}

// guestDNSRecorder is the real PodNetAdapter with every SetupGuest's dnsCfg
// recorded, so a test sees the config the vm guest's resolv.conf is derived from,
// and every host-process Setup counted, so a test sees whether a /32 was drawn.
type guestDNSRecorder struct {
	*PodNetAdapter
	ipam   *fakeIPAM
	mu     sync.Mutex
	cfgs   []netv1.DNSConfig
	setups int
}

func newGuestDNSRecorder(t *testing.T) *guestDNSRecorder {
	t.Helper()
	ipam := newFakeIPAM(t, "100.64.0.0/24")
	return &guestDNSRecorder{PodNetAdapter: NewPodNetAdapter(ipam, testNodeIP, nil), ipam: ipam}
}

func (g *guestDNSRecorder) Setup(ctx context.Context, podID string) (string, error) {
	g.mu.Lock()
	g.setups++
	g.mu.Unlock()
	return g.PodNetAdapter.Setup(ctx, podID)
}

func (g *guestDNSRecorder) setupCount() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.setups
}

func (g *guestDNSRecorder) SetupGuest(ctx context.Context, podID string, dnsCfg netv1.DNSConfig) (sandbox.GuestNetworkConfig, error) {
	g.mu.Lock()
	g.cfgs = append(g.cfgs, dnsCfg)
	g.mu.Unlock()
	return g.PodNetAdapter.SetupGuest(ctx, podID, dnsCfg)
}

func (g *guestDNSRecorder) recorded() []netv1.DNSConfig {
	g.mu.Lock()
	defer g.mu.Unlock()
	return slices.Clone(g.cfgs)
}

// TestPodDNSConfigNoneFeedsGuestResolvConf pins B20b step 3 on the vm path: the
// config handed to SetupGuest for a vm dnsPolicy None pod is the pod's own (its
// nameservers, no ClusterDNSIP), so the guest's resolv.conf names the pod's IPv4
// nameservers; and an all-IPv6 None vm pod is refused before an address is drawn.
//
// Non-vacuity: before the change podDNSConfig returned the unmerged cluster base
// for None, so SetupGuest received ClusterDNSIP 10.43.0.10 and no nameservers.
func TestPodDNSConfigNoneFeedsGuestResolvConf(t *testing.T) {
	ctx := context.Background()
	vmNonePod := func(name string, ns ...string) *corev1.Pod {
		pod := nonePod(name, corev1.DNSNone, &corev1.PodDNSConfig{
			Nameservers: ns,
			Searches:    []string{"a.example"},
			Options:     []corev1.PodDNSConfigOption{{Name: "edns0"}},
		})
		vm := "vm"
		pod.Spec.RuntimeClassName = &vm
		pod.Spec.InitContainers = nil
		return pod
	}

	t.Run("SetupGuest receives the pod's nameservers and no ClusterDNSIP", func(t *testing.T) {
		g := newGuestDNSRecorder(t)
		r, _, _ := noneTestProvider(t, g)
		pod := vmNonePod("vmnone", "1.1.1.1", "9.9.9.9")
		// The create's outcome past the guest network (the vm boot) is not what
		// is asserted here; the config SetupGuest received is.
		_ = r.CreatePod(ctx, pod)
		cfgs := g.recorded()
		if len(cfgs) == 0 {
			t.Fatal("SetupGuest was never called for the vm None pod")
		}
		for i, c := range cfgs {
			if c.ClusterDNSIP != "" {
				t.Errorf("SetupGuest call %d: ClusterDNSIP = %q, want empty (None takes nothing from the cluster)", i, c.ClusterDNSIP)
			}
			if c.Policy != netv1.DNSPolicyNone {
				t.Errorf("SetupGuest call %d: Policy = %q, want %q", i, c.Policy, netv1.DNSPolicyNone)
			}
			if want := []string{"1.1.1.1", "9.9.9.9"}; !slices.Equal(c.Nameservers, want) {
				t.Errorf("SetupGuest call %d: Nameservers = %v, want %v", i, c.Nameservers, want)
			}
		}
		gn, ok := g.GuestNetwork(string(pod.UID))
		if !ok {
			t.Fatal("the adapter recorded no guest network for the vm None pod")
		}
		if want := []string{"1.1.1.1", "9.9.9.9"}; !slices.Equal(gn.Nameservers, want) {
			t.Errorf("guest Nameservers = %v, want the pod's own %v", gn.Nameservers, want)
		}
		if want := []string{"a.example"}; !slices.Equal(gn.Searches, want) {
			t.Errorf("guest Searches = %v, want the pod's own %v", gn.Searches, want)
		}
		if want := []string{"ndots:5", "edns0"}; !slices.Equal(gn.Options, want) {
			t.Errorf("guest Options = %v, want %v", gn.Options, want)
		}
		if strings.Contains(gn.ResolvConf, noneTestVIP) {
			t.Errorf("guest resolv.conf names the cluster VIP:\n%s", gn.ResolvConf)
		}
	})

	t.Run("an all-IPv6 None vm pod is refused before an address is drawn", func(t *testing.T) {
		g := newGuestDNSRecorder(t)
		r, f, _ := noneTestProvider(t, g)
		pod := vmNonePod("vmv6", "2606:4700:4700::1111")
		if err := r.CreatePod(ctx, pod); err != nil {
			t.Fatalf("CreatePod = %v, want the pod parked", err)
		}
		if n := len(g.recorded()); n != 0 {
			t.Errorf("SetupGuest called %d times, want 0 (refused before allocation)", n)
		}
		if box := liveBox(f, pod); box != nil {
			t.Error("the runtime received a box for an all-IPv6 None vm pod")
		}
		st, err := r.GetPodStatus(ctx, pod.Namespace, pod.Name)
		if err != nil {
			t.Fatalf("GetPodStatus: %v", err)
		}
		if w := waitingOf(st, "c0"); w == nil || w.Reason != reasonCreateContainerConfigError || w.Message != msgDNSNoneIPv6Only {
			t.Errorf("c0 waiting = %+v, want Waiting{CreateContainerConfigError, %q}", w, msgDNSNoneIPv6Only)
		}
	})
}

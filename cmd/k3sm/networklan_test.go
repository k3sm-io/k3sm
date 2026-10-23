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
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"

	"k3sm.io/k3sm/pkg/install"
	"k3sm.io/k3sm/pkg/status"
	"k3sm.io/k3sm/pkg/svclb"
)

// lanFakeSys is the slice of install.System the network verb touches: an
// in-memory root filesystem and launchd's pid answer. Any other method is the
// nil embedded interface, so a stray call panics the test rather than
// passing silently.
type lanFakeSys struct {
	install.System
	mu      sync.Mutex
	files   map[string][]byte
	modes   map[string]fs.FileMode
	running bool
}

func newLANFakeSys() *lanFakeSys {
	return &lanFakeSys{files: map[string][]byte{}, modes: map[string]fs.FileMode{}, running: true}
}

func (f *lanFakeSys) ReadFile(path string) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if b, ok := f.files[path]; ok {
		return slices.Clone(b), nil
	}
	return nil, fmt.Errorf("open %s: %w", path, fs.ErrNotExist)
}

func (f *lanFakeSys) put(path string, data []byte) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.files[path] = slices.Clone(data)
}

func (f *lanFakeSys) WriteRootOnlyFile(path string, data []byte, mode fs.FileMode) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.files[path] = slices.Clone(data)
	f.modes[path] = mode
	return nil
}

func (f *lanFakeSys) RemoveAll(path string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.files, path)
	return nil
}

func (f *lanFakeSys) ReadStopMarker(path string) ([]byte, error) { return f.ReadFile(path) }

// Owner describes every file the fake holds as WriteRootOnlyFile leaves it:
// a root-owned regular file at its written mode.
func (f *lanFakeSys) Owner(path string) (install.OwnedEntry, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.files[path]; !ok {
		return install.OwnedEntry{}, fmt.Errorf("lstat %s: %w", path, fs.ErrNotExist)
	}
	mode, ok := f.modes[path]
	if !ok {
		mode = 0o644
	}
	return install.OwnedEntry{Path: path, Mode: mode, Kind: install.EntryRegular}, nil
}

func (f *lanFakeSys) LaunchctlServicePID(string) (int, error) {
	if !f.running {
		return 0, errors.New("not loaded")
	}
	return 4242, nil
}

// recordedLAN reads the record back.
func (f *lanFakeSys) recordedLAN(t *testing.T, path string) (install.LAN, bool) {
	t.Helper()
	rec, present, err := install.ReadNetworkRecord(install.SystemNetworkRecordReader(f), path)
	if err != nil {
		t.Fatalf("read the record: %v", err)
	}
	return rec.LAN, present
}

// fakeFamily records every set it is asked to move to, and can refuse one
// LAN state.
type fakeFamily struct {
	fam    string
	failOn install.LAN
	// commitFailOn makes the commit (not the prepare) of that state fail.
	commitFailOn install.LAN
	mu           sync.Mutex
	current      []netip.Addr
	ports        []netip.Addr
	events       []string
}

func (f *fakeFamily) name() string { return f.fam }

func (f *fakeFamily) prepare(_ context.Context, sets lanSets) (lanStep, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failOn == sets.lan {
		f.events = append(f.events, "refuse:"+string(sets.lan))
		return lanStep{}, errors.New("bind 127.0.0.1: address already in use")
	}
	f.events = append(f.events, "prepare:"+string(sets.lan))
	return lanStep{
		commit: func() error {
			f.mu.Lock()
			defer f.mu.Unlock()
			if f.commitFailOn == sets.lan {
				f.events = append(f.events, "commit-failed:"+string(sets.lan))
				return errors.New("the hoster abandoned the swap")
			}
			f.current, f.ports = sets.listeners, sets.nodePorts
			f.events = append(f.events, "commit:"+string(sets.lan))
			return nil
		},
		abort: func() {
			f.mu.Lock()
			defer f.mu.Unlock()
			f.events = append(f.events, "abort:"+string(sets.lan))
		},
	}, nil
}

func (f *fakeFamily) log() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.events)
}

var (
	lanNode     = netip.MustParseAddr("100.64.0.1")
	lanLocal    = []netip.Addr{lanNode, netip.MustParseAddr("127.0.0.1")}
	lanWildcard = []netip.Addr{netip.IPv4Unspecified()}
)

// lanRig is a daemon-side switch over a fake filesystem plus the CLI
// environment that drives it: Signal runs the daemon's apply, as SIGHUP does.
type lanRig struct {
	// forged, when set, is what the socket lister reports instead of the
	// sockets the daemon's state implies.
	forged []netip.AddrPort
	sys    *lanFakeSys
	sw     *lanSwitch
	env    networkEnv
	out    *bytes.Buffer
	errOut *bytes.Buffer
	record string
}

func newLANRig(t *testing.T, role install.Role) *lanRig {
	t.Helper()
	sys := newLANFakeSys()
	dataRoot := "/var/lib/k3sm"
	label := install.ServerLabel
	if role == install.RoleAgent {
		label = install.AgentLabel
	}
	sys.put(filepath.Join(install.DefaultLaunchDaemonDir, label+".plist"), []byte("<plist/>"))
	record := "/Library/Preferences/io.k3sm.network.json"
	sw := &lanSwitch{
		recordPath:  record,
		appliedPath: install.NetworkAppliedPath(dataRoot, role),
		readRecord:  install.SystemNetworkRecordReader(sys),
		writeFile:   func(p string, b []byte) error { sys.put(p, b); return nil },
		hostAddrs:   lanRigHost,
		log:         slog.New(slog.DiscardHandler),
		node:        lanNode,
	}
	sw.load()
	out, errOut := &bytes.Buffer{}, &bytes.Buffer{}
	rig := &lanRig{sys: sys, sw: sw, out: out, errOut: errOut, record: record}
	rig.env = networkEnv{
		Sys:        sys,
		RecordPath: record,
		DataRoot:   dataRoot,
		StopMarker: "/Library/Preferences/io.k3sm.stop.json",
		Geteuid:    func() int { return 0 },
		Signal: func(ctx context.Context, got string) error {
			if got != label {
				return fmt.Errorf("signalled %s, want %s", got, label)
			}
			_ = sw.apply(ctx)
			return nil
		},
		Restart:    func(context.Context) error { return errors.New("no restart expected") },
		ReadRecord: install.SystemNetworkRecordReader(sys),
		Sockets: func(context.Context, int) ([]netip.AddrPort, error) {
			if rig.forged != nil {
				return rig.forged, nil
			}
			return socketsFor(rig.sw.state(), role), nil
		},
		HostAddrs: lanRigHost,
		NodeArgs:  func(install.Role) ([]string, error) { return nil, nil },
		Wait:      2 * time.Second,
		Poll:      time.Millisecond,
		Stdout:    out,
		Stderr:    errOut,
	}
	return rig
}

// lanRigHost is a lab Mac's interface addresses: a Wi-Fi address,
// loopback and the mesh address on its utun.
func lanRigHost() ([]netip.Addr, error) {
	return []netip.Addr{netip.MustParseAddr("192.0.2.20"), netip.MustParseAddr("127.0.0.1"), lanNode}, nil
}

// socketsFor is what a node daemon of role in state lan listens on: one
// NodePort, the kubelet API on the node address and, on a server, the join
// port on every interface.
func socketsFor(lan install.LAN, role install.Role) []netip.AddrPort {
	socks := []netip.AddrPort{netip.AddrPortFrom(lanNode, 10250)}
	if role != install.RoleAgent {
		socks = append(socks, netip.MustParseAddrPort("0.0.0.0:9345"))
	}
	if lan == install.LANOff {
		return append(socks, netip.MustParseAddrPort("127.0.0.1:30090"), netip.AddrPortFrom(lanNode, 30090))
	}
	return append(socks, netip.MustParseAddrPort("0.0.0.0:30090"))
}

func (r *lanRig) run(args ...string) int {
	r.out.Reset()
	r.errOut.Reset()
	return runNetworkEnv(context.Background(), args, r.env)
}

// echoServe accepts on ln and echoes every connection until ln closes.
func echoServe(ln net.Listener) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go func() { defer c.Close(); _, _ = io.Copy(c, c) }()
	}
}

// echoOnce writes msg on c and reads it back.
func echoOnce(c net.Conn, msg string) error {
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.WriteString(c, msg); err != nil {
		return err
	}
	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(c, buf); err != nil {
		return err
	}
	if string(buf) != msg {
		return fmt.Errorf("echo %q, want %q", buf, msg)
	}
	return nil
}

// memListener is an in-memory listener: connect hands Accept a pipe end.
type memListener struct {
	ap     netip.AddrPort
	conns  chan net.Conn
	closed chan struct{}
	once   sync.Once
}

func (l *memListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.conns:
		return c, nil
	case <-l.closed:
		return nil, net.ErrClosed
	}
}
func (l *memListener) Close() error   { l.once.Do(func() { close(l.closed) }); return nil }
func (l *memListener) Addr() net.Addr { return net.TCPAddrFromAddrPort(l.ap) }
func (l *memListener) isClosed() bool {
	select {
	case <-l.closed:
		return true
	default:
		return false
	}
}
func (l *memListener) connect(t *testing.T) net.Conn {
	t.Helper()
	client, server := net.Pipe()
	select {
	case l.conns <- server:
	case <-time.After(5 * time.Second):
		t.Fatalf("connect %s: not accepted", l.ap)
	}
	return client
}

// memBinder opens memListeners, refusing deny with its error.
type memBinder struct {
	mu   sync.Mutex
	deny map[netip.AddrPort]error
	open map[netip.AddrPort]*memListener
}

func (b *memBinder) Listen(_ context.Context, _ string, ap netip.AddrPort) (net.Listener, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if err := b.deny[ap]; err != nil {
		return nil, err
	}
	if b.open == nil {
		b.open = map[netip.AddrPort]*memListener{}
	}
	l := &memListener{ap: ap, conns: make(chan net.Conn), closed: make(chan struct{})}
	b.open[ap] = l
	return l, nil
}

func (b *memBinder) get(ap string) *memListener {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.open[netip.MustParseAddrPort(ap)]
}

// addrSetFamily moves one svclb.AddrSetListener, the listener the
// LoadBalancer and ingress families are built on.
type addrSetFamily struct{ set *svclb.AddrSetListener }

func (addrSetFamily) name() string { return install.LANFamilyIngress }

func (f addrSetFamily) prepare(ctx context.Context, sets lanSets) (lanStep, error) {
	if err := f.set.Prepare(ctx, sets.listeners); err != nil {
		return lanStep{}, err
	}
	return lanStep{commit: func() error { f.set.Commit(sets.listeners); return nil }, abort: f.set.Abort}, nil
}

// TestNetworkLanToggle is the gate for `k3sm network lan on|off|status`: the
// verb round-trips through the one recorded value; the daemon's apply moves
// every listener family to the resolved set as one all-or-nothing change; a
// refusal in any family rolls all of them back and the verb restores the old
// value; a daemon that does not answer is restarted in place; an upgraded
// install with no value reads as on and a fresh one writes off; the svclb
// hoster withdraws its report before it unbinds; a connection in flight
// survives a rebind; and the status JSON gains an additive network block.
func TestNetworkLanToggle(t *testing.T) {
	t.Run("on, off and status round-trip through the recorded value", func(t *testing.T) {
		rig := newLANRig(t, install.RoleServer)
		nodePorts, lb, ingress := &fakeFamily{fam: "nodeports"}, &fakeFamily{fam: "loadbalancers"}, &fakeFamily{fam: "ingress"}
		for _, f := range []*fakeFamily{nodePorts, lb, ingress} {
			if err := rig.sw.attach("", "", func(lanSets) (lanFamily, error) { return f, nil }); err != nil {
				t.Fatal(err)
			}
		}
		if code := rig.run("lan", "off"); code != 0 {
			t.Fatalf("lan off exit %d: %s", code, rig.errOut)
		}
		if lan, present := rig.sys.recordedLAN(t, rig.record); lan != install.LANOff || !present {
			t.Fatalf("recorded %s (present=%v), want off", lan, present)
		}
		if mode := rig.sys.modes[rig.record]; mode != 0o644 {
			t.Errorf("record mode = %#o, want 0644 (root writes it, the daemon and status read it)", mode)
		}
		if !strings.Contains(rig.out.String(), "LAN access is off") {
			t.Errorf("lan off said %q", rig.out)
		}
		if rig.sw.state() != install.LANOff {
			t.Errorf("daemon state = %s, want off", rig.sw.state())
		}
		for _, f := range []*fakeFamily{lb, ingress} {
			if !slices.Equal(f.current, lanLocal) {
				t.Errorf("%s listens on %v, want %v", f.fam, f.current, lanLocal)
			}
		}
		if !slices.Equal(nodePorts.ports, lanLocal) {
			t.Errorf("NodePorts on %v, want %v", nodePorts.ports, lanLocal)
		}

		if code := rig.run("lan", "status"); code != 0 {
			t.Fatalf("status exit %d: %s", code, rig.errOut)
		}
		for _, want := range []string{"Recorded: LAN access is off", "Covers: nodeports, loadbalancers, ingress", "Always on: apiserver, join, mesh", "Applied: the node daemon reports LAN access off"} {
			if !strings.Contains(rig.out.String(), want) {
				t.Errorf("status lacks %q:\n%s", want, rig.out)
			}
		}

		if code := rig.run("lan", "on"); code != 0 {
			t.Fatalf("lan on exit %d: %s", code, rig.errOut)
		}
		if lan, _ := rig.sys.recordedLAN(t, rig.record); lan != install.LANOn {
			t.Fatalf("recorded %s, want on", lan)
		}
		if !slices.Equal(lb.current, lanWildcard) || !slices.Equal(ingress.current, lanWildcard) || nodePorts.ports != nil {
			t.Errorf("after on: lb=%v ingress=%v nodeports=%v, want the wildcard everywhere", lb.current, ingress.current, nodePorts.ports)
		}

		rig.env.Geteuid = func() int { return 501 }
		if code := rig.run("lan", "off"); code != exitNeedsRoot {
			t.Errorf("lan off as a user exit %d, want %d", code, exitNeedsRoot)
		}
		if code := rig.run("lan", "status"); code != 0 {
			t.Errorf("status as a user exit %d, want 0", code)
		}
		if code := rig.run("lan", "sideways"); code != exitLifecycleUsage {
			t.Errorf("bad value exit %d, want usage", code)
		}
	})

	t.Run("each family rebinds to the resolved set, NodePorts keep an explicit spec when on", func(t *testing.T) {
		rig := newLANRig(t, install.RoleServer)
		f := &fakeFamily{fam: "nodeports"}
		if err := rig.sw.attach("192.0.2.0/24", lanNode.String(), func(sets lanSets) (lanFamily, error) {
			if want := []netip.Addr{netip.MustParseAddr("192.0.2.20")}; !slices.Equal(sets.nodePorts, want) {
				t.Errorf("initial (upgraded, no record: on) NodePort set = %v, want the spec's %v", sets.nodePorts, want)
			}
			return f, nil
		}); err != nil {
			t.Fatal(err)
		}
		rig.sys.put(rig.record, mustRecord(t, install.LANOff))
		if err := rig.sw.apply(context.Background()); err != nil {
			t.Fatal(err)
		}
		if !slices.Equal(f.ports, lanLocal) {
			t.Errorf("off: NodePorts on %v, want the local set %v whatever the spec says", f.ports, lanLocal)
		}
		rig.sys.put(rig.record, mustRecord(t, install.LANOn))
		if err := rig.sw.apply(context.Background()); err != nil {
			t.Fatal(err)
		}
		if want := []netip.Addr{netip.MustParseAddr("192.0.2.20")}; !slices.Equal(f.ports, want) {
			t.Errorf("on: NodePorts on %v, want the spec's %v", f.ports, want)
		}
	})

	t.Run("a refusal in any family rolls back all three and the verb restores the old value", func(t *testing.T) {
		for failing := 0; failing < 3; failing++ {
			rig := newLANRig(t, install.RoleServer)
			fams := []*fakeFamily{{fam: "nodeports"}, {fam: "loadbalancers"}, {fam: "ingress"}}
			fams[failing].failOn = install.LANOff
			for _, f := range fams {
				if err := rig.sw.attach("", "", func(lanSets) (lanFamily, error) { return f, nil }); err != nil {
					t.Fatal(err)
				}
			}
			rig.sys.put(rig.record, mustRecord(t, install.LANOn))
			if code := rig.run("lan", "off"); code != exitLifecycleFailed {
				t.Fatalf("family %d refusing: exit %d, want %d", failing, code, exitLifecycleFailed)
			}
			if lan, _ := rig.sys.recordedLAN(t, rig.record); lan != install.LANOn {
				t.Errorf("family %d refusing: record left at %s, want on restored", failing, lan)
			}
			if !strings.Contains(rig.errOut.String(), fams[failing].fam) || !strings.Contains(rig.errOut.String(), "stays on") {
				t.Errorf("family %d refusing: the error does not name the family and the restored value: %s", failing, rig.errOut)
			}
			if rig.sw.state() != install.LANOn {
				t.Errorf("family %d refusing: daemon state %s, want on", failing, rig.sw.state())
			}
			for i, f := range fams {
				var want []string
				switch {
				case i < failing:
					want = []string{"prepare:off", "abort:off"}
				case i == failing:
					want = []string{"refuse:off"}
				}
				// The restore re-applies on, which every family takes.
				want = append(want, "prepare:on", "commit:on")
				if got := f.log(); !slices.Equal(got, want) {
					t.Errorf("family %d refusing: %s saw %v, want %v", failing, f.fam, got, want)
				}
			}
		}
	})

	t.Run("a daemon that does not answer is restarted in place", func(t *testing.T) {
		rig := newLANRig(t, install.RoleAgent)
		rig.env.Wait = 50 * time.Millisecond
		rig.env.Signal = func(context.Context, string) error { return nil } // an old daemon: no report
		restarted := false
		rig.env.Restart = func(ctx context.Context) error {
			restarted = true
			rig.sw.load()
			rig.sw.report(rig.sw.serial, nil) // what a starting daemon writes
			return nil
		}
		if code := rig.run("lan", "off"); code != 0 {
			t.Fatalf("exit %d: %s", code, rig.errOut)
		}
		if !restarted || !strings.Contains(rig.out.String(), "restarting the node daemon in place") {
			t.Errorf("restarted=%v out=%q", restarted, rig.out)
		}
		if !strings.Contains(rig.errOut.String(), "pods keep running") {
			t.Errorf("the fallback was not announced: %q", rig.errOut)
		}
	})

	t.Run("no record reads as on, a fresh install writes off, --lan is parsed", func(t *testing.T) {
		rig := newLANRig(t, install.RoleServer)
		if rig.sw.state() != install.LANOn {
			t.Errorf("upgraded daemon with no record serves %s, want on", rig.sw.state())
		}
		if lan, write := install.DecideInstallLAN(nil, false, "", true); lan != install.LANOn || !write {
			t.Errorf("upgrade with no record: %s write=%v, want on, written", lan, write)
		}
		if lan, write := install.DecideInstallLAN(nil, false, "", false); lan != install.LANOff || !write {
			t.Errorf("fresh install: %s write=%v, want off, written", lan, write)
		}
		o, err := parseInstallFlags([]string{"--lan", "off"})
		if err != nil {
			t.Fatal(err)
		}
		if got := o.recordedLAN(); got == nil || *got != install.LANOff {
			t.Errorf("--lan off reached the install as %v", got)
		}
		if o, err := parseInstallFlags(nil); err != nil || o.recordedLAN() != nil {
			t.Errorf("no --lan: %v, %v; want nil (keep or decide)", o.recordedLAN(), err)
		}
		if _, err := parseInstallFlags([]string{"--lan", "maybe"}); err == nil {
			t.Error("--lan maybe was accepted")
		}
	})

	t.Run("the hoster withdraws its report before it unbinds", func(t *testing.T) {
		const node = "my-mac"
		cs := fake.NewClientset(&corev1.Node{
			ObjectMeta: metav1.ObjectMeta{Name: node},
			Status:     corev1.NodeStatus{Conditions: []corev1.NodeCondition{{Type: corev1.NodeReady, Status: corev1.ConditionTrue}}},
		})
		web := &corev1.Service{
			ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "www", UID: types.UID("uid-www"), Annotations: map[string]string{svclb.HostsAnnotation: node}},
			Spec:       corev1.ServiceSpec{Type: corev1.ServiceTypeLoadBalancer, ClusterIP: "10.43.0.80", Ports: []corev1.ServicePort{{Port: 80, Protocol: corev1.ProtocolTCP}}},
		}
		if _, err := cs.CoreV1().Services("default").Create(context.Background(), web, metav1.CreateOptions{}); err != nil {
			t.Fatal(err)
		}
		b := &memBinder{deny: map[netip.AddrPort]error{netip.AddrPortFrom(lanNode, 80): fmt.Errorf("bind: %w", syscall.EACCES)}}
		rig := newLANRig(t, install.RoleServer)
		var h *svclb.Hoster
		if err := rig.sw.attach("", "", func(sets lanSets) (lanFamily, error) {
			var err error
			h, err = svclb.NewHoster(svclb.HosterConfig{Client: cs, NodeName: node, BindAddr: lanWildcard[0], BindAddrs: sets.listeners, ReservedPorts: map[int32]bool{}, Binder: b, Logger: slog.New(slog.DiscardHandler)})
			return hosterLANFamily{h: h}, err
		}); err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan struct{})
		go func() { defer close(done); _ = h.Run(ctx) }()
		defer func() { cancel(); <-done }()

		reported := func() bool {
			n, err := cs.CoreV1().Nodes().Get(context.Background(), node, metav1.GetOptions{})
			return err == nil && strings.Contains(n.Annotations[svclb.BoundAnnotation], "www")
		}
		deadline := time.Now().Add(10 * time.Second)
		for !reported() || b.get("0.0.0.0:80") == nil {
			if time.Now().After(deadline) {
				t.Fatal("the hoster never bound and reported the service on the wildcard")
			}
			time.Sleep(10 * time.Millisecond)
		}
		port80 := b.get("0.0.0.0:80")
		var mu sync.Mutex
		var withdrawn, openAtWithdraw bool
		cs.PrependReactor("patch", "nodes", func(a k8stesting.Action) (bool, runtime.Object, error) {
			if p, ok := a.(k8stesting.PatchAction); ok && !strings.Contains(string(p.GetPatch()), "www") {
				mu.Lock()
				if !withdrawn {
					withdrawn, openAtWithdraw = true, !port80.isClosed()
				}
				mu.Unlock()
			}
			return false, nil, nil
		})
		if code := rig.run("lan", "off"); code != 0 {
			t.Fatalf("lan off exit %d: %s", code, rig.errOut)
		}
		mu.Lock()
		defer mu.Unlock()
		if !withdrawn || !openAtWithdraw {
			t.Errorf("withdrawn=%v listener open at the withdrawal=%v; want the report withdrawn while the listener was still open", withdrawn, openAtWithdraw)
		}
		if !port80.isClosed() {
			t.Error("the port-80 listener is still open on every interface")
		}
	})

	t.Run("a connection in flight survives a rebind", func(t *testing.T) {
		rig := newLANRig(t, install.RoleServer)
		b := &memBinder{}
		var set *svclb.AddrSetListener
		if err := rig.sw.attach("", "", func(sets lanSets) (lanFamily, error) {
			var err error
			set, err = svclb.ListenAddrSet(context.Background(), b.Listen, sets.listeners, 8443)
			return addrSetFamily{set: set}, err
		}); err != nil {
			t.Fatal(err)
		}
		defer set.Close()
		go echoServe(set)
		wild := b.get("0.0.0.0:8443")
		client := wild.connect(t)
		defer client.Close()
		if err := echoOnce(client, "before"); err != nil {
			t.Fatal(err)
		}
		if code := rig.run("lan", "off"); code != 0 {
			t.Fatalf("lan off exit %d: %s", code, rig.errOut)
		}
		if !wild.isClosed() {
			t.Fatal("the wildcard still accepts new connections after lan off")
		}
		if err := echoOnce(client, "after"); err != nil {
			t.Fatalf("the established connection did not survive lan off: %v", err)
		}
		c2 := b.get("100.64.0.1:8443").connect(t)
		defer c2.Close()
		if err := echoOnce(c2, "mesh"); err != nil {
			t.Fatalf("the mesh address does not serve after lan off: %v", err)
		}
	})

	t.Run("a forged report is not proof: the sockets decide", func(t *testing.T) {
		rig := newLANRig(t, install.RoleServer)
		rig.sys.put(rig.record, mustRecord(t, install.LANOn))
		// The daemon reports off, but its NodePort still listens on every
		// interface.
		rig.forged = []netip.AddrPort{netip.MustParseAddrPort("0.0.0.0:30090"), netip.AddrPortFrom(lanNode, 10250)}
		if code := rig.run("lan", "off"); code != exitLifecycleFailed {
			t.Fatalf("exit %d, want %d: %s", code, exitLifecycleFailed, rig.errOut)
		}
		for _, want := range []string{"listening sockets do not match", "port 30090 listens on every interface", "stays on"} {
			if !strings.Contains(rig.errOut.String(), want) {
				t.Errorf("the error lacks %q: %s", want, rig.errOut)
			}
		}
		if lan, _ := rig.sys.recordedLAN(t, rig.record); lan != install.LANOn {
			t.Errorf("record left at %s, want on restored", lan)
		}
		if rig.sw.state() != install.LANOn {
			t.Errorf("daemon state %s, want on re-applied", rig.sw.state())
		}
	})

	t.Run("a family that fails to commit fails the apply", func(t *testing.T) {
		rig := newLANRig(t, install.RoleServer)
		rig.sys.put(rig.record, mustRecord(t, install.LANOn))
		ok1, bad, ok2 := &fakeFamily{fam: "nodeports"}, &fakeFamily{fam: "loadbalancers", commitFailOn: install.LANOff}, &fakeFamily{fam: "ingress"}
		for _, f := range []*fakeFamily{ok1, bad, ok2} {
			if err := rig.sw.attach("", "", func(lanSets) (lanFamily, error) { return f, nil }); err != nil {
				t.Fatal(err)
			}
		}
		rig.sys.put(rig.record, mustRecord(t, install.LANOff))
		if err := rig.sw.apply(context.Background()); err == nil || !strings.Contains(err.Error(), "loadbalancers did not commit") {
			t.Fatalf("apply = %v, want the failed commit reported", err)
		}
		if rig.sw.state() != install.LANOn {
			t.Errorf("state advanced to %s past a failed commit", rig.sw.state())
		}
		data, _ := rig.sys.ReadFile(install.NetworkAppliedPath(rig.env.DataRoot, install.RoleServer))
		a, err := install.DecodeNetworkApplied(data)
		if err != nil || a.Error == "" || a.LAN != install.LANOn {
			t.Errorf("applied report = %+v, %v; want lan on with the error", a, err)
		}
		if code := rig.run("lan", "status"); code != 0 || !strings.Contains(rig.out.String(), "Its last change was refused") {
			t.Errorf("status (exit %d) does not show the refusal:\n%s", code, rig.out)
		}
		// Through the verb: a failure, and on is restored on every family.
		rig.sys.put(rig.record, mustRecord(t, install.LANOn))
		if code := rig.run("lan", "off"); code != exitLifecycleFailed {
			t.Fatalf("lan off with a failing commit: exit %d", code)
		}
		if lan, _ := rig.sys.recordedLAN(t, rig.record); lan != install.LANOn {
			t.Errorf("record left at %s, want on", lan)
		}
		if !slices.Equal(ok1.current, lanWildcard) || ok1.ports != nil {
			t.Errorf("a family that committed off was not brought back to on: %v", ok1.ports)
		}
	})

	t.Run("a restore that fails is loud and exits 4", func(t *testing.T) {
		rig := newLANRig(t, install.RoleServer)
		rig.sys.put(rig.record, mustRecord(t, install.LANOn))
		rig.forged = []netip.AddrPort{netip.MustParseAddrPort("0.0.0.0:30090")}
		calls := 0
		apply := rig.env.Signal
		rig.env.Signal = func(ctx context.Context, label string) error {
			calls++
			if calls > 1 {
				return errors.New("launchctl: no such process")
			}
			return apply(ctx, label)
		}
		if code := rig.run("lan", "off"); code != exitNetworkRestoreFailed {
			t.Fatalf("exit %d, want %d: %s", code, exitNetworkRestoreFailed, rig.errOut)
		}
		if !strings.Contains(rig.errOut.String(), "COULD NOT BE RESTORED") {
			t.Errorf("the restore failure is not loud: %s", rig.errOut)
		}
	})

	t.Run("status says when on is only the no-record default", func(t *testing.T) {
		rig := newLANRig(t, install.RoleAgent)
		if code := rig.run("lan", "status"); code != 0 {
			t.Fatalf("exit %d: %s", code, rig.errOut)
		}
		for _, want := range []string{"Recorded: LAN access is on", "LAN access is on because no setting is recorded", "Covers: nodeports, loadbalancers\n", "Applied: unknown"} {
			if !strings.Contains(rig.out.String(), want) {
				t.Errorf("status lacks %q:\n%s", want, rig.out)
			}
		}
	})

	t.Run("the socket check", func(t *testing.T) {
		host := []netip.Addr{netip.MustParseAddr("192.0.2.20"), netip.MustParseAddr("127.0.0.1"), lanNode, netip.MustParseAddr("192.168.64.1")}
		ap := netip.MustParseAddrPort
		cases := []struct {
			name  string
			want  install.LAN
			role  install.Role
			args  []string
			socks []netip.AddrPort
			ok    bool
		}{
			{"off: local listeners, kubelet, ClusterIP, the join wildcard", install.LANOff, install.RoleServer, nil,
				[]netip.AddrPort{ap("127.0.0.1:30090"), ap("100.64.0.1:30090"), ap("100.64.0.1:10250"), ap("10.43.0.10:53"), ap("0.0.0.0:9345"), ap("100.64.0.1:443")}, true},
			{"off: a wildcard NodePort", install.LANOff, install.RoleServer, nil, []netip.AddrPort{ap("0.0.0.0:30090")}, false},
			{"off: a LoadBalancer on the Wi-Fi address", install.LANOff, install.RoleServer, nil, []netip.AddrPort{ap("192.0.2.20:8080")}, false},
			{"off: the join wildcard on a worker is not allowed", install.LANOff, install.RoleAgent, nil, []netip.AddrPort{ap("0.0.0.0:9345")}, false},
			{"off: the vm NAT gateway relay is not the LAN", install.LANOff, install.RoleServer, []string{"--registry-port", "5000"}, []netip.AddrPort{ap("192.168.64.1:5000")}, true},
			{"on: wildcard NodePort, LoadBalancer and ingress", install.LANOn, install.RoleServer, nil,
				[]netip.AddrPort{ap("0.0.0.0:30090"), ap("0.0.0.0:8080"), ap("0.0.0.0:80"), ap("0.0.0.0:443"), ap("100.64.0.1:10250"), ap("10.43.0.1:443")}, true},
			{"on: a NodePort left on the local set", install.LANOn, install.RoleServer, nil, []netip.AddrPort{ap("127.0.0.1:30090"), ap("100.64.0.1:30090")}, false},
			{"on: an ingress port left on the node address", install.LANOn, install.RoleServer, nil, []netip.AddrPort{ap("100.64.0.1:443")}, false},
			{"on: a LoadBalancer left on loopback", install.LANOn, install.RoleAgent, nil, []netip.AddrPort{ap("127.0.0.1:8080"), ap("100.64.0.1:8080")}, false},
			{"on: an explicit --nodeport-addresses narrows NodePorts", install.LANOn, install.RoleAgent, []string{"--nodeport-addresses", "local"}, []netip.AddrPort{ap("127.0.0.1:30090")}, true},
			{"on: the registry on loopback is not covered", install.LANOn, install.RoleServer, []string{"--registry-port", "5000"}, []netip.AddrPort{ap("127.0.0.1:5000")}, true},
		}
		for _, tc := range cases {
			err := verifyLANSockets(lanPolicyFor(tc.want, tc.role, tc.args, host), tc.socks)
			if (err == nil) != tc.ok {
				t.Errorf("%s: err = %v, want ok=%v", tc.name, err, tc.ok)
			}
			if err != nil && !errors.Is(err, errLANMismatch) {
				t.Errorf("%s: err = %v, want errLANMismatch", tc.name, err)
			}
		}
		socks, err := parseLsofListeners([]byte("p4242\nf7\nn*:30090\nf8\nn127.0.0.1:8080\nf9\nn[::1]:6060\nf10\nn100.64.0.1:10250\n"))
		want := []netip.AddrPort{ap("0.0.0.0:30090"), ap("127.0.0.1:8080"), ap("[::1]:6060"), ap("100.64.0.1:10250")}
		if err != nil || !slices.Equal(socks, want) {
			t.Errorf("parseLsofListeners = %v, %v; want %v", socks, err, want)
		}
	})

	t.Run("status JSON gains an additive network block", func(t *testing.T) {
		r := status.Report{SchemaVersion: status.SchemaVersion, Role: install.RoleServer}
		plain, err := json.Marshal(r)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(plain, []byte(`"network"`)) {
			t.Errorf("a report without the block encodes a network key: %s", plain)
		}
		r.Network = &status.Network{LAN: "off", Covers: install.LANCovers(install.RoleServer), AlwaysOn: install.LANAlwaysOn(install.RoleServer)}
		withBlock, err := json.Marshal(r)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Contains(withBlock, []byte(`"network":{"lan":"off","recorded":false,"covers":["nodeports","loadbalancers","ingress"],"alwaysOn":["apiserver","join","mesh"]}`)) {
			t.Errorf("network block = %s", withBlock)
		}
		// The goldens from before the block carry no network key, and still
		// decode: the contract is additive. Only the network-* postures,
		// added with it, carry one.
		goldens, err := filepath.Glob(filepath.Join("..", "..", "pkg", "status", "testdata", "status_*json_*.json"))
		if err != nil || len(goldens) == 0 {
			t.Fatalf("no status goldens found: %v", err)
		}
		withNetwork := 0
		for _, g := range goldens {
			data, err := os.ReadFile(g)
			if err != nil {
				t.Fatal(err)
			}
			has := bytes.Contains(data, []byte(`"network"`))
			if strings.Contains(filepath.Base(g), "_network-") {
				if !has {
					t.Errorf("golden %s carries no network key", g)
				}
				withNetwork++
				continue
			}
			if has {
				t.Errorf("golden %s carries a network key", g)
			}
		}
		if withNetwork == 0 {
			t.Error("no network-* golden found; the block's goldens are missing")
		}
	})
}

// mustRecord encodes a record of lan.
func mustRecord(t *testing.T, lan install.LAN) []byte {
	t.Helper()
	data, err := install.EncodeNetworkRecord(install.NewNetworkRecord(lan, "test"))
	if err != nil {
		t.Fatal(err)
	}
	return data
}

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

package status

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"testing"

	"golang.org/x/net/dns/dnsmessage"

	"k3sm.io/k3sm/pkg/dataroot"
	"k3sm.io/k3sm/pkg/install"
)

// fakeDNS is a DNSQuerier that answers per transport: an address, or an error.
// A nil fakeDNS map entry is a resolver that never answers on that transport.
type fakeDNS struct {
	mu      sync.Mutex
	answers map[string]netip.Addr
	errs    map[string]error
	asked   []string
}

func (f *fakeDNS) Query(ctx context.Context, network string, server netip.AddrPort, name string) (netip.Addr, error) {
	f.mu.Lock()
	f.asked = append(f.asked, network+" "+server.String()+" "+name)
	f.mu.Unlock()
	if _, ok := ctx.Deadline(); !ok {
		return netip.Addr{}, errors.New("query without a deadline")
	}
	if a, ok := f.answers[network]; ok {
		return a, nil
	}
	if err, ok := f.errs[network]; ok {
		return netip.Addr{}, err
	}
	return netip.Addr{}, context.DeadlineExceeded
}

// answeringDNS answers the kubernetes Service over both transports.
func answeringDNS() *fakeDNS {
	a := netip.MustParseAddr("10.43.0.1")
	return &fakeDNS{answers: map[string]netip.Addr{"udp": a, "tcp": a}}
}

// TestDNSRowFailsWhenTheVIPDoesNotAnswer pins the dns row: a resolver that
// answers over UDP is ok with the address; one that answers over TCP only (a
// UDP socket that stopped receiving) warns, names the TCP answer in wide.tcp
// and degrades the verdict; one that answers neither warns without that note.
func TestDNSRowFailsWhenTheVIPDoesNotAnswer(t *testing.T) {
	t.Parallel()
	svc := netip.MustParseAddr("10.43.0.1")
	running := Row{Name: RowServer, State: StateRunning, Severity: SeverityOK}

	t.Run("an answer over UDP is ok", func(t *testing.T) {
		t.Parallel()
		q := &fakeDNS{answers: map[string]netip.Addr{"udp": svc}}
		r, ok := Collector{DNS: q, Paths: testPaths(contractWorkDir)}.dnsRow(context.Background(), dataroot.RoleServer, true, running)
		if !ok || r.State != StateOK || r.Severity != SeverityOK || r.Wide["answer"] != "10.43.0.1" || r.Remedy != "" {
			t.Fatalf("row = %+v, want ok answering 10.43.0.1", r)
		}
		if _, has := r.Wide["tcp"]; has {
			t.Errorf("an ok row carries wide.tcp: %+v", r)
		}
		if want := []string{"udp 10.43.0.10:53 kubernetes.default.svc.cluster.local"}; fmt.Sprint(q.asked) != fmt.Sprint(want) {
			t.Errorf("asked %v, want %v", q.asked, want)
		}
	})

	t.Run("an answer over TCP only warns with the TCP note", func(t *testing.T) {
		t.Parallel()
		q := &fakeDNS{answers: map[string]netip.Addr{"tcp": svc}}
		r, _ := Collector{DNS: q, Paths: testPaths(contractWorkDir)}.dnsRow(context.Background(), dataroot.RoleServer, true, running)
		if r.State != StateDown || r.Severity != SeverityWarn {
			t.Fatalf("row = %+v, want a down warn", r)
		}
		if want := "the resolver at 10.43.0.10 did not answer over UDP in 3 s"; r.Detail != want {
			t.Errorf("detail = %q, want %q", r.Detail, want)
		}
		if !strings.Contains(r.Wide["tcp"], "10.43.0.1 over TCP") {
			t.Errorf("wide.tcp = %q, want the TCP answer", r.Wide["tcp"])
		}
		if r.Remedy != "sudo launchctl kickstart -k system/io.k3sm.server" {
			t.Errorf("remedy = %q, want the server kickstart", r.Remedy)
		}
	})

	t.Run("no answer on either transport warns without the note", func(t *testing.T) {
		t.Parallel()
		q := &fakeDNS{}
		r, _ := Collector{DNS: q, Paths: testPaths(contractWorkDir)}.dnsRow(context.Background(), dataroot.RoleServer, true, running)
		if r.State != StateDown || r.Severity != SeverityWarn || !strings.Contains(r.Detail, "did not answer over UDP in 3 s") {
			t.Fatalf("row = %+v, want a down warn", r)
		}
		if _, has := r.Wide["tcp"]; has {
			t.Errorf("wide.tcp = %q with no TCP answer", r.Wide["tcp"])
		}
		if len(q.asked) != 2 {
			t.Errorf("asked %v, want UDP then TCP", q.asked)
		}
	})

	t.Run("a TCP-only resolver degrades a running report", func(t *testing.T) {
		t.Parallel()
		c := contractServer(t, "launchctl_netd_running.txt", "launchctl_netd_running.txt", heartbeatingKube(goldenTime), nil)
		c.DNS = &fakeDNS{answers: map[string]netip.Addr{"tcp": svc}}
		rep := c.Collect(context.Background())
		if rep.Verdict != VerdictDegraded || !strings.HasPrefix(rep.Summary, RowDNS+": ") {
			t.Fatalf("verdict %v %q, want degraded naming the dns row", rep.Verdict, rep.Summary)
		}
		if !contains(rep.Next, "sudo launchctl kickstart -k system/io.k3sm.server") {
			t.Errorf("next = %v, want the server kickstart", rep.Next)
		}
	})
}

// TestDNSRowPostures pins the rest of the row: absent without a querier, skip
// on a Mac with no install or a stopped node daemon, the agent's remedy, an
// answer with no address, and the VIP read from the daemon's --dns-vip.
func TestDNSRowPostures(t *testing.T) {
	t.Parallel()
	running := Row{Name: RowServer, State: StateRunning, Severity: SeverityOK}
	p := testPaths(contractWorkDir)
	ctx := context.Background()

	if _, ok := (Collector{Paths: p}).dnsRow(ctx, dataroot.RoleServer, true, running); ok {
		t.Fatal("a dns row without a querier")
	}
	for name, tc := range map[string]struct {
		installed bool
		node      RowState
	}{
		"not installed": {false, StateRunning},
		"stopped":       {true, StateStopped},
		"not loaded":    {true, StateNotLoaded},
		"crash-looping": {true, StateCrashLoop},
	} {
		q := &fakeDNS{}
		r, _ := Collector{DNS: q, Paths: p}.dnsRow(ctx, dataroot.RoleServer, tc.installed, Row{Name: RowServer, State: tc.node})
		if r.State != StateSkip || r.Severity != SeveritySkip || len(q.asked) != 0 {
			t.Errorf("%s: row = %+v asked %v, want a skip that sends nothing", name, r, q.asked)
		}
	}

	agent := Row{Name: RowAgent, State: StateRunning, Severity: SeverityOK}
	r, _ := Collector{DNS: &fakeDNS{}, Paths: p}.dnsRow(ctx, dataroot.RoleAgent, true, agent)
	if r.Severity != SeverityWarn || r.Remedy != "sudo launchctl kickstart -k system/"+p.AgentLabel {
		t.Errorf("agent row = %+v, want a warn naming the agent kickstart", r)
	}
	if advisory(dataroot.RoleAgent, RowDNS) || advisory(dataroot.RoleServer, RowDNS) {
		t.Error("the dns row is advisory; its warn must degrade the verdict")
	}

	nx := &fakeDNS{errs: map[string]error{"udp": fmt.Errorf("%w: rcode RCodeNameError", ErrDNSNoAddress)}}
	r, _ = Collector{DNS: nx, Paths: p}.dnsRow(ctx, dataroot.RoleServer, true, running)
	if r.State != StateUnhealthy || r.Severity != SeverityWarn || !strings.Contains(r.Detail, "answered over UDP with no address") || len(nx.asked) != 1 {
		t.Errorf("no-address row = %+v asked %v, want unhealthy with no TCP retry", r, nx.asked)
	}

	q := answeringDNS()
	c := Collector{DNS: q, Paths: p, NodeArgs: func(install.Role) ([]string, error) {
		return []string{"--mesh-ip", "100.64.0.1", "--dns-vip=10.96.0.10"}, nil
	}}
	if r, _ := c.dnsRow(ctx, dataroot.RoleServer, true, running); r.Wide["vip"] != "10.96.0.10" || !strings.HasPrefix(q.asked[0], "udp 10.96.0.10:53 ") {
		t.Errorf("row = %+v asked %v, want the --dns-vip address", r, q.asked)
	}
	c.NodeArgs = func(install.Role) ([]string, error) { return nil, errors.New("permission denied") }
	if r, _ := c.dnsRow(ctx, dataroot.RoleServer, true, running); r.Wide["vip"] != "10.43.0.10" {
		t.Errorf("unreadable arguments row = %+v, want the default VIP", r)
	}
	c.NodeArgs = func(install.Role) ([]string, error) { return []string{"--dns-vip", "nope"}, nil }
	if r, _ := c.dnsRow(ctx, dataroot.RoleServer, true, running); r.Severity != SeverityUnknown {
		t.Errorf("unparsable --dns-vip row = %+v, want unknown", r)
	}
}

// TestDNSQueryWire pins the message NetDNS sends and how it reads a reply,
// without a socket: the query is a recursive A question for the name, and a
// reply yields its A record only when it answers that query with success.
func TestDNSQueryWire(t *testing.T) {
	t.Parallel()
	q, err := buildDNSQuery(0x1234, dnsProbeName)
	if err != nil {
		t.Fatal(err)
	}
	var msg dnsmessage.Message
	if err := msg.Unpack(q); err != nil {
		t.Fatal(err)
	}
	if msg.ID != 0x1234 || msg.Response || !msg.RecursionDesired || len(msg.Questions) != 1 ||
		msg.Questions[0].Name.String() != dnsProbeName+"." || msg.Questions[0].Type != dnsmessage.TypeA {
		t.Fatalf("query = %+v", msg)
	}

	reply := func(id uint16, rcode dnsmessage.RCode, answers ...dnsmessage.Resource) []byte {
		m := dnsmessage.Message{
			Header:    dnsmessage.Header{ID: id, Response: true, RCode: rcode},
			Questions: msg.Questions,
			Answers:   answers,
		}
		b, err := m.Pack()
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	hdr := func(typ dnsmessage.Type) dnsmessage.ResourceHeader {
		return dnsmessage.ResourceHeader{Name: msg.Questions[0].Name, Type: typ, Class: dnsmessage.ClassINET, TTL: 5}
	}
	a := dnsmessage.Resource{Header: hdr(dnsmessage.TypeA), Body: &dnsmessage.AResource{A: [4]byte{10, 43, 0, 1}}}
	cname := dnsmessage.Resource{Header: hdr(dnsmessage.TypeCNAME), Body: &dnsmessage.CNAMEResource{CNAME: msg.Questions[0].Name}}

	if got, err := parseDNSAnswer(0x1234, reply(0x1234, dnsmessage.RCodeSuccess, cname, a)); err != nil || got != netip.MustParseAddr("10.43.0.1") {
		t.Errorf("answer = %v, %v; want 10.43.0.1", got, err)
	}
	for name, b := range map[string][]byte{
		"another id": reply(0x4321, dnsmessage.RCodeSuccess, a),
		"nxdomain":   reply(0x1234, dnsmessage.RCodeNameError),
		"no answers": reply(0x1234, dnsmessage.RCodeSuccess),
		"garbage":    []byte{1, 2, 3},
		"the query":  q,
	} {
		if _, err := parseDNSAnswer(0x1234, b); !errors.Is(err, ErrDNSNoAddress) {
			t.Errorf("%s: err = %v, want ErrDNSNoAddress", name, err)
		}
	}
	if v, ok := argValue([]string{"-dns-vip", "1.2.3.4", "--other", "x"}, "dns-vip"); !ok || v != "1.2.3.4" {
		t.Errorf("argValue = %q %v", v, ok)
	}
	if _, ok := argValue([]string{"--dns-vip"}, "dns-vip"); ok {
		t.Error("a trailing flag with no value reads as set")
	}
}

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
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"k3sm.io/k3sm/pkg/install"
)

// TestLanStatusReportsLANReachableListeners drives `k3sm network lan status`
// as root over a fake socket table and checks the exposure section.
func TestLanStatusReportsLANReachableListeners(t *testing.T) {
	const daemon = 4242 // the rig's node daemon pid
	ap := netip.MustParseAddrPort
	sock := func(pid, ppid int, cmd, proto, addr string) lanSocket {
		return lanSocket{PID: pid, PPID: ppid, Command: cmd, Protocol: proto, Local: ap(addr)}
	}
	const (
		k3smHeading  = "k3sm control-plane ports (not moved by LAN access):"
		otherHeading = "Listening on a LAN-reachable address (not moved by LAN access):"
	)
	cases := []struct {
		name    string
		socks   []lanSocket
		err     error
		want    []string
		notWant []string
	}{
		{
			name: "wildcard pod listener and LAN-address listener are listed",
			socks: []lanSocket{
				sock(900, 1, "nginx", "TCP", "0.0.0.0:8080"),
				sock(901, 1, "redis-server", "TCP", "192.168.1.23:6379"),
				sock(902, 1, "dnsd", "UDP", "192.168.1.23:5353"),
			},
			want: []string{otherHeading, "  pid 900 nginx tcp *:8080", "  pid 901 redis-server tcp 192.168.1.23:6379", "  pid 902 dnsd udp 192.168.1.23:5353", k3smHeading + " none."},
		},
		{
			name: "loopback, mesh, pod-range and service-range sockets are excluded",
			socks: []lanSocket{
				sock(900, 1, "a", "TCP", "127.0.0.1:8080"),
				sock(900, 1, "a", "TCP", "[::1]:8080"),
				sock(900, 1, "a", "TCP", "100.64.0.1:8080"),
				sock(900, 1, "a", "TCP", "100.64.3.7:8080"),
				sock(900, 1, "a", "TCP", "10.43.0.10:53"),
			},
			want:    []string{otherHeading + " none.", k3smHeading + " none."},
			notWant: []string{"pid 900"},
		},
		{
			name: "the daemon and its children are k3sm, in their own block",
			socks: []lanSocket{
				sock(daemon, 1, "k3sm", "TCP", "0.0.0.0:9345"),
				sock(5000, daemon, "kine", "TCP", "192.168.1.23:2379"),
				sock(daemon, 1, "k3sm", "TCP", "127.0.0.1:6443"),
			},
			want: []string{k3smHeading, "  pid 4242 k3sm tcp *:9345", "  pid 5000 kine tcp 192.168.1.23:2379", otherHeading + " none."},
		},
		{
			name:  "a spoofed command name k3sm from another pid is listed as other",
			socks: []lanSocket{sock(777, 1, "k3sm", "TCP", "0.0.0.0:8443")},
			want:  []string{otherHeading, "  pid 777 k3sm tcp *:8443", k3smHeading + " none."},
		},
		{
			name:  "a v6 wildcard is listed",
			socks: []lanSocket{sock(778, 1, "srv", "TCP", "[::]:9000")},
			want:  []string{otherHeading, "  pid 778 srv tcp [::]:9000"},
		},
		{
			name:  "a command name is sanitized before printing",
			socks: []lanSocket{sock(779, 1, "evil\x1b[2Jname-that-is-much-longer-than-32", "TCP", "0.0.0.0:9001")},
			want:  []string{"  pid 779 evil?[2Jname-that-is-much-longer tcp *:9001"},
		},
		{
			name:    "a seam error yields the named line, never a clean list",
			err:     errors.New("lsof exploded"),
			want:    []string{"LAN listeners: unknown, the check failed (list this Mac's listening sockets: lsof exploded)."},
			notWant: []string{otherHeading, k3smHeading},
		},
		{
			name:    "an over-cap table yields the named line",
			err:     errLsofTooLarge,
			want:    []string{"LAN listeners: unknown, the check failed (list this Mac's listening sockets: lsof output exceeds the size cap)."},
			notWant: []string{otherHeading},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rig := newLANRig(t, install.RoleServer)
			rig.env.SocketTable = func(context.Context) ([]lanSocket, error) { return tc.socks, tc.err }
			if code := rig.run("lan", "status"); code != 0 {
				t.Fatalf("exit %d: %s", code, rig.errOut)
			}
			out := rig.out.String()
			lines := strings.Split(out, "\n")
			for _, w := range tc.want {
				if !slices.Contains(lines, w) {
					t.Errorf("status lacks line %q:\n%s", w, out)
				}
			}
			for _, nw := range tc.notWant {
				if strings.Contains(out, nw) {
					t.Errorf("status has %q:\n%s", nw, out)
				}
			}
		})
	}

	t.Run("not root says the check needs root", func(t *testing.T) {
		rig := newLANRig(t, install.RoleServer)
		rig.env.Geteuid = func() int { return 501 }
		rig.env.SocketTable = func(context.Context) ([]lanSocket, error) {
			t.Error("the socket table was read without root")
			return nil, nil
		}
		if code := rig.run("lan", "status"); code != 0 {
			t.Fatalf("exit %d: %s", code, rig.errOut)
		}
		if !strings.Contains(rig.out.String(), "LAN listeners: unknown to this user (the check needs root") {
			t.Errorf("status:\n%s", rig.out)
		}
	})

	t.Run("JSON carries protocol, address, port and class counts only", func(t *testing.T) {
		e := lanExposure{Listeners: lanReachable([]lanSocket{
			sock(daemon, 1, "k3sm", "TCP", "0.0.0.0:9345"),
			sock(900, 1, "secret-name", "UDP", "192.168.1.23:5353"),
		}, daemon, nil), Counts: map[string]int{lanClassK3sm: 1, lanClassOther: 1}}
		data, err := json.Marshal(e)
		if err != nil {
			t.Fatal(err)
		}
		const want = `{"listeners":[{"class":"k3sm","protocol":"tcp","address":"*","port":9345},{"class":"other","protocol":"udp","address":"192.168.1.23","port":5353}],"counts":{"k3sm":1,"other":1}}`
		if string(data) != want {
			t.Errorf("JSON = %s\nwant   %s", data, want)
		}
	})
}

// TestLsofSocketTableExposureParse parses a captured lsof -F pRcPn sample and
// refuses anything it does not recognise.
func TestLsofSocketTableExposureParse(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "lsof-pRcPn.txt"))
	if err != nil {
		t.Fatal(err)
	}
	got, err := parseLsofSocketTable(data)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	ap := netip.MustParseAddrPort
	want := []lanSocket{
		{PID: 312, PPID: 1, Command: "mDNSResponder", Protocol: "UDP", Local: ap("0.0.0.0:5353")},
		{PID: 312, PPID: 1, Command: "mDNSResponder", Protocol: "UDP", Local: ap("0.0.0.0:5353")},
		{PID: 501, PPID: 1, Command: "ControlCenter", Protocol: "TCP", Local: ap("0.0.0.0:7000")},
		{PID: 501, PPID: 1, Command: "ControlCenter", Protocol: "TCP", Local: ap("[::]:7000")},
		{PID: 501, PPID: 1, Command: "ControlCenter", Protocol: "UDP", Local: ap("192.168.1.23:57621")},
		{PID: 4242, PPID: 1, Command: "k3sm", Protocol: "TCP", Local: ap("0.0.0.0:9345")},
		{PID: 4242, PPID: 1, Command: "k3sm", Protocol: "TCP", Local: ap("127.0.0.1:6443")},
		{PID: 4242, PPID: 1, Command: "k3sm", Protocol: "TCP", Local: ap("[fe80::1%en0]:8080")},
	}
	if !slices.Equal(got, want) {
		t.Errorf("parsed\n%v\nwant\n%v", got, want)
	}

	bad := []struct{ name, in string }{
		{"unknown field", "p1\nc x\nf3\nPTCP\nn*:80\nZsurprise\n"},
		{"socket before process", "n*:80\n"},
		{"bad pid", "pabc\n"},
		{"bad port", "p1\nf3\nPTCP\nn*:http\n"},
		{"bad address", "p1\nf3\nPTCP\nnlocalhost:80\n"},
		{"empty line", "p1\n\n"},
	}
	for _, tc := range bad {
		t.Run(tc.name, func(t *testing.T) {
			if socks, err := parseLsofSocketTable([]byte(tc.in)); err == nil {
				t.Errorf("parsed %v, want an error", socks)
			}
		})
	}
	t.Run("over the line cap", func(t *testing.T) {
		in := "p1\n" + strings.Repeat("f3\nPTCP\nn*:80\n", lsofMaxLines/3+1)
		if _, err := parseLsofSocketTable([]byte(in)); !errors.Is(err, errLsofTooLarge) {
			t.Errorf("err = %v, want %v", err, errLsofTooLarge)
		}
	})
	t.Run("capped buffer flags overflow", func(t *testing.T) {
		c := &cappedBuffer{max: 4}
		_, _ = c.Write([]byte("abcdef"))
		if !c.over || c.buf.String() != "abcd" {
			t.Errorf("over=%v buf=%q", c.over, c.buf.String())
		}
	})
}

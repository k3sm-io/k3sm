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
	"fmt"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	netv1alpha1 "k3sm.io/apis/net/v1alpha1"
	"k3sm.io/darwin-net/pkg/linkenum"

	"k3sm.io/k3sm/pkg/status"
)

func boolp(b bool) *bool { return &b }

// cabledProbe is a TB4 Mac with en2 cabled up to worker-2 and en3 cabled to a
// Mac that is not in the cluster.
func cabledProbe() directLinkProbe {
	last := metav1.NewTime(time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC))
	return directLinkProbe{
		Ports: []linkenum.Port{
			{Iface: "en2", PortOrdinal: 0, DomainUUID: "a", PeerDomainUUID: "b", SpeedGbps: 40},
			{Iface: "en3", PortOrdinal: 1, DomainUUID: "c", PeerDomainUUID: "z", SpeedGbps: 40},
			{Iface: "en4", PortOrdinal: 2, DomainUUID: "d", SpeedGbps: 40},
		},
		BridgeMembers: map[string]bool{"en4": true},
		Object: &netv1alpha1.DirectLink{Status: netv1alpha1.DirectLinkStatus{Ports: []netv1alpha1.DirectLinkPortStatus{
			{Iface: "en2", State: netv1alpha1.DirectLinkStateUp, PeerNodeName: "worker-2", PeerLinkIP: "169.254.0.9", LastTransition: &last},
			{Iface: "en3", State: netv1alpha1.DirectLinkStatePeerUnknown, LastTransition: &last},
		}}},
		IdleSleepOff: boolp(false),
		AutoLogin:    boolp(true),
		AutoRestart:  boolp(true),
	}
}

func rowsByName(rows []checkResult) map[string]checkResult {
	m := map[string]checkResult{}
	for _, r := range rows {
		m[r.name] = r
	}
	return m
}

// TestDoctorDirectLinkSection pins the doctor's direct-link section and the
// status links row over fakes: ports and peers (including a cabled Mac that is
// not a member), bridge membership, rdma_ctl, the last transition, the three
// TN3205 settings as advisories with their remedies (the Recovery step printed,
// never attempted), and the status row naming the medium, the speed and the
// PLAINTEXT state.
func TestDoctorDirectLinkSection(t *testing.T) {
	t.Run("a cabled Thunderbolt 4 Mac", func(t *testing.T) {
		rows := rowsByName(directLinkChecks(cabledProbe()))
		ports := rows["direct-links"]
		if ports.status != statusWarn {
			t.Errorf("direct-links status = %v, want WARN (a cabled non-member)", ports.status)
		}
		for _, want := range []string{"en2", "up to worker-2", "PLAINTEXT", "not in this cluster", "nothing cabled", "last transition 2026-10-05T12:00:00Z"} {
			if !strings.Contains(ports.detail, want) {
				t.Errorf("direct-links detail lacks %q: %s", want, ports.detail)
			}
		}
		if !strings.Contains(ports.remedy, "k3sm pair --for") {
			t.Errorf("a peer-unknown cable's remedy does not name pairing: %q", ports.remedy)
		}
		if b := rows["direct-link-bridge"]; b.status != statusPass {
			t.Errorf("bridge row = %v (%s), want PASS: only the uncabled en4 is a member", b.status, b.detail)
		}
		if r := rows["rdma"]; r.status != statusPass || !strings.Contains(r.detail, "Thunderbolt 5") {
			t.Errorf("rdma row on a TB4 Mac = %v %q, want PASS naming the Thunderbolt 5 requirement", r.status, r.detail)
		}
		if s := rows["idle-sleep"]; s.status != statusWarn || s.remedy != "sudo pmset -a sleep 0" {
			t.Errorf("idle-sleep row = %+v, want WARN with the pmset remedy", s)
		}
		if a := rows["auto-login"]; a.status != statusPass {
			t.Errorf("auto-login row = %+v, want PASS", a)
		}
		line, ok := directLinkStatusLine(cabledProbe())
		if !ok || line != "direct links: 1 up (thunderbolt, 40 Gb/s, plaintext) · rdma: no" {
			t.Errorf("status line = %q", line)
		}
	})

	t.Run("a cabled port still in the bridge", func(t *testing.T) {
		p := cabledProbe()
		p.BridgeMembers = map[string]bool{"en2": true}
		if b := rowsByName(directLinkChecks(p))["direct-link-bridge"]; b.status != statusWarn || !strings.Contains(b.detail, "en2") || b.remedy == "" {
			t.Errorf("bridge row = %+v, want WARN naming en2 with a remedy", b)
		}
	})

	t.Run("a Thunderbolt 5 Mac with RDMA disabled prints the Recovery step", func(t *testing.T) {
		p := cabledProbe()
		for i := range p.Ports {
			p.Ports[i].SpeedGbps = 80
		}
		r := rowsByName(directLinkChecks(p))["rdma"]
		if r.status != statusWarn || r.remedy != rdmaRecoveryRemedy || !strings.Contains(r.remedy, "never attempts") {
			t.Errorf("rdma row = %+v, want WARN with the Recovery remedy", r)
		}
	})

	t.Run("a Mac with no Thunderbolt port skips the whole section", func(t *testing.T) {
		p := directLinkProbe{EnumErr: fmt.Errorf("x: %w", linkenum.ErrNoThunderboltService)}
		for _, r := range directLinkChecks(p) {
			if r.status != statusSkip {
				t.Errorf("row %s = %v, want SKIP", r.name, r.status)
			}
		}
		if _, ok := directLinkStatusLine(p); ok {
			t.Error("a Mac with no port renders a links row")
		}
	})

	t.Run("the doctor registry carries the section", func(t *testing.T) {
		env := healthyDoctorEnv()
		env.directLinks = cabledProbe
		rep := doctorReport(env, doctorTestVersion, doctorTestTime)
		for _, name := range []string{"direct-links", "direct-link-bridge", "rdma", "idle-sleep", "auto-login", "power-restart"} {
			if _, ok := rep.Row(name); !ok {
				t.Errorf("doctor report has no %s row", name)
			}
		}
		if doctorExitCode(rep) == exitDoctorCheckFailed {
			t.Error("the direct-link section failed doctor; its rows are advisories")
		}
	})

	t.Run("the status links row is informational", func(t *testing.T) {
		rep := withDirectLinkRow(status.Report{}, cabledProbe())
		row, ok := rep.Row(directLinkStatusRowName)
		if !ok || row.Severity != status.SeverityOK || !strings.Contains(row.Detail, "plaintext") {
			t.Fatalf("status links row = %+v %v", row, ok)
		}
	})
}

// TestDirectLinkLabels pins the advisory labels' presence-only discipline.
func TestDirectLinkLabels(t *testing.T) {
	n := &corev1.Node{}
	applyDirectLinkLabels(n, &directLinkFacts{Ports: 3, SpeedGbps: 40})
	l := n.Labels
	if l[netv1alpha1.LabelDirectLinkPorts] != "3" || l[netv1alpha1.LabelDirectLinkMedium] != "thunderbolt" || l[netv1alpha1.LabelDirectLinkSpeedGbps] != "40" {
		t.Fatalf("labels = %v", l)
	}
	if _, ok := l[netv1alpha1.LabelRDMA]; ok {
		t.Fatal("k3sm.io/rdma set without RDMA")
	}
	applyDirectLinkLabels(n, &directLinkFacts{Ports: 3, SpeedGbps: 80, RDMA: true})
	if _, ok := n.Labels[netv1alpha1.LabelRDMA]; !ok {
		t.Fatal("k3sm.io/rdma absent with RDMA enabled and a device")
	}
	applyDirectLinkLabels(n, nil)
	for _, k := range []string{netv1alpha1.LabelDirectLinkPorts, netv1alpha1.LabelDirectLinkMedium, netv1alpha1.LabelDirectLinkSpeedGbps, netv1alpha1.LabelRDMA} {
		if _, ok := n.Labels[k]; ok {
			t.Errorf("label %s survived the loss of the ports", k)
		}
	}
	if f := factsFromPorts([]linkenum.Port{{SpeedGbps: 80, RDMADevice: "rdma_en2"}}, false); f.RDMA {
		t.Error("RDMA without rdma_ctl enabled")
	}
	if f := factsFromPorts([]linkenum.Port{{SpeedGbps: 80}}, true); f.RDMA {
		t.Error("RDMA enabled with no rdma_enX device")
	}
}

func TestDirectLinkProbeParsers(t *testing.T) {
	m := parseBridgeMembers([]byte("bridge0: flags=8863<UP>\n\tmember: en2 flags=3<LEARNING,DISCOVER>\n\tmember: en3 flags=3<LEARNING,DISCOVER>\n"))
	if !m["en2"] || !m["en3"] || len(m) != 2 {
		t.Errorf("bridge members = %v", m)
	}
	sleep, restart := parsePmset([]byte("System-wide power settings:\nCurrently in use:\n sleep                0\n autorestart          1\n"))
	if sleep == nil || !*sleep || restart == nil || !*restart {
		t.Errorf("pmset = %v %v", sleep, restart)
	}
	if !parseRDMACtlStatus([]byte("enabled\n")) || parseRDMACtlStatus([]byte("disabled\n")) {
		t.Error("rdma_ctl status parse")
	}
}

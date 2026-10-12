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
	"fmt"
	"io/fs"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	netv1alpha1 "k3sm.io/apis/net/v1alpha1"
	"k3sm.io/darwin-net/pkg/linkenum"
	"k3sm.io/darwin-net/pkg/netd/wire"

	"k3sm.io/k3sm/pkg/install"
	"k3sm.io/k3sm/pkg/netdsvc"
	"k3sm.io/k3sm/pkg/status"
)

// icProbeTimeout bounds each interconnect probe; system_profiler (inside the
// port enumeration) is the slow one.
const icProbeTimeout = 20 * time.Second

// icPingTimeout bounds one peer ping, in whole seconds as `ping -t` takes it.
const icPingTimeout = 2

// realInterconnectEnv wires the interconnect section's probes. Every one is a
// read: ifconfig, netstat, arp, ping, pmset and defaults print state; the netd
// socket is dialled and closed without a request; the two netd records are
// read, never written; and the apiserver is read with the same credentials and
// client `k3sm status` uses.
func realInterconnectEnv() *interconnectEnv {
	return &interconnectEnv{
		ports: func() ([]linkenum.Port, error) {
			ctx, cancel := context.WithTimeout(context.Background(), icProbeTimeout)
			defer cancel()
			return linkenum.Exec{}.Ports(ctx)
		},
		bridge: probeBridge,
		routes: func() ([]icRoute, error) {
			out, err := icCommand("netstat", "-rn", "-f", "inet")
			if err != nil {
				return nil, err
			}
			return parseNetstatRoutes(out), nil
		},
		neighbors: func() ([]netip.Addr, error) {
			out, err := icCommand("arp", "-an", "-i", install.InterconnectBridge)
			if err != nil {
				return nil, err
			}
			return parseARPNeighbors(out), nil
		},
		rtt:    pingAll,
		helper: dialNetd,
		ledger: func() ([]install.InterconnectAlias, error) {
			raw, err := os.ReadFile(netdsvc.InterconnectStatePath(install.MeshKeyDir))
			if errors.Is(err, fs.ErrNotExist) {
				return nil, nil
			}
			if err != nil {
				return nil, err
			}
			return install.ParseInterconnectLedger(raw)
		},
		identity: func() (netip.Prefix, error) {
			raw, err := os.ReadFile(netdsvc.NodeIdentityPath(install.MeshKeyDir))
			if err != nil {
				return netip.Prefix{}, err
			}
			p, err := netip.ParsePrefix(strings.TrimSpace(string(raw)))
			if err != nil {
				return netip.Prefix{}, fmt.Errorf("parse %s: %w", netdsvc.NodeIdentityPath(install.MeshKeyDir), err)
			}
			return p.Masked(), nil
		},
		cluster: probeICCluster,
		power: func() (powerSettings, error) {
			out, err := icCommand("pmset", "-g")
			if err != nil {
				return powerSettings{}, err
			}
			return parsePmset(out), nil
		},
		autoLogin: func() (string, error) {
			// `defaults read` exits non-zero when the key is unset, which is the
			// ordinary "automatic login is off".
			out, err := icCommand("defaults", "read", "/Library/Preferences/com.apple.loginwindow", "autoLoginUser")
			if err != nil {
				return "", nil
			}
			return strings.TrimSpace(out), nil
		},
	}
}

// icCommand runs one read-only command under icProbeTimeout and returns its
// standard output.
func icCommand(name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), icProbeTimeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, name, args...).Output()
	if err != nil {
		return string(out), fmt.Errorf("%s: %w", name, err)
	}
	return string(out), nil
}

// probeBridge reads `ifconfig bridge0`; ifconfig saying the interface does not
// exist is errNoBridge.
func probeBridge() (install.BridgeState, error) {
	ctx, cancel := context.WithTimeout(context.Background(), icProbeTimeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, "ifconfig", install.InterconnectBridge).CombinedOutput()
	if err != nil {
		if strings.Contains(string(out), "does not exist") {
			return install.BridgeState{}, errNoBridge
		}
		return install.BridgeState{}, fmt.Errorf("ifconfig %s: %w", install.InterconnectBridge, err)
	}
	return install.ParseBridgeIfconfig(out), nil
}

// pingAll pings every address once, concurrently, and returns the round trip of
// each one that answered.
func pingAll(addrs []netip.Addr) map[netip.Addr]time.Duration {
	out := make(map[netip.Addr]time.Duration, len(addrs))
	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, a := range addrs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), (icPingTimeout+1)*time.Second)
			defer cancel()
			raw, err := exec.CommandContext(ctx, "ping", "-c", "1", "-t", fmt.Sprint(icPingTimeout), "-q", a.String()).Output()
			if err != nil {
				return
			}
			if d, ok := parsePingRTT(string(raw)); ok {
				mu.Lock()
				out[a] = d
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	return out
}

// dialNetd opens and closes a connection to netd's socket, sending nothing.
func dialNetd() error {
	conn, err := net.DialTimeout("unix", wire.DefaultSocketPath, 2*time.Second)
	if err != nil {
		return err
	}
	return conn.Close()
}

// probeICCluster reads this node's interconnect view from the apiserver: its
// Node (by host name), the desired annotation the server writes there, its
// member state when this credential may read the Interconnect, and the pods
// on it holding an interconnect address.
func probeICCluster() (icCluster, error) {
	ctx, cancel := context.WithTimeout(context.Background(), icProbeTimeout)
	defer cancel()
	euid := os.Geteuid()
	role, _ := installedRole()
	kube, _, err := newStatusKube(statusKubeInputsFor(role, statusPaths(statusWorkDir(euid, lookupServiceUID()))))
	if err != nil {
		return icCluster{}, err
	}
	nodes, err := kube.Nodes(ctx)
	if err != nil {
		return icCluster{}, err
	}
	node, ok := status.PickNode(nodes, hostnameOrEmpty())
	if !ok {
		return icCluster{}, fmt.Errorf("no node named for this Mac's host name %q", hostnameOrEmpty())
	}
	view := icCluster{Node: node.Name}
	if raw, ok := node.Annotations[netv1alpha1.AnnotationInterconnectDesired]; ok {
		_, derr := netv1alpha1.ParseInterconnectDesired(raw)
		view.Desired = derr == nil
	}
	// A worker's node credential may not read the Interconnect; that leaves
	// the member state unknown, which is not an error here.
	if ic, err := status.ReadInterconnect(ctx, kube); err == nil && ic != nil {
		for _, m := range ic.Status.Members {
			if m.Node == node.Name {
				view.MemberState = m.State
			}
		}
	}
	pods, err := kube.Pods(ctx)
	if err != nil {
		return icCluster{}, err
	}
	for _, p := range status.InterconnectPods(pods) {
		if p.Node == node.Name {
			view.Pods = append(view.Pods, p)
		}
	}
	return view, nil
}

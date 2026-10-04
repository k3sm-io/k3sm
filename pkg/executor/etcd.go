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

package executor

import (
	"net"
	"strconv"

	"k3sm.io/k3sm/pkg/certs"
)

// The embedded-etcd HA posture: one etcd member per server, run as a supervised child
// built from the pinned wrapper module (etcdstage.go), the apiserver pointed at the
// LOCAL member over mutual TLS. Peers reach each other on the node's LAN address under
// the dedicated etcd peer CA; the client API listens on loopback only, so no pod (and
// no LAN host) can dial it.

// etcdTokenPinChars is how many hex characters of the cluster CA pin the
// --initial-cluster-token carries. The token separates one cluster's members from
// another's at bootstrap; it is not an authentication control (peer mTLS is).
const etcdTokenPinChars = 16

// etcdArgsInput is everything etcdArgs renders from. It is a plain value so the argv
// is a pure function, table-tested without a work dir, a CA or a child process.
type etcdArgsInput struct {
	// Name is the member name, DataDir its data directory.
	Name, DataDir string
	// ClientPort is the loopback client listener (Config.KinePort); PeerPort and
	// PeerIP the peer listener; MetricsPort the loopback metrics listener.
	ClientPort, PeerPort, MetricsPort int
	PeerIP                            string
	// ClusterCAPin is the cluster CA's PinHash; the initial-cluster token derives
	// from it.
	ClusterCAPin string
	// Paths names the etcd PKI files.
	Paths certs.EtcdPaths
	// MemberExists reports a restart: the data dir already holds a member, so no
	// initial-cluster flag is rendered.
	MemberExists bool
	// Role, InitialCluster and Reset are EtcdConfig's.
	Role           EtcdRole
	InitialCluster string
	Reset          bool
	// HeartbeatMS / ElectionMS, when non-zero, set --heartbeat-interval and
	// --election-timeout. Zero omits both (upstream's defaults); only tests that
	// run several members on one loaded host set them.
	HeartbeatMS, ElectionMS int
}

// etcdArgsInputFor builds etcdArgs' input from a defaulted Config (Etcd non-nil), the
// cluster CA pin, and whether the member already exists.
func etcdArgsInputFor(cfg Config, clusterCAPin string, memberExists bool) etcdArgsInput {
	e := cfg.Etcd
	return etcdArgsInput{
		Name:           e.Name,
		DataDir:        EtcdDataDir(cfg.WorkDir),
		ClientPort:     cfg.KinePort,
		PeerPort:       e.PeerPort,
		MetricsPort:    e.MetricsPort,
		PeerIP:         e.PeerIP,
		ClusterCAPin:   clusterCAPin,
		Paths:          certs.EtcdCertPaths(cfg.WorkDir),
		MemberExists:   memberExists,
		Role:           e.Role,
		InitialCluster: e.InitialCluster,
		Reset:          e.Reset,
	}
}

// etcdClientURL is the member's loopback client URL: what it listens on, what it
// advertises, and what the apiserver and the admin client dial.
func etcdClientURL(port int) string {
	return "https://" + net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
}

// etcdPeerURL is a member's peer URL on its node IP.
func etcdPeerURL(ip string, port int) string {
	return "https://" + net.JoinHostPort(ip, strconv.Itoa(port))
}

// etcdClusterToken derives --initial-cluster-token from the cluster CA pin.
// Cert rotation over the existing CA keeps the pin invariant, so a live cluster's
// token never changes.
func etcdClusterToken(pin string) string {
	if len(pin) > etcdTokenPinChars {
		pin = pin[:etcdTokenPinChars]
	}
	return "k3sm-" + pin
}

// etcdArgs renders the etcd member's argv. Pure.
//
// Client traffic is TLS on loopback only (--client-cert-auth, the etcd server CA);
// peer traffic is TLS on the node IP (--peer-client-cert-auth, the etcd peer CA);
// metrics are plain HTTP on loopback only. The three --initial-cluster* flags are a
// FIRST-BOOT concern and are rendered only when no member exists yet: an init member
// starts a new cluster of itself, a joining member starts `existing` with the set the
// member route returned. --force-new-cluster appears only under Reset.
//
// Deliberately never rendered: --auto-tls / --peer-auto-tls (self-signed, unpinned),
// any http:// client or peer URL, any non-loopback client URL,
// --listen-client-http-urls, --enable-v2 and --enable-pprof.
func etcdArgs(in etcdArgsInput) []string {
	client := etcdClientURL(in.ClientPort)
	peer := etcdPeerURL(in.PeerIP, in.PeerPort)
	args := []string{
		"--name", in.Name,
		"--data-dir", in.DataDir,
		"--listen-client-urls", client,
		"--advertise-client-urls", client,
		"--listen-peer-urls", peer,
		"--initial-advertise-peer-urls", peer,
	}
	if !in.MemberExists {
		initial, state := in.Name+"="+peer, "new"
		if in.Role == EtcdJoin {
			initial, state = in.InitialCluster, "existing"
		}
		args = append(args,
			"--initial-cluster", initial,
			"--initial-cluster-state", state,
			"--initial-cluster-token", etcdClusterToken(in.ClusterCAPin),
		)
	}
	args = append(args,
		"--cert-file", in.Paths.ServerClientCert,
		"--key-file", in.Paths.ServerClientKey,
		"--trusted-ca-file", in.Paths.ServerCACert,
		"--client-cert-auth=true",
		"--peer-cert-file", in.Paths.PeerServerClientCert,
		"--peer-key-file", in.Paths.PeerServerClientKey,
		"--peer-trusted-ca-file", in.Paths.PeerCACert,
		"--peer-client-cert-auth=true",
		"--listen-metrics-urls", "http://"+net.JoinHostPort("127.0.0.1", strconv.Itoa(in.MetricsPort)),
		"--logger", "zap",
		"--log-outputs", "stderr",
	)
	if in.HeartbeatMS > 0 && in.ElectionMS > 0 {
		args = append(args,
			"--heartbeat-interval", strconv.Itoa(in.HeartbeatMS),
			"--election-timeout", strconv.Itoa(in.ElectionMS),
		)
	}
	if in.Reset {
		args = append(args, "--force-new-cluster")
	}
	return args
}

// apiServerDatastoreArgs renders the apiserver's datastore flags. The kine posture
// renders exactly `--etcd-servers http://127.0.0.1:<KinePort>`, byte-identical to the
// argv before the etcd posture existed. The etcd posture points at the local member
// over TLS and presents the etcd client identity (client.crt, clientAuth only, from
// the etcd server CA) — the k3s shape: each apiserver talks to its own member only.
func apiServerDatastoreArgs(cfg Config) []string {
	if cfg.Etcd == nil {
		return []string{"--etcd-servers", "http://127.0.0.1:" + strconv.Itoa(cfg.KinePort)}
	}
	p := certs.EtcdCertPaths(cfg.WorkDir)
	return []string{
		"--etcd-servers", etcdClientURL(cfg.KinePort),
		"--etcd-cafile", p.ServerCACert,
		"--etcd-certfile", p.ClientCert,
		"--etcd-keyfile", p.ClientKey,
	}
}

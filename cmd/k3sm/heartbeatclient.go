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
	"net/http"
	"time"

	utilnet "k8s.io/apimachinery/pkg/util/net"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"k3sm.io/darwin-net/pkg/tcpseg"
)

// heartbeatTiming is the set of bounds on the client a node's two liveness
// writes (the node-status update and the Lease renewal) go through.
type heartbeatTiming struct {
	// request bounds one apiserver round trip, end to end.
	request time.Duration
	// dial bounds the TCP connect of a new connection.
	dial time.Duration
	// handshake bounds the TLS handshake of a new connection.
	handshake time.Duration
	// readIdle is how long the connection may go without reading a frame
	// before the client sends an HTTP/2 PING (http.HTTP2Config.SendPingTimeout,
	// the x/net ReadIdleTimeout the kubelet's client sets).
	readIdle time.Duration
	// ping is how long that PING may go unanswered before the connection is
	// closed, so the next request dials a new one.
	ping time.Duration
}

// nodeHeartbeatTiming is the heartbeat client's bounds, chosen against the
// numbers the node lifecycle depends on:
//
//   - the Lease is renewed every 10 s (VK: 40 s lease duration x 0.25) and the
//     controller-manager marks a node NotReady once nothing has renewed it for
//     its node-monitor grace period, 50 s by default (40 s before Kubernetes
//     1.32);
//   - so one renewal must fail and the next must have a working connection well
//     inside that window. A 10 s request bound fails a stalled renewal before
//     the next one is due, and a 5 s idle + 5 s PING health check closes a
//     connection that went half-open (a Wi-Fi roam, a dropped NAT entry) about
//     10 s after its last frame, so the renewal after that dials a new
//     connection.
//
// Worst case after the path to the apiserver breaks and comes back at once: one
// renewal lost to the request bound, the connection closed by the health check,
// the next renewal on a fresh connection, about 20 to 30 s after the last
// successful one, inside the 50 s grace.
//
// The general node client (nodeAPIRequestTimeout, 90 s) is untouched: it
// carries the informers' watches, which a 10 s bound would cut.
var nodeHeartbeatTiming = heartbeatTiming{
	request:   10 * time.Second,
	dial:      5 * time.Second,
	handshake: 5 * time.Second,
	readIdle:  5 * time.Second,
	ping:      5 * time.Second,
}

// heartbeatRESTConfig derives the heartbeat client's config from the node's
// own: the same apiserver and credentials, the request bound, and a transport
// of its own built here.
//
// The transport is built rather than left to client-go for two reasons. First,
// client-go shares one transport (and so one HTTP/2 connection) between every
// client built from equal TLS settings, so without it the heartbeat would ride
// the same connection as every informer and fail with it. Second, client-go
// takes its HTTP/2 health-check timings from environment variables (30 s idle,
// 15 s PING by default); a node's heartbeat needs them shorter and needs them
// to be constants, not an environment knob.
//
// The dialer sets no local address, so every new connection takes the source
// address the kernel picks at dial time: after a roam to a new Wi-Fi address
// the redial leaves from the new one.
//
// base is not modified.
func heartbeatRESTConfig(base *rest.Config, tm heartbeatTiming) (*rest.Config, error) {
	tlsCfg, err := rest.TLSConfigFor(base)
	if err != nil {
		return nil, fmt.Errorf("heartbeat client tls: %w", err)
	}
	proxy := base.Proxy
	if proxy == nil {
		proxy = utilnet.NewProxierWithNoProxyCIDR(http.ProxyFromEnvironment)
	}
	t := &http.Transport{
		Proxy: proxy,
		// Segment-clamped like every other dial this node makes toward the mesh
		// (tcpseg). A kubeconfig-loaded config never carries a custom Dial, so
		// there is none to preserve.
		DialContext:         (&tcpseg.Dialer{Timeout: tm.dial, KeepAlive: 15 * time.Second}).DialContext,
		TLSClientConfig:     tlsCfg,
		TLSHandshakeTimeout: tm.handshake,
		ForceAttemptHTTP2:   true,
		MaxIdleConnsPerHost: 4,
		IdleConnTimeout:     90 * time.Second,
		HTTP2: &http.HTTP2Config{
			SendPingTimeout: tm.readIdle,
			PingTimeout:     tm.ping,
		},
	}
	cfg := rest.CopyConfig(base)
	// The TLS material now lives in the transport; client-go refuses a custom
	// transport alongside TLS options, and would otherwise build its own.
	cfg.TLSClientConfig = rest.TLSClientConfig{}
	cfg.Transport = t
	cfg.Dial = nil
	cfg.Proxy = nil
	cfg.Timeout = tm.request
	return cfg, nil
}

// nodeHeartbeatClient returns the client a kubeconfig-loaded node (the agent,
// `k3sm node`) writes its status and Lease through, or nil for the server's
// in-process node, whose loopback client is left as it is.
func nodeHeartbeatClient(opts nodeOptions, restCfg *rest.Config) (kubernetes.Interface, error) {
	if opts.restConfig != nil {
		return nil, nil
	}
	cfg, err := heartbeatRESTConfig(restCfg, nodeHeartbeatTiming)
	if err != nil {
		return nil, err
	}
	cs, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("build heartbeat client: %w", err)
	}
	return cs, nil
}

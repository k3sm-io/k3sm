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

// Package ingresshost hosts darwin-net's L7 ingress datapath inside the `k3sm
// server` process (M10.3, SERVER-PROCESS-ONLY — multi-node ingress is a named
// follow-up): it assembles the ingress.RouteTable + SNI CertStore +
// class-filtered Watcher + Server, provisions the `k3sm` IngressClass
// (controller k3sm.io/ingress) and the canonical kube-system/k3sm-ingress
// LoadBalancer Service (the DECLARING SUBJECT the netd port authorizer checks
// a privileged 80/443 node-address bind against), and writes Ingress /
// LoadBalancer statuses.
//
// # TLS Secret discipline (SECURITY-BINDING)
//
// The Watcher surfaces tls[] Secret NAMES only; this package fetches each one
// by a targeted Secrets(ns).Get — deliberately NO Secret informer/lister (the
// pkg/provider resolver.go imagePullSecret precedent), so the control plane
// never caches the cluster's Secrets. A Secret whose type is not
// kubernetes.io/tls is rejected by name; parsing is in-memory via
// ingress.ParseKeyPair (errors carry the NAME, never data); rotation is an
// event-driven re-read on the next reconcile callback. Key bytes NEVER touch
// disk, logs, or object status — they live only in the in-process CertStore.
//
// # Listener honesty
//
// The Server binds the node's own InternalIP through the shared pkg/netbind
// seam (the netd helper when unprivileged — authorized because k3sm-ingress
// declares 80/443 — or directly as root). The high-port mode
// (--ingress-http-port/--ingress-https-port) is an explicit config, never a
// silent fallback: a failed privileged bind surfaces as ingress.ErrBind, is
// logged, retried on a bounded schedule, and then gives up loudly while the
// server keeps running. Statuses are written only while the listeners are
// actually bound — never advertise a dead address.
package ingresshost

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
// LoadBalancer Service, and writes Ingress / LoadBalancer statuses.
//
// The canonical Service remains the declaring subject the netd port authorizer
// would check a privileged NODE-ADDRESS bind against, but since B116 the ingress
// listeners bind the WILDCARD in-process and never reach netd, so that authorizer
// branch is dormant BY CONFIGURATION (see pkg/netdsvc, B133) — not by removal.
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
// The Server binds Config.BindAddr — the WILDCARD in production — through the
// shared pkg/netbind seam, in-process: on Darwin a wildcard bind needs no
// privilege even at 80/443 (it is the SPECIFIC-address bind that returns EACCES,
// inverted from Linux), so no privileged binder is wired. The high-port mode
// (--ingress-http-port/--ingress-https-port) is an explicit config, never a
// silent fallback: a failed bind surfaces as ingress.ErrBind, is logged, retried
// on a bounded schedule, and then gives up loudly while the server keeps running.
//
// Statuses advertise Config.AdvertiseAddr (a DIFFERENT address from the bind —
// the wildcard cannot be advertised) and only while the listeners are actually
// bound; when they go away, or when no advertisable address could be derived,
// this host RETRACTS what it wrote (svclb.Retractable — one rule shared with
// svclb) rather than leaving a dead EXTERNAL-IP behind.
package ingresshost

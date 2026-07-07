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

// Package svclb is k3sm's klipper-lite LoadBalancer implementation (M10.3,
// closes B32): a server-side controller that, for every Service of type
// LoadBalancer, binds nodeIP:servicePort listeners and splices each accepted
// connection to the Service's ClusterIP VIP (a plain two-way TCP forward —
// the L4 Service proxy behind the VIP keeps EndpointSlice tracking, affinity,
// and mesh-egress discipline). It is DISTINCT from pkg/loadbalancer, the M6
// client-side HA apiserver LB.
//
// Privileged (<1024) ports bind through the shared pkg/netbind seam (the netd
// helper authorizes them because the Service ITSELF declares the port — the
// netdsvc node-address LoadBalancer rule); >=1024 ports bind directly.
//
// # Status honesty
//
// status.loadBalancer.ingress = [{ip: nodeIP}] is written ONLY once every TCP
// port's listener is actually bound — never advertise a dead address. An
// un-bindable port (conflict) leaves the status empty with a throttled Warn;
// a Service that loses its listeners has this node's IP cleared. UDP
// LoadBalancer ports are DEFERRED (the userspace splice is TCP-only today):
// they are skipped with a throttled Warn and do not gate the TCP ports'
// status. Services carrying IgnoreLabel (the canonical kube-system/
// k3sm-ingress, whose listeners the in-process ingress Server owns) are
// skipped entirely.
package svclb

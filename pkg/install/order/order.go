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

// Package order is the order the k3sm launchd jobs are started and stopped in.
//
// It is a leaf: it imports only the standard library, so the installer
// (pkg/install) and the root updater share one definition of the sequence
// without the updater importing the installer's launchd renderer or client-go.
//
// The order exists because launchd offers none. The data-volume mount
// (a oneshot, present only on a Mac with a declared data volume) runs first, so
// the daemons that refuse an unmounted data root find it mounted. netd runs
// next, because the node daemon dials netd's helper socket before it does
// anything else. The node daemon runs last: io.k3sm.server on a control plane,
// io.k3sm.agent on a joining worker, never both. Stopping walks the long-running
// jobs in reverse, the node daemon before the netd helper it drives; the oneshot
// has nothing to stop.
package order

// Reverse-DNS launchd labels of the k3sm jobs.
const (
	// NetdLabel is the root privileged-network helper LaunchDaemon.
	NetdLabel = "io.k3sm.netd"
	// ServerLabel is the control-plane LaunchDaemon (UserName=_k3sm).
	ServerLabel = "io.k3sm.server"
	// AgentLabel is the joining-worker LaunchDaemon (UserName=_k3sm).
	AgentLabel = "io.k3sm.agent"
	// DatavolLabel is the root data-volume mount LaunchDaemon, a oneshot.
	DatavolLabel = "io.k3sm.datavol"
)

// Role names which node daemon a Mac carries.
type Role int

const (
	// Server is a control-plane Mac; its node daemon is io.k3sm.server.
	Server Role = iota
	// Agent is a joining worker; its node daemon is io.k3sm.agent.
	Agent
)

// NodeLabel returns the label of the role's node daemon.
func (r Role) NodeLabel() string {
	if r == Agent {
		return AgentLabel
	}
	return ServerLabel
}

// Job is one launchd job in the order.
type Job struct {
	// Label is the job's launchd label.
	Label string
	// Oneshot is true for a job that runs and exits rather than staying up.
	Oneshot bool
}

// Start returns the jobs in the order they are started: the data-volume mount
// when dataVolume is true, then netd, then the role's node daemon.
func Start(r Role, dataVolume bool) []Job {
	jobs := make([]Job, 0, 3)
	if dataVolume {
		jobs = append(jobs, Job{Label: DatavolLabel, Oneshot: true})
	}
	return append(jobs, LongRunning(r)...)
}

// LongRunning returns the role's long-running jobs in start order: netd, then
// the node daemon.
func LongRunning(r Role) []Job {
	return []Job{{Label: NetdLabel}, {Label: r.NodeLabel()}}
}

// Stop returns the role's long-running jobs in the order they are stopped: the
// node daemon, then netd. It is LongRunning reversed.
func Stop(r Role) []Job {
	jobs := LongRunning(r)
	for i, j := 0, len(jobs)-1; i < j; i, j = i+1, j-1 {
		jobs[i], jobs[j] = jobs[j], jobs[i]
	}
	return jobs
}

// IsNodeDaemon reports whether label is a node daemon (server or agent), the
// job that waits for netd to answer before it starts.
func IsNodeDaemon(label string) bool { return label == ServerLabel || label == AgentLabel }

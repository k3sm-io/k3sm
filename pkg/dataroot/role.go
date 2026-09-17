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

package dataroot

// Role is which k3sm node a Mac is: the control plane, or a worker that joins
// one. It is a closed pair because a Mac is one or the other — the server IS a
// node (it runs its own Virtual Kubelet), so a machine carrying both daemons
// would register twice and fight itself over the same data root, the same run
// dir and the same netd helper.
//
// The empty Role is RoleServer, so every caller — and every install Config a
// test writes without thinking about roles — keeps describing the install k3sm
// has always performed.
//
// It lives in this leaf package rather than in the installer because the role
// is an ON-DISK FACT about a Mac, and the readers of on-disk facts are not all
// installers: `k3sm status` decides which daemon to probe from it, and the
// status package is a reporting leaf that must not pull the installer — and
// with it the sandbox, podnet and mesh stacks — in behind one enum. pkg/install
// re-exports the names, so its own callers are unaffected.
type Role string

const (
	// RoleServer is the control plane (io.k3sm.server). The default.
	RoleServer Role = "server"
	// RoleAgent is a joining worker (io.k3sm.agent) instead.
	RoleAgent Role = "agent"
)

// Other returns the role this one is not — the one whose daemon must not be on
// disk when this one is installed.
func (r Role) Other() Role {
	if r == RoleAgent {
		return RoleServer
	}
	return RoleAgent
}

// RoleFromPlists decides which k3sm node a Mac IS from the two node-daemon
// plists on disk, and whether it is installed at all. It is pure so the whole
// decision — including the two postures that are not a plain "one plist, one
// role" — is table-tested, and so every caller reaches the same verdict from
// the same two booleans.
//
// The disk is the only honest source. A running pid is not: the server daemon
// and the agent daemon are both `k3sm` processes under launchd, so a probe that
// asked the process table which one this Mac is would report "neither" on a Mac
// whose daemon is merely stopped, and would report a role from a crash-looping
// job that launchd is about to give up on. The plist is what `k3sm install`
// wrote and what `k3sm uninstall` removes, so it says what this Mac was set up
// to be regardless of what it is doing right now.
//
// Two postures decide the shape:
//
//   - BOTH plists present → RoleServer, installed. It is a posture install
//     refuses to create, so it only arises from a hand-edited
//     /Library/LaunchDaemons or an interrupted role change — and there the
//     control plane is the role a report must lead with, because it is the one
//     that owns the datastore. A caller that wants to SAY both are there still
//     can: it holds both booleans.
//   - NEITHER plist present → not installed, and the role returned is the zero
//     Role (RoleServer), which is what every uninstalled path already assumes.
//     The bool, not the role, is what a caller must branch on.
func RoleFromPlists(serverPresent, agentPresent bool) (Role, bool) {
	switch {
	case serverPresent:
		return RoleServer, true
	case agentPresent:
		return RoleAgent, true
	default:
		return RoleServer, false
	}
}

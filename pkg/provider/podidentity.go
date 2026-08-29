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

package provider

import (
	"log/slog"
	"os/user"
	"strconv"

	"k3sm.io/k3sm/pkg/install"
)

// PodExecutionUID reports the uid a pod that declares NO securityContext actually
// executes as on this node — the parameter the foreign-user admission ceiling is
// built from (pkg/policy.EnsureNoForeignUserAdmission). It is DELIBERATELY not a
// synonym for os.Geteuid() at the call site; see podExecutionUID for why the two
// diverge under a root server.
//
// The chain it summarises, from the authorities that own each link:
//
//   - the provider NEVER sets PodBox.uid/gid (translate.go builds no such field),
//     so runtimed's resolveCredential (runtimed/pkg/runtime/security.go) resolves
//     uid/gid from the pod/container securityContext ALONE;
//   - with every source zero it returns Credential{Drop: false}, and a non-Drop
//     credential means "the pod keeps the daemon's OWN identity, confined by
//     Seatbelt" (runtimed/pkg/supervisor/privdrop.go Credential doc + Validate);
//   - runtimed is embedded in this process (cmd/k3sm startNode drives it by direct
//     RPC), and the exec-shim runs the launch sequence at os.Geteuid() of that
//     process (runtimed/internal/execshim/launch_darwin.go).
//
// So a no-securityContext pod runs at THIS process's euid.
func PodExecutionUID(euid int) int64 {
	uid, why := podExecutionUID(euid, lookupUID)
	slog.Debug("resolved pod-execution uid", "uid", uid, "euid", euid, "source", why)
	if uid == 0 {
		slog.Warn("pods on this node execute as ROOT and the "+install.DefaultServiceUser+
			" service user does not resolve, so the foreign-user admission ceiling is pinned to uid 0: "+
			"a pod explicitly requesting runAsUser 0 is ADMITTED (it would run as root regardless), "+
			"and a pod requesting the service-user identity is REJECTED. Install k3sm (`sudo k3sm install`) "+
			"or run the server unprivileged for the shipped posture", "euid", euid)
	}
	return uid
}

// podExecutionUID is the testable core of PodExecutionUID. It returns the uid and
// a short human reason for it.
//
// Unprivileged server (the SHIPPED posture — the io.k3sm.server LaunchDaemon runs
// UserName=_k3sm, and `k3sm dev` runs as the developer): the daemon euid IS the pod
// execution uid, so it is used directly.
//
// Root server (`--network direct`, `sudo k3sm dev up --datapath`): a no-drop pod
// literally runs as uid 0, but pinning the ceiling to 0 would name ROOT as "the
// k3sm pod identity" — contradicting the policy's own message and every doc — while
// rejecting the one foreign identity this posture CAN honour (root may setuid, so a
// pod asking for the service user genuinely gets it). The service user is therefore
// the ceiling here, resolved BY NAME from install.DefaultServiceUser so the uid is
// never hard-coded.
//
// Root server with no service user (an uninstalled host running the server under
// sudo): there is no honest non-zero answer, so it falls back to the euid (0) and
// PodExecutionUID warns. A phantom uid would make the rejection message a lie.
func podExecutionUID(euid int, lookupUID func(name string) (int, error)) (int64, string) {
	if euid != 0 {
		return int64(euid), "the unprivileged daemon euid pods inherit"
	}
	if uid, err := lookupUID(install.DefaultServiceUser); err == nil && uid != 0 {
		return int64(uid), "the " + install.DefaultServiceUser + " service user"
	}
	return int64(euid), "the root daemon euid (no " + install.DefaultServiceUser + " service user)"
}

// lookupUID resolves a system user name to its numeric uid.
func lookupUID(name string) (int, error) {
	u, err := user.Lookup(name)
	if err != nil {
		return 0, err
	}
	return strconv.Atoi(u.Uid)
}

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

package status

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"k3sm.io/k3sm/pkg/dataroot"
	"k3sm.io/k3sm/pkg/executor"
)

// Alert is the structured answer to "what is wrong with this row and how do I
// fix it", carried by every row that needs attention (see NeedsAlert). It is
// written for a reader with no other context, a person in the app's Alerts tab
// or a model reading `k3sm alerts -o json`: the cause in plain words, the facts
// the collector saw, numbered fix steps, and the user documentation page that
// covers the failure. Row.Detail and Row.Remedy stay as they were, so a reader
// that predates Alert loses nothing.
type Alert struct {
	// Cause is one plain sentence: what is wrong, in user terms.
	Cause string `json:"cause"`
	// Evidence is the facts the collector saw: the row's detail sentence first,
	// then the wide facts that bear on it (the quoted log line, the last exit,
	// the file it read, the counts). Every entry has been through Redact.
	Evidence []string `json:"evidence"`
	// Fix is the ordered steps that repair the row. A step with no Command is
	// something to check or decide by hand.
	Fix []FixStep `json:"fix"`
	// Docs is the user documentation page and anchor that covers the failure,
	// relative to docs/user (for example "troubleshooting.md#the-ingest-registry").
	Docs string `json:"docs"`
	// Since is when the condition began, RFC 3339 in UTC, when the collector
	// knows it. Omitted otherwise.
	Since string `json:"since,omitempty"`

	// generic marks an alert built by genericAlert, the floor for a row mode no
	// writer knows. It is never encoded; a test fails on any failure path that
	// reaches it.
	generic bool
}

// FixStep is one step of an Alert's fix.
type FixStep struct {
	// Step says what the step does, in a sentence.
	Step string `json:"step"`
	// Command is the shell command that does it; omitted for a step done by hand.
	Command string `json:"command,omitempty"`
	// NeedsAdmin is whether the command needs an administrator (it runs under sudo).
	NeedsAdmin bool `json:"needsAdmin"`
}

// NeedsAlert reports whether a row carries an Alert: every row whose severity is
// warn, fail or unknown, and every needs-admin row (whose severity is skip, so
// it never moves the verdict, but whose answer this account could not read). A
// row that is ok carries none, and neither does a row that is skip for any other
// reason: "there is nothing here to check" (a worker's datastore, an etcd member
// that has not started) is not something to fix.
func NeedsAlert(r Row) bool {
	switch r.Severity {
	case SeverityWarn, SeverityFail, SeverityUnknown:
		return true
	}
	return r.State == StateNeedsAdmin
}

// alertContext is what an alert needs beyond its row: the report's clock (for
// Since), the role (a worker's rows read differently), and the stop marker (a
// daemon disabled by `k3sm stop` is fixed by `k3sm start`, not by launchctl).
type alertContext struct {
	now     time.Time
	role    dataroot.Role
	stopped *StoppedBy
}

// attachAlerts sets the Alert of every row that NeedsAlert, and clears it on
// every other row.
func attachAlerts(rows []Row, ac alertContext) {
	for i := range rows {
		rows[i].Alert = nil
		if NeedsAlert(rows[i]) {
			rows[i].Alert = alertFor(rows[i], ac)
		}
	}
}

// The user documentation anchors alerts point at, relative to docs/user. A test
// resolves every one against the headings of the page it names.
const (
	docsSudo             = "troubleshooting.md#checks-that-need-sudo"
	docsDaemon           = "troubleshooting.md#a-k3sm-daemon-is-not-running"
	docsStartup          = "troubleshooting.md#control-plane-startup-failure"
	docsCrashLoop        = "troubleshooting.md#the-crash-loop-breaker-tripped"
	docsStaged           = "troubleshooting.md#the-staged-control-plane-does-not-match-this-build"
	docsStopped          = "stop-start.md#a-stop-survives-reboot"
	docsInstall          = "install.md#one-time-admin-step"
	docsServerFlags      = "install.md#server-flags-across-a-reinstall"
	docsJoin             = "multi-node.md#joining-an-agent"
	docsAddressChange    = "multi-node.md#if-a-nodes-address-changes"
	docsJoinFails        = "troubleshooting.md#multi-node-join-fails"
	docsNodeNotReady     = "troubleshooting.md#a-node-is-not-ready"
	docsStuckTerminating = "troubleshooting.md#a-node-went-offline-and-pods-are-stuck-terminating"
	docsPods             = "troubleshooting.md#stuck-or-crash-looping-pods"
	docsInterconnect     = "troubleshooting.md#the-thunderbolt-interconnect-is-not-used"
	docsNotMounted       = "troubleshooting.md#the-data-root-is-declared-but-not-mounted"
	docsWrongOwner       = "troubleshooting.md#the-data-root-has-the-wrong-owner"
	docsDataVolume       = "storage.md#the-data-volume"
	docsDatastore        = "backup-restore.md#what-holds-the-state"
	docsEtcd             = "troubleshooting.md#the-etcd-member-is-unhealthy"
	docsServingCert      = "certificates.md#what-rotation-is"
	docsAdminKubeconfig  = "certificates.md#upgrading-a-single-node-server"
	docsRequestHeader    = "certificates.md#the-request-header-ca"
	docsMeshClaims       = "ha.md#mesh-addresses-and-pod-ranges"
	docsServices         = "troubleshooting.md#a-service-routes-to-the-wrong-backends"
	docsRegistry         = "troubleshooting.md#the-ingest-registry"
	docsUpdate           = "upgrade.md#checking-for-an-update"
	docsKubeconfig       = "kubectl-access.md#bundled-path"
	docsRuntimed         = "troubleshooting.md#the-runtime-daemon-is-unhealthy"
	docsDNS              = "troubleshooting.md#the-node-resolver-does-not-answer"
	docsShadow           = "troubleshooting.md#host-binaries-changed-after-a-macos-update"
)

// alertFor builds the alert of one row that NeedsAlert. Each row has its own
// writer, keyed by name, which reads the row's state, detail and remedy to tell
// its failure modes apart; a row no writer knows, or a mode its writer does not,
// still gets an alert built from its detail and remedy (genericAlert), so the
// NeedsAlert contract holds for every row a later change adds.
func alertFor(r Row, ac alertContext) *Alert {
	var a *Alert
	switch r.Name {
	case RowInstall:
		a = installAlert(r)
	case RowNetd, RowServer, RowAgent:
		a = daemonAlert(r, ac)
	case RowDatavol:
		a = datavolAlert(r)
	case RowServerArgs, RowSettings:
		a = argsAlert(r)
	case RowAPIServer:
		a = apiserverAlert(r, ac)
	case RowNode:
		a = nodeAlert(r, ac)
	case RowHeartbeat:
		a = heartbeatAlert(r, ac)
	case RowWorkloads:
		a = workloadsAlert(r, ac)
	case RowInterconnect:
		a = interconnectAlert(r)
	case RowDataRoot:
		a = dataRootAlert(r)
	case RowPreVolume:
		a = preVolumeAlert(r)
	case RowDatastore:
		a = datastoreAlert(r)
	case RowUpdate:
		a = updateAlert(r)
	case RowEtcd:
		a = etcdAlert(r)
	case RowServingCert:
		a = servingCertAlert(r)
	case RowAdminKubeconfig:
		a = adminKubeconfigAlert(r)
	case RowRequestHeader:
		a = requestHeaderAlert(r)
	case RowMeshClaims:
		a = meshClaimsAlert(r)
	case RowServices:
		a = servicesAlert(r)
	case RowIngestRegistry:
		a = registryAlert(r)
	case RowKubeconfig:
		a = kubeconfigAlert(r, ac)
	case RowRuntimed:
		a = runtimedAlert(r)
	case RowDNS:
		a = dnsAlert(r)
	case RowNodeResolver:
		a = nodeResolverAlert(r)
	case RowShadowShells:
		a = shadowAlert(r)
	}
	if a == nil {
		a = genericAlert(r)
	}
	a.Evidence = evidence(r)
	if len(a.Fix) == 0 {
		a.Fix = []FixStep{reportAsAdmin()}
	}
	return a
}

// alert is the constructor every writer uses: the cause, the docs anchor, and
// the steps.
func alert(cause, docs string, fix ...FixStep) *Alert {
	return &Alert{Cause: cause, Docs: docs, Fix: fix}
}

// genericAlert is the alert of a row or mode no writer knows: the detail is the
// cause and the remedy the steps. It is the floor, not the design; the test
// that drives every row's failure paths fails on any path that lands here.
func genericAlert(r Row) *Alert {
	a := alert(sentence(r.Name+": "+r.Detail), "troubleshooting.md#start-with-k3sm-status", remedySteps(r.Remedy)...)
	a.generic = true
	return a
}

// ---- steps -----------------------------------------------------------------

// cmd is a step that runs a command.
func cmd(step, command string) FixStep {
	return FixStep{Step: step, Command: command, NeedsAdmin: strings.HasPrefix(command, "sudo ")}
}

// manual is a step done by hand: a check, a decision, or a command that runs on
// another Mac and is named in the step's own words.
func manual(step string) FixStep { return FixStep{Step: step} }

// reportAsAdmin is the step every needs-admin and unreadable row ends with.
func reportAsAdmin() FixStep {
	return cmd("Run the report as an administrator, which can read what this account cannot", needsAdminRemedy)
}

// remedySteps turns a Remedy (one command per line, an optional "   # note"
// after it) into steps. A line that is not a command (a sentence, or a line that
// is only a "# note") becomes a manual step. Note-only lines go first: they are
// the caveats a reader must see before running anything.
func remedySteps(remedy string) []FixStep {
	var notes, steps []FixStep
	for _, line := range strings.Split(remedy, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "#") {
			notes = append(notes, manual(sentence(strings.TrimSpace(strings.TrimPrefix(line, "#")))))
			continue
		}
		command, note, _ := strings.Cut(line, "   # ")
		command, note = strings.TrimSpace(command), strings.TrimSpace(note)
		if !isCommand(command) {
			steps = append(steps, manual(sentence(line)))
			continue
		}
		step := describe(command)
		if note != "" {
			step += " (" + note + ")"
		}
		steps = append(steps, cmd(step, command))
	}
	return append(notes, steps...)
}

// commandPrefixes are the words a remedy line that is a command starts with.
var commandPrefixes = []string{"sudo ", "k3sm ", "kubectl ", "curl ", "launchctl "}

// isCommand reports whether a remedy line is a shell command rather than prose.
func isCommand(s string) bool {
	for _, p := range commandPrefixes {
		if strings.HasPrefix(s, p) {
			return true
		}
	}
	return false
}

// describers name what a remedy command does, matched in order (the first whose
// match function accepts the command wins), so a more specific shape is listed
// before the general one it shares a prefix with.
var describers = []struct {
	match func(string) bool
	step  string
}{
	{func(s string) bool { return strings.Count(s, "kickstart") > 1 }, "Restart netd and this Mac's node daemon so they reopen the data root"},
	{func(s string) bool { return strings.Contains(s, "diskutil mount") }, "Remove the shadow directory and mount the volume over the data root by hand"},
	{prefix("sudo launchctl kickstart -k system/"), "Restart the daemon"},
	{prefix("sudo launchctl enable system/"), "Re-enable the daemon in launchd"},
	{prefix("sudo k3sm install --role agent"), "Install this Mac as a worker with that token"},
	{prefix("sudo k3sm install --data-volume"), "Re-run the install with the data volume, which loads its mount job"},
	{prefix("sudo k3sm install"), "Re-run the install, which is idempotent and puts back what is missing"},
	{prefix("sudo k3sm status"), "Run the report as an administrator, which can read what this account cannot"},
	{prefix("sudo k3sm datavol mount"), "Mount the data volume"},
	{prefix("sudo k3sm update check"), "Check for a new release now"},
	{prefix("k3sm update check"), "Check for a new release now"},
	{prefix("sudo k3sm server --clear-crashloop"), "Clear the crash-loop record; the parked daemon restarts itself"},
	{prefix("sudo tail -n "), "Read the recorded failures and their log tails"},
	{prefix("sudo rm -r "), "Delete the leftover copy"},
	{prefix("k3sm status logs "), "Read the daemon's log for the failure"},
	{prefix("k3sm status"), "Read the report"},
	{prefix("k3sm token create"), "Mint a join token"},
	{prefix("k3sm kubeconfig --write"), "Write the admin kubeconfig into ~/.kube/config"},
	{prefix("k3sm kubectl get pods"), "List the pods to find the ones that are pending or failed"},
	{prefix("k3sm kubectl patch interconnect"), "Exclude the out-of-range node from the interconnect"},
	{prefix("k3sm image prune"), "Reclaim the space unused images take"},
	{prefix("k3sm datavol status"), "See what is using the volume"},
	{prefix("k3sm doctor"), "Run the preflight checks"},
	{prefix("kubectl taint node "), "Mark the node out of service so the pods on it can finish terminating"},
	{prefix("kubectl delete pod "), "Force-delete the pod left on the deleted node"},
	{prefix("curl -fsSL https://k3sm.io/install.sh"), "Upgrade k3sm with the install script"},
}

func prefix(p string) func(string) bool {
	return func(s string) bool { return strings.HasPrefix(s, p) }
}

// describe names what a remedy command does.
func describe(command string) string {
	for _, d := range describers {
		if d.match(command) {
			return d.step
		}
	}
	return "Run this command"
}

// sentence capitalises the first letter and ends the text with a full stop.
func sentence(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return s
	}
	s = strings.ToUpper(s[:1]) + s[1:]
	if !strings.HasSuffix(s, ".") {
		s += "."
	}
	return s
}

// ---- evidence and since ----------------------------------------------------

// evidenceKeys are the wide facts an alert quotes, in the order it quotes them.
// They are the ones that bear on a failure: what was read, what launchd said,
// the quoted log line, the counts and ages. The others (pod tables, verbose
// readiness bodies) stay in the wide view.
var evidenceKeys = []string{
	"label", "plist", "pid", "runs", "last-exit", "log-path", "crash-loop", "leader-lost",
	"credential", "credential-expires", "credential-dir",
	"server", "tls",
	"node", "statusAgeSeconds", "leaseAgeSeconds",
	"stuckNode", "stuckPods", "deletedNode", "deletedNodePods",
	"declared", "declared-by", "mounted", "owner", "volume", "quota", "used", "used-source",
	"path", "record", "recorded", "checked", "latest",
	"cert", "ca", "pin", "trusted", "ha-role", "kubeconfig",
	"vip", "name", "answer", "tcp",
	"port", "since", "runtime", "version", "api", "source",
}

// evidence is the row's detail followed by the wide facts in evidenceKeys, and
// the quoted log line with its repeat count. Every value in a row has already
// been through Redact; the alert adds no text the row did not carry.
func evidence(r Row) []string {
	out := []string{r.Detail}
	if line := r.Wide["log"]; line != "" {
		if n := r.Wide["log-repeats"]; n != "" && n != "1" {
			line += " (×" + n + ")"
		}
		out = append(out, "last log line: "+line)
	}
	if cp := r.Wide["cp-binaries"]; cp != "" && cp != r.Detail && !strings.HasPrefix(cp, "unknown-staged") && !strings.Contains(r.Detail, cp) {
		out = append(out, "cp-binaries: "+cp)
	}
	for _, k := range evidenceKeys {
		if v, ok := r.Wide[k]; ok && v != "" {
			out = append(out, k+": "+v)
		}
	}
	return out
}

// rfc3339InText finds an RFC 3339 timestamp inside a sentence.
var rfc3339InText = regexp.MustCompile(`\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})`)

// sinceIn returns the timestamp that follows marker in text, in UTC RFC 3339,
// or "" when there is none.
func sinceIn(text, marker string) string {
	i := strings.Index(text, marker)
	if i < 0 {
		return ""
	}
	return sinceText(rfc3339InText.FindString(text[i+len(marker):]))
}

// sinceText normalises an RFC 3339 timestamp to UTC, or returns "" when it does
// not parse.
func sinceText(s string) string {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

// ---- the writers -----------------------------------------------------------

func installAlert(r Row) *Alert {
	switch r.State {
	case StateAbsent:
		return alert("k3sm is not installed on this Mac: the binary, the launcher and the LaunchDaemons are all missing.",
			docsInstall, remedySteps(r.Remedy)...)
	case StatePartial:
		return alert("The k3sm install on this Mac is incomplete: some of its files are missing, so its daemons may not run or start at boot.",
			docsInstall, remedySteps(r.Remedy)...)
	}
	return nil
}

// daemonWho names a node daemon row's subject and what its failure costs.
func daemonWho(name string) (who, effect string) {
	switch name {
	case RowNetd:
		return "The network helper (netd)", "pods on this Mac lose their network and the node resolver is not maintained"
	case RowAgent:
		return "The worker daemon", "this Mac is not working as a node of its cluster"
	default:
		return "The control-plane daemon", "the cluster's control plane is not serving"
	}
}

func daemonAlert(r Row, ac alertContext) *Alert {
	if a := agentCredentialAlert(r); a != nil {
		return a
	}
	who, effect := daemonWho(r.Name)
	steps := remedySteps(r.Remedy)
	switch crash := r.Wide["crash-loop"]; {
	case crash == "tripped":
		return crashLoopParkedAlert(r)
	case r.Severity == SeverityWarn && r.State == StateRunning && r.Detail == r.Wide["cp-binaries"]:
		return stagedAlert(r)
	case crash == "restarting" && strings.HasPrefix(r.Detail, "lost the leader lease"):
		return alert("This server keeps losing its leader lease and restarting, which points at etcd quorum or an overloaded apiserver or datastore.",
			docsEtcd, append([]FixStep{manual("Check the etcd and apiserver rows on every server")}, steps...)...)
	case crash == "restarting" && r.State == StateCrashLoop:
		return alert("The control plane keeps failing and being restarted; if it goes on, the crash-loop breaker parks the daemon and the cluster stops serving.",
			docsStartup, steps...)
	}
	if ac.stopped != nil && (r.State == StateDisabled || r.State == StateStopped) {
		by := ac.stopped.Actor
		if ac.stopped.Reason != "" {
			by += ": " + ac.stopped.Reason
		}
		a := alert(fmt.Sprintf("k3sm was stopped on this Mac on purpose (by %s), so %s stays off, even across a reboot, until it is started again.", by, lowerFirst(who)),
			docsStopped, cmd("Start k3sm again", "sudo k3sm start"))
		if !ac.stopped.At.IsZero() {
			a.Since = ac.stopped.At.UTC().Format(time.RFC3339)
		}
		return a
	}
	switch r.State {
	case StateUnknown:
		if r.Severity == SeverityWarn {
			return alert(fmt.Sprintf("launchd says %s is running, but its process is gone, so %s.", lowerFirst(who), effect), docsDaemon, steps...)
		}
		return alert(fmt.Sprintf("launchd's answer about %s could not be read, so whether it runs is unknown.", lowerFirst(who)), docsDaemon, steps...)
	case StateCrashLoop:
		return alert(fmt.Sprintf("%s keeps exiting and launchd keeps restarting it, so %s.", who, effect), daemonDocs(r.Name), steps...)
	case StateFailed:
		return alert(fmt.Sprintf("%s exited with an error and is not running, so %s.", who, effect), daemonDocs(r.Name), steps...)
	case StateStopped:
		return alert(fmt.Sprintf("%s is loaded in launchd but not running, so %s.", who, effect), docsDaemon, steps...)
	case StateDisabled:
		return alert(fmt.Sprintf("%s is disabled in launchd, so it does not run, not even at boot, and %s.", who, effect), docsDaemon, steps...)
	case StateNotLoaded:
		return alert(fmt.Sprintf("%s is not loaded in launchd, so nothing runs it and %s.", who, effect), docsDaemon, steps...)
	}
	return nil
}

// daemonDocs is where a failing daemon's reader goes: the control plane's own
// startup section for the server, the generic daemon section otherwise.
func daemonDocs(name string) string {
	if name == RowServer {
		return docsStartup
	}
	return docsDaemon
}

func lowerFirst(s string) string {
	if s == "" {
		return s
	}
	return strings.ToLower(s[:1]) + s[1:]
}

// agentCredentialAlert is the worker row's alert when the daemon is healthy and
// the node credential is not: the one case launchd cannot see.
func agentCredentialAlert(r Row) *Alert {
	if r.Name != RowAgent {
		return nil
	}
	steps := remedySteps(r.Remedy)
	switch r.State {
	case StateWaiting:
		return alert("The worker daemon is running but this Mac has never joined a cluster: it holds no node credential, so it is not a node yet.",
			docsJoin, steps...)
	case StateExpired:
		a := alert("The worker's node credential has expired, so this Mac can no longer authenticate to the control plane and its node goes NotReady.",
			docsJoin, steps...)
		a.Since = r.Wide["credential-expires"]
		return a
	case StateCorrupt:
		return alert("The node credential stored on this Mac does not parse, so the worker cannot authenticate to the control plane.",
			docsJoin, steps...)
	case StateAddressMismatch:
		return alert("This node's kubelet serving certificate names a different address than the one the cluster assigned it, so kubectl logs, exec and port-forward against this node fail the TLS check.",
			docsAddressChange, steps...)
	case StateRunning:
		if r.Severity == SeverityUnknown {
			return alert("This account may not read the worker's node credential, so whether this Mac is joined could not be checked; the daemon itself is running.",
				docsSudo, steps...)
		}
	}
	return nil
}

// crashLoopParkedAlert is the server row whose crash-loop breaker tripped.
func crashLoopParkedAlert(r Row) *Alert {
	clear := cmd("Clear the crash-loop record; the parked daemon restarts itself", "sudo k3sm server --clear-crashloop")
	var a *Alert
	switch {
	case strings.Contains(r.Detail, "leader-lease loss"):
		a = alert("The control-plane daemon parked itself after losing its leader lease again and again: it is running but serves nothing, and it is no longer an etcd voter.",
			docsCrashLoop,
			cmd("Check etcd quorum and apiserver health; run this on every server", needsAdminRemedy),
			clear)
	case strings.Contains(r.Detail, "cannot heal on retry"):
		first, _, _ := strings.Cut(r.Remedy, "; then sudo k3sm server --clear-crashloop")
		fix := manual(sentence(first))
		if isCommand(first) {
			fix = cmd("Fix the fault the control plane reported", first)
		}
		a = alert("The control plane never came up, with a fault that does not heal on retry, so the crash-loop breaker parked the daemon: it is running but serves nothing.",
			docsCrashLoop, fix, clear)
	default:
		cause := "A control-plane component crashed again and again, so the crash-loop breaker parked the daemon: it is running but serves nothing."
		if strings.Contains(r.Detail, "never came up") {
			cause = "The control plane failed to come up again and again, so the crash-loop breaker parked the daemon: it is running but serves nothing."
		}
		steps := []FixStep{}
		if path := crashRecordPath(r.Remedy); path != "" {
			steps = append(steps, cmd("Read the recorded failures and their log tails, and fix the fault they name", "sudo tail -n 50 "+path))
		}
		steps = append(steps, cmd("Read the daemon's log for the failure", "k3sm status logs "+RowServer), clear)
		a = alert(cause, docsCrashLoop, steps...)
	}
	a.Since = sinceIn(r.Detail, "tripped at ")
	return a
}

// crashRecordPath is the crash-loop record a parked remedy names.
func crashRecordPath(remedy string) string {
	const marker = "named in "
	i := strings.Index(remedy, marker)
	if i < 0 {
		return ""
	}
	rest := remedy[i+len(marker):]
	if j := strings.IndexAny(rest, "; "); j >= 0 {
		rest = rest[:j]
	}
	return rest
}

// stagedAlert is the server row whose staged control-plane binaries are not the
// ones this build pins.
func stagedAlert(r Row) *Alert {
	switch r.Remedy {
	case executor.NewerControlPlaneRemedy:
		return alert("The staged control-plane binaries are newer than this k3sm build, so the daemon refuses the downgrade and keeps serving the newer set.",
			docsStaged, manual("Install a k3sm release whose control-plane version is at or above the staged one"))
	default:
		return alert("k3sm was upgraded but the control-plane binaries were not re-staged, so the old Kubernetes control plane is still serving.",
			docsStaged,
			cmd("Re-run the install so the staged payload carries this build's control plane; the next boot re-seeds it", "sudo k3sm install"))
	}
}

func datavolAlert(r Row) *Alert {
	steps := remedySteps(r.Remedy)
	switch r.State {
	case StateMissing:
		return alert("The data volume's mount job is not loaded, so nothing mounts the volume at boot and the data root comes up unmounted after a restart.", docsDataVolume, steps...)
	case StateDisabled:
		return alert("The data volume's mount job is disabled in launchd, so the volume is not mounted at boot.", docsDataVolume, steps...)
	case StateFailed:
		return alert("The data volume's mount job failed on its last run, so the volume may not be mounted over the data root.", docsDataVolume, steps...)
	case StateUnknown:
		return alert("launchd's answer about the data volume's mount job could not be read, so whether it mounted the volume is unknown.", docsDataVolume, steps...)
	}
	return nil
}

func argsAlert(r Row) *Alert {
	if r.State == StateNeedsAdmin {
		return needsAdminAlert(r, "The installed daemon's launchd plist is readable by root only, so this account could not read the settings it runs with; nothing is known to be wrong.")
	}
	if r.State != StateUnknown {
		return nil
	}
	reinstall := cmd("Re-run the install, which rewrites the plist with the settings you give it", "sudo k3sm install")
	if strings.HasPrefix(r.Detail, "unreadable:") {
		return alert("The installed server's launchd plist carries no argument list this k3sm can parse: it is from another k3sm version, or it was edited by hand.",
			docsServerFlags, reinstall)
	}
	return alert("The installed node daemon's launchd plist could not be read, so the settings it runs with are unknown.",
		docsServerFlags, reportAsAdmin(), reinstall)
}

// needsAdminAlert is the alert of a needs-admin row.
func needsAdminAlert(r Row, cause string) *Alert {
	return alert(cause, docsSudo, remedySteps(r.Remedy)...)
}

func apiserverAlert(r Row, ac alertContext) *Alert {
	steps := remedySteps(r.Remedy)
	worker := ac.role == dataroot.RoleAgent
	server := r.Wide["server"]
	switch r.State {
	case StateUnknown:
		if !worker {
			return alert("No kubeconfig was found for this account, so the control plane could not be asked whether it is serving.", docsKubeconfig, steps...)
		}
		switch {
		case strings.HasPrefix(r.Detail, credentialClause(CredentialAbsent)):
			return alert("This Mac has not joined a cluster, so there is no control plane for it to reach.", docsJoin, steps...)
		case strings.HasPrefix(r.Detail, credentialClause(CredentialExpired)):
			return alert("The worker's node credential has expired, so it can no longer reach its control plane.", docsJoin, steps...)
		case strings.HasPrefix(r.Detail, credentialClause(CredentialCorrupt)):
			return alert("The worker's node credential does not parse, so the address of its control plane could not be read.", docsJoin, steps...)
		}
		return alert("This account may not read the worker's node credential, so the address of its control plane is unknown from here; nothing is known to be wrong.", docsSudo, steps...)
	case StateDown:
		if worker {
			return alert(fmt.Sprintf("This worker cannot reach its control plane at %s; the control plane runs on another Mac.", server), docsJoinFails, steps...)
		}
		return alert(fmt.Sprintf("The control plane does not answer at %s, so the cluster is not serving.", server), docsStartup, steps...)
	case StateNotReady:
		return alert("The apiserver answers but reports it is not ready, so requests to the cluster may fail.", docsStartup, steps...)
	}
	return nil
}

func nodeAlert(r Row, ac alertContext) *Alert {
	steps := remedySteps(r.Remedy)
	switch r.State {
	case StateUnknown:
		if r.Detail == "apiserver unreachable" {
			return alert("The node list could not be read because the apiserver could not be reached from here; this row clears once the apiserver row does.",
				unreachableDocs(ac), append([]FixStep{manual("Fix the apiserver row first")}, steps...)...)
		}
		return alert("The node list could not be read from the apiserver.", docsNodeNotReady, steps...)
	case StateNotReady:
		list := cmd("Find the nodes that are not Ready", "k3sm kubectl get nodes")
		if strings.HasPrefix(r.Detail, "0/") {
			return alert("No node in the cluster is Ready, so no pod can be scheduled or kept running.", docsNodeNotReady, append([]FixStep{list}, steps...)...)
		}
		return alert("Some nodes in the cluster are not Ready, so their pods are not running and nothing new is scheduled on them.", docsNodeNotReady, append([]FixStep{list}, steps...)...)
	}
	return nil
}

// unreachableDocs is where a row that waits on the apiserver points: the
// control plane's startup section on a server, reaching the server on a worker.
func unreachableDocs(ac alertContext) string {
	if ac.role == dataroot.RoleAgent {
		return docsJoinFails
	}
	return docsStartup
}

func heartbeatAlert(r Row, ac alertContext) *Alert {
	if r.State != StateStale {
		return nil
	}
	a := alert("This Mac's node has stopped reporting in to the control plane on time, so the cluster marks it NotReady, or already has.",
		docsNodeNotReady, remedySteps(r.Remedy)...)
	for _, k := range []string{"leaseAgeSeconds", "statusAgeSeconds"} {
		if s, err := strconv.Atoi(r.Wide[k]); err == nil && !ac.now.IsZero() {
			a.Since = ac.now.Add(-time.Duration(s) * time.Second).UTC().Format(time.RFC3339)
			break
		}
	}
	return a
}

func workloadsAlert(r Row, ac alertContext) *Alert {
	steps := remedySteps(r.Remedy)
	switch r.State {
	case StateUnknown:
		if r.Detail == "apiserver unreachable" {
			return alert("The pods could not be listed because the apiserver could not be reached from here; this row clears once the apiserver row does.",
				unreachableDocs(ac), manual("Fix the apiserver row first"))
		}
		return alert("The pods could not be listed from the apiserver.", docsPods, steps...)
	case StateNotReady:
		stuck, deleted := r.Wide["stuckNode"], r.Wide["deletedNode"]
		switch {
		case stuck != "" && deleted != "":
			return alert(fmt.Sprintf("Pods are stuck terminating on a node that has been NotReady too long (%s) and on a node that was deleted (%s); nothing can confirm their containers stopped.", stuck, deleted),
				docsStuckTerminating, steps...)
		case stuck != "":
			return alert(fmt.Sprintf("Pods are stuck terminating on %s, which has been NotReady too long; nothing on that Mac can confirm their containers stopped.", stuck),
				docsStuckTerminating, steps...)
		case deleted != "":
			return alert(fmt.Sprintf("Pods are stuck terminating on %s, a node that was deleted while they ran on it; no kubelet is left to finish them.", deleted),
				docsStuckTerminating, steps...)
		}
		return alert("Some pods are pending or have failed.", docsPods,
			append(steps, cmd("Read a pod's events for the reason it is pending or failed", "k3sm kubectl describe pod -n <namespace> <pod>"))...)
	}
	return nil
}

func interconnectAlert(r Row) *Alert {
	steps := remedySteps(r.Remedy)
	switch r.State {
	case StatePartial:
		return alert("The Thunderbolt interconnect is armed but not every cabled node is on it, so pods on those nodes use the mesh instead of the cable.", docsInterconnect, steps...)
	case StateDown:
		return alert("The Thunderbolt interconnect is armed but no node is up on it, so every pod uses the mesh instead of the cable.", docsInterconnect, steps...)
	case StateUnknown:
		return alert("The Interconnect object could not be read from the apiserver, so whether the cable is in use is unknown.", docsInterconnect,
			cmd("Read the Interconnect object directly", "k3sm kubectl get interconnect -o yaml"))
	}
	return nil
}

func dataRootAlert(r Row) *Alert {
	steps := remedySteps(r.Remedy)
	switch r.State {
	case StateNotMounted:
		return alert("The data root is declared as a mount point but nothing is mounted there, so the daemons refuse to run rather than build an empty cluster on the boot disk.",
			docsNotMounted, steps...)
	case StateAbsent:
		return alert("The data root does not exist, so k3sm has nowhere to keep the cluster's state.", docsInstall, steps...)
	case StateWrongOwner:
		return alert("The data root is not owned by root, the layout older releases left; the service user could rename the root-only key directory under it.",
			docsWrongOwner, steps...)
	case StateOK:
		if r.Severity == SeverityWarn {
			return alert("The data volume is past 90% of its quota; when it fills, image pulls and datastore writes fail.", docsDataVolume, steps...)
		}
	case StateUnknown:
		if len(steps) == 0 {
			steps = []FixStep{reportAsAdmin()}
		}
		return alert("The data root could not be inspected from this account, so whether it is mounted and owned correctly is unknown.", docsSudo, steps...)
	}
	return nil
}

func preVolumeAlert(r Row) *Alert {
	cause := "A full copy of the data root from a data-volume migration is still on disk, using space the cluster may need."
	if r.State == StateNeedsAdmin {
		cause = "A full copy of the data root from a data-volume migration is still on disk; this account could measure only part of it, so it is at least as large as shown."
	}
	return alert(cause, docsDataVolume, remedySteps(r.Remedy)...)
}

func datastoreAlert(r Row) *Alert {
	steps := remedySteps(r.Remedy)
	switch r.State {
	case StateUnknown:
		switch {
		case strings.Contains(r.Detail, "did not answer its readiness check"):
			return alert("This account may not read the datastore file, and the apiserver did not answer, so nothing showed that the datastore answers.", docsSudo, steps...)
		case strings.Contains(r.Detail, NotThisServerDetail):
			return alert("This account may not read the datastore file, and your kubeconfig points at another server, so this report cannot vouch for this Mac's datastore.", docsSudo, steps...)
		}
		return alert("The datastore file could not be read, so its state is unknown.", docsSudo, steps...)
	case StateNotReady:
		return alert("The kine datastore is not in WAL mode, the mode k3sm runs it in: the control plane opened it wrongly, or the file was replaced.", docsDatastore, steps...)
	}
	return nil
}

func updateAlert(r Row) *Alert {
	steps := remedySteps(r.Remedy)
	if r.State == StateBehind {
		return alert("A newer k3sm release is available, and at least one node runs an older one.", docsUpdate, steps...)
	}
	if r.State != StateUnknown {
		return nil
	}
	onServer := manual("Run k3sm status on a control-plane Mac; a server checks for a release once an hour and publishes the result")
	switch d := r.Detail; {
	case d == updateMissingDetail:
		return alert("No update check is recorded yet, so whether a newer release exists is unknown.", docsUpdate, steps...)
	case strings.HasPrefix(d, "unreadable as this user"):
		return alert("This account may not read the update record, so whether a newer release exists is unknown from here; nothing is known to be wrong.", docsSudo, steps...)
	case strings.HasPrefix(d, errUpdateRecordInvalid.Error()):
		return alert("The update record holds a value this k3sm refuses to read, so whether a newer release exists is unknown.", docsUpdate, steps...)
	case strings.HasPrefix(d, "the update record does not parse"):
		return alert("The update record does not parse, so whether a newer release exists is unknown.", docsUpdate, steps...)
	case strings.HasPrefix(d, "the last update check ran"):
		return alert("The last update check is out of date: the server has not checked for a release recently.", docsUpdate,
			append(steps, manual("Check that the server daemon is running; it checks once an hour"))...)
	case strings.HasPrefix(d, "could not check for an update"):
		return alert("The last update check failed, so whether a newer release exists is unknown.", docsUpdate,
			append(steps, manual("Check that this Mac can reach the release server"))...)
	case strings.HasPrefix(d, "the update check found no release"):
		return alert("The update check found no release to compare this cluster with.", docsUpdate, steps...)
	case strings.Contains(d, "no tagged k3sm release reported by"):
		return alert("Some nodes run a k3sm build that is not a tagged release, so they cannot be compared with the latest release.", docsUpdate,
			cmd("Install a tagged release on those nodes", UpdateUpgradeRemedy))
	case strings.HasPrefix(d, agentUpdateCannot):
		return alert("This worker could not read the update check its server publishes, so whether a newer release exists is unknown from here.", docsUpdate,
			append(steps, onServer)...)
	case strings.HasPrefix(d, "no server has published"):
		return alert("No server has published an update check yet, so this worker cannot tell whether a newer release exists.", docsUpdate, onServer)
	}
	return nil
}

func etcdAlert(r Row) *Alert {
	switch {
	case r.Remedy == EtcdNoSpaceRemedy:
		steps := []FixStep{
			manual("Compact the etcd keyspace to the current revision"),
			manual("Defragment every member"),
			manual("Disarm the NOSPACE alarm; writes resume only after the disarm"),
		}
		if r.Severity == SeverityFail {
			return alert("The etcd member ran out of its backend quota and raised the NOSPACE alarm, so the cluster is read-only.", docsEtcd, steps...)
		}
		return alert("The etcd database is nearing its backend quota; at the quota etcd raises NOSPACE and the cluster turns read-only.", docsEtcd, steps...)
	case r.Remedy == EtcdNoLeaderRemedy:
		return alert("The etcd member sees no leader, so the cluster accepts no writes until a majority of servers is reachable.", docsEtcd,
			manual("Start the other servers; each waits for its peers"),
			manual("If a majority is gone for good, stop the daemon on one survivor, run sudo k3sm server --cluster-reset there, then start it again"))
	case r.Remedy == executor.EtcdPeerURLDriftRemedy:
		return alert("This server's etcd member is registered under a peer address that is no longer this server's, so its peers cannot reach it.", docsEtcd,
			manual("Restore the previous etcd peer address (--etcd-peer-ip); server addresses must be stable, for example a DHCP reservation"),
			manual("Or remove this member through another server and re-join it with a wiped etcd data dir"))
	case strings.Contains(r.Detail, executor.EtcdPeerForeignMessage):
		return alert("A peer address answers for a different etcd cluster than this server's.", docsEtcd,
			manual("Check the Mac at that peer address: if it was reinstalled there by mistake, stop its server"),
			manual("If it is the server you restored, wipe this server's etcd data dir and re-join it"))
	case r.Severity == SeverityFail && strings.Contains(r.Detail, "alarms:"):
		return alert("The etcd member has raised an alarm, so the cluster may be read-only or serving damaged data.", docsEtcd,
			cmd("Read the server log for the alarm's cause", "k3sm status logs "+RowServer),
			manual("A CORRUPT member must be removed and re-joined with a wiped etcd data dir"))
	case r.Severity == SeverityFail:
		return alert("This server's etcd member belongs to a cluster that a restore replaced, so the data it serves no longer counts.", docsEtcd,
			manual(sentence(r.Remedy)))
	case r.State == StateUnknown:
		switch {
		case strings.HasPrefix(r.Detail, "unreadable as this user"):
			return alert("This account may not read the etcd status record, so the member's health is unknown from here; nothing is known to be wrong.", docsSudo, remedySteps(r.Remedy)...)
		case strings.Contains(r.Detail, "does not parse"):
			return alert("The etcd status record does not parse, so the member's health is unknown.", docsEtcd,
				cmd("Read the server log; the running server rewrites the record every minute", "k3sm status logs "+RowServer))
		case strings.Contains(r.Detail, "not refreshing it"):
			a := alert("The etcd status record is out of date: the server stopped refreshing it, so the member's health is unknown.", docsEtcd,
				cmd("Read the server log for why it stopped", "k3sm status logs "+RowServer))
			a.Since = sinceText(r.Wide["recorded"])
			return a
		}
		return alert("The etcd member's health could not be read.", docsEtcd, reportAsAdmin())
	}
	return nil
}

func servingCertAlert(r Row) *Alert {
	steps := remedySteps(r.Remedy)
	switch {
	case r.State == StateUnknown:
		if strings.Contains(r.Detail, "pins no cluster CA") {
			return alert("Your kubeconfig pins no cluster CA, so the certificate the apiserver presents could not be checked against it.", docsServingCert, steps...)
		}
		return alert("This account may not read the apiserver serving certificate, so whether it is valid is unknown from here; nothing is known to be wrong.", docsSudo, steps...)
	case r.State == StateAbsent:
		return alert("The apiserver serving certificate is missing, and the control plane does not start without it.", docsServingCert, steps...)
	case r.State == StateCorrupt && strings.HasPrefix(r.Detail, "the cluster CA"):
		return alert("The cluster CA certificate does not parse, and every certificate in the cluster is issued from it.", docsServingCert,
			manual("Restore the server work dir's tls directory from a backup; the cluster CA cannot be re-issued without changing every node's trust"))
	case r.State == StateCorrupt && strings.Contains(r.Detail, "does not name"):
		return alert("The certificate the apiserver presents does not name the host it was reached by, so clients refuse it.", docsServingCert, steps...)
	case r.State == StateCorrupt && strings.Contains(r.Detail, "the CA your kubeconfig pins"):
		return alert("The certificate the apiserver presents does not chain to the CA your kubeconfig pins, so clients refuse it.", docsServingCert,
			append([]FixStep{cmd("Rewrite your kubeconfig from this server", "k3sm kubeconfig --write")}, steps...)...)
	case r.State == StateCorrupt && strings.Contains(r.Detail, "not issued by"):
		return alert("The apiserver serving certificate is not issued by this server's cluster CA, so clients refuse it.", docsServingCert, steps...)
	case r.State == StateCorrupt:
		return alert("The apiserver serving certificate does not parse.", docsServingCert, steps...)
	case r.State == StateExpired:
		a := alert("The apiserver serving certificate has expired, so every client refuses the control plane.", docsServingCert, steps...)
		a.Since = sinceIn(r.Detail, "expired ")
		return a
	}
	return nil
}

func adminKubeconfigAlert(r Row) *Alert {
	switch r.State {
	case StateNeedsAdmin:
		return needsAdminAlert(r, "Only an administrator can check the admin kubeconfig against the cluster CA, so it was not checked; nothing is known to be wrong.")
	case StateDrift:
		return alert("The admin kubeconfig the install wrote does not pin this server's cluster CA, so kubectl with it fails TLS verification.",
			docsAdminKubeconfig, remedySteps(r.Remedy)...)
	}
	return nil
}

func requestHeaderAlert(r Row) *Alert {
	compare := manual("Compare the request-header row on every server; every server must hold the same request-header CA")
	switch {
	case r.State == StateUnknown:
		return alert("This account may not read the request-header CA, so it was not checked; nothing is known to be wrong.", docsSudo, remedySteps(r.Remedy)...)
	case r.State == StateCorrupt:
		return alert("The request-header CA file does not parse as a certificate, so the aggregation layer (metrics, extension apiservers) cannot trust this server's proxy.",
			docsRequestHeader, compare, cmd("Read the server log for the CA it loaded", "k3sm status logs "+RowServer))
	case r.State == StateAbsent:
		return alert("This server holds no request-header CA: it has not booted a release with the aggregation layer, or it is a joined server still waiting for its CA bundle.",
			"ha.md#upgrading-an-ha-cluster-to-the-aggregation-layer",
			manual("Upgrade the mint-authority server first"),
			manual("Then restart this server with its install flags"))
	case r.Severity == SeverityWarn && strings.Contains(r.Detail, "second impersonation root"):
		return alert("The cluster trusts more than one request-header CA, so a second identity that can act as any user exists.",
			docsRequestHeader, compare,
			manual("A CA no server holds came from outside the upgrade procedure: investigate it before anything else"))
	case r.Severity == SeverityWarn:
		return alert("The cluster trusts a request-header CA other than this server's, so requests this server proxies are refused.",
			docsRequestHeader, compare)
	}
	return nil
}

func meshClaimsAlert(r Row) *Alert {
	restart := cmd("Restart a server, which sweeps abandoned claims when it starts", "sudo launchctl kickstart -k system/io.k3sm.server")
	switch r.State {
	case StateNeedsAdmin:
		return needsAdminAlert(r, "The mesh claim record is readable by root only, so this account could not check it; nothing is known to be wrong.")
	case StateUnhealthy:
		return alert("Pod-range claims are held for servers that never joined, so those ranges stay reserved and no new node can use them.",
			docsMeshClaims, restart,
			manual("Or remove each by hand: kubectl -n kube-system delete lease <claim>, then kubectl delete meshpeer <holder>"))
	case StateUnknown:
		switch {
		case strings.Contains(r.Detail, "not refreshing it"):
			a := alert("The mesh claim record is out of date: the server stopped refreshing it.", docsMeshClaims,
				cmd("Read the server log for why it stopped", "k3sm status logs "+RowServer))
			a.Since = sinceText(r.Wide["recorded"])
			return a
		case strings.Contains(r.Detail, "does not parse"):
			return alert("The mesh claim record does not parse, so abandoned claims could not be checked.", docsMeshClaims, restart)
		}
		return alert("The mesh claim record could not be read.", docsSudo, remedySteps(r.Remedy)...)
	}
	return nil
}

func servicesAlert(r Row) *Alert {
	wait := manual("Wait a minute: the Service proxy re-lists Services and EndpointSlices every 30 seconds and repairs a lost update")
	restart := cmd("If the row still differs, restart the server", "sudo launchctl kickstart -k system/io.k3sm.server")
	switch r.State {
	case StateNeedsAdmin:
		return needsAdminAlert(r, "The Service proxy record is readable by root only, so this account could not compare it with the API; nothing is known to be wrong.")
	case StateUnhealthy:
		return alert("Some Service ports route to backends that differ from the API's Ready endpoints, so their traffic may reach the wrong pods or none.",
			docsServices, wait, restart)
	case StateUnknown:
		d := r.Detail
		switch {
		case strings.HasPrefix(d, "the server has not recorded"):
			return alert("The server has not recorded its Service proxy yet; it does 30 seconds after it starts.", docsServices, wait,
				cmd("If it stays this way, read the server log", "k3sm status logs "+RowServer))
		case strings.HasPrefix(d, "could not read "):
			return alert("The Service proxy record could not be read.", docsSudo, remedySteps(r.Remedy)...)
		case strings.Contains(d, "does not parse"):
			return alert("The Service proxy record does not parse, so it could not be compared with the API.", docsServices, restart)
		case strings.Contains(d, "not refreshing it"):
			a := alert("The Service proxy record is out of date: the server stopped refreshing it.", docsServices,
				cmd("Read the server log for why it stopped", "k3sm status logs "+RowServer))
			a.Since = sinceText(r.Wide["recorded"])
			return a
		case strings.HasPrefix(d, "the apiserver is not serving"):
			return alert("The apiserver is not serving, so the Service proxy could not be compared with it; this row clears once the apiserver row does.",
				docsStartup, manual("Fix the apiserver row first"))
		case strings.HasPrefix(d, "could not list Services"):
			return alert("Services and EndpointSlices could not be listed from the apiserver, so the Service proxy could not be compared with them.",
				docsServices, cmd("Check that the API answers for this account", "k3sm kubectl get endpointslices -A"))
		default:
			return alert("Some Service ports differ from the API and changed after the proxy last recorded them, so they cannot be compared yet.",
				docsServices, wait, restart)
		}
	}
	return nil
}

func registryAlert(r Row) *Alert {
	steps := remedySteps(r.Remedy)
	switch r.State {
	case StateNeedsAdmin:
		return needsAdminAlert(r, "The ingest registry's state record is readable by root only, so this account could not check the registry; nothing is known to be wrong.")
	case StateDown:
		a := alert("The node-local ingest registry is recorded as serving but does not answer, so image pushes and pulls through it fail.", docsRegistry, steps...)
		a.Since = sinceText(r.Wide["since"])
		return a
	case StateDisabled:
		a := alert("The node-local ingest registry is configured but disabled, so image pushes and pulls through it fail; the detail says why the server turned it off.",
			docsRegistry, steps...)
		a.Since = sinceText(r.Wide["since"])
		return a
	case StateUnknown:
		switch {
		case strings.Contains(r.Detail, "does not parse"):
			return alert("The ingest registry's state record does not parse, so whether the registry serves is unknown.", docsRegistry,
				cmd("Restart the server, which rewrites the record when the registry starts", "sudo launchctl kickstart -k system/io.k3sm.server"))
		case strings.Contains(r.Detail, "unknown state"):
			return alert("The ingest registry's state record names a state this k3sm does not know: it was written by a newer k3sm.", docsRegistry,
				manual("Run the report with the k3sm the server runs"))
		}
		return alert("The ingest registry's state record could not be read.", docsSudo, steps...)
	}
	return nil
}

func kubeconfigAlert(r Row, ac alertContext) *Alert {
	if r.State != StateMissing {
		return nil
	}
	if ac.role == dataroot.RoleAgent {
		return alert("This account has no kubeconfig for the cluster. On a worker that is expected: kubectl runs against the control-plane Mac.",
			docsKubeconfig,
			manual("To use kubectl here, run k3sm kubeconfig on the control-plane Mac and copy the result into ~/.kube/config on this Mac"))
	}
	return alert("No kubeconfig was found for this account, so kubectl and this report cannot reach the cluster as you.", docsKubeconfig, remedySteps(r.Remedy)...)
}

func runtimedAlert(r Row) *Alert {
	steps := remedySteps(r.Remedy)
	switch r.State {
	case StateNeedsAdmin:
		return needsAdminAlert(r, "The runtime daemon's socket is owner-only, so only an administrator can ask it whether it is healthy; nothing is known to be wrong.")
	case StateDown:
		return alert("The runtime daemon did not answer, so this node cannot start, stop or inspect containers.", docsRuntimed, steps...)
	case StateUnhealthy:
		return alert("The runtime daemon reports itself unhealthy, so pods on this node may not start.", docsRuntimed, steps...)
	}
	return nil
}

func dnsAlert(r Row) *Alert {
	steps := remedySteps(r.Remedy)
	switch r.State {
	case StateDown:
		cause := "The node resolver did not answer over UDP, so pods and the host cannot resolve cluster names."
		if r.Wide["tcp"] != "" {
			cause = "The node resolver answers over TCP but not over UDP: its UDP socket stopped receiving, so pods and the host cannot resolve cluster names."
		}
		return alert(cause, docsDNS, steps...)
	case StateUnhealthy:
		return alert("The node resolver answered but returned no address for the kubernetes Service, so cluster names do not resolve.", docsDNS, steps...)
	case StateUnknown:
		return alert("The node daemon is configured with a cluster DNS address (--dns-vip) that is not an IP address, so it serves no resolver.", docsDNS,
			manual("Re-run sudo k3sm install with a --dns-vip that is an IP address, or without the flag to take the default"))
	}
	return nil
}

func nodeResolverAlert(r Row) *Alert {
	steps := remedySteps(r.Remedy)
	switch r.State {
	case StateMissing:
		return alert("netd has not published the node resolver entry, so host processes, and pods whose shell lost the shim, cannot resolve cluster names.", docsDNS, steps...)
	case StateDown:
		return alert("The node resolver entry is published but netd is not running to maintain it, so cluster names route to a resolver that may not answer.", docsDNS, steps...)
	case StateUnknown:
		return alert("The host resolver configuration could not be read, so whether cluster names route to the node resolver is unknown.", docsDNS,
			cmd("Read the host resolver configuration directly", "scutil --dns"))
	}
	return nil
}

func shadowAlert(r Row) *Alert {
	steps := remedySteps(r.Remedy)
	switch r.State {
	case StateMissing:
		return alert("The shadow binary set is missing, so pods that start through /bin/sh lose k3sm's DNS and path shims.", docsShadow, steps...)
	case StateCorrupt:
		return alert("The shadow binary set's manifest does not parse, so the copies pods run could not be checked against the host.", docsShadow, steps...)
	case StateDrift:
		if strings.Contains(r.Detail, "older install") {
			return alert("The shadow binary set is from an older install and lacks copies this k3sm makes.", docsShadow, steps...)
		}
		return alert("macOS replaced host binaries since the last install, so pods keep running the older copies.", docsShadow, steps...)
	case StateUnknown:
		return alert("The shadow binary set's manifest could not be read.", docsShadow, reportAsAdmin())
	}
	return nil
}

// AlertRows returns the rows of a report that carry an alert, in report order.
func AlertRows(r Report) []Row {
	var out []Row
	for _, row := range r.Rows {
		if row.Alert != nil {
			out = append(out, row)
		}
	}
	return out
}

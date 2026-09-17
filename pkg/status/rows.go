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
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	corev1 "k8s.io/api/core/v1"

	"golang.org/x/sys/unix"

	runtimev1 "k3sm.io/apis/runtime/v1"
	"k3sm.io/k3sm/pkg/dataroot"
	"k3sm.io/k3sm/pkg/datavol"
	"k3sm.io/k3sm/pkg/executor"
)

// logTailLines is how far back the server row reads for the line it quotes. A
// crash-looping daemon writes its failure and exits, so the interesting line is
// always near the end; reading further would only quote an older crash.
const logTailLines = 200

// Collect probes every subsystem and returns the whole report. It never fails:
// a probe that cannot answer produces an unknown row, because "I could not see
// this" is a result an operator needs, and an error return would throw away the
// nine rows that did answer.
func (c Collector) Collect(ctx context.Context) Report {
	now := time.Now
	if c.Now != nil {
		now = c.Now
	}

	// Which node this Mac IS decides which daemon is probed and which rows the
	// report carries. It is read from the plists on disk before anything else,
	// because every row below is about one role or the other.
	role, _, bothRoles := c.installedRole()

	dataRoot, volume := c.dataRootRow(ctx)
	instRow, installed := c.installRow(volume != nil, role, bothRoles)
	netd, _ := c.daemonRow(RowNetd, c.Paths.NetdLabel, c.Paths.NetdLog, false)
	var node Row
	var nodePID int
	// credential is the worker's node credential state, read once: the agent
	// row reports it, and the apiserver row needs it to tell "this Mac has not
	// joined" apart from "the control plane is down". It stays unknown on a
	// server, which holds no such credential.
	credential := CredentialUnknown
	if role == dataroot.RoleAgent {
		node, nodePID, credential = c.agentRow(now())
	} else {
		node, nodePID = c.daemonRow(RowServer, c.Paths.ServerLabel, c.Paths.ServerLog, true)
		c.crashLoop(&node)
	}
	apiserver := c.apiserverRow(ctx, role, credential)
	serving := apiserver.Severity == SeverityOK

	rows := []Row{instRow}
	// The mount oneshot goes before netd, mirroring the order install lays the
	// three daemons down in, and exists only on a Mac that has a data volume:
	// every other Mac would get a row saying "not loaded" about a daemon it was
	// never meant to have.
	if volume != nil {
		rows = append(rows, c.oneshotRow(RowDatavol, c.Paths.DatavolLabel, c.Paths.DatavolLog))
	}
	rows = append(rows,
		netd,
		node,
	)
	// Immediately after the server it describes, and only when there is a plist
	// to read it from: on a Mac with no install the row would say nothing the
	// install row has not already said.
	if args, ok := c.serverArgsRow(); ok {
		rows = append(rows, args)
	}
	rows = append(rows,
		apiserver,
		c.nodeRow(ctx, serving, role),
		c.workloadsRow(ctx, serving, nodePID),
		dataRoot,
	)
	// Immediately after the data root it sits beside, and only while it is
	// there: the copy is the operator's rollback from a migration, and the row
	// is how they learn it is still costing them disk.
	if pre, ok := c.preVolumeRow(); ok {
		rows = append(rows, pre)
	}
	rows = append(rows,
		c.datastoreRow(),
		c.kubeconfigRow(),
		c.runtimedRow(ctx),
	)

	verdict, summary, next := Aggregate(rows, installed, role)
	return Report{
		Verdict:   verdict,
		Role:      role,
		Summary:   summary,
		Rows:      rows,
		Next:      next,
		Version:   c.Version,
		Host:      c.Host,
		Timestamp: now(),
	}
}

// exists reports whether path is there, through the FS seam.
func (c Collector) exists(path string) bool {
	if c.FS == nil || path == "" {
		return false
	}
	_, err := c.FS.Stat(path)
	return err == nil
}

// plistPath is the LaunchDaemon plist a label is installed as.
func (c Collector) plistPath(label string) string {
	return filepath.Join(c.Paths.LaunchDaemonDir, label+".plist")
}

// installRow reports the on-disk install: the binary, the /usr/local/bin
// launcher symlink, and the LaunchDaemon plists of the role this Mac carries.
//
// It also decides `installed`, which gates the whole verdict — and does so on
// the BINARY plus THIS ROLE's node-daemon plist, not on all four parts, because
// a machine with those two has a node to report on even if the launcher link
// was removed by hand. Keying it on the server plist alone is what made a
// perfectly good worker report "not installed": an agent Mac has no
// io.k3sm.server.plist and never will.
func (c Collector) installRow(hasDataVolume bool, role dataroot.Role, bothRoles bool) (Row, bool) {
	row := Row{Name: RowInstall, Remedy: "sudo k3sm install"}
	binary := c.exists(c.Paths.Binary)
	netdPlist := c.exists(c.plistPath(c.Paths.NetdLabel))
	nodeLabel := c.nodeLabel(role)
	nodePlist := c.exists(c.plistPath(nodeLabel))
	// The mount oneshot is counted when it is THERE and demanded when a record
	// says it should be. Those are different conditions on purpose: a Mac with
	// no data volume is complete without it, and a plist left behind by a
	// deleted volume is still a plist in that directory, so saying "2
	// LaunchDaemons" while three sit there would be a count nobody can verify.
	datavolPlist := c.Paths.DatavolLabel != "" && c.exists(c.plistPath(c.Paths.DatavolLabel))

	link := false
	if c.FS != nil {
		if target, err := c.FS.Readlink(c.Paths.Link); err == nil {
			link = target == c.Paths.Binary
		}
	}
	installed := binary && nodePlist

	var missing []string
	if !binary {
		missing = append(missing, c.Paths.Binary)
	}
	if !link {
		missing = append(missing, c.Paths.Link+" launcher symlink")
	}
	if !netdPlist {
		missing = append(missing, c.Paths.NetdLabel+".plist")
	}
	if !nodePlist {
		missing = append(missing, nodeLabel+".plist")
	}
	// parts is how many pieces a COMPLETE install has here, so the all-missing
	// arm below stays "every piece is gone" rather than a hard-coded four that a
	// fifth artifact silently falsified.
	parts := 4
	if hasDataVolume {
		parts = 5
		if !datavolPlist {
			missing = append(missing, c.Paths.DatavolLabel+".plist")
		}
	}
	// The count is of the plists actually on disk, so a Mac that somehow
	// carries both node daemons is not described with a number that quietly
	// omits one of them.
	daemons := 1 // netd
	if nodePlist {
		daemons++
	}
	if bothRoles {
		daemons++
	}
	if datavolPlist {
		daemons++
	}

	switch {
	case len(missing) == 0:
		row.State, row.Severity, row.Remedy = StateOK, SeverityOK, ""
		row.Detail = fmt.Sprintf("%s · launcher %s · %d LaunchDaemons in %s", c.Paths.Binary, c.Paths.Link, daemons, c.Paths.LaunchDaemonDir)
	case len(missing) == parts:
		row.State, row.Severity = StateAbsent, SeverityFail
		row.Detail = "no k3sm install found on this Mac"
	default:
		row.State, row.Severity = StatePartial, SeverityWarn
		row.Detail = "missing: " + strings.Join(missing, ", ")
	}
	// A Mac carrying BOTH node daemons is a posture `k3sm install` refuses to
	// create, so it is said out loud rather than hidden behind a role the
	// report picked: the operator has to know which daemon is being described.
	// The severity is left where the missing-parts arms put it — the row
	// describes an install, and neither daemon is missing here.
	if bothRoles {
		row.Detail += fmt.Sprintf(" · both node daemons are on disk (%s as well); reporting the %s role",
			c.Paths.AgentLabel, dataroot.RoleServer)
	}
	// A control-plane work dir sitting beside an AGENT install is a leftover:
	// `k3sm install --role agent` never creates one, so it is an earlier
	// server-era install whose state directory outlived its daemon. It is said
	// out loud because an operator who finds that directory reasonably concludes
	// this Mac still runs a control plane, and because until B324 the report
	// itself drew that conclusion — it read the stale admin kubeconfig and
	// probed the loopback apiserver. Nothing reads it now, so the note is
	// advisory: like the bothRoles clause above it leaves the severity where the
	// missing-parts arms put it, and never moves the verdict.
	if role == dataroot.RoleAgent && !bothRoles && c.Paths.WorkDir != "" && c.exists(c.Paths.WorkDir) {
		row.Detail += fmt.Sprintf(" · a control-plane data directory is on disk beside the agent role (%s); it is not used by this node",
			c.Paths.WorkDir)
	}
	row.Wide = map[string]string{
		"binary": c.Paths.Binary,
		"link":   c.Paths.Link,
		"plists": c.Paths.LaunchDaemonDir,
		"role":   string(role),
	}
	return row, installed
}

// serverArgsRow reports the operator-supplied `k3sm server` arguments the
// installed daemon is configured with — everything on its argv that the
// installer does not render itself. It reports ok=false when there is nothing to
// report about: no parser was wired, or no server plist exists.
//
// It is read-only and it never moves the verdict. An install whose flags this
// account cannot read is not a degraded cluster, it is an unprivileged report,
// so an unreadable or unparsable plist is UNKNOWN rather than a warning — the
// same posture every other "could not see it from here" row takes.
//
// The row exists because these arguments were, until now, only knowable by
// reading LaunchDaemon XML: --registry-port in particular disables the node
// registry by its ABSENCE, with no log line either way, so "is it set" had no
// answer an operator could ask for.
func (c Collector) serverArgsRow() (Row, bool) {
	if c.ServerArgs == nil || c.FS == nil || c.Paths.ServerLabel == "" {
		return Row{}, false
	}
	path := c.plistPath(c.Paths.ServerLabel)
	row := Row{Name: RowServerArgs, Wide: map[string]string{"plist": path}}
	raw, err := c.FS.ReadFile(path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return Row{}, false // no install to report arguments for
	case err != nil:
		row.State, row.Severity = StateUnknown, SeverityUnknown
		row.Detail = "unreadable as this user: " + path
		return row, true
	}
	args, err := c.ServerArgs(raw)
	if err != nil {
		row.State, row.Severity = StateUnknown, SeverityUnknown
		row.Detail = "unreadable: " + path + " carries no argument list this k3sm can parse"
		return row, true
	}
	row.State, row.Severity = StateOK, SeverityOK
	if len(args) == 0 {
		row.Detail = "none (the stock template: no --mesh-ip, no --registry-port)"
		return row, true
	}
	// Redacted for the same reason the quoted server log line is: the argv is
	// where a credential would be if one ever reached this row.
	row.Detail = Redact(strings.Join(args, " "))
	return row, true
}

// daemonRow reports one LaunchDaemon. It returns the row and the job's pid (0
// when it has none), which the workloads row needs to attribute vm hosts.
//
// withLog is set for the server, the only job whose log this report quotes: its
// crash is the one an operator most often has to read, and it is the one whose
// argv carries a token — so the quoted line goes through Redact and the raw
// launchctl output never leaves this function.
func (c Collector) daemonRow(name, label, logPath string, withLog bool) (Row, int) {
	// "log-path" is the FILE; "log" is the quoted line. They are different keys
	// on purpose — the renderer prints Wide["log"] as the crash line, and a path
	// sitting in that key would print a filename as if it were the failure.
	row := Row{Name: name, Wide: map[string]string{"label": label, "plist": c.plistPath(label), "log-path": logPath}}
	if c.Launchd == nil {
		row.State, row.Severity = StateUnknown, SeverityUnknown
		row.Detail = "launchd was not probed"
		return row, 0
	}
	out, err := c.Launchd.Print(label)
	info := ParseLaunchctlPrint(out, err)
	if disabled, derr := c.Launchd.PrintDisabled(); derr == nil {
		MarkDisabled(&info, disabled, label)
	}
	class := ClassifyDaemon(info)
	row.State, row.Severity = class.State(), class.Severity()

	row.Wide["runs"] = fmt.Sprint(info.Runs)
	row.Wide["pid"] = fmt.Sprint(info.PID)
	row.Wide["last-exit"] = "(never exited)"
	if info.LastExit != nil {
		row.Wide["last-exit"] = fmt.Sprint(*info.LastExit)
	}

	switch class {
	case ClassRunning:
		row.Detail = fmt.Sprintf("pid %d", info.PID)
		// launchd's own state is a bookkeeping fact; the process table is the
		// ground truth. An unprobeable pid (EPERM from an ordinary account
		// against a root daemon) counts as present — see Liveness.
		if c.Procs != nil && !c.Procs.Liveness(info.PID).Exists() {
			row.State, row.Severity = StateUnknown, SeverityWarn
			row.Detail = fmt.Sprintf("launchd reports running, but pid %d is not in the process table", info.PID)
		}
	case ClassCrashLooping, ClassFailed:
		row.Detail = fmt.Sprintf("%s, last exit %s", plural(info.Runs, "run"), row.Wide["last-exit"])
	case ClassStopped:
		row.Detail = fmt.Sprintf("loaded but not running (%s)", plural(info.Runs, "run"))
	case ClassDisabled:
		row.Detail = label + " is disabled in the system domain"
	case ClassNotLoaded:
		row.Detail = label + " is not loaded in the system domain"
	default:
		row.Detail = "launchctl reported a state this build cannot read"
	}

	if name == RowNetd && class == ClassRunning {
		row.Detail += " · " + c.socketClause()
	}
	if withLog && (class == ClassCrashLooping || class == ClassFailed) {
		if line, count := c.logLine(logPath); line != "" {
			row.Wide["log"] = line
			row.Wide["log-repeats"] = fmt.Sprint(count)
		}
	}

	switch class {
	case ClassRunning:
		if row.Severity == SeverityWarn {
			row.Remedy = "sudo launchctl kickstart -k system/" + label
		}
	case ClassDisabled:
		row.Remedy = "sudo launchctl enable system/" + label + "\nsudo launchctl kickstart -k system/" + label
	case ClassNotLoaded:
		row.Remedy = "sudo k3sm install"
	case ClassUnknown:
		row.Remedy = "sudo k3sm status"
	default:
		row.Remedy = "sudo launchctl kickstart -k system/" + label
		if withLog {
			row.Remedy += "\nk3sm status logs server"
		}
	}
	return row, info.PID
}

// socketClause reports whether the netd rendezvous socket is there, and says so
// honestly when the run directory simply is not readable from this account.
func (c Collector) socketClause() string {
	if c.FS == nil || c.Paths.NetdSocket == "" {
		return "socket: unknown (not probed)"
	}
	switch _, err := c.FS.Stat(c.Paths.NetdSocket); {
	case err == nil:
		return "socket " + c.Paths.NetdSocket
	case errors.Is(err, fs.ErrPermission):
		return "socket: unknown (run dir not readable as this user)"
	default:
		return "socket " + c.Paths.NetdSocket + " absent"
	}
}

// logLine returns the last distinct line of a log file with the number of times
// it repeats, timestamp-stripped and REDACTED. A permission error is reported as
// such in Wide rather than dropped, so an operator learns the tail exists and
// needs sudo instead of learning nothing.
func (c Collector) logLine(path string) (string, int) {
	if c.FS == nil || path == "" {
		return "", 0
	}
	lines, err := c.FS.ReadTail(path, logTailLines)
	if err != nil {
		if errors.Is(err, fs.ErrPermission) {
			return "unreadable as this user", 1
		}
		return "", 0
	}
	return lastDistinctLine(lines)
}

// lastDistinctLine reduces a log tail to the last meaningful line and the length
// of the identical run it ends. A crash loop writes the same line hundreds of
// times, and "× 497" is the fact worth printing, not 497 copies of it.
func lastDistinctLine(lines []string) (string, int) {
	cleaned := make([]string, 0, len(lines))
	for _, l := range lines {
		l = Redact(stripTimestamp(l))
		if strings.TrimSpace(l) == "" {
			continue
		}
		cleaned = append(cleaned, l)
	}
	if len(cleaned) == 0 {
		return "", 0
	}
	last := cleaned[len(cleaned)-1]
	count := 0
	for i := len(cleaned) - 1; i >= 0 && cleaned[i] == last; i-- {
		count++
	}
	return last, count
}

// apiserverRow reports whether the control plane is serving, which on a SERVER
// is the single fact the verdict turns on.
//
// On a worker it is a different row about a different machine. The apiserver it
// names is the one this node's own credential targets, reached over the mesh,
// and this Mac does not run it: an unreachable control plane is reported as a
// WARN, not a failure of the node reading the report. See workerAdvisoryRows.
func (c Collector) apiserverRow(ctx context.Context, role dataroot.Role, credential CredentialState) Row {
	row := Row{Name: RowAPIServer}
	worker := role == dataroot.RoleAgent
	if c.Kube == nil {
		row.State, row.Severity = StateUnknown, SeverityUnknown
		if worker {
			// A worker's apiserver URL is IN the credential a join writes, so
			// with no credential there is nothing to probe rather than
			// something down — and WHICH of those sentences is true, and what
			// to do about it, is the credential's state, not this row's guess.
			// The remedy comes from credentialRemedy for exactly that reason:
			// the ordinary unprivileged invocation cannot read the
			// service-user-owned store at all, and telling that operator to
			// re-join a healthy worker (as a single joinRemedy arm here did)
			// contradicts the agent row two lines above it.
			row.Detail = credentialClause(credential) + ": " + errText(c.KubeErr)
			row.Remedy = c.credentialRemedy(credential)
			return row
		}
		row.Detail = "no kubeconfig: " + errText(c.KubeErr)
		row.Remedy = "sudo k3sm install\nk3sm kubeconfig --write"
		return row
	}
	row.Wide = map[string]string{"tls": c.Kube.TLSPosture(), "server": c.Kube.Server()}
	body, err := c.Kube.RawGet(ctx, "/readyz")
	if err != nil {
		row.State, row.Severity = StateDown, SeverityFail
		row.Detail = fmt.Sprintf("%s: %s", c.Kube.Server(), errText(err))
		row.Remedy = c.controlPlaneRemedy(role)
		if worker {
			row.Severity = SeverityWarn
			row.Detail += " · " + controlPlaneLayer(err)
		}
		return row
	}
	if strings.TrimSpace(string(body)) != "ok" {
		row.State, row.Severity = StateNotReady, SeverityWarn
		row.Detail = fmt.Sprintf("%s readyz: %s", c.Kube.Server(), firstLine(string(body)))
		row.Remedy = c.nodeLogRemedy(role)
		return row
	}
	row.State, row.Severity = StateReady, SeverityOK
	row.Detail = c.Kube.Server() + " readyz ok"
	if verbose, verr := c.Kube.RawGet(ctx, "/readyz?verbose"); verr == nil {
		row.Wide["readyz"] = strings.TrimSpace(string(verbose))
	}
	return row
}

// nodeRow reports node readiness.
//
// Which node is "this Mac" is answered by PickNode, from the hostname. When it
// cannot answer, the row reports the ready/total counts alone rather than naming
// a node it did not identify.
func (c Collector) nodeRow(ctx context.Context, serving bool, role dataroot.Role) Row {
	row := Row{Name: RowNode, Remedy: c.nodeLogRemedy(role)}
	if c.Kube == nil || !serving {
		row.State, row.Severity = StateUnknown, SeverityUnknown
		row.Detail = "apiserver unreachable"
		return row
	}
	nodes, err := c.Kube.Nodes(ctx)
	if err != nil {
		row.State, row.Severity = StateUnknown, SeverityUnknown
		row.Detail = "could not list nodes: " + errText(err)
		return row
	}
	ready := 0
	for i := range nodes {
		if nodeReady(nodes[i]) {
			ready++
		}
	}
	detail := fmt.Sprintf("%d/%d nodes ready", ready, len(nodes))
	if mine, ok := PickNode(nodes, c.Hostname); ok {
		detail += fmt.Sprintf(" · %s kubelet %s", mine.Name, mine.Status.NodeInfo.KubeletVersion)
		row.Wide = map[string]string{"node": mine.Name, "kubelet": mine.Status.NodeInfo.KubeletVersion}
	}
	row.Detail = detail
	switch {
	case len(nodes) == 0 || ready == 0:
		row.State, row.Severity = StateNotReady, SeverityFail
	case ready < len(nodes):
		row.State, row.Severity = StateNotReady, SeverityWarn
	default:
		row.State, row.Severity, row.Remedy = StateReady, SeverityOK, ""
	}
	// A WORKER reading this row is reading about the CLUSTER, not about itself:
	// a node that is not Ready is not necessarily this node, and even when it
	// is, the fact came from an apiserver on another Mac. Reported as a WARN
	// there, so the exemption in workerAdvisoryRows never has to exempt a FAIL.
	if role == dataroot.RoleAgent && row.Severity == SeverityFail {
		row.Severity = SeverityWarn
	}
	return row
}

// controlPlaneRemedy is what an operator does about a control plane that is not
// answering, from the node they are standing on. On a server it is that Mac's
// own daemon; on a worker there is no control plane here to restart, so the
// remedy points at this node's log and at the other Mac.
func (c Collector) controlPlaneRemedy(role dataroot.Role) string {
	if role == dataroot.RoleAgent {
		return "k3sm status logs " + RowAgent + "\nk3sm status   # on the control-plane Mac"
	}
	return "sudo launchctl kickstart -k system/" + c.Paths.ServerLabel + "\nk3sm status logs " + RowServer
}

// nodeLogRemedy names the log of the node daemon THIS Mac runs.
func (c Collector) nodeLogRemedy(role dataroot.Role) string {
	return "k3sm status logs " + nodeRowName(role)
}

// credentialClause is the first half of a worker's apiserver-row detail when
// there is nothing to probe: what the node credential's state means for the
// question "which apiserver would this node talk to".
//
// It is separate from the agent row's own wording because the two rows answer
// different questions about one fact — that row reports the credential, this
// one reports the consequence — but they are driven by the SAME state value, so
// they can never disagree about which case they are in.
func credentialClause(credential CredentialState) string {
	switch credential {
	case CredentialAbsent:
		return "this Mac has not joined a cluster, so there is no apiserver to probe"
	case CredentialExpired:
		return "the node credential has expired, so this worker can no longer reach its apiserver"
	case CredentialCorrupt:
		return "the stored node credential does not parse, so no apiserver URL could be read from it"
	default:
		// Unknown: the store was not readable from this account, which is the
		// ordinary posture for an unprivileged run and NOT a fault.
		return "the node credential was not readable, so no apiserver URL could be read from it"
	}
}

// controlPlaneLayer names the layer a worker's failed apiserver probe points
// at, from the error class.
//
// A worker reaches its control plane over the mesh, so a failure has two very
// different repairs and the row that does not distinguish them sends half its
// readers to the wrong Mac. A refused connection or a TLS fault means the path
// carried the packets and something answered (or refused) at the far end: that
// is the server daemon. A timeout or an unreachable host/network means nothing
// answered at all, which on this topology is the wireguard path — netd and the
// peer programming — far more often than a dead daemon.
//
// An unrecognised error deliberately names NEITHER layer: a guess printed as a
// diagnosis is worse than the honest "it is on another Mac", which is the one
// thing every arm here still says.
func controlPlaneLayer(err error) string {
	const elsewhere = "the control plane is on another Mac"
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return elsewhere + "; the probe timed out, so check the mesh to it (netd and the mesh peer)"
	}
	switch {
	case errors.Is(err, syscall.EHOSTUNREACH), errors.Is(err, syscall.ENETUNREACH):
		return elsewhere + "; it is unreachable, so check the mesh to it (netd and the mesh peer)"
	case errors.Is(err, syscall.ECONNREFUSED):
		return elsewhere + "; the connection was refused, so check its k3sm server daemon"
	case isTLSError(err):
		return elsewhere + "; the TLS handshake failed, so check its k3sm server daemon"
	}
	return elsewhere
}

// isTLSError reports whether err is a certificate or TLS-record fault — the
// class that proves the far end answered, which is what makes it a statement
// about the server daemon rather than about the path.
func isTLSError(err error) bool {
	var (
		verify   *tls.CertificateVerificationError
		record   tls.RecordHeaderError
		unknown  x509.UnknownAuthorityError
		invalid  x509.CertificateInvalidError
		hostname x509.HostnameError
	)
	return errors.As(err, &verify) || errors.As(err, &record) ||
		errors.As(err, &unknown) || errors.As(err, &invalid) || errors.As(err, &hostname)
}

// PickNode picks THIS Mac's node out of a cluster's node list.
//
// k3sm names a node after its host — "k3sm-<lowercased short hostname>" — so the
// hostname is the only identity a status report has to work with; there is no
// node-name file to read, and asking the apiserver "which of these is me" is not
// a question the API answers. The match is therefore by shape, in order: the
// exact name, then the "-<host>" suffix, then — for the single-node cluster that
// is every default install — the only node there is.
//
// A multi-node cluster whose hostname matches nothing returns ok=false, and the
// row falls back to the ready counts alone. That is the honest outcome: naming
// an arbitrary node "this Mac" would be a guess printed as a fact.
func PickNode(nodes []corev1.Node, hostname string) (corev1.Node, bool) {
	if len(nodes) == 0 {
		return corev1.Node{}, false
	}
	short := strings.ToLower(strings.TrimSpace(hostname))
	if i := strings.IndexByte(short, '.'); i > 0 {
		short = short[:i]
	}
	if short != "" {
		for i := range nodes {
			if strings.ToLower(nodes[i].Name) == short {
				return nodes[i], true
			}
		}
		for i := range nodes {
			if strings.HasSuffix(strings.ToLower(nodes[i].Name), "-"+short) {
				return nodes[i], true
			}
		}
	}
	if len(nodes) == 1 {
		return nodes[0], true
	}
	return corev1.Node{}, false
}

// nodeReady reports the node's Ready condition.
func nodeReady(n corev1.Node) bool {
	for _, cond := range n.Status.Conditions {
		if cond.Type == corev1.NodeReady {
			return cond.Status == corev1.ConditionTrue
		}
	}
	return false
}

// workloadsRow counts pods by phase across every namespace, plus the vm hosts
// the control plane has spawned (the one workload kind that is a host process
// rather than a pod entry).
func (c Collector) workloadsRow(ctx context.Context, serving bool, serverPID int) Row {
	row := Row{Name: RowWorkloads, Remedy: "k3sm kubectl get pods -A"}
	if c.Kube == nil || !serving {
		row.State, row.Severity = StateUnknown, SeverityUnknown
		row.Detail = "apiserver unreachable"
		return row
	}
	pods, err := c.Kube.Pods(ctx)
	if err != nil {
		row.State, row.Severity = StateUnknown, SeverityUnknown
		row.Detail = "could not list pods: " + errText(err)
		return row
	}
	byPhase := map[corev1.PodPhase]int{}
	for i := range pods {
		byPhase[pods[i].Status.Phase]++
	}
	clauses := []string{fmt.Sprintf("%d running", byPhase[corev1.PodRunning])}
	for _, phase := range []corev1.PodPhase{corev1.PodPending, corev1.PodFailed, corev1.PodSucceeded} {
		if n := byPhase[phase]; n > 0 {
			clauses = append(clauses, fmt.Sprintf("%d %s", n, strings.ToLower(string(phase))))
		}
	}
	if c.Procs != nil && serverPID > 0 {
		if n, verr := c.Procs.VMHosts(serverPID); verr == nil && n > 0 {
			clauses = append(clauses, fmt.Sprintf("%d vm", n))
		}
	}
	row.Detail = strings.Join(clauses, " · ")
	if byPhase[corev1.PodPending] > 0 || byPhase[corev1.PodFailed] > 0 {
		row.State, row.Severity = StateNotReady, SeverityWarn
		return row
	}
	row.State, row.Severity, row.Remedy = StateOK, SeverityOK, ""
	return row
}

// dataRootRow reports the posture of /var/lib/k3sm.
//
// The failure worth the most words is the SHADOW: the root is declared in
// /etc/fstab as a mount point and nothing is mounted there, so every write lands
// on the boot disk and hides the real volume. It looks exactly like an empty
// cluster, which is why the remedy is spelled out in full rather than reduced to
// "re-install" — `sudo k3sm install` refuses this posture on purpose.
func (c Collector) dataRootRow(ctx context.Context) (Row, *dataroot.Record) {
	row := Row{Name: RowDataRoot}
	var usage volumeUsage
	if c.DataRoot == nil {
		row.State, row.Severity = StateUnknown, SeverityUnknown
		row.Detail = "the data root was not probed"
		return row, nil
	}
	st, err := dataroot.Read(c.DataRoot, c.Paths.DataRoot)
	if err != nil {
		row.State, row.Severity = StateUnknown, SeverityUnknown
		row.Detail = "could not read " + c.Paths.DataRoot + ": " + errText(err)
		row.Remedy = "sudo k3sm status"
		return row, nil
	}
	kick := "sudo launchctl kickstart -k system/" + c.Paths.NetdLabel + " && sudo launchctl kickstart -k system/" + c.Paths.ServerLabel
	switch {
	case st.Shadowed():
		row.State, row.Severity = StateNotMounted, SeverityFail
		row.Detail = fmt.Sprintf("%s but nothing is mounted there; a shadow directory (%s) holds %s",
			declarationText(st), ownerText(st.OwnerUID), shadowText(st.ShadowEntries))
		// With a record, k3sm knows WHICH volume belongs here and can mount it
		// by UUID; the operator does not have to find it with diskutil. Without
		// one, all that is known is that some line in /etc/fstab claims this
		// directory, so the remedy still asks them to name the volume.
		if st.Volume != nil {
			row.Remedy = "sudo k3sm datavol mount\n" + kick
		} else {
			row.Remedy = fmt.Sprintf("sudo rm -r %s/run && sudo diskutil mount -mountPoint %s <volume>   # the shadow holds only the netd socket\n%s",
				c.Paths.DataRoot, c.Paths.DataRoot, kick)
		}
	case !st.Exists:
		row.State, row.Severity = StateAbsent, SeverityFail
		row.Detail = c.Paths.DataRoot + " does not exist"
		row.Remedy = "sudo k3sm install"
	case c.ServiceUID >= 0 && (st.OwnerUID != c.ServiceUID || !st.OwnerWritable):
		row.State, row.Severity = StateWrongOwner, SeverityFail
		row.Detail = fmt.Sprintf("%s is owned by uid %d; the %s service user cannot write it", c.Paths.DataRoot, st.OwnerUID, serviceUserName)
		row.Remedy = "sudo launchctl kickstart -k system/" + c.Paths.NetdLabel + "   # realigns it\nsudo k3sm install"
	case st.Mounted && st.Volume != nil:
		row.State, row.Severity = StateOK, SeverityOK
		usage = c.volumeUsage(ctx, st.Volume)
		row.Detail = fmt.Sprintf("%s (%s volume %s, %s, mounted)", c.Paths.DataRoot, st.FSType, st.Volume.Name, usage.clause(st.Volume))
		if usage.nearlyFull(st.Volume) {
			// State stays ok: the cluster is serving, and it is the TREND that
			// needs attention. The clause says what reclaim can and cannot free,
			// because the obvious next command frees only images -- the datastore
			// and PersistentVolume growth are the operator's to deal with.
			row.Severity = SeverityWarn
			row.Detail += "; nearly full (reclaim frees images only; see docs/user/storage.md)"
			row.Remedy = "k3sm image prune\nk3sm datavol status"
		}
	case st.Mounted:
		row.State, row.Severity = StateOK, SeverityOK
		row.Detail = fmt.Sprintf("%s (%s device %s, mounted)", c.Paths.DataRoot, st.FSType, st.VolumeName)
	default:
		row.State, row.Severity = StateOK, SeverityOK
		row.Detail = c.Paths.DataRoot + " (plain directory)"
	}
	row.Wide = map[string]string{
		"declared": fmt.Sprint(st.DeclaredMount),
		"mounted":  fmt.Sprint(st.Mounted),
		"owner":    fmt.Sprint(st.OwnerUID),
	}
	if len(st.DeclaredBy) > 0 {
		row.Wide["declared-by"] = strings.Join(st.DeclaredBy, ",")
	}
	if st.Volume != nil {
		row.Wide["volume"] = st.Volume.Name
		row.Wide["quota"] = quotaText(st.Volume.QuotaBytes)
		// used-source is reported even when used is not, because "which probe
		// answered" is the fact that makes the number trustworthy -- and the
		// absence of a number legible.
		row.Wide["used-source"] = usage.source
		if usage.known {
			row.Wide["used"] = datavol.FormatSize(usage.bytes)
		}
	}
	return row, st.Volume
}

// volumeUsage is how much a data volume is using, and WHICH probe said so.
//
// The source is carried rather than discarded because the two probes are not
// interchangeable and one of them is wrong in a specific, invisible way. See
// Collector.Volumes: statfs on a quota-less APFS volume reports the container's
// numbers, so a figure taken from it there is the whole disk's usage wearing
// the volume's name.
type volumeUsage struct {
	bytes uint64
	known bool
	// source is "statfs", "apfs" or "unknown" -- the last meaning no probe
	// could answer, which is reported as an absence and never as a zero.
	source string
}

// The three answers to "where did this number come from".
const (
	usedFromStatfs  = "statfs"
	usedFromAPFS    = "apfs"
	usedFromNowhere = "unknown"
)

// volumeUsage measures the data volume, choosing the probe by whether the
// volume carries a quota.
//
// With a quota, statfs is correct and is what the reclaim ladder itself reads,
// so it stays the source. Without one, statfs describes the container and the
// only honest source is diskutil's own container listing. If that cannot be
// reached -- no seam wired, or the command failed -- the answer is UNKNOWN, and
// the row prints no usage at all. Falling back to statfs there would be
// printing the wrong number rather than no number, which is the defect this
// function exists to fix.
func (c Collector) volumeUsage(ctx context.Context, rec *dataroot.Record) volumeUsage {
	if rec.QuotaBytes > 0 {
		if used, ok := c.statfsUsed(); ok {
			return volumeUsage{bytes: used, known: true, source: usedFromStatfs}
		}
		return volumeUsage{source: usedFromNowhere}
	}
	if used, ok := c.apfsUsed(ctx, rec.UUID); ok {
		return volumeUsage{bytes: used, known: true, source: usedFromAPFS}
	}
	return volumeUsage{source: usedFromNowhere}
}

// clause renders the usage half of the data-root detail: "30G of 100G used"
// with a quota, "34.8G used, no quota" without one, and "no quota" when nothing
// could measure it. It never prints "of 0" -- a volume with no quota can grow
// to fill its container, and saying it is using some of nothing would be worse
// than saying nothing about the bound.
func (u volumeUsage) clause(rec *dataroot.Record) string {
	switch {
	case rec.QuotaBytes > 0 && u.known:
		return fmt.Sprintf("%s of %s used", datavol.FormatSize(u.bytes), datavol.FormatSize(rec.QuotaBytes))
	case rec.QuotaBytes > 0:
		return datavol.FormatSize(rec.QuotaBytes) + " quota"
	case u.known:
		return datavol.FormatSize(u.bytes) + " used, no quota"
	default:
		return "no quota"
	}
}

// nearlyFull reports whether the volume has passed nearlyFullFraction of its
// quota. A volume with no quota is never nearly full: there is no bound to be
// near, which is exactly what the warning would otherwise be claiming. An
// unmeasured volume is not nearly full either -- the warning has to rest on a
// number somebody actually read.
func (u volumeUsage) nearlyFull(rec *dataroot.Record) bool {
	if rec.QuotaBytes == 0 || !u.known {
		return false
	}
	return float64(u.bytes) >= float64(rec.QuotaBytes)*nearlyFullFraction
}

// apfsUsed asks diskutil what the volume itself is using: one Info to learn the
// container the volume lives in, one Capacity to read its usage inside it.
// Both are unprivileged reads, and both are bounded, because `k3sm status` is
// the command an operator runs when something is already wrong and a probe that
// hangs makes the tool part of the problem.
func (c Collector) apfsUsed(ctx context.Context, uuid string) (uint64, bool) {
	if c.Volumes == nil || uuid == "" {
		return 0, false
	}
	ctx, cancel := context.WithTimeout(ctx, volumeProbeBudget)
	defer cancel()
	info, err := c.Volumes.Info(ctx, uuid)
	if err != nil || info.ContainerReference == "" {
		return 0, false
	}
	capacity, err := c.Volumes.Capacity(ctx, info.ContainerReference, uuid)
	if err != nil {
		return 0, false
	}
	return capacity.InUse, true
}

// volumeProbeBudget bounds the two diskutil reads together.
const volumeProbeBudget = 3 * time.Second

// nearlyFullFraction is the share of a volume's quota at which the data-root row
// starts warning. Ninety percent is the point at which the remaining headroom
// is comparable to what a single image pull or a few hours of datastore growth
// consumes, i.e. the last moment a warning is still an early one.
const nearlyFullFraction = 0.9

// statfsUsed is the data root's consumption as statfs(2) reports it:
// (blocks - free) * block size, the same arithmetic `k3sm datavol status` does
// and the same numbers runtimed's reclaim ladder reads. It is unavailable
// rather than zero when the probe cannot answer, because a report that says a
// full volume is empty is worse than one that says nothing.
//
// It is correct ONLY for a volume that carries a quota; see Collector.Volumes
// for what it reports on one that does not, and why that is not a number this
// row may print.
func (c Collector) statfsUsed() (uint64, bool) {
	if c.DataRoot == nil {
		return 0, false
	}
	var st unix.Statfs_t
	if err := c.DataRoot.Statfs(c.Paths.DataRoot, &st); err != nil {
		return 0, false
	}
	if st.Bsize == 0 || st.Blocks == 0 {
		return 0, false
	}
	return (st.Blocks - st.Bfree) * uint64(st.Bsize), true
}

// quotaText renders a quota for the wide column, naming the absence of one
// rather than printing a zero that reads like a measurement.
func quotaText(bytes uint64) string {
	if bytes == 0 {
		return "none"
	}
	return datavol.FormatSize(bytes)
}

// declarationText names what declares the data root a mount point, for the
// shadow sentence. The two sources have different remedies, so the sentence
// that precedes the remedy has to say which one is talking.
func declarationText(st dataroot.State) string {
	if st.Volume != nil {
		return fmt.Sprintf("declared by the k3sm data volume %s (%s)", st.Volume.Name, st.Volume.UUID)
	}
	return "declared in /etc/fstab (apfs)"
}

// preVolumeRow reports the copy a data-root migration left behind, and reports
// nothing at all when there is none.
//
// It warns rather than informs because the copy is a full duplicate of the data
// root -- on a real cluster, tens of gigabytes that look like free space until
// somebody goes looking. It does not move the verdict (see advisoryRows): a
// leftover backup is not a degraded cluster.
func (c Collector) preVolumeRow() (Row, bool) {
	if c.DataRoot == nil || c.Paths.DataRoot == "" {
		return Row{}, false
	}
	path := c.Paths.DataRoot + datavol.PreVolumeSuffix
	info, err := c.DataRoot.Stat(path)
	if err != nil || !info.IsDir() {
		return Row{}, false
	}
	size, partial := c.treeBytes(path, preVolumeWalkBudget)
	sizeText := datavol.FormatSize(size)
	if partial {
		// An unreadable subtree (an unprivileged run against a root-owned copy)
		// or an exhausted budget under-counts; say so rather than print a
		// smaller number as if it were the whole.
		sizeText = "at least " + sizeText + ", re-run with sudo for the full size"
	}
	row := Row{
		Name:     RowPreVolume,
		State:    StateOK,
		Severity: SeverityWarn,
		Detail:   fmt.Sprintf("%s holds the pre-migration copy (%s, %s)", path, sizeText, ageText(c.since(info.ModTime()))),
		Remedy:   "sudo rm -r " + path + "   # once you are satisfied with the migrated cluster",
		Wide:     map[string]string{"path": path, "bytes": fmt.Sprint(size), "partial": fmt.Sprint(partial)},
	}
	return row, true
}

// preVolumeWalkBudget bounds the pre-volume size walk. A migrated data root can
// hold hundreds of thousands of image-layer files, and `k3sm status` is the
// command an operator runs when something is already wrong: a probe that spends
// seconds walking a tree would make the tool part of the problem. The number is
// a floor on accuracy, not on truth -- the size is reported as at-least when the
// budget runs out.
const preVolumeWalkBudget = 20000

// treeBytes totals the regular files under root through the FS seam, visiting
// at most budget entries. An unreadable subtree contributes nothing: the number
// tells an operator whether the copy is worth reclaiming, and a permission
// error on one directory must not turn that into no answer at all. partial
// reports that the total is a lower bound, because a directory could not be
// read or the budget ran out.
func (c Collector) treeBytes(root string, budget int) (total uint64, partial bool) {
	visited := 0
	var walk func(dir string, depth int)
	walk = func(dir string, depth int) {
		if visited >= budget || depth > preVolumeWalkDepth {
			partial = true
			return
		}
		entries, err := c.DataRoot.ReadDir(dir)
		if err != nil {
			partial = true
			return
		}
		for _, e := range entries {
			if visited >= budget {
				partial = true
				return
			}
			visited++
			if e.IsDir() {
				walk(filepath.Join(dir, e.Name()), depth+1)
				continue
			}
			if !e.Type().IsRegular() {
				continue
			}
			if info, err := e.Info(); err == nil && info.Size() > 0 {
				total += uint64(info.Size())
			}
		}
	}
	walk(root, 0)
	return total, partial
}

// preVolumeWalkDepth bounds the walk's recursion. A data root is shallow; a
// depth this far past it means a symlink loop or a fake, neither of which is
// worth following forever.
const preVolumeWalkDepth = 24

// since is the collector's clock, so a test can pin an age.
func (c Collector) since(t time.Time) time.Duration {
	now := time.Now
	if c.Now != nil {
		now = c.Now
	}
	return now().Sub(t)
}

// ageText renders how long ago something happened, in the largest unit that
// still says something: days for a copy an operator has been keeping, hours or
// minutes for one they just made. A zero or negative age (an unreadable
// timestamp, a clock that moved) reads as "just now" rather than as a negative
// number of days.
func ageText(d time.Duration) string {
	switch {
	case d < time.Minute:
		return "just now"
	case d < time.Hour:
		return fmt.Sprintf("%d minutes ago", int(d.Minutes()))
	case d < 24*time.Hour:
		return fmt.Sprintf("%d hours ago", int(d.Hours()))
	default:
		return fmt.Sprintf("%d days ago", int(d.Hours()/24))
	}
}

// oneshotRow reports a launchd job that RUNS AND EXITS, which is a different
// health question from the one daemonRow answers.
//
// For a KeepAlive daemon, "not running" is a fault. For the datavol mount job it
// is the ordinary, healthy state: it mounted the volume and stopped. The fact
// that carries the verdict is therefore the LAST EXIT CODE, not the pid, and a
// job that has never run is loaded and waiting rather than broken.
func (c Collector) oneshotRow(name, label, logPath string) Row {
	row := Row{Name: name, Wide: map[string]string{"label": label, "plist": c.plistPath(label), "log-path": logPath}}
	if c.Launchd == nil {
		row.State, row.Severity = StateUnknown, SeverityUnknown
		row.Detail = "launchd was not probed"
		return row
	}
	out, err := c.Launchd.Print(label)
	info := ParseLaunchctlPrint(out, err)
	if disabled, derr := c.Launchd.PrintDisabled(); derr == nil {
		MarkDisabled(&info, disabled, label)
	}
	row.Wide["runs"] = fmt.Sprint(info.Runs)
	row.Wide["last-exit"] = "(never exited)"
	if info.LastExit != nil {
		row.Wide["last-exit"] = fmt.Sprint(*info.LastExit)
	}

	switch {
	case !info.Loaded:
		row.State, row.Severity = StateMissing, SeverityWarn
		row.Detail = label + " is not loaded, so nothing mounts the data volume at boot"
		row.Remedy = "sudo k3sm install --data-volume"
	case info.Disabled:
		row.State, row.Severity = StateDisabled, SeverityFail
		row.Detail = label + " is disabled in the system domain"
		row.Remedy = "sudo launchctl enable system/" + label + "\nsudo k3sm datavol mount"
	case info.KeysMatched == 0:
		row.State, row.Severity = StateUnknown, SeverityUnknown
		row.Detail = "launchctl reported a state this build cannot read"
		row.Remedy = "sudo k3sm status"
	case info.LastExit != nil && *info.LastExit != 0:
		row.State, row.Severity = StateFailed, SeverityFail
		row.Detail = fmt.Sprintf("last run exit %d (%s)", *info.LastExit, plural(info.Runs, "run"))
		row.Remedy = "sudo k3sm datavol mount"
	case info.LastExit == nil && info.Runs == 0:
		row.State, row.Severity = StateOK, SeverityOK
		row.Detail = "loaded, has not run yet"
	case info.LastExit == nil:
		row.State, row.Severity = StateOK, SeverityOK
		row.Detail = fmt.Sprintf("running now (%s)", plural(info.Runs, "run"))
	default:
		row.State, row.Severity = StateOK, SeverityOK
		row.Detail = "last run exit 0"
	}
	return row
}

// serviceUserName is the account the control plane runs as, named in the
// wrong-owner sentence. It is a literal rather than an install import so
// pkg/status keeps no dependency on the installer.
const serviceUserName = "_k3sm"

// ownerText renders a uid for the shadow sentence.
func ownerText(uid int) string { return fmt.Sprintf("uid %d", uid) }

// shadowText renders what a shadow directory holds.
func shadowText(entries []string) string {
	if len(entries) == 0 {
		return "nothing"
	}
	sorted := append([]string(nil), entries...)
	sort.Strings(sorted)
	return strings.Join(sorted, ", ")
}

// datastoreRow reports the kine SQLite datastore's posture. The db lives inside
// the service user's mode-0700 home, so an ordinary account is EXPECTED to be
// unable to read it — that is an unknown row, never a fault.
func (c Collector) datastoreRow() Row {
	row := Row{Name: RowDatastore}
	path := executor.StateDBPath(c.Paths.WorkDir)
	row.Wide = map[string]string{"path": path}
	present, uv, jm, err := DatastorePosture(path)
	switch {
	case errors.Is(err, fs.ErrPermission):
		row.State, row.Severity = StateUnknown, SeverityUnknown
		row.Detail = "state.db not readable as this user (re-run with sudo)"
		row.Remedy = "sudo k3sm status"
	case err != nil:
		row.State, row.Severity = StateUnknown, SeverityUnknown
		row.Detail = "could not read " + path + ": " + errText(err)
		row.Remedy = "sudo k3sm status"
	case !present:
		row.State, row.Severity = StateSkip, SeveritySkip
		row.Detail = "no state.db yet"
	case jm != "wal":
		row.State, row.Severity = StateNotReady, SeverityWarn
		row.Detail = fmt.Sprintf("kine sqlite, %s, user_version %d (expected wal)", jm, uv)
		row.Remedy = "k3sm status logs server"
	default:
		row.State, row.Severity = StateOK, SeverityOK
		row.Detail = fmt.Sprintf("kine sqlite, wal, user_version %d", uv)
	}
	return row
}

// kubeconfigRow reports the credentials this command found, and where.
func (c Collector) kubeconfigRow() Row {
	row := Row{Name: RowKubeconfig}
	if c.Kube == nil {
		row.State, row.Severity = StateMissing, SeverityWarn
		row.Detail = errText(c.KubeErr)
		row.Remedy = "sudo k3sm install\nk3sm kubeconfig --write"
		return row
	}
	row.State, row.Severity = StateOK, SeverityOK
	row.Detail = c.KubeSource
	if row.Detail == "" {
		row.Detail = "resolved"
	}
	return row
}

// runtimedRow reports the native runtime daemon's health. It is rendered only by
// the cluster view and by JSON — the overview has no room for it and it is the
// row an ordinary account can least often answer — but it still participates in
// the verdict, because a node whose runtime is unhealthy runs no pods.
func (c Collector) runtimedRow(ctx context.Context) Row {
	row := Row{Name: RowRuntimed}
	// The uid test is repeated here, not just in the adapter that builds the
	// seam: a caller that wires a Runtimed anyway must still not have this
	// command dial an owner-only socket it has no business opening.
	if c.Runtimed == nil || !RuntimedReachable(c.EUID, c.ServiceUID) {
		row.State, row.Severity = StateUnknown, SeverityUnknown
		row.Detail = "needs sudo (socket is owner-only)"
		return row
	}
	info, err := c.Runtimed.Info(ctx)
	if err != nil {
		row.State, row.Severity = StateDown, SeverityWarn
		row.Detail = "runtime daemon did not answer: " + errText(err)
		row.Remedy = "sudo launchctl kickstart -k system/" + c.Paths.ServerLabel
		return row
	}
	row.Wide = map[string]string{"runtime": info.GetRuntimeName(), "version": info.GetRuntimeVersion(), "api": info.GetApiVersion()}
	if info.GetHealthy() {
		row.State, row.Severity = StateHealthy, SeverityOK
		row.Detail = fmt.Sprintf("%s %s, api %s", info.GetRuntimeName(), info.GetRuntimeVersion(), info.GetApiVersion())
		return row
	}
	row.State, row.Severity = StateUnhealthy, SeverityWarn
	row.Detail = fmt.Sprintf("%s reports unhealthy: %s", info.GetRuntimeName(), conditionSummary(info.GetConditions()))
	row.Remedy = "sudo launchctl kickstart -k system/" + c.Paths.ServerLabel
	return row
}

// conditionSummary names the conditions that are not true, which is the only
// part of the condition list a status line has room for.
func conditionSummary(conds []*runtimev1.RuntimeCondition) string {
	var bad []string
	for _, cond := range conds {
		if cond.GetStatus() != runtimev1.ConditionStatus_CONDITION_STATUS_TRUE {
			bad = append(bad, cond.GetType()+"="+strings.TrimSpace(cond.GetReason()))
		}
	}
	if len(bad) == 0 {
		return "no condition says why"
	}
	return strings.Join(bad, ", ")
}

// errText renders an error for a row detail, never empty.
func errText(err error) string {
	if err == nil {
		return "unknown"
	}
	return Redact(firstLine(err.Error()))
}

// firstLine reduces a multi-line body to its first non-empty line.
func firstLine(s string) string {
	for _, line := range strings.Split(s, "\n") {
		if strings.TrimSpace(line) != "" {
			return strings.TrimSpace(line)
		}
	}
	return strings.TrimSpace(s)
}

// plural renders a count with a singular or plural noun.
func plural(n int, noun string) string {
	if n == 1 {
		return fmt.Sprintf("%d %s", n, noun)
	}
	return fmt.Sprintf("%d %ss", n, noun)
}

// crashLoop folds the daemon's crash record into the server row (see
// crashloop.go). The record is read through the FS seam; when the collector has
// none, or no work dir, the row is left to launchd's verdict.
func (c Collector) crashLoop(row *Row) {
	if c.FS == nil || c.Paths.WorkDir == "" {
		return
	}
	path := executor.CrashLoopPath(c.Paths.WorkDir)
	now := time.Now()
	if c.Now != nil {
		now = c.Now()
	}
	b, err := c.FS.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return
	}
	var rec executor.CrashRecord
	if err == nil {
		err = json.Unmarshal(b, &rec)
	}
	applyCrashLoop(row, ClassifyCrashLoop(rec, err, path, now))
}

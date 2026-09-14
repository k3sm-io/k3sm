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
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
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

	install, installed := c.installRow()
	netd, _ := c.daemonRow(RowNetd, c.Paths.NetdLabel, c.Paths.NetdLog, false)
	server, serverPID := c.daemonRow(RowServer, c.Paths.ServerLabel, c.Paths.ServerLog, true)
	c.crashLoop(&server)
	apiserver := c.apiserverRow(ctx)
	serving := apiserver.Severity == SeverityOK
	dataRoot, volume := c.dataRootRow()

	rows := []Row{install}
	// The mount oneshot goes before netd, mirroring the order install lays the
	// three daemons down in, and exists only on a Mac that has a data volume:
	// every other Mac would get a row saying "not loaded" about a daemon it was
	// never meant to have.
	if volume != nil {
		rows = append(rows, c.oneshotRow(RowDatavol, c.Paths.DatavolLabel, c.Paths.DatavolLog))
	}
	rows = append(rows,
		netd,
		server,
		apiserver,
		c.nodeRow(ctx, serving),
		c.workloadsRow(ctx, serving, serverPID),
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

	verdict, summary, next := Aggregate(rows, installed)
	return Report{
		Verdict:   verdict,
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
// launcher symlink, and the two LaunchDaemon plists.
//
// It also decides `installed`, which gates the whole verdict — and does so on
// the BINARY plus the SERVER plist, not on all four parts, because a machine
// with those two has a cluster to report on even if the launcher link was
// removed by hand.
func (c Collector) installRow() (Row, bool) {
	row := Row{Name: RowInstall, Remedy: "sudo k3sm install"}
	binary := c.exists(c.Paths.Binary)
	netdPlist := c.exists(c.plistPath(c.Paths.NetdLabel))
	serverPlist := c.exists(c.plistPath(c.Paths.ServerLabel))

	link := false
	if c.FS != nil {
		if target, err := c.FS.Readlink(c.Paths.Link); err == nil {
			link = target == c.Paths.Binary
		}
	}
	installed := binary && serverPlist

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
	if !serverPlist {
		missing = append(missing, c.Paths.ServerLabel+".plist")
	}

	switch {
	case len(missing) == 0:
		row.State, row.Severity, row.Remedy = StateOK, SeverityOK, ""
		row.Detail = fmt.Sprintf("%s · launcher %s · 2 LaunchDaemons in %s", c.Paths.Binary, c.Paths.Link, c.Paths.LaunchDaemonDir)
	case len(missing) == 4:
		row.State, row.Severity = StateAbsent, SeverityFail
		row.Detail = "no k3sm install found on this Mac"
	default:
		row.State, row.Severity = StatePartial, SeverityWarn
		row.Detail = "missing: " + strings.Join(missing, ", ")
	}
	row.Wide = map[string]string{
		"binary": c.Paths.Binary,
		"link":   c.Paths.Link,
		"plists": c.Paths.LaunchDaemonDir,
	}
	return row, installed
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

// apiserverRow reports whether the control plane is serving, which is the single
// fact the verdict turns on.
func (c Collector) apiserverRow(ctx context.Context) Row {
	row := Row{Name: RowAPIServer}
	if c.Kube == nil {
		row.State, row.Severity = StateUnknown, SeverityUnknown
		row.Detail = "no kubeconfig: " + errText(c.KubeErr)
		row.Remedy = "sudo k3sm install\nk3sm kubeconfig --write"
		return row
	}
	row.Wide = map[string]string{"tls": c.Kube.TLSPosture(), "server": c.Kube.Server()}
	body, err := c.Kube.RawGet(ctx, "/readyz")
	if err != nil {
		row.State, row.Severity = StateDown, SeverityFail
		row.Detail = fmt.Sprintf("%s: %s", c.Kube.Server(), errText(err))
		row.Remedy = "sudo launchctl kickstart -k system/" + c.Paths.ServerLabel + "\nk3sm status logs server"
		return row
	}
	if strings.TrimSpace(string(body)) != "ok" {
		row.State, row.Severity = StateNotReady, SeverityWarn
		row.Detail = fmt.Sprintf("%s readyz: %s", c.Kube.Server(), firstLine(string(body)))
		row.Remedy = "k3sm status logs server"
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
func (c Collector) nodeRow(ctx context.Context, serving bool) Row {
	row := Row{Name: RowNode, Remedy: "k3sm status logs server"}
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
	return row
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
func (c Collector) dataRootRow() (Row, *dataroot.Record) {
	row := Row{Name: RowDataRoot}
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
		row.Detail = fmt.Sprintf("%s (%s volume %s, %s, mounted)", c.Paths.DataRoot, st.FSType, st.Volume.Name, c.usageClause(st.Volume))
		if c.nearlyFull(st.Volume) {
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
		row.Detail = fmt.Sprintf("%s (%s volume %s, mounted)", c.Paths.DataRoot, st.FSType, st.VolumeName)
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
	}
	return row, st.Volume
}

// nearlyFullFraction is the share of a volume's quota at which the data-root row
// starts warning. Ninety percent is the point at which the remaining headroom
// is comparable to what a single image pull or a few hours of datastore growth
// consumes, i.e. the last moment a warning is still an early one.
const nearlyFullFraction = 0.9

// usageClause renders the "29.9G of 100G used" half of the data-root detail, or
// "29.9G used" for a volume that carries no quota. It never prints "of 0": a
// volume with no quota can grow to fill its container, and saying it is using
// some of nothing would be worse than saying nothing about the bound.
func (c Collector) usageClause(rec *dataroot.Record) string {
	used, ok := c.usedBytes()
	switch {
	case ok && rec.QuotaBytes > 0:
		return fmt.Sprintf("%s of %s used", datavol.FormatSize(used), datavol.FormatSize(rec.QuotaBytes))
	case ok:
		return datavol.FormatSize(used) + " used"
	case rec.QuotaBytes > 0:
		return datavol.FormatSize(rec.QuotaBytes) + " quota"
	default:
		return "no quota"
	}
}

// nearlyFull reports whether the volume has passed nearlyFullFraction of its
// quota. A volume with no quota is never nearly full: there is no bound to be
// near, which is exactly what the warning would otherwise be claiming.
func (c Collector) nearlyFull(rec *dataroot.Record) bool {
	if rec.QuotaBytes == 0 {
		return false
	}
	used, ok := c.usedBytes()
	return ok && float64(used) >= float64(rec.QuotaBytes)*nearlyFullFraction
}

// usedBytes is the data root's consumption as statfs(2) reports it:
// (blocks - free) * block size, the same arithmetic `k3sm datavol status` does
// and the same numbers runtimed's reclaim ladder reads. It is unavailable
// rather than zero when the probe cannot answer, because a report that says a
// full volume is empty is worse than one that says nothing.
func (c Collector) usedBytes() (uint64, bool) {
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
	size := c.treeBytes(path, preVolumeWalkBudget)
	row := Row{
		Name:     RowPreVolume,
		State:    StateOK,
		Severity: SeverityWarn,
		Detail:   fmt.Sprintf("%s holds the pre-migration copy (%s, %s)", path, datavol.FormatSize(size), ageText(c.since(info.ModTime()))),
		Remedy:   "sudo rm -r " + path + "   # once you are satisfied with the migrated cluster",
		Wide:     map[string]string{"path": path, "bytes": fmt.Sprint(size)},
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
// error on one directory must not turn that into no answer at all.
func (c Collector) treeBytes(root string, budget int) uint64 {
	var total uint64
	visited := 0
	var walk func(dir string, depth int)
	walk = func(dir string, depth int) {
		if visited >= budget || depth > preVolumeWalkDepth {
			return
		}
		entries, err := c.DataRoot.ReadDir(dir)
		if err != nil {
			return
		}
		for _, e := range entries {
			if visited >= budget {
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
	return total
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

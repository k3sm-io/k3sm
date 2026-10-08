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
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math"
	"net"
	"net/http"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"k3sm.io/k3sm/pkg/executor"
)

// RowEtcd is the embedded etcd member of an HA server: quorum, alarms, size and
// fsync latency. The row exists only on a server in the etcd posture.
const RowEtcd = "etcd"

// etcdStaleAfter is how old the status record may get before the row stops
// vouching for it. The running server refreshes it every minute once it has quorum.
const etcdStaleAfter = 5 * time.Minute

// etcdQuotaWarnFraction is the DB-size share of the backend quota past which the row
// warns: at the quota etcd raises NOSPACE and the cluster turns read-only.
const etcdQuotaWarnFraction = 0.8

// etcdMetricsTimeout bounds the loopback metrics read.
const etcdMetricsTimeout = 2 * time.Second

// Remedies the etcd row names.
const (
	// EtcdNoSpaceRemedy is the NOSPACE runbook: the cluster is read-only until space
	// is reclaimed.
	EtcdNoSpaceRemedy = "reclaim space, then clear the alarm: compact the keyspace to the current revision, defragment every member, then disarm the NOSPACE alarm; writes resume only after the disarm"
	// EtcdNoLeaderRemedy is what to do when the member sees no leader.
	EtcdNoLeaderRemedy = "start the other servers (each waits for its peers); if a majority is gone for good, stop the daemon on one survivor and run `sudo k3sm server --cluster-reset` there, then start it again"
)

// walFsyncMetric is the WAL fsync latency histogram etcd exports.
const walFsyncMetric = "etcd_disk_wal_fsync_duration_seconds_bucket"

// WALFsyncP99 computes the 99th-percentile WAL fsync latency, in seconds, from etcd's
// Prometheus text exposition, the way histogram_quantile does: find the bucket the
// 0.99 rank falls in and interpolate linearly inside it. ok is false when the
// histogram is absent or has no observations. A rank that lands in the +Inf bucket
// reports the highest finite bound (the honest lower bound).
func WALFsyncP99(metrics []byte) (p99 float64, ok bool) {
	type bucket struct{ le, count float64 }
	var buckets []bucket
	sc := bufio.NewScanner(bytes.NewReader(metrics))
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		line := sc.Text()
		if !strings.HasPrefix(line, walFsyncMetric+"{") {
			continue
		}
		i := strings.Index(line, `le="`)
		if i < 0 {
			continue
		}
		rest := line[i+len(`le="`):]
		j := strings.IndexByte(rest, '"')
		if j < 0 {
			continue
		}
		le, err := strconv.ParseFloat(rest[:j], 64) // "+Inf" parses as +Inf
		if err != nil {
			continue
		}
		fields := strings.Fields(line[strings.LastIndexByte(line, '}')+1:])
		if len(fields) == 0 {
			continue
		}
		count, err := strconv.ParseFloat(fields[0], 64)
		if err != nil {
			continue
		}
		buckets = append(buckets, bucket{le, count})
	}
	if len(buckets) == 0 {
		return 0, false
	}
	sort.Slice(buckets, func(a, b int) bool { return buckets[a].le < buckets[b].le })
	total := buckets[len(buckets)-1].count
	if !math.IsInf(buckets[len(buckets)-1].le, 1) || total <= 0 {
		return 0, false
	}
	rank := 0.99 * total
	lower, below := 0.0, 0.0
	for _, b := range buckets {
		if b.count >= rank {
			if math.IsInf(b.le, 1) {
				return lower, true
			}
			if b.count == below {
				return b.le, true
			}
			return lower + (b.le-lower)*(rank-below)/(b.count-below), true
		}
		lower, below = b.le, b.count
	}
	return lower, true
}

// EtcdHealth judges an etcd status record: whether the member is healthy, a
// one-line detail, and the remedy when it is not. It is shared by `k3sm status`'s
// etcd row and `k3sm doctor`'s datastore check, so the two cannot disagree.
func EtcdHealth(st executor.EtcdStatus) (severity Severity, detail, remedy string) {
	var parts []string
	parts = append(parts, fmt.Sprintf("%d voting, %d learner", st.Members, st.Learners))
	if st.Learners != 1 {
		parts[0] += "s"
	}
	if st.LeaderPresent {
		parts = append(parts, "leader present")
	} else {
		parts = append(parts, "NO LEADER")
	}
	if st.QuotaBytes > 0 {
		parts = append(parts, fmt.Sprintf("db %s of %s quota", humanBytes(st.DBSizeBytes), humanBytes(st.QuotaBytes)))
	} else if st.DBSizeBytes > 0 {
		parts = append(parts, "db "+humanBytes(st.DBSizeBytes))
	}
	if len(st.Alarms) > 0 {
		parts = append(parts, "alarms: "+strings.Join(st.Alarms, ","))
	}
	detail = strings.Join(parts, ", ")

	switch {
	case st.Superseded:
		// Ahead of everything: this member's view of its own cluster is the
		// replaced cluster's, so every other figure here describes data that no
		// longer counts.
		return SeverityFail, executor.EtcdMemberSupersededMessage + " (" + st.SupersededDetail + ")", executor.EtcdMemberSupersededRemedy
	case slices.Contains(st.Alarms, "NOSPACE"):
		return SeverityFail, detail + "; the cluster is read-only (NOSPACE)", EtcdNoSpaceRemedy
	case len(st.Alarms) > 0:
		return SeverityFail, detail, "read the server log for the alarm's cause; a CORRUPT member must be removed and re-joined with a wiped etcd data dir"
	case !st.LeaderPresent:
		return SeverityFail, detail + "; writes are stopped until a majority of members is reachable", EtcdNoLeaderRemedy
	case st.PeerURLDrift:
		return SeverityWarn, fmt.Sprintf("%s; registered peer URL %s is not this server's %s", detail, strings.Join(st.RegisteredPeerURLs, ","), st.ExpectedPeerURL), executor.EtcdPeerURLDriftRemedy
	case st.QuotaBytes > 0 && float64(st.DBSizeBytes) >= etcdQuotaWarnFraction*float64(st.QuotaBytes):
		return SeverityWarn, detail + "; nearing the backend quota (NOSPACE makes the cluster read-only)", EtcdNoSpaceRemedy
	}
	return SeverityOK, detail, ""
}

// etcdRowFrom renders the etcd row from a status record and the live WAL fsync p99
// (nil when the metrics endpoint did not answer). Pure.
func etcdRowFrom(st executor.EtcdStatus, p99 *float64, now time.Time) Row {
	row := Row{Name: RowEtcd, Wide: map[string]string{"client": st.ClientURL, "peer": st.ExpectedPeerURL}}
	if !st.UpdatedAt.IsZero() {
		row.Wide["recorded"] = st.UpdatedAt.UTC().Format(time.RFC3339)
	}
	sev, detail, remedy := EtcdHealth(st)
	if p99 == nil {
		p99 = st.WALFsyncP99Seconds
	}
	if p99 != nil {
		detail += fmt.Sprintf(", wal fsync p99 %.1fms", *p99*1000)
	} else {
		detail += ", wal fsync p99 unknown"
	}
	stale := !st.UpdatedAt.IsZero() && now.Sub(st.UpdatedAt) > etcdStaleAfter
	switch {
	case sev == SeverityFail:
		row.State = StateUnhealthy
	case stale:
		// Only a failure outranks staleness: a record the server stopped
		// refreshing cannot vouch for a healthy member.
		row.State, row.Severity = StateUnknown, SeverityUnknown
		row.Detail = fmt.Sprintf("%s (recorded %s ago; the server is not refreshing it)", detail, now.Sub(st.UpdatedAt).Round(time.Second))
		return row
	case sev == SeverityWarn && st.PeerURLDrift:
		row.State = StateDrift
	case sev == SeverityWarn:
		row.State = StateUnhealthy
	default:
		row.State = StateHealthy
	}
	row.Severity, row.Detail, row.Remedy = sev, detail, remedy
	return row
}

// etcdRow reports this server's etcd member, or false when this is not an etcd
// server. The posture is the server plist's --cluster-init / --server-join, an
// initialized member dir, or a status record; the record is read through the FS
// seam, so a plain-user run of a 0700 work dir reports unknown, not a failure. The
// metrics endpoint is loopback-only and an unreachable one leaves the p99 unknown.
func (c Collector) etcdRow(ctx context.Context, serverArgs []string) (Row, bool) {
	wd := c.Paths.WorkDir
	if wd == "" {
		return Row{}, false
	}
	path := executor.EtcdStatusPath(wd)
	etcdArgs := argsSelectEtcd(serverArgs)
	if !etcdArgs && !executor.EtcdMemberExists(wd) && !c.exists(path) {
		return Row{}, false
	}
	row := Row{Name: RowEtcd, Wide: map[string]string{"record": path}}
	if c.FS == nil {
		row.State, row.Severity, row.Detail = StateUnknown, SeverityUnknown, "no filesystem probe wired"
		return row, true
	}
	raw, err := c.FS.ReadFile(path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		row.State, row.Severity = StateSkip, SeveritySkip
		row.Detail = "no etcd status recorded yet (the member has not started)"
		return row, true
	case err != nil:
		row.State, row.Severity = StateUnknown, SeverityUnknown
		row.Detail = "unreadable as this user: " + path
		row.Remedy = "sudo k3sm status"
		return row, true
	}
	var st executor.EtcdStatus
	if err := json.Unmarshal(raw, &st); err != nil {
		row.State, row.Severity = StateUnknown, SeverityUnknown
		row.Detail = "the etcd status record does not parse: " + path
		return row, true
	}
	var p99 *float64
	port := executor.DefaultEtcdMetricsPort
	if v, ok := flagFromArgs(serverArgs, "etcd-metrics-port"); ok {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n < 65536 {
			port = n
		}
	}
	fetch := c.EtcdMetrics
	if fetch == nil {
		fetch = httpGetLoopback
	}
	url := "http://" + net.JoinHostPort("127.0.0.1", strconv.Itoa(port)) + "/metrics"
	mctx, cancel := context.WithTimeout(ctx, etcdMetricsTimeout)
	defer cancel()
	if body, err := fetch(mctx, url); err == nil {
		if v, ok := WALFsyncP99(body); ok {
			p99 = &v
		}
	}
	now := time.Now()
	if c.Now != nil {
		now = c.Now()
	}
	out := etcdRowFrom(st, p99, now)
	out.Wide["record"] = path
	out.Wide["metrics"] = url
	return out, true
}

// httpGetLoopback is the shipped metrics reader.
func httpGetLoopback(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: %s", url, resp.Status)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 8<<20))
}

// argsSelectEtcd reports whether server arguments carry --cluster-init or
// --server-join (any dash count, bare or =true; =false does not count).
func argsSelectEtcd(args []string) bool {
	for _, a := range args {
		name, value, inline := strings.Cut(strings.TrimLeft(a, "-"), "=")
		if strings.HasPrefix(a, "-") && (name == "cluster-init" || name == "server-join") && (!inline || value != "false") {
			return true
		}
	}
	return false
}

// flagFromArgs returns a flag's value from server arguments, in either spelling
// (--name value / --name=value).
func flagFromArgs(args []string, name string) (string, bool) {
	for i, a := range args {
		if !strings.HasPrefix(a, "-") {
			continue
		}
		n, v, inline := strings.Cut(strings.TrimLeft(a, "-"), "=")
		if n != name {
			continue
		}
		if inline {
			return v, true
		}
		if i+1 < len(args) {
			return args[i+1], true
		}
	}
	return "", false
}

// humanBytes renders a byte count in binary units.
func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return strconv.FormatInt(n, 10) + " B"
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}

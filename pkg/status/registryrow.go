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
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"strconv"
	"time"

	"k3sm.io/k3sm/pkg/dataroot"
	"k3sm.io/k3sm/pkg/registrysvc"
)

// RowIngestRegistry reports the server's node-local OCI ingest registry: the
// state the server recorded for it (pkg/registrysvc's state record) and whether
// its /v2/ endpoint answers on loopback. The row exists only on a server that
// has written the record and whose installed arguments do not leave the
// registry off; a server older than the record writes none and gets no row.
const RowIngestRegistry = "ingest-registry"

// registryProbeTimeout bounds the /v2/ probe, so the row never holds a report
// open for longer than about a second.
const registryProbeTimeout = time.Second

// RegistryProbe is the ingest registry's liveness probe: an HTTP GET of url that
// returns nil when the registry answered.
type RegistryProbe func(ctx context.Context, url string) error

// ingestRegistryRow reports the ingest registry, or false when there is nothing
// to report: a worker, a server whose arguments configure no registry, or no
// state record.
func (c Collector) ingestRegistryRow(ctx context.Context, role dataroot.Role) (Row, bool) {
	wd := c.Paths.WorkDir
	if role == dataroot.RoleAgent || wd == "" || c.FS == nil {
		return Row{}, false
	}
	configured, known := c.registryConfigured()
	if known && !configured {
		return Row{}, false
	}
	path, raw, err := c.readRegistryState(wd)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return Row{}, false
	case errors.Is(err, fs.ErrPermission):
		if !known {
			// No argument list says a registry is configured, and the record
			// cannot be seen: there is nothing this account can report.
			return Row{}, false
		}
		row := Row{Name: RowIngestRegistry, Wide: map[string]string{"record": path}}
		needsAdmin(&row, "needs sudo: "+path+" is readable by root only, and no user-readable copy is in "+Dir(wd))
		return row, true
	case err != nil:
		return Row{Name: RowIngestRegistry, State: StateUnknown, Severity: SeverityUnknown,
			Detail: "could not read " + path + ": " + errText(err), Remedy: needsAdminRemedy}, true
	}
	st, err := registrysvc.ParseState(raw)
	if err != nil {
		return Row{Name: RowIngestRegistry, State: StateUnknown, Severity: SeverityUnknown,
			Detail: "the ingest registry state record does not parse: " + path}, true
	}
	var probeErr error
	if st.State == registrysvc.StateServing || st.State == registrysvc.StateReclaimed {
		probe := c.RegistryProbe
		if probe == nil {
			probe = probeRegistry
		}
		pctx, cancel := context.WithTimeout(ctx, registryProbeTimeout)
		probeErr = probe(pctx, registryProbeURL(st.Port))
		cancel()
	}
	row := ingestRegistryRowFrom(st, probeErr, c.registryRemedy())
	row.Wide["record"] = path
	return row, true
}

// readRegistryState reads the registry state record: the world-readable copy the
// server publishes in the status directory first, so an ordinary account (the
// app's) reads the same record root does, and the 0600 work-dir original only
// when no copy is there (a server older than the copy, or one with no status
// directory). It returns the path read, or the one that failed.
func (c Collector) readRegistryState(workDir string) (string, []byte, error) {
	published := registrysvc.PublishedStatePath(workDir)
	raw, err := c.FS.ReadFile(published)
	if !errors.Is(err, fs.ErrNotExist) {
		return published, raw, err
	}
	path := registrysvc.StatePath(workDir)
	raw, err = c.FS.ReadFile(path)
	return path, raw, err
}

// ingestRegistryRowFrom renders the row from a state record and the probe's
// answer (nil means /v2/ answered; it is ignored for a state that claims no
// listener). Pure.
func ingestRegistryRowFrom(st registrysvc.State, probeErr error, remedy string) Row {
	row := Row{Name: RowIngestRegistry, Wide: map[string]string{
		"port":  strconv.Itoa(st.Port),
		"since": st.Since.UTC().Format(time.RFC3339),
	}}
	addr := st.Addr
	if addr == "" {
		addr = net.JoinHostPort(registrysvc.LoopbackAddress, strconv.Itoa(st.Port))
	}
	switch st.State {
	case registrysvc.StateServing, registrysvc.StateReclaimed:
		if probeErr != nil {
			row.State, row.Severity = StateDown, SeverityWarn
			row.Detail = fmt.Sprintf("the server recorded it serving on %s, but /v2/ did not answer: %s", addr, errText(probeErr))
			row.Remedy = remedy
			return row
		}
		row.State, row.Severity = StateOK, SeverityOK
		row.Detail = "serving on " + addr
		if st.State == registrysvc.StateReclaimed {
			row.Detail += fmt.Sprintf("; reclaimed an orphaned registry child (pid %d) at this start", st.ReclaimedPID)
		}
		return row
	case registrysvc.StateDisabled:
		row.State, row.Severity = StateDisabled, SeverityWarn
		reason := "no reason recorded"
		if st.Reason != "" {
			reason = Redact(firstLine(st.Reason))
		}
		row.Detail = "disabled on " + addr + ": " + reason
		row.Remedy = remedy
		return row
	case registrysvc.StateStopped:
		row.State, row.Severity = StateStopped, SeveritySkip
		row.Detail = "stopped with the server"
		return row
	}
	row.State, row.Severity = StateUnknown, SeverityUnknown
	row.Detail = fmt.Sprintf("the ingest registry state record names an unknown state %q", st.State)
	return row
}

// registryRemedy is what to do about a registry that is not serving: read the
// server log for why, then restart the server, which brings the registry up again.
func (c Collector) registryRemedy() string {
	label := c.Paths.ServerLabel
	if label == "" {
		label = "io.k3sm.server"
	}
	return "k3sm status logs server\nsudo launchctl kickstart -k system/" + label
}

// registryConfigured reports whether the installed server's arguments configure
// the ingest registry (a --registry-port above 0), and whether that is known at
// all: no parser, no readable plist, or an unparsable one leaves it unknown, and
// the row then rests on the state record alone.
func (c Collector) registryConfigured() (configured, known bool) {
	if c.ServerArgs == nil || c.FS == nil || c.Paths.ServerLabel == "" {
		return false, false
	}
	raw, err := c.FS.ReadFile(c.plistPath(c.Paths.ServerLabel))
	if err != nil {
		return false, false
	}
	args, err := c.ServerArgs(raw)
	if err != nil {
		return false, false
	}
	v, ok := argValue(args, "registry-port")
	if !ok {
		return false, true
	}
	n, err := strconv.Atoi(v)
	return err == nil && n > 0, true
}

// registryProbeURL is the dist-spec base endpoint on the registry's loopback port.
func registryProbeURL(port int) string {
	return "http://" + net.JoinHostPort(registrysvc.LoopbackAddress, strconv.Itoa(port)) + "/v2/"
}

// probeRegistry is the shipped RegistryProbe. The URL is always 127.0.0.1
// (registryProbeURL), which the default client never sends through a proxy.
func probeRegistry(ctx context.Context, url string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	_ = resp.Body.Close()
	return registryAnswered(url, resp.StatusCode, resp.Status)
}

// registryAnswered decides whether a /v2/ status is a registry serving. The
// distribution spec answers /v2/ with 200, or 401 where it wants a credential;
// any other status is not a registry serving.
func registryAnswered(url string, code int, status string) error {
	if code != http.StatusOK && code != http.StatusUnauthorized {
		return fmt.Errorf("GET %s: %s", url, status)
	}
	return nil
}

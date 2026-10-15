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
	"strings"
	"time"
)

// RowServices compares the Ready backends this server's Service proxy routes
// each Service port to with the Ready endpoints the API's EndpointSlices hold. It
// exists only on a server, and only when a comparer is wired in.
const RowServices = "services"

// servicesStaleAfter is how old the record may get before the row stops
// vouching for it: two refreshes missed.
const servicesStaleAfter = 2 * ServicesRecordInterval

// ServicesRemedy is what to do about a Service port whose backends differ.
const ServicesRemedy = "the proxy re-lists Services and EndpointSlices every 30 seconds and repairs a lost update; if the row still differs after a minute, restart the server (`sudo launchctl kickstart -k system/io.k3sm.server`)"

// ServicesComparer compares a services record with the API. It is a seam because
// the comparison belongs to the Service proxy's own package, which this
// reporting leaf does not import; cmd/k3sm wires svcstatus.Comparer here.
type ServicesComparer interface {
	CompareServices(ctx context.Context, rec ServicesRecord) (ServicesComparison, error)
}

// ServicesComparison is the answer of a ServicesComparer.
type ServicesComparison struct {
	// Diverging are the Service ports whose routed backends differ from the API
	// although nothing about them changed after the record was written.
	Diverging []ServicePortDivergence
	// Settling are the Service ports that differ and whose Service or
	// EndpointSlices changed after the record was written (or whose Service is
	// gone), so the record cannot have seen the change yet.
	Settling []ServicePortDivergence
}

// ServicePortDivergence is one Service port whose backend sets differ.
type ServicePortDivergence struct {
	// Namespace and Name identify the Service; both are empty when no Service
	// owns the port.
	Namespace string
	Name      string
	// Port is clusterIP:port/protocol.
	Port string
	// Missing are the Ready endpoints the API has and the proxy does not route;
	// Extra are the backends the proxy routes and the API does not have Ready.
	Missing []string
	Extra   []string
}

// servicesRow reports the proxy's backend sets against the API, or false when
// this report has no comparer or no work dir. It reads the record before it
// lists anything, so a run that cannot read the record costs no API call.
func (c Collector) servicesRow(ctx context.Context, serving bool, now time.Time) (Row, bool) {
	wd := c.Paths.WorkDir
	if wd == "" || c.FS == nil || c.Services == nil {
		return Row{}, false
	}
	path := ServicesPath(wd)
	row := Row{Name: RowServices, State: StateUnknown, Severity: SeverityUnknown, Wide: map[string]string{"record": path}}
	raw, err := c.FS.ReadFile(path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		row.Detail = "the server has not recorded its Service proxy yet (it does 30 seconds after it starts)"
		return row, true
	case err != nil:
		row.Detail, row.Remedy = "unreadable as this user: "+path, "sudo k3sm status"
		return row, true
	}
	var rec ServicesRecord
	if err := json.Unmarshal(raw, &rec); err != nil {
		row.Detail = "the Service proxy record does not parse: " + path
		return row, true
	}
	row.Wide["recorded"] = rec.UpdatedAt.UTC().Format(time.RFC3339)
	if age := now.Sub(rec.UpdatedAt); age > servicesStaleAfter {
		row.Detail = fmt.Sprintf("recorded %s ago; the server is not refreshing it", age.Round(time.Second))
		return row, true
	}
	if !serving {
		row.Detail = "the apiserver is not serving, so there is nothing to compare the Service proxy with"
		return row, true
	}
	cmp, err := c.Services.CompareServices(ctx, rec)
	if err != nil {
		row.Detail = "could not list Services and EndpointSlices: " + firstLine(err.Error())
		return row, true
	}
	return servicesRowFrom(row, rec, cmp), true
}

// servicesRowFrom renders the verdict of a comparison onto row. Pure.
func servicesRowFrom(row Row, rec ServicesRecord, cmp ServicesComparison) Row {
	row.Wide["ports"] = fmt.Sprint(len(rec.VIPs))
	if len(cmp.Settling) > 0 {
		row.Wide["settling"] = describeDivergences(cmp.Settling)
	}
	if len(cmp.Diverging) == 0 {
		row.State, row.Severity = StateOK, SeverityOK
		row.Detail = fmt.Sprintf("%d Service port(s) route to the API's Ready endpoints", len(rec.VIPs))
		if n := len(cmp.Settling); n > 0 {
			row.Detail += fmt.Sprintf("; %d changed since the record and are not compared yet", n)
		}
		return row
	}
	row.State, row.Severity = StateUnhealthy, SeverityWarn
	row.Detail = fmt.Sprintf("%d Service port(s) route to backends that differ from the API's Ready endpoints: %s",
		len(cmp.Diverging), describeDivergences(cmp.Diverging))
	row.Remedy = ServicesRemedy
	return row
}

// describeDivergences renders each port as "ns/name ip:port/proto missing a, b
// extra c", joined with "; ".
func describeDivergences(ds []ServicePortDivergence) string {
	parts := make([]string, 0, len(ds))
	for _, d := range ds {
		owner := "(no Service)"
		if d.Name != "" {
			owner = d.Namespace + "/" + d.Name
		}
		p := owner + " " + d.Port
		if len(d.Missing) > 0 {
			p += " missing " + strings.Join(d.Missing, ", ")
		}
		if len(d.Extra) > 0 {
			p += " extra " + strings.Join(d.Extra, ", ")
		}
		parts = append(parts, p)
	}
	return strings.Join(parts, "; ")
}

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
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"strings"

	corev1 "k8s.io/api/core/v1"

	"k3sm.io/k3sm/pkg/certs"
)

// RowRequestHeader is the aggregation layer's trust root as this server sees it: its
// HA role (mint-authority or joined, from the installed arguments), its own
// request-header CA pin, and how many request-header CAs the cluster trusts in
// kube-system/extension-apiserver-authentication. It is how an operator picks the
// server to upgrade first and tells when an HA upgrade is done: every server shows
// the same pin and a count of 1.
const RowRequestHeader = "request-header"

// extensionAuthConfigMapPath is the ConfigMap the apiserver's cluster-authentication
// trust controller publishes the request-header trust in.
const extensionAuthConfigMapPath = "/api/v1/namespaces/kube-system/configmaps/extension-apiserver-authentication"

// requestHeaderRow reports RowRequestHeader. It exists on a server in the etcd HA
// posture, and on any server whose work dir holds a request-header CA; it reports
// ok=false elsewhere (an agent, or a server that predates the CA outside HA).
//
// It WARNs when the cluster trusts more than one request-header CA (a second
// impersonation root: the trust controller unions every apiserver's CA and drops one
// only when it expires), when the one it trusts is not this server's, and when an HA
// server holds none (it has not booted this release, or it is a joined server waiting
// on its bundle source). An unread count is not a warning: the apiserver row already
// says why the cluster could not be asked.
func (c Collector) requestHeaderRow(ctx context.Context, serverArgs []string, serving bool) (Row, bool) {
	wd := c.Paths.WorkDir
	if wd == "" || c.FS == nil {
		return Row{}, false
	}
	path := certs.RequestHeaderCACertPath(wd)
	ha := argsSelectEtcd(serverArgs)
	if !ha && !c.exists(path) {
		return Row{}, false
	}
	role := certs.RoleMintAuthority
	if v, ok := flagFromArgs(serverArgs, "server-join"); ok && v != "false" {
		role = certs.RoleJoined
	}
	row := Row{Name: RowRequestHeader, Wide: map[string]string{"ha-role": role.String(), "ca": path}}

	pin := ""
	raw, err := c.FS.ReadFile(path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
	case err != nil:
		row.State, row.Severity = StateUnknown, SeverityUnknown
		row.Detail = fmt.Sprintf("ha-role %s · request-header CA unreadable as this user: %s", role, path)
		row.Remedy = "sudo k3sm status"
		return row, true
	default:
		if pin, err = certs.CertPin(raw); err != nil {
			row.State, row.Severity = StateCorrupt, SeverityWarn
			row.Detail = fmt.Sprintf("ha-role %s · %s does not parse as a certificate", role, path)
			return row, true
		}
	}
	row.Wide["pin"] = pin
	if pin == "" {
		row.State, row.Severity = StateAbsent, SeverityWarn
		row.Detail = fmt.Sprintf("ha-role %s · no request-header CA on this server: it has not booted a release with the aggregation layer, or it is a joined server waiting for its bundle source", role)
		row.Remedy = "upgrade the mint-authority server first; then restart this one with its install flags"
		return row, true
	}

	trusted, why := c.trustedRequestHeaderPins(ctx, serving)
	row.State, row.Severity = StateOK, SeverityOK
	switch {
	case trusted == nil:
		row.Detail = fmt.Sprintf("ha-role %s · request-header CA sha256:%s · trusted count not read (%s)", role, shortPin(pin), why)
	case len(trusted) > 1:
		row.Severity = SeverityWarn
		row.Detail = fmt.Sprintf("ha-role %s · request-header CA sha256:%s · %d request-header CAs trusted in extension-apiserver-authentication, want 1: a second impersonation root exists", role, shortPin(pin), len(trusted))
		row.Remedy = "compare this row on every server; a CA no server holds came from outside the upgrade procedure and must be investigated"
	case len(trusted) == 1 && trusted[0] != pin:
		row.Severity = SeverityWarn
		row.Detail = fmt.Sprintf("ha-role %s · request-header CA sha256:%s · the cluster trusts sha256:%s, not this server's", role, shortPin(pin), shortPin(trusted[0]))
		row.Remedy = "compare this row on every server: every server must hold the same request-header CA"
	default:
		row.Detail = fmt.Sprintf("ha-role %s · request-header CA sha256:%s · %d trusted in extension-apiserver-authentication", role, shortPin(pin), len(trusted))
	}
	row.Wide["trusted"] = strings.Join(trusted, ",")
	return row, true
}

// trustedRequestHeaderPins returns the pins of the certificates in the cluster's
// requestheader-client-ca-file, or nil and the reason they could not be read.
func (c Collector) trustedRequestHeaderPins(ctx context.Context, serving bool) ([]string, string) {
	if c.Kube == nil || !serving {
		return nil, "the apiserver is not serving"
	}
	body, err := c.Kube.RawGet(ctx, extensionAuthConfigMapPath)
	if err != nil {
		return nil, "extension-apiserver-authentication not readable"
	}
	var cm corev1.ConfigMap
	if err := json.Unmarshal(body, &cm); err != nil {
		return nil, "extension-apiserver-authentication does not parse"
	}
	bundle, ok := cm.Data["requestheader-client-ca-file"]
	if !ok {
		return nil, "no request-header trust published yet"
	}
	pins := []string{}
	rest := []byte(bundle)
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		if p, err := certs.CertPin(pem.EncodeToMemory(block)); err == nil {
			pins = append(pins, p)
		}
	}
	return pins, ""
}

// shortPin is a pin's first 16 hex digits, enough to compare rows by eye.
func shortPin(pin string) string {
	if len(pin) > 16 {
		return pin[:16]
	}
	return pin
}

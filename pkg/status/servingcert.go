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
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"time"

	"k8s.io/client-go/tools/clientcmd"

	"k3sm.io/k3sm/pkg/certs"
	"k3sm.io/k3sm/pkg/dataroot"
	"k3sm.io/k3sm/pkg/install"
)

// RowServingCert is the apiserver's serving certificate as this server holds it:
// present, issued by this server's cluster CA, and in date. Every server, single-node
// and mesh, issues it from the cluster CA on every boot and the control plane does
// not start without it, so a row that is not ok names the file and the recovery.
const RowServingCert = "serving-cert"

// servingCertRow reports RowServingCert. It exists on a server whose work dir holds
// a cluster CA (a control plane has booted there); it reports ok=false elsewhere.
// An unreadable work dir (a plain-user run) is an unknown row, not a failure.
func (c Collector) servingCertRow(now time.Time) (Row, bool) {
	wd := c.Paths.WorkDir
	if wd == "" || c.FS == nil {
		return Row{}, false
	}
	caPath, leafPath := certs.ClusterCACertPath(wd), certs.APIServerServingCertPath(wd)
	row := Row{Name: RowServingCert, Wide: map[string]string{"cert": leafPath, "ca": caPath}}
	caRaw, err := c.FS.ReadFile(caPath)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return Row{}, false
	case err != nil:
		row.State, row.Severity = StateUnknown, SeverityUnknown
		row.Detail = "the apiserver serving certificate is unreadable as this user: " + leafPath
		row.Remedy = "sudo k3sm status"
		return row, true
	}
	remedy := "sudo launchctl kickstart -k system/" + c.Paths.ServerLabel +
		"\nor remove " + leafPath + " and " + certs.APIServerServingKeyPath(wd) + ", then kickstart"
	leafRaw, err := c.FS.ReadFile(leafPath)
	if err != nil {
		row.State, row.Severity = StateAbsent, SeverityFail
		row.Detail = "no apiserver serving certificate at " + leafPath + "; the control plane issues it from the cluster CA on every start and does not start without it"
		row.Remedy = remedy
		return row, true
	}
	ca, caErr := parseFirstCert(caRaw)
	leaf, leafErr := parseFirstCert(leafRaw)
	switch {
	case caErr != nil:
		row.State, row.Severity = StateCorrupt, SeverityFail
		row.Detail = fmt.Sprintf("the cluster CA %s does not parse: %v", caPath, caErr)
		return row, true
	case leafErr != nil:
		row.State, row.Severity = StateCorrupt, SeverityFail
		row.Detail = fmt.Sprintf("the apiserver serving certificate %s does not parse: %v", leafPath, leafErr)
		row.Remedy = remedy
		return row, true
	case leaf.CheckSignatureFrom(ca) != nil:
		row.State, row.Severity = StateCorrupt, SeverityFail
		row.Detail = "the apiserver serving certificate " + leafPath + " is not issued by this server's cluster CA"
		row.Remedy = remedy
		return row, true
	case now.After(leaf.NotAfter):
		row.State, row.Severity = StateExpired, SeverityFail
		row.Detail = fmt.Sprintf("the apiserver serving certificate %s expired %s", leafPath, leaf.NotAfter.UTC().Format(time.RFC3339))
		row.Remedy = remedy
		return row, true
	}
	row.Wide["not-after"] = leaf.NotAfter.UTC().Format(time.RFC3339)
	row.State, row.Severity = StateOK, SeverityOK
	row.Detail = "issued by the cluster CA, valid until " + leaf.NotAfter.UTC().Format("2006-01-02")
	return row, true
}

// parseFirstCert parses the first CERTIFICATE block of a PEM file.
func parseFirstCert(raw []byte) (*x509.Certificate, error) {
	for rest := raw; ; {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			return nil, errors.New("no certificate block")
		}
		if block.Type == "CERTIFICATE" {
			return x509.ParseCertificate(block.Bytes)
		}
	}
}

// RowAdminKubeconfig is the admin kubeconfig `k3sm install` wrote, checked against
// this server's cluster CA: its certificate-authority-data must be the cluster CA
// and it must not skip verification. A daemon restarted onto a new release without
// `sudo k3sm install` leaves a kubeconfig that pins the old anchor; this row is how
// that shows. Only root runs the check, and only on the path install recorded in
// the server arguments record: it never guesses a home directory.
const RowAdminKubeconfig = "admin-kubeconfig"

// adminKubeconfigAnchorRow reports RowAdminKubeconfig. Like servingCertRow it
// exists only on a server whose work dir holds a cluster CA.
func (c Collector) adminKubeconfigAnchorRow() (Row, bool) {
	wd := c.Paths.WorkDir
	if wd == "" || c.FS == nil {
		return Row{}, false
	}
	row := Row{Name: RowAdminKubeconfig}
	skip := func(detail, remedy string) (Row, bool) {
		row.State, row.Severity, row.Detail, row.Remedy = StateSkip, SeveritySkip, detail, remedy
		return row, true
	}
	if c.EUID != 0 {
		// A plain user cannot see inside the 0700 work dir, so only a definite
		// "no cluster CA here" drops the row.
		if _, err := c.FS.Stat(certs.ClusterCACertPath(wd)); errors.Is(err, fs.ErrNotExist) {
			return Row{}, false
		}
		return skip("not checked: not root", "sudo k3sm status")
	}
	caRaw, err := c.FS.ReadFile(certs.ClusterCACertPath(wd))
	if err != nil {
		return Row{}, false
	}
	recordPath := c.Paths.ServerArgsRecord
	if recordPath == "" {
		recordPath = dataroot.DefaultServerArgsRecordPath
	}
	rec, err := dataroot.ReadServerArgsRecord(c.FS, recordPath)
	if err != nil || rec == nil || rec.AdminKubeconfig == "" {
		return skip("not recorded", "sudo k3sm install")
	}
	path := rec.AdminKubeconfig
	row.Wide = map[string]string{"kubeconfig": path}
	mismatch := func(why string) (Row, bool) {
		row.State, row.Severity = StateDrift, SeverityWarn
		row.Detail = "MISMATCH: re-run sudo k3sm install (" + why + ")"
		row.Remedy = "sudo k3sm install"
		return row, true
	}
	name := install.DefaultKubeconfigName
	if n, err := install.InstalledKubeconfigName(c.FS.ReadFile, c.plistPath(c.Paths.ServerLabel), recordPath); err == nil {
		name = n
	}
	raw, err := c.FS.ReadFile(path)
	if err != nil {
		return mismatch(path + " is not readable")
	}
	kc, err := clientcmd.Load(raw)
	if err != nil {
		return mismatch(path + " does not parse")
	}
	kctx := kc.Contexts[name]
	if kctx == nil || kc.Clusters[kctx.Cluster] == nil {
		return mismatch(fmt.Sprintf("%s has no %q context", path, name))
	}
	cl := kc.Clusters[kctx.Cluster]
	if cl.InsecureSkipTLSVerify || !bytes.Equal(bytes.TrimSpace(cl.CertificateAuthorityData), bytes.TrimSpace(caRaw)) {
		return mismatch(fmt.Sprintf("the %q context in %s does not pin the cluster CA", name, path))
	}
	row.State, row.Severity = StateOK, SeverityOK
	row.Detail = "admin kubeconfig anchor: cluster CA"
	return row, true
}

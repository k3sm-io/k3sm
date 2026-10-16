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
	"context"
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
// An unreadable work dir (a plain-user run) reads the certificate the apiserver
// presents in its TLS handshake instead (servingCertFromHandshake), and is an
// unknown row, not a failure, when that cannot be read either.
func (c Collector) servingCertRow(ctx context.Context, now time.Time) (Row, bool) {
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
	case errors.Is(err, fs.ErrPermission) && c.ServingChain != nil:
		return c.servingCertFromHandshake(ctx, row, now), true
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

// PresentedChain is what an apiserver presented in a TLS handshake, read the way
// kubectl reaches it: the chain it sent, the name it was reached by, and the CA
// the reader's kubeconfig pins for it.
type PresentedChain struct {
	// Server is the apiserver URL that was dialled.
	Server string
	// Host is the name the leaf must carry: the kubeconfig's TLS server name
	// when it sets one, else the URL's host.
	Host string
	// Chain is the certificates the apiserver sent, leaf first.
	Chain []*x509.Certificate
	// CA is the PEM the kubeconfig pins; empty when it pins none.
	CA []byte
}

// servingCertFromHandshake fills the serving-cert row from the chain the
// apiserver presents, for an account that may not read the certificate file.
// It runs the file path's checks on that certificate: in date, issued by the CA
// the reader's kubeconfig pins (the trust kubectl uses), and naming the host it
// was reached by. It vouches for nothing unless ServerAnchor accepts the
// endpoint as this server's own control plane.
func (c Collector) servingCertFromHandshake(ctx context.Context, row Row, now time.Time) Row {
	row.Wide["source"] = "handshake"
	pc, err := c.ServingChain(ctx)
	if pc.Server != "" {
		row.Wide["server"] = pc.Server
	}
	if err == nil && len(pc.Chain) == 0 {
		err = errors.New("the apiserver presented no certificate")
	}
	if err != nil {
		row.State, row.Severity = StateUnknown, SeverityUnknown
		row.Detail = "the serving certificate file is unreadable as this user, and the apiserver's TLS handshake could not be read: " + errText(err)
		row.Remedy = "sudo k3sm status"
		return row
	}
	if !c.anchored(pc.Server) {
		row.State, row.Severity = StateUnknown, SeverityUnknown
		row.Detail = "the serving certificate file is unreadable as this user, and " + NotThisServerDetail + " (" + pc.Server + ")"
		row.Remedy = "sudo k3sm status"
		return row
	}
	leaf := pc.Chain[0]
	row.Wide["not-after"] = leaf.NotAfter.UTC().Format(time.RFC3339)
	if now.After(leaf.NotAfter) {
		row.State, row.Severity = StateExpired, SeverityFail
		row.Detail = "the certificate the apiserver presents expired " + leaf.NotAfter.UTC().Format(time.RFC3339)
		row.Remedy = "sudo k3sm status"
		return row
	}
	roots := x509.NewCertPool()
	if len(pc.CA) == 0 || !roots.AppendCertsFromPEM(pc.CA) {
		row.State, row.Severity = StateUnknown, SeverityUnknown
		row.Detail = "the apiserver presents a certificate valid until " + leaf.NotAfter.UTC().Format("2006-01-02") +
			", and your kubeconfig pins no cluster CA to check its issuer against"
		row.Remedy = "k3sm kubeconfig --write\nsudo k3sm status"
		return row
	}
	intermediates := x509.NewCertPool()
	for _, cert := range pc.Chain[1:] {
		intermediates.AddCert(cert)
	}
	_, err = leaf.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		DNSName:       pc.Host,
		CurrentTime:   now,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	var hostErr x509.HostnameError
	var authErr x509.UnknownAuthorityError
	switch {
	case errors.As(err, &hostErr):
		row.State, row.Severity = StateCorrupt, SeverityFail
		row.Detail = fmt.Sprintf("the certificate the apiserver presents does not name %s, the host it was reached by", pc.Host)
		row.Remedy = "sudo k3sm status"
	case errors.As(err, &authErr):
		row.State, row.Severity = StateCorrupt, SeverityFail
		row.Detail = "the certificate the apiserver presents is not issued by the CA your kubeconfig pins"
		row.Remedy = "sudo k3sm status"
	case err != nil:
		row.State, row.Severity = StateCorrupt, SeverityFail
		row.Detail = "the certificate the apiserver presents does not verify against the CA your kubeconfig pins: " + errText(err)
		row.Remedy = "sudo k3sm status"
	default:
		row.State, row.Severity = StateOK, SeverityOK
		row.Detail = "issued by the CA your kubeconfig pins, valid until " + leaf.NotAfter.UTC().Format("2006-01-02") + " (read from the TLS handshake)"
	}
	return row
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
		needsAdmin(&row, "needs sudo: only root checks the admin kubeconfig against the cluster CA")
		return row, true
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

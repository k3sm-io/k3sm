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

package certs

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"k3sm.io/k3sm/internal/atomicfile"
)

// ErrHierarchyDiverged reports that a CA already on disk is not the CA the imported
// bootstrap bundle carries (their pins differ). A server that holds one CA of a
// hierarchy and is handed a different one must stop: replacing the local CA would
// orphan every certificate it issued, and keeping it beside the bundle's others
// would split cluster trust. Compare with errors.Is.
var ErrHierarchyDiverged = errors.New("certs: the local CA hierarchy diverges from the imported bundle")

// MissingOnDisk returns the ids of the CAs posture needs whose certificate AND private
// key are both absent from workDir's PKI directory, in table order. It creates nothing
// and opens no file: every path is lstat'ed only.
//
// A half-present CA (a key without its certificate, or a certificate without its key)
// is never "missing": it is an ErrIncompleteHierarchy naming the leftover file and the
// remedy (remove it and restart, so the server-join re-imports that CA). An install
// that crashed between the key and the certificate leaves exactly that, and
// re-importing over it would hide which half survived. An entry that is not a regular
// file is also an ErrIncompleteHierarchy.
func MissingOnDisk(workDir string, posture Posture) ([]CAID, error) {
	rows, err := postureRows(posture)
	if err != nil {
		return nil, err
	}
	var missing []CAID
	for _, spec := range rows {
		present, err := caOnDisk(workDir, spec)
		if err != nil {
			return nil, err
		}
		if !present {
			missing = append(missing, spec.id)
		}
	}
	return missing, nil
}

// ReconcileImportedHierarchy brings workDir's on-disk CA hierarchy level with h, the
// hierarchy an HA server-join decoded from the bootstrap bundle, for every CA posture
// needs, without ever replacing a CA that is already present.
//
// Before touching the disk it validates every bundle CA: h must hold all of them
// (Hierarchy.Missing), and each must be a self-signed, path-length-zero CA whose key
// is its certificate's (LoadCA). It then removes any temp file a killed earlier
// install left beside a CA file (atomicfile.ReapOrphans), and runs in two passes. The
// first writes nothing: every CA present on disk is compared with the bundle's by pin
// (certificate only; no private key is read), and any difference returns
// ErrHierarchyDiverged naming both pins; a half-present CA returns
// ErrIncompleteHierarchy (see MissingOnDisk). Only when every CA checks out does the
// second pass install the absent ones, the key before the certificate, each through
// atomicfile.WriteNew: an existing file fails with fs.ErrExist and is never replaced,
// and a crash leaves at most a key without its certificate, which MissingOnDisk and
// EnsureHierarchy then report. Keys are 0600, certificates 0644, the etcd pairs go
// under <PKI>/etcd (0700). A hierarchy that is already complete and identical is a
// no-op.
func ReconcileImportedHierarchy(workDir string, h *Hierarchy, posture Posture) error {
	rows, err := postureRows(posture)
	if err != nil {
		return err
	}
	if missing := h.Missing(posture); len(missing) > 0 {
		return fmt.Errorf("certs: reconcile hierarchy: the bundle lacks the %s CA; nothing was written", joinIDs(missing))
	}
	for _, spec := range rows {
		if err := validateBundleCA(spec.ca(h)); err != nil {
			return fmt.Errorf("certs: reconcile hierarchy: the bundle's %s CA: %w; nothing was written", spec.label, err)
		}
	}
	if err := reapOrphanTemps(workDir); err != nil {
		return err
	}
	var missing []caSpec
	for _, spec := range rows {
		present, err := caOnDisk(workDir, spec)
		if err != nil {
			return err
		}
		if !present {
			missing = append(missing, spec)
			continue
		}
		dir := spec.dir(workDir)
		local, err := caPin(filepath.Join(dir, spec.certFile), filepath.Join(dir, spec.keyFile))
		if err != nil {
			return fmt.Errorf("%s CA: %w", spec.id, err)
		}
		imported, err := CertPin(spec.ca(h).CertPEM)
		if err != nil {
			return fmt.Errorf("%s CA: bundle certificate: %w", spec.id, err)
		}
		if local != imported {
			return fmt.Errorf("%w: %s CA: local pin %s, bundle pin %s; the local CA is kept and nothing was written",
				ErrHierarchyDiverged, spec.id, local, imported)
		}
	}
	for _, spec := range missing {
		dir, err := spec.ensureDir(workDir)
		if err != nil {
			return err
		}
		ca := spec.ca(h)
		if err := installCAFile(dir, spec.keyFile, ca.KeyPEM, 0o600); err != nil {
			return fmt.Errorf("%s CA: %w", spec.id, err)
		}
		if err := installCAFile(dir, spec.certFile, ca.CertPEM, 0o644); err != nil {
			return fmt.Errorf("%s CA: %w", spec.id, err)
		}
	}
	return nil
}

// validateBundleCA checks that ca's PEMs (the bytes that would be installed) are a
// self-signed, path-length-zero CA certificate and its own private key.
func validateBundleCA(ca *CA) error {
	loaded, err := LoadCA(ca.CertPEM, ca.KeyPEM)
	if err != nil {
		return err
	}
	c := loaded.Cert
	if !c.BasicConstraintsValid || !c.IsCA || !c.MaxPathLenZero || c.MaxPathLen != 0 {
		return errors.New("the certificate is not a path-length-zero CA")
	}
	if err := c.CheckSignatureFrom(c); err != nil {
		return fmt.Errorf("the certificate is not self-signed: %w", err)
	}
	return nil
}

// caOnDisk reports whether spec's CA keypair is fully present under workDir (true) or
// fully absent (false). A half-present pair and a non-regular entry are errors.
func caOnDisk(workDir string, spec caSpec) (bool, error) {
	dir := spec.dir(workDir)
	certPath := filepath.Join(dir, spec.certFile)
	keyPath := filepath.Join(dir, spec.keyFile)
	certOK, err := regularExists(certPath)
	if err != nil {
		return false, err
	}
	keyOK, err := regularExists(keyPath)
	if err != nil {
		return false, err
	}
	if certOK == keyOK {
		return certOK, nil
	}
	orphan, absent := certPath, keyPath
	if keyOK {
		orphan, absent = keyPath, certPath
	}
	return false, fmt.Errorf("%w: the %s CA is half-present: %s exists but %s does not; remove %s and restart, and the server-join re-imports the %s CA from the bootstrap bundle",
		ErrIncompleteHierarchy, spec.id, orphan, absent, orphan, spec.id)
}

// regularExists lstats path: absent is (false, nil), a regular file is (true, nil),
// anything else is ErrIncompleteHierarchy, and a stat failure other than absence is
// returned wrapped.
func regularExists(path string) (bool, error) {
	info, err := os.Lstat(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return false, nil
		}
		return false, fmt.Errorf("stat %s: %w", path, err)
	}
	if !info.Mode().IsRegular() {
		return false, fmt.Errorf("%w: %s is not a regular file", ErrIncompleteHierarchy, path)
	}
	return true, nil
}

// installCAFile is the one write of a reconciled CA file: installNew, swapped only by
// the tests that crash an install between its key and its certificate.
var installCAFile = installNew

// installNew installs data at dir/name with mode through atomicfile.WriteNew, so an
// existing file is never replaced and no temp file outlives the call.
func installNew(dir, name string, data []byte, mode os.FileMode) error {
	if err := atomicfile.WriteNew(filepath.Join(dir, name), data, mode); err != nil {
		if errors.Is(err, fs.ErrExist) {
			return fmt.Errorf("certs: install %s: already exists (refusing to overwrite an existing CA): %w", name, err)
		}
		return fmt.Errorf("install %s: %w", name, err)
	}
	return nil
}

// reapOrphanTemps removes the temp files a killed install of any CA file may have left
// (a 0600 temp can hold a CA private key). Only atomicfile's own temp names go.
func reapOrphanTemps(workDir string) error {
	for _, spec := range caSpecs {
		dir := spec.dir(workDir)
		for _, name := range []string{spec.certFile, spec.keyFile} {
			if err := atomicfile.ReapOrphans(dir, name); err != nil {
				return fmt.Errorf("%s CA: %w", spec.id, err)
			}
		}
	}
	return nil
}

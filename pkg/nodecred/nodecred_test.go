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

package nodecred

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io/fs"
	"math/big"
	"net"
	"path/filepath"
	"testing"
	"time"

	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
)

// mapFS is a credential store held in memory: the artifacts it has, and the
// ones it refuses to hand over. It is how a test describes a store no
// unprivileged process could create on a real disk — most importantly the
// service-user-owned directory an ordinary `k3sm status` run cannot read.
type mapFS struct {
	files  map[string][]byte
	denied map[string]bool
}

func (m mapFS) Stat(name string) (fs.FileInfo, error) {
	if m.denied[name] {
		return nil, &fs.PathError{Op: "stat", Path: name, Err: fs.ErrPermission}
	}
	if _, ok := m.files[name]; !ok {
		return nil, &fs.PathError{Op: "stat", Path: name, Err: fs.ErrNotExist}
	}
	return nil, nil
}

func (m mapFS) ReadFile(name string) ([]byte, error) {
	if m.denied[name] {
		return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrPermission}
	}
	blob, ok := m.files[name]
	if !ok {
		return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrNotExist}
	}
	return blob, nil
}

const testDir = "/var/lib/k3sm/agent"

// testMeshIP is the mesh address the staged assignment names — the address the
// server assigned this node, and therefore the one its serving certificate has
// to carry as an IP SAN.
const testMeshIP = "100.64.2.1"

// storeFiles builds a complete, self-consistent store whose certificates expire
// at notAfter. The keypairs genuinely match, because proving that is the check
// this package exists for, and the serving certificate names the assigned
// address, because that is the shape a join produces.
func storeFiles(t *testing.T, notAfter time.Time) map[string][]byte {
	t.Helper()
	return storeFilesServing(t, notAfter, net.ParseIP(testMeshIP))
}

// storeFilesServing is storeFiles with the serving certificate issued for
// servingIPs rather than for the assigned address. No IP at all is a third
// case, and a deliberate one: it is the shape of a certificate this cluster's
// join cannot produce.
func storeFilesServing(t *testing.T, notAfter time.Time, servingIPs ...net.IP) map[string][]byte {
	t.Helper()
	certPEM, keyPEM := selfSigned(t, notAfter)
	servingCertPEM, servingKeyPEM := selfSigned(t, notAfter, servingIPs...)
	return map[string][]byte{
		filepath.Join(testDir, KubeconfigFile):     kubeconfigBytes(t, certPEM, keyPEM),
		filepath.Join(testDir, ServingCertFile):    servingCertPEM,
		filepath.Join(testDir, ServingKeyFile):     servingKeyPEM,
		filepath.Join(testDir, ClientCAFile):       certPEM,
		filepath.Join(testDir, NodeAssignmentFile): []byte(`{"podCIDR":"100.64.2.0/24","meshIP":"` + testMeshIP + `"}`),
	}
}

func selfSigned(t *testing.T, notAfter time.Time, ips ...net.IP) (certPEM, keyPEM []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "system:node:k3sm-worker", Organization: []string{"system:nodes"}},
		NotBefore:    notAfter.Add(-365 * 24 * time.Hour),
		NotAfter:     notAfter,
		IsCA:         true,
		IPAddresses:  ips,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	der8, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der8})
}

func kubeconfigBytes(t *testing.T, certPEM, keyPEM []byte) []byte {
	t.Helper()
	cfg := clientcmdapi.NewConfig()
	cfg.Clusters["k3sm"] = &clientcmdapi.Cluster{Server: "https://100.64.1.1:6443", CertificateAuthorityData: certPEM}
	cfg.AuthInfos["node"] = &clientcmdapi.AuthInfo{ClientCertificateData: certPEM, ClientKeyData: keyPEM}
	cfg.Contexts["k3sm"] = &clientcmdapi.Context{Cluster: "k3sm", AuthInfo: "node"}
	cfg.CurrentContext = "k3sm"
	raw, err := clientcmd.Write(*cfg)
	if err != nil {
		t.Fatalf("write kubeconfig: %v", err)
	}
	return raw
}

// TestStatusOverTheReadSeam is the package's own contract: every verdict, over
// the seam a reporting caller hands in. The deep round-trip against real files
// the agent wrote lives with the writer (cmd/k3sm), which is the only side that
// can produce one.
func TestStatusOverTheReadSeam(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 9, 17, 12, 0, 0, 0, time.UTC)

	t.Run("a complete store is valid, and reports its own expiry", func(t *testing.T) {
		t.Parallel()
		notAfter := now.Add(90 * 24 * time.Hour)
		state, cred, err := Status(mapFS{files: storeFiles(t, notAfter)}, testDir, now)
		if state != Valid || err != nil {
			t.Fatalf("Status = %s (err %v), want valid", state, err)
		}
		if !cred.ClientNotAfter.Equal(notAfter) {
			t.Errorf("ClientNotAfter = %s, want %s", cred.ClientNotAfter, notAfter)
		}
		if cred.Assignment.PodCIDR != "100.64.2.0/24" || cred.ClusterCAPin == "" {
			t.Errorf("credential did not carry the assignment and the CA pin: %+v", cred.Assignment)
		}
	})

	t.Run("expiry is decided by the margin, not by NotAfter alone", func(t *testing.T) {
		t.Parallel()
		cases := []struct {
			name     string
			notAfter time.Time
			want     State
		}{
			{"well inside its validity", now.Add(90 * 24 * time.Hour), Valid},
			{"an hour outside the margin", now.Add(ExpiryMargin + time.Hour), Valid},
			{"an hour inside the margin", now.Add(ExpiryMargin - time.Hour), Expired},
			{"already past NotAfter", now.Add(-time.Hour), Expired},
		}
		for _, c := range cases {
			t.Run(c.name, func(t *testing.T) {
				t.Parallel()
				if state, _, err := Status(mapFS{files: storeFiles(t, c.notAfter)}, testDir, now); state != c.want {
					t.Fatalf("Status = %s (err %v), want %s", state, err, c.want)
				}
			})
		}
	})

	// The B340 verdict: a credential that is complete, matched and in date and
	// still cannot serve :10250 to the apiserver, because its certificate names
	// an address this node was not assigned.
	t.Run("a serving certificate for another address is an address mismatch", func(t *testing.T) {
		t.Parallel()
		notAfter := now.Add(90 * 24 * time.Hour)
		cases := []struct {
			name  string
			files map[string][]byte
			want  State
		}{
			{
				name:  "the assigned address",
				files: storeFilesServing(t, notAfter, net.ParseIP(testMeshIP)),
				want:  Valid,
			},
			{
				name:  "another address entirely",
				files: storeFilesServing(t, notAfter, net.ParseIP("100.64.9.9")),
				want:  AddressMismatch,
			},
			{
				name:  "the assigned address among others",
				files: storeFilesServing(t, notAfter, net.ParseIP("127.0.0.1"), net.ParseIP(testMeshIP)),
				want:  Valid,
			},
			{
				// A LAN-shaped address, which is the realistic mistake: an
				// operator asserted this Mac's own underlay address. The
				// verdict is about the address not being the ASSIGNED one, so
				// nothing here may turn on its shape or its range.
				name:  "a LAN address rather than a mesh one",
				files: storeFilesServing(t, notAfter, net.ParseIP("192.168.0.122")),
				want:  AddressMismatch,
			},
			{
				// Not judged here: the join binds exactly the assigned address,
				// so a certificate with no IP SAN is a different fault, and
				// calling it the wrong address would name the wrong remedy.
				name:  "no IP SAN at all",
				files: storeFilesServing(t, notAfter),
				want:  Valid,
			},
			{
				// Expiry wins: the two share a remedy, and an expired
				// credential is the one an agent start can still recover from
				// on its own with a token.
				name:  "expired as well as mismatched",
				files: storeFilesServing(t, now.Add(-time.Hour), net.ParseIP("100.64.9.9")),
				want:  Expired,
			},
		}
		for _, c := range cases {
			t.Run(c.name, func(t *testing.T) {
				t.Parallel()
				state, cred, err := Status(mapFS{files: c.files}, testDir, now)
				if state != c.want || err != nil {
					t.Fatalf("Status = %s (err %v), want %s", state, err, c.want)
				}
				if cred == nil {
					t.Fatal("no credential returned: every one of these parses, and a caller has to be able to name the addresses")
				}
			})
		}
	})

	t.Run("a missing artifact is absent, whichever one it is", func(t *testing.T) {
		t.Parallel()
		for _, name := range []string{KubeconfigFile, ServingCertFile, ServingKeyFile, ClientCAFile, NodeAssignmentFile} {
			files := storeFiles(t, now.Add(90*24*time.Hour))
			delete(files, filepath.Join(testDir, name))
			if state, cred, err := Status(mapFS{files: files}, testDir, now); state != Absent || cred != nil || err != nil {
				t.Errorf("without %s: Status = %s (cred %v, err %v), want absent", name, state, cred != nil, err)
			}
		}
	})

	// The property pkg/status depends on: a store this account may not read is
	// reported with an error that still says PERMISSION, so a report can tell
	// "I could not look" apart from "it is damaged". Flattening the cause here
	// would make every unprivileged `k3sm status` accuse a healthy worker.
	t.Run("an unreadable store carries a permission error, not a bare corruption", func(t *testing.T) {
		t.Parallel()
		files := storeFiles(t, now.Add(90*24*time.Hour))
		denied := map[string]bool{filepath.Join(testDir, KubeconfigFile): true}
		state, _, err := Status(mapFS{files: files, denied: denied}, testDir, now)
		if state != Corrupt {
			t.Fatalf("Status = %s, want corrupt (the daemon's own verdict for a store it cannot read)", state)
		}
		if !errors.Is(err, fs.ErrPermission) {
			t.Fatalf("err = %v, want one that wraps fs.ErrPermission", err)
		}
	})

	t.Run("a store with no directory at all is absent", func(t *testing.T) {
		t.Parallel()
		if state, _, err := Status(mapFS{}, testDir, now); state != Absent || err != nil {
			t.Fatalf("Status = %s (err %v), want absent", state, err)
		}
	})

	// Every state prints a distinct word: the report and the daemon logs both
	// quote it, so two states sharing a word would be two failures an operator
	// cannot tell apart.
	t.Run("the state words are distinct", func(t *testing.T) {
		t.Parallel()
		seen := map[string]bool{}
		for _, s := range []State{Absent, Corrupt, Expired, Valid, AddressMismatch} {
			if seen[s.String()] {
				t.Fatalf("two states print %q", s.String())
			}
			seen[s.String()] = true
		}
	})
}

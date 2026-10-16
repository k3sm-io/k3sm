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
	"errors"
	"io/fs"
	"path/filepath"
	"testing"
	"time"

	"k3sm.io/k3sm/pkg/certs"
)

// TestNetserveStatus pins the netserve credential verdict the agent decides
// whether to fetch on: only nodeName's own netserve identity, chaining to the
// recorded client-identity CA and outside ExpiryMargin, is Valid. Everything
// else is a fetch, which is why the netserve kubeconfig is not one of the five
// artifacts Status requires: a node without one is not a node without a
// credential.
func TestNetserveStatus(t *testing.T) {
	signing, err := certs.NewCA("k3sm-signing-ca")
	if err != nil {
		t.Fatalf("signing CA: %v", err)
	}
	other, err := certs.NewCA("some-other-ca")
	if err != nil {
		t.Fatalf("other CA: %v", err)
	}
	now := time.Now()
	path := filepath.Join(testDir, NetserveKubeconfigFile)
	pair := func(ca *certs.CA, cn string, org []string, validFor time.Duration) []byte {
		certPEM, keyPEM, err := ca.IssueClient(cn, org, validFor)
		if err != nil {
			t.Fatalf("issue: %v", err)
		}
		return kubeconfigBytes(t, certPEM, keyPEM)
	}
	ns := certs.NetserveSubject("worker-a")
	for _, tc := range []struct {
		name    string
		files   map[string][]byte
		want    State
		wantErr bool
	}{
		{name: "absent", files: map[string][]byte{}, want: Absent},
		{name: "valid for this node", files: map[string][]byte{path: pair(signing, ns.CommonName, ns.Organization, 48*time.Hour)}, want: Valid},
		{name: "within the expiry margin", files: map[string][]byte{path: pair(signing, ns.CommonName, ns.Organization, time.Hour)}, want: Expired},
		{name: "another node's netserve identity", files: map[string][]byte{path: pair(signing, certs.NetserveUserPrefix+"worker-b", ns.Organization, 48*time.Hour)}, want: Corrupt, wantErr: true},
		{name: "a node identity, not a netserve one", files: map[string][]byte{path: pair(signing, "system:node:worker-a", []string{"system:nodes"}, 48*time.Hour)}, want: Corrupt, wantErr: true},
		{name: "an extra group", files: map[string][]byte{path: pair(signing, ns.CommonName, []string{certs.NetserveGroup, "system:masters"}, 48*time.Hour)}, want: Corrupt, wantErr: true},
		{name: "issued by a CA the node does not record", files: map[string][]byte{path: pair(other, ns.CommonName, ns.Organization, 48*time.Hour)}, want: Corrupt, wantErr: true},
		{name: "not a kubeconfig", files: map[string][]byte{path: []byte("not yaml: [")}, want: Corrupt, wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := Store{Dir: testDir, FS: mapFS{files: tc.files}}
			got, _, err := s.NetserveStatus(now, "worker-a", signing.CertPEM)
			if got != tc.want {
				t.Errorf("state = %v, want %v (err %v)", got, tc.want, err)
			}
			if (err != nil) != tc.wantErr {
				t.Errorf("err = %v, want error %v", err, tc.wantErr)
			}
		})
	}

	t.Run("an unreadable file is Corrupt with the cause", func(t *testing.T) {
		s := Store{Dir: testDir, FS: mapFS{files: map[string][]byte{}, denied: map[string]bool{path: true}}}
		got, _, err := s.NetserveStatus(now, "worker-a", signing.CertPEM)
		if got != Corrupt || !errors.Is(err, fs.ErrPermission) {
			t.Errorf("state = %v err = %v, want Corrupt wrapping ErrPermission", got, err)
		}
	})

	t.Run("the netserve kubeconfig is not a required artifact", func(t *testing.T) {
		for _, p := range (Store{Dir: testDir}).Paths() {
			if filepath.Base(p) == NetserveKubeconfigFile {
				t.Fatalf("Paths lists %s; a node joined before the netserve identity would read as Absent and be forced to rejoin", p)
			}
		}
	})
}

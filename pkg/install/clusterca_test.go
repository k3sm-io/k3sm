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

package install

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"k3sm.io/k3sm/pkg/certs"
)

// TestProvisionAgentClusterCA pins the worker's root-only cluster CA copy,
// the anchor its netd checks a managed update's signer against: an install
// with a token writes the CA the token pinned, a later install without one
// keeps that copy (the service user can change neither it nor its directory),
// a node joined before the copy existed gets it once from its credential, and
// a server writes none.
func TestProvisionAgentClusterCA(t *testing.T) {
	t.Run("an agent install with a token writes the pinned CA before netd starts", func(t *testing.T) {
		shrinkRestartBudgets(t)
		f := &fakeSystem{}
		seedJoinedAgent(t, f)
		if err := Install(context.Background(), f, agentCfg(t)); err != nil {
			t.Fatalf("Install: %v", err)
		}
		got, ok := f.files[AgentClusterCAPath]
		if !ok {
			t.Fatalf("no %s written", AgentClusterCAPath)
		}
		if err := checkCAPEM(got); err != nil {
			t.Fatalf("%s is not a CA: %v", AgentClusterCAPath, err)
		}
		pin, err := certs.CertPin(got)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.EqualFold(pin, theTokenPinOf(f)) {
			t.Errorf("the written CA pins %s, the token pins %s", pin, theTokenPinOf(f))
		}
		write, boot := -1, -1
		for i, c := range f.calls {
			if write < 0 && strings.HasPrefix(c, "WriteRootOnlyFile:"+AgentClusterCAPath+":") {
				write = i
			}
			if boot < 0 && c == "Bootstrap:"+NetdLabel {
				boot = i
			}
		}
		if write < 0 || boot < 0 || write > boot {
			t.Errorf("the cluster CA copy (call %d) must be written before netd is bootstrapped (call %d)", write, boot)
		}
	})
	t.Run("an agent reinstall without a token keeps the existing copy", func(t *testing.T) {
		f := &fakeSystem{}
		seedJoinedAgent(t, f)
		other, err := certs.NewCA("k3sm-cluster-ca")
		if err != nil {
			t.Fatal(err)
		}
		f.putFile(AgentClusterCAPath, other.CertPEM)
		cfg := agentCfg(t).withDefaults()
		if err := provisionAgentClusterCA(f, cfg, nil); err != nil {
			t.Fatalf("provisionAgentClusterCA = %v", err)
		}
		if !bytes.Equal(f.files[AgentClusterCAPath], other.CertPEM) {
			t.Error("the root-only copy was replaced without a pinned CA")
		}
	})
	t.Run("a node joined before the copy existed gets it from its credential", func(t *testing.T) {
		f := &fakeSystem{}
		cred := mintNodeCredential(t, Config{}.withDefaults().agentWorkDir())
		cred.seed(f)
		cfg := agentCfg(t).withDefaults()
		if err := provisionAgentClusterCA(f, cfg, nil); err != nil {
			t.Fatalf("provisionAgentClusterCA = %v", err)
		}
		if !bytes.Equal(f.files[AgentClusterCAPath], cred.caPEM) {
			t.Error("the copy is not the credential's cluster CA")
		}
	})
	t.Run("a server writes no worker copy", func(t *testing.T) {
		f := &fakeSystem{}
		if err := provisionAgentClusterCA(f, testConfig(t).withDefaults(), []byte("x")); err != nil {
			t.Fatal(err)
		}
		if _, ok := f.files[AgentClusterCAPath]; ok {
			t.Error("a server wrote the worker's cluster CA copy")
		}
	})
	t.Run("a served CA that is not a CA refuses", func(t *testing.T) {
		f := &fakeSystem{}
		if err := provisionAgentClusterCA(f, agentCfg(t).withDefaults(), []byte("not pem")); err == nil {
			t.Fatal("provisionAgentClusterCA accepted a non-CA")
		}
	})
}

// theTokenPinOf is the CA hash the fake's staged operator token carries.
func theTokenPinOf(f *fakeSystem) string {
	tok := strings.TrimSpace(string(f.files[operatorTokenFile]))
	tok = strings.TrimPrefix(tok, "K10")
	if i := strings.Index(tok, "::"); i >= 0 {
		return tok[:i]
	}
	return tok
}

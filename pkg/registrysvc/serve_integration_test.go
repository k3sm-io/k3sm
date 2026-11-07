//go:build integration

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

package registrysvc

import (
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"k3sm.io/k3sm/pkg/ociregistry/auth"
)

// TestServedRegistryRefusesAnonymousPush proves the auth package on a live TCP
// listener: an anonymous push gets 401 with a Basic challenge, anonymous pulls
// still work, and the gate principal gets 202. It binds a real socket, so it is
// integration-tagged; TestServeAuthorizesAndReports covers the same stack in the
// unit tier over an in-memory listener.
func TestServedRegistryRefusesAnonymousPush(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	work := writeTestServeConfig(t, func(c *ServeConfig) { c.Listen = addr })
	d := testServeDeps(ln)
	listen := d.listen
	d.listen = func(got string) (net.Listener, error) {
		if got != addr {
			t.Errorf("serve bound %q, the config says %q", got, addr)
		}
		return listen(got)
	}
	result, cancel := runTestServe(t, work, d)
	tr := &http.Transport{}
	t.Cleanup(tr.CloseIdleConnections)
	c := &http.Client{Transport: tr, Timeout: 30 * time.Second}
	base := "http://" + addr + "/v2/"

	if resp := do(t, c, http.MethodGet, base, "", ""); resp.StatusCode != http.StatusOK {
		t.Errorf("anonymous /v2/: %d, want 200", resp.StatusCode)
	}
	for _, write := range []struct{ method, path string }{
		{http.MethodPost, "demo/blobs/uploads/"},
		{http.MethodPut, "demo/manifests/latest"},
	} {
		resp := do(t, c, write.method, base+write.path, "", "")
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("anonymous %s %s: %d, want 401", write.method, write.path, resp.StatusCode)
		}
		if got := resp.Header.Get("WWW-Authenticate"); !strings.HasPrefix(got, "Basic ") {
			t.Errorf("anonymous %s %s: challenge %q, want Basic", write.method, write.path, got)
		}
	}
	if resp := do(t, c, http.MethodPost, base+"demo/blobs/uploads/", auth.UserGate, "not-the-secret"); resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("a wrong secret: %d, want 401", resp.StatusCode)
	}
	if resp := do(t, c, http.MethodPost, base+"demo/blobs/uploads/", auth.UserGate, testGateSecret); resp.StatusCode != http.StatusAccepted {
		t.Errorf("the gate principal: %d, want 202", resp.StatusCode)
	}
	cancel()
	if err := <-result; err != nil {
		t.Errorf("serve: %v", err)
	}
}

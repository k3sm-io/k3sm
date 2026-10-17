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

package svclb

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"syscall"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	"k3sm.io/darwin-net/pkg/netbind"
)

// TestWildcardBindDetectsAnIPv4Holder pins the address family of the hoster's
// wildcard listener. On macOS a "tcp" bind of 0.0.0.0:p is a dual-stack
// AF_INET6 socket, which binds beside an IPv4-only process already holding
// *:p; the hoster then reported a Service bound while the other process
// answered every IPv4 connection. Binding the IPv4 wildcard "tcp4" makes the
// holder an EADDRINUSE, so the Service stays unreported with the bind-failed
// warning. It uses real sockets, so it is integration-tier: the property is
// the kernel's and no seam can fake it.
func TestWildcardBindDetectsAnIPv4Holder(t *testing.T) {
	holder, err := net.Listen("tcp4", "0.0.0.0:0")
	if err != nil {
		t.Skipf("cannot hold an IPv4 wildcard port: %v", err)
	}
	defer holder.Close()
	port := holder.Addr().(*net.TCPAddr).Port

	t.Run("the address set bind fails EADDRINUSE", func(t *testing.T) {
		set, err := ListenAddrSet(context.Background(), netbind.Direct{}.Listen, []netip.Addr{testBindAddr}, uint16(port))
		if err == nil {
			_ = set.Close()
			t.Fatalf("wildcard bind on :%d succeeded beside an IPv4 holder (a dual-stack socket); want EADDRINUSE", port)
		}
		if !errors.Is(err, syscall.EADDRINUSE) {
			t.Fatalf("wildcard bind on :%d: err = %v, want EADDRINUSE", port, err)
		}
	})

	t.Run("the Service is reported unbound with the bind-failed warning", func(t *testing.T) {
		ctx := context.Background()
		cs := fake.NewClientset(testNodeObject(testNode, nil))
		svc := lbService("default", "held", "10.43.0.9", int32(port))
		if _, err := cs.CoreV1().Services(svc.Namespace).Create(ctx, svc, metav1.CreateOptions{}); err != nil {
			t.Fatalf("seed service: %v", err)
		}
		var buf bytes.Buffer
		h := newTestHoster(t, cs, testNode, netbind.Direct{}, map[int32]bool{}, slog.New(slog.NewTextHandler(&buf, nil)))
		h.reconcile(ctx, []*corev1.Service{svc})
		if reportOf(t, cs, testNode).entries[reportEntry(svc)] {
			t.Errorf("service on :%d reported bound while an IPv4 process holds the port", port)
		}
		if !strings.Contains(buf.String(), "listener bind failed") {
			t.Errorf("want the bind-failed warning, log = %s", buf.String())
		}
	})
}

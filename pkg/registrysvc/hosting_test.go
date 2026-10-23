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
	"context"
	"errors"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/yaml"
)

// TestHostingDocument pins the KEP-1755 payload in BOTH of its shapes: the
// flat-name form a server that publishes the registry-k3sm Service writes, and
// the loopback form a server with no relay writes. hostFromClusterNetwork is
// present exactly when it is true.
func TestHostingDocument(t *testing.T) {
	t.Run("the flat name is host and hostFromClusterNetwork", func(t *testing.T) {
		got := decodeHosting(t, 6450, FlatAuthority())
		if want := "registry-k3sm:6450"; got["host"] != want {
			t.Errorf("host = %q, want %q", got["host"], want)
		}
		if want := "registry-k3sm:6450"; got["hostFromClusterNetwork"] != want {
			t.Errorf("hostFromClusterNetwork = %q, want %q", got["hostFromClusterNetwork"], want)
		}
		// The node runtime still pulls the server's registry on loopback until
		// it maps the flat name itself.
		if want := "localhost:6450"; got["hostFromContainerRuntime"] != want {
			t.Errorf("hostFromContainerRuntime = %q, want %q", got["hostFromContainerRuntime"], want)
		}
		if !strings.HasPrefix(got["help"], "https://") {
			t.Errorf("help = %q, want a documentation URL first", got["help"])
		}
		// The KEP has no transport field, so the document says it in help.
		if !strings.Contains(got["help"], "HTTPS") || !strings.Contains(got["help"], "ca.crt") {
			t.Errorf("help = %q, does not state that the cluster name is HTTPS under the cluster CA", got["help"])
		}
	})

	t.Run("loopback only when there is no Service", func(t *testing.T) {
		got := decodeHosting(t, 6450, "")
		if _, present := got["hostFromClusterNetwork"]; present {
			t.Errorf("hostFromClusterNetwork = %q on a server with no relay; nothing off loopback answers there",
				got["hostFromClusterNetwork"])
		}
		if want := "localhost:6450"; got["host"] != want {
			t.Errorf("host = %q, want %q", got["host"], want)
		}
	})

	t.Run("the loopback address follows the registry port, the flat name does not", func(t *testing.T) {
		got := decodeHosting(t, 14507, FlatAuthority())
		if got["hostFromContainerRuntime"] != "localhost:14507" {
			t.Errorf("hostFromContainerRuntime = %q, want the live port", got["hostFromContainerRuntime"])
		}
		if got["host"] != "registry-k3sm:6450" {
			t.Errorf("host = %q, want the fixed flat authority", got["host"])
		}
	})
}

// decodeHosting renders and decodes the KEP-1755 document.
func decodeHosting(t *testing.T, port int, clusterNetworkHost string) map[string]string {
	t.Helper()
	b, err := HostingDocument(port, clusterNetworkHost)
	if err != nil {
		t.Fatalf("HostingDocument: %v", err)
	}
	var got map[string]string
	if err := yaml.Unmarshal(b, &got); err != nil {
		t.Fatalf("the document is not valid YAML: %v", err)
	}
	return got
}

// TestPublishHosting drives the three states the publisher has to get right:
// absent (create), stale (refresh — the case that matters, because a dev instance
// allocates a different port every boot), and identical (no write at all).
func TestPublishHosting(t *testing.T) {
	t.Run("absent is created", func(t *testing.T) {
		c := &fakeConfigMaps{}
		if err := PublishHosting(t.Context(), c, 6450, ""); err != nil {
			t.Fatalf("PublishHosting: %v", err)
		}
		if c.creates != 1 || c.updates != 0 {
			t.Fatalf("creates=%d updates=%d, want 1/0", c.creates, c.updates)
		}
		if c.cm.Name != HostingConfigMapName || c.cm.Namespace != HostingNamespace {
			t.Errorf("published %s/%s, want %s/%s", c.cm.Namespace, c.cm.Name, HostingNamespace, HostingConfigMapName)
		}
		if !strings.Contains(c.cm.Data[HostingDataKey], "localhost:6450") {
			t.Errorf("data[%s] = %q, does not name the port", HostingDataKey, c.cm.Data[HostingDataKey])
		}
	})

	t.Run("a stale port is refreshed", func(t *testing.T) {
		c := &fakeConfigMaps{}
		if err := PublishHosting(t.Context(), c, 6450, ""); err != nil {
			t.Fatalf("PublishHosting: %v", err)
		}
		if err := PublishHosting(t.Context(), c, 14507, ""); err != nil {
			t.Fatalf("PublishHosting: %v", err)
		}
		if c.updates != 1 {
			t.Fatalf("updates = %d after a port change, want 1 — readers would be sent to a dead port", c.updates)
		}
		if !strings.Contains(c.cm.Data[HostingDataKey], "localhost:14507") {
			t.Errorf("data = %q, want the new port", c.cm.Data[HostingDataKey])
		}
		if strings.Contains(c.cm.Data[HostingDataKey], "6450") {
			t.Errorf("data = %q, still carries the old port", c.cm.Data[HostingDataKey])
		}
	})

	t.Run("an identical document is not rewritten", func(t *testing.T) {
		c := &fakeConfigMaps{}
		if err := PublishHosting(t.Context(), c, 6450, ""); err != nil {
			t.Fatalf("PublishHosting: %v", err)
		}
		if err := PublishHosting(t.Context(), c, 6450, ""); err != nil {
			t.Fatalf("PublishHosting: %v", err)
		}
		if c.updates != 0 {
			t.Errorf("updates = %d for an unchanged document, want 0", c.updates)
		}
	})

	t.Run("a changed cluster address is refreshed", func(t *testing.T) {
		// A Service that appears after a boot that had none (a relay address
		// came up) must reach the document.
		c := &fakeConfigMaps{}
		if err := PublishHosting(t.Context(), c, 6450, ""); err != nil {
			t.Fatalf("PublishHosting: %v", err)
		}
		authority := FlatAuthority()
		if err := PublishHosting(t.Context(), c, 6450, authority); err != nil {
			t.Fatalf("PublishHosting: %v", err)
		}
		if c.updates != 1 {
			t.Fatalf("updates = %d after the cluster address appeared, want 1", c.updates)
		}
		if !strings.Contains(c.cm.Data[HostingDataKey], authority) {
			t.Errorf("data = %q, does not carry the cluster address", c.cm.Data[HostingDataKey])
		}
	})

	t.Run("a read failure is reported, not swallowed", func(t *testing.T) {
		c := &fakeConfigMaps{getErr: errors.New("apiserver said no")}
		if err := PublishHosting(t.Context(), c, 6450, ""); err == nil {
			t.Fatal("PublishHosting = nil on a read failure, want an error")
		}
	})

	t.Run("an update conflict is reported", func(t *testing.T) {
		c := &fakeConfigMaps{updateErr: errors.New("conflict")}
		if err := PublishHosting(t.Context(), c, 6450, ""); err != nil {
			t.Fatalf("the create leg must not see the update error: %v", err)
		}
		if err := PublishHosting(t.Context(), c, 14507, ""); err == nil {
			t.Fatal("PublishHosting = nil on a failed refresh, want an error")
		}
	})
}

// fakeConfigMaps is the three-method ConfigMapClient the publisher declares,
// backed by one stored object. No client-go machinery is involved, which is the
// point of declaring the interface at the consumer.
type fakeConfigMaps struct {
	cm                *corev1.ConfigMap
	creates, updates  int
	getErr, updateErr error
}

func (f *fakeConfigMaps) Get(_ context.Context, name string, _ metav1.GetOptions) (*corev1.ConfigMap, error) {
	if f.getErr != nil {
		return nil, f.getErr
	}
	if f.cm == nil {
		return nil, apierrors.NewNotFound(schema.GroupResource{Resource: "configmaps"}, name)
	}
	return f.cm.DeepCopy(), nil
}

func (f *fakeConfigMaps) Create(_ context.Context, cm *corev1.ConfigMap, _ metav1.CreateOptions) (*corev1.ConfigMap, error) {
	f.creates++
	f.cm = cm.DeepCopy()
	return f.cm, nil
}

func (f *fakeConfigMaps) Update(_ context.Context, cm *corev1.ConfigMap, _ metav1.UpdateOptions) (*corev1.ConfigMap, error) {
	if f.updateErr != nil {
		return nil, f.updateErr
	}
	f.updates++
	f.cm = cm.DeepCopy()
	return f.cm, nil
}

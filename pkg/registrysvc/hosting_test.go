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

// TestHostingDocument pins the KEP-1755 payload, including the field that is
// DELIBERATELY ABSENT. hostFromClusterNetwork means "an address a workload inside
// the cluster network can pull from", and k3sm has none: a native Pod shares this
// host's loopback (already covered by hostFromContainerRuntime), and a vm Pod is a
// guest whose own loopback has nothing listening on it. Publishing a value would
// send a guest to pull from itself.
func TestHostingDocument(t *testing.T) {
	b, err := HostingDocument(6450)
	if err != nil {
		t.Fatalf("HostingDocument: %v", err)
	}
	var got map[string]string
	if err := yaml.Unmarshal(b, &got); err != nil {
		t.Fatalf("the document is not valid YAML: %v", err)
	}
	if want := "localhost:6450"; got["host"] != want {
		t.Errorf("host = %q, want %q", got["host"], want)
	}
	// The literal name `localhost` is what the OCI toolchain special-cases as an
	// insecure registry, and this one serves plain HTTP.
	if want := "localhost:6450"; got["hostFromContainerRuntime"] != want {
		t.Errorf("hostFromContainerRuntime = %q, want %q", got["hostFromContainerRuntime"], want)
	}
	if _, present := got["hostFromClusterNetwork"]; present {
		t.Error("hostFromClusterNetwork is published; a vm guest's own loopback has nothing listening on it")
	}
	if !strings.HasPrefix(got["help"], "https://") {
		t.Errorf("help = %q, want a documentation URL", got["help"])
	}
}

// TestPublishHosting drives the three states the publisher has to get right:
// absent (create), stale (refresh — the case that matters, because a dev instance
// allocates a different port every boot), and identical (no write at all).
func TestPublishHosting(t *testing.T) {
	t.Run("absent is created", func(t *testing.T) {
		c := &fakeConfigMaps{}
		if err := PublishHosting(t.Context(), c, 6450); err != nil {
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
		if err := PublishHosting(t.Context(), c, 6450); err != nil {
			t.Fatalf("PublishHosting: %v", err)
		}
		if err := PublishHosting(t.Context(), c, 14507); err != nil {
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
		if err := PublishHosting(t.Context(), c, 6450); err != nil {
			t.Fatalf("PublishHosting: %v", err)
		}
		if err := PublishHosting(t.Context(), c, 6450); err != nil {
			t.Fatalf("PublishHosting: %v", err)
		}
		if c.updates != 0 {
			t.Errorf("updates = %d for an unchanged document, want 0", c.updates)
		}
	})

	t.Run("a read failure is reported, not swallowed", func(t *testing.T) {
		c := &fakeConfigMaps{getErr: errors.New("apiserver said no")}
		if err := PublishHosting(t.Context(), c, 6450); err == nil {
			t.Fatal("PublishHosting = nil on a read failure, want an error")
		}
	})

	t.Run("an update conflict is reported", func(t *testing.T) {
		c := &fakeConfigMaps{updateErr: errors.New("conflict")}
		if err := PublishHosting(t.Context(), c, 6450); err != nil {
			t.Fatalf("the create leg must not see the update error: %v", err)
		}
		if err := PublishHosting(t.Context(), c, 14507); err == nil {
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

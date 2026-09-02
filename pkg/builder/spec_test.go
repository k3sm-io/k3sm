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

package builder

import (
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"

	storagev1 "k3sm.io/apis/storage/v1"
	"k3sm.io/k3sm/pkg/images"
	"k3sm.io/k3sm/pkg/runtimeclass"
)

// TestDefaultImageIsUpstreamAtMirrorDigest asserts the bring-up default is the
// UPSTREAM moby/buildkit ref at the SAME digest the GHCR mirror pins — the
// documented GHCR-outage runbook made the default, because the mirror is private
// and dormant today.
func TestDefaultImageIsUpstreamAtMirrorDigest(t *testing.T) {
	img := DefaultImage()
	if !strings.HasPrefix(img, "docker.io/moby/buildkit@sha256:") {
		t.Fatalf("DefaultImage()=%q is not an upstream digest ref", img)
	}
	digest := images.Buildkitd[strings.LastIndex(images.Buildkitd, "@"):]
	if !strings.HasSuffix(img, digest) {
		t.Errorf("DefaultImage()=%q does not carry the mirror pin digest %q", img, digest)
	}
}

// TestNormalizeDefaults pins every defaulted field.
func TestNormalizeDefaults(t *testing.T) {
	n := Config{}.Normalize()
	cases := map[string]struct{ got, want string }{
		"namespace":    {n.Namespace, DefaultNamespace},
		"name":         {n.Name, DefaultName},
		"cacheSize":    {n.CacheSize, DefaultCacheSize},
		"storageClass": {n.StorageClassName, storagev1.DefaultStorageClassName},
		"cpu":          {n.CPU, DefaultCPU},
		"memory":       {n.Memory, DefaultMemory},
		"image":        {n.Image, DefaultImage()},
	}
	for k, c := range cases {
		if c.got != c.want {
			t.Errorf("Normalize %s = %q, want %q", k, c.got, c.want)
		}
	}
	if n.TCPPort != DefaultTCPPort {
		t.Errorf("Normalize port = %d, want %d", n.TCPPort, DefaultTCPPort)
	}
	if n.GCKeepBytes != DefaultGCKeepBytes {
		t.Errorf("Normalize gcKeepBytes = %d, want %d", n.GCKeepBytes, DefaultGCKeepBytes)
	}
}

// TestNormalizeMirror asserts --mirror selects the GHCR mirror ref.
func TestNormalizeMirror(t *testing.T) {
	n := Config{UseMirror: true}.Normalize()
	if n.Image != images.Buildkitd {
		t.Errorf("mirror image = %q, want %q", n.Image, images.Buildkitd)
	}
}

// TestValidate covers the values the renderers cannot express.
func TestValidate(t *testing.T) {
	cases := []struct {
		name    string
		cfg     Config
		wantErr bool
	}{
		{"defaults ok", Config{}, false},
		{"port zero defaults ok", Config{TCPPort: 0}, false},
		{"port too high", Config{TCPPort: 70000}, true},
		{"port negative", Config{TCPPort: -1}, true},
		{"bad cache size", Config{CacheSize: "lots"}, true},
		{"bad cpu", Config{CPU: "some"}, true},
		{"bad memory", Config{Memory: "plenty"}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.cfg.Validate()
			if tc.wantErr != (err != nil) {
				t.Fatalf("Validate() err=%v, wantErr=%v", err, tc.wantErr)
			}
		})
	}
}

// TestPodSpec pins the load-bearing shape of the engine Pod.
func TestPodSpec(t *testing.T) {
	pod := Config{}.Pod()
	spec := pod.Spec

	t.Run("no securityContext anywhere (Resolution 5)", func(t *testing.T) {
		if spec.SecurityContext != nil {
			t.Errorf("pod carries a podSecurityContext; the vm is the boundary, none is allowed")
		}
		for _, c := range spec.Containers {
			if c.SecurityContext != nil {
				t.Errorf("container %s carries a securityContext; none is allowed on the guest-root builder", c.Name)
			}
		}
	})
	t.Run("vm runtimeClass", func(t *testing.T) {
		if spec.RuntimeClassName == nil || *spec.RuntimeClassName != runtimeclass.Name {
			t.Errorf("runtimeClassName = %v, want %q", spec.RuntimeClassName, runtimeclass.Name)
		}
	})
	t.Run("long-lived server restartPolicy", func(t *testing.T) {
		if spec.RestartPolicy != corev1.RestartPolicyAlways {
			t.Errorf("restartPolicy = %q, want Always", spec.RestartPolicy)
		}
	})
	t.Run("darwin nodeSelector", func(t *testing.T) {
		if spec.NodeSelector[corev1.LabelOSStable] != "darwin" {
			t.Errorf("nodeSelector missing kubernetes.io/os=darwin: %v", spec.NodeSelector)
		}
		if _, pinned := spec.NodeSelector[corev1.LabelHostname]; pinned {
			t.Errorf("no NodeName was set but a hostname selector was pinned: %v", spec.NodeSelector)
		}
	})
	t.Run("provider toleration", func(t *testing.T) {
		found := false
		for _, tol := range spec.Tolerations {
			if tol.Key == "k3sm.io/provider" && tol.Operator == corev1.TolerationOpExists {
				found = true
			}
		}
		if !found {
			t.Errorf("missing k3sm.io/provider toleration: %v", spec.Tolerations)
		}
	})
	t.Run("cache mount + pvc volume", func(t *testing.T) {
		c := spec.Containers[0]
		if len(c.VolumeMounts) != 1 || c.VolumeMounts[0].MountPath != "/cache" {
			t.Errorf("cache mount = %v, want /cache", c.VolumeMounts)
		}
		if len(spec.Volumes) != 1 || spec.Volumes[0].PersistentVolumeClaim == nil {
			t.Errorf("expected a single PVC-backed volume, got %v", spec.Volumes)
		}
	})
	t.Run("digest-pinned pull policy", func(t *testing.T) {
		if spec.Containers[0].ImagePullPolicy != corev1.PullIfNotPresent {
			t.Errorf("imagePullPolicy = %q, want IfNotPresent", spec.Containers[0].ImagePullPolicy)
		}
	})
	t.Run("tcp container port", func(t *testing.T) {
		ports := spec.Containers[0].Ports
		if len(ports) != 1 || ports[0].ContainerPort != int32(DefaultTCPPort) {
			t.Errorf("container ports = %v, want one on %d", ports, DefaultTCPPort)
		}
	})
	t.Run("no pull secret by default", func(t *testing.T) {
		if len(spec.ImagePullSecrets) != 0 {
			t.Errorf("default (upstream anonymous) pull needs no secret, got %v", spec.ImagePullSecrets)
		}
	})
	t.Run("entrypoint delivered as command", func(t *testing.T) {
		cmd := spec.Containers[0].Command
		if len(cmd) != 3 || cmd[0] != "/bin/sh" || cmd[1] != "-c" {
			t.Fatalf("command = %v, want [/bin/sh -c <script>]", cmd[:min(2, len(cmd))])
		}
		if !strings.Contains(cmd[2], "buildkitd") {
			t.Errorf("embedded entrypoint does not start buildkitd")
		}
	})
}

// TestPodEnvCarriesBuildxPin asserts the pin travels to the pod as env and lives
// ONLY in Go (the entrypoint reads env, never a hard-coded hash).
func TestPodEnvCarriesBuildxPin(t *testing.T) {
	env := map[string]string{}
	for _, e := range (Config{}).Pod().Spec.Containers[0].Env {
		env[e.Name] = e.Value
	}
	want := map[string]string{
		"BUILDX_VERSION": BuildxVersion,
		"BUILDX_ASSET":   BuildxAsset,
		"BUILDX_SHA256":  BuildxSHA256,
		"BUILDX_URL":     BuildxURL(),
	}
	for k, v := range want {
		if env[k] != v {
			t.Errorf("pod env %s = %q, want %q", k, env[k], v)
		}
	}
	if env["K3SM_BUILDER_TCP_PORT"] == "" {
		t.Errorf("pod env missing K3SM_BUILDER_TCP_PORT")
	}
}

// TestPodNodePinAndPullSecret covers the optional wiring.
func TestPodNodePinAndPullSecret(t *testing.T) {
	pod := Config{NodeName: "mac-1", UseMirror: true, PullSecret: "ghcr-read"}.Pod()
	if pod.Spec.NodeSelector[corev1.LabelHostname] != "mac-1" {
		t.Errorf("hostname pin missing: %v", pod.Spec.NodeSelector)
	}
	if len(pod.Spec.ImagePullSecrets) != 1 || pod.Spec.ImagePullSecrets[0].Name != "ghcr-read" {
		t.Errorf("pull secret not wired: %v", pod.Spec.ImagePullSecrets)
	}
	if pod.Spec.Containers[0].Image != images.Buildkitd {
		t.Errorf("mirror image not used: %q", pod.Spec.Containers[0].Image)
	}
}

// TestServiceSpec pins the ClusterIP dial shape.
func TestServiceSpec(t *testing.T) {
	svc := Config{}.Service()
	if svc.Spec.Type != corev1.ServiceTypeClusterIP {
		t.Errorf("service type = %q, want ClusterIP", svc.Spec.Type)
	}
	if svc.Spec.Selector[appLabel] != DefaultName {
		t.Errorf("service selector = %v", svc.Spec.Selector)
	}
	if len(svc.Spec.Ports) != 1 || svc.Spec.Ports[0].Port != int32(DefaultTCPPort) {
		t.Errorf("service ports = %v, want one on %d", svc.Spec.Ports, DefaultTCPPort)
	}
}

// TestPVCSpec pins the cache claim.
func TestPVCSpec(t *testing.T) {
	pvc := Config{}.PersistentVolumeClaim()
	if len(pvc.Spec.AccessModes) != 1 || pvc.Spec.AccessModes[0] != corev1.ReadWriteOnce {
		t.Errorf("access modes = %v, want [ReadWriteOnce]", pvc.Spec.AccessModes)
	}
	if pvc.Spec.StorageClassName == nil || *pvc.Spec.StorageClassName != storagev1.DefaultStorageClassName {
		t.Errorf("storageClassName = %v, want %q", pvc.Spec.StorageClassName, storagev1.DefaultStorageClassName)
	}
	if got := pvc.Spec.Resources.Requests[corev1.ResourceStorage]; got.String() != DefaultCacheSize {
		t.Errorf("cache size = %s, want %s", got.String(), DefaultCacheSize)
	}
}

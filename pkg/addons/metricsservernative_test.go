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

package addons

import (
	"crypto/sha256"
	"encoding/hex"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/yaml"

	"k3sm.io/k3sm/pkg/policy"
)

// controlPlaneNodeLabel is the server role label the server sets on its own Node
// (cmd/k3sm servernodelabels.go, as k3s sets it); the add-on pins to it.
const controlPlaneNodeLabel = "node-role.kubernetes.io/control-plane"

// upstreamObjectsSHA256 pins, byte for byte, every document of the manifest except
// the Deployment: the ServiceAccount, both ClusterRoles, the three bindings, the
// Service and the APIService, exactly as upstream v0.9.0's components.yaml ships
// them (its sha256 is in the manifest header). Running the add-on natively changes
// the Deployment only, so this never moves with it.
const upstreamObjectsSHA256 = "640a533d24476312b21ed9959211862342222ab5b92f0cf2775956bcab82fd81"

// wantNativeSecurityContext is upstream's container securityContext minus
// runAsNonRoot: a native pod runs as the node's fixed _k3sm uid by construction,
// and a FROM-scratch image carries no numeric USER the kubelet-side check could
// read, so the field is the one documented difference from upstream's securityContext.
var wantNativeSecurityContext = &corev1.SecurityContext{
	AllowPrivilegeEscalation: ptr.To(false),
	Capabilities:             &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}},
	ReadOnlyRootFilesystem:   ptr.To(true),
	SeccompProfile:           &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault},
}

// TestMetricsServerAddonRunsNative is the native add-on gate: the add-on runs k3sm's
// native darwin/arm64 build of metrics-server as a native pod (no
// runtimeClassName), pinned to server nodes by node affinity on the control-plane
// role label, with the ServiceAccount token mounted explicitly, upstream's args
// exactly (so --kubelet-insecure-tls cannot slip in) and upstream's RBAC, Service
// and APIService byte for byte; and the gate applies it on the cluster-CA kubelet
// serving posture whether or not any node can run vm pods, and still skips it
// where the kubelet certs do not chain to the in-cluster CA. Before this gate the Deployment was a vm pod running the upstream
// Linux image, and the gate skipped it on a cluster with no vm-labelled node.
func TestMetricsServerAddonRunsNative(t *testing.T) {
	d := metricsServerDeployment(t)
	spec := d.Spec.Template.Spec

	if spec.RuntimeClassName != nil {
		t.Errorf("runtimeClassName = %q, want none: the add-on is a native pod", *spec.RuntimeClassName)
	}
	if !reflect.DeepEqual(spec.NodeSelector, map[string]string{corev1.LabelOSStable: "darwin"}) {
		t.Errorf("nodeSelector = %v, want exactly kubernetes.io/os=darwin", spec.NodeSelector)
	}
	wantTol := []corev1.Toleration{{Key: policy.ProviderTaintKey, Operator: corev1.TolerationOpExists, Effect: corev1.TaintEffectNoSchedule}}
	if !reflect.DeepEqual(spec.Tolerations, wantTol) {
		t.Errorf("tolerations = %+v, want exactly %+v (never a blanket operator: Exists)", spec.Tolerations, wantTol)
	}
	wantAffinity := &corev1.Affinity{NodeAffinity: &corev1.NodeAffinity{
		RequiredDuringSchedulingIgnoredDuringExecution: &corev1.NodeSelector{NodeSelectorTerms: []corev1.NodeSelectorTerm{{
			MatchExpressions: []corev1.NodeSelectorRequirement{{Key: controlPlaneNodeLabel, Operator: corev1.NodeSelectorOpIn, Values: []string{"true"}}},
		}}},
	}}
	if !reflect.DeepEqual(spec.Affinity, wantAffinity) {
		t.Errorf("affinity = %+v, want exactly a required node affinity on %s=true", spec.Affinity, controlPlaneNodeLabel)
	}
	if spec.AutomountServiceAccountToken == nil || !*spec.AutomountServiceAccountToken {
		t.Error("automountServiceAccountToken is not explicitly true: the scrape authenticates with that token")
	}
	if spec.ServiceAccountName != "metrics-server" {
		t.Errorf("serviceAccountName = %q, want metrics-server", spec.ServiceAccountName)
	}
	if spec.HostNetwork || spec.HostPID || spec.HostIPC {
		t.Error("the pod asks for a host namespace")
	}
	if psc := spec.SecurityContext; psc != nil && (psc.RunAsUser != nil || psc.RunAsGroup != nil || psc.FSGroup != nil || len(psc.SupplementalGroups) != 0) {
		t.Errorf("pod securityContext pins a uid/gid (%+v); k3sm admission refuses a foreign identity", psc)
	}
	if len(spec.Containers) != 1 || len(spec.InitContainers) != 0 {
		t.Fatalf("containers = %d (init %d), want exactly one", len(spec.Containers), len(spec.InitContainers))
	}
	c := spec.Containers[0]
	if strings.HasPrefix(c.Image, "registry.k8s.io/") {
		t.Errorf("image = %q: the upstream image is linux; the add-on runs k3sm's native build", c.Image)
	}
	if !digestPinned.MatchString(c.Image) {
		t.Errorf("image %q is not pinned by digest alone (want <repo>@sha256:<64 hex>, no tag)", c.Image)
	}
	if len(c.Command) != 0 {
		t.Errorf("command = %v, want the image entrypoint", c.Command)
	}
	for _, a := range c.Args {
		if strings.HasPrefix(a, "--kubelet-insecure-tls") {
			t.Fatalf("arg %q disables kubelet serving-cert verification: stop and report, never ship it", a)
		}
	}
	if !reflect.DeepEqual(c.Args, wantMetricsServerArgs) {
		t.Errorf("args =\n  %v\nwant exactly upstream's\n  %v", c.Args, wantMetricsServerArgs)
	}
	if !reflect.DeepEqual(c.SecurityContext, wantNativeSecurityContext) {
		t.Errorf("container securityContext = %+v, want exactly upstream's minus runAsNonRoot: %+v", c.SecurityContext, wantNativeSecurityContext)
	}

	t.Run("RBAC, Service and APIService are upstream's bytes", func(t *testing.T) {
		if got := upstreamObjectsDigest(t); got != upstreamObjectsSHA256 {
			t.Errorf("sha256 of the non-Deployment documents = %s, want %s: running natively changes the Deployment only", got, upstreamObjectsSHA256)
		}
	})

	t.Run("the gate applies it with no vm node and skips it without cluster-CA kubelet certs", func(t *testing.T) {
		if reason := metricsServerRequirement(Posture{ClusterCAKubeletServing: true}); reason != "" {
			t.Errorf("cluster-CA kubelet serving posture, no vm-labelled node: skipped (%s), want applied", reason)
		}
		if reason := metricsServerRequirement(Posture{}); !strings.Contains(reason, "do not chain to the in-cluster CA") {
			t.Errorf("no cluster-CA kubelet serving: reason %q, want the unverifiable-scrape skip", reason)
		}
	})
}

// imageRecord is hack/images/metrics-server/image.yaml, the one home of the
// add-on image's digest (field names as written there; unknown fields refused).
type imageRecord struct {
	Image struct {
		Ref       string            `json:"ref"`
		Tag       string            `json:"tag"`
		Index     string            `json:"index"`
		Platforms map[string]string `json:"platforms"`
	} `json:"image"`
	Source struct {
		Module  string `json:"module"`
		Version string `json:"version"`
		Commit  string `json:"commit"`
		Sum     string `json:"sum"`
	} `json:"source"`
	Build struct {
		Toolchain    string `json:"toolchain"`
		BinarySHA256 string `json:"binarySHA256"`
	} `json:"build"`
	Published bool `json:"published"`
}

// imageRecordPath is the committed record; the relative path is the seam.
var imageRecordPath = filepath.Join("..", "..", "hack", "images", "metrics-server", "image.yaml")

var (
	sha256Digest   = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	sumdbHash      = regexp.MustCompile(`^h1:[A-Za-z0-9+/]{43}=$`)
	gitCommit      = regexp.MustCompile(`^[0-9a-f]{40}$`)
	headerVersion  = regexp.MustCompile(`(?m)^# Vendored from upstream metrics-server (v[0-9]+\.[0-9]+\.[0-9]+):$`)
	recordRepoName = "ghcr.io/k3sm-io/metrics-server"
)

// TestMetricsServerImageLockstep binds the manifest's image line to its one
// record, hack/images/metrics-server/image.yaml: the Deployment's image IS the
// record's digest-pinned ref, the ref names the darwin/arm64 manifest the record
// lists (or the index, when one is recorded), and the source version is the one
// the manifest header vendors. The record is what the reviewer re-derives from
// the published artifact; this test only proves the two copies agree.
func TestMetricsServerImageLockstep(t *testing.T) {
	raw, err := os.ReadFile(imageRecordPath)
	if err != nil {
		t.Fatalf("read the image record: %v", err)
	}
	var rec imageRecord
	if err := yaml.UnmarshalStrict(raw, &rec); err != nil {
		t.Fatalf("decode %s: %v", imageRecordPath, err)
	}
	if !rec.Published {
		t.Logf("%s records a local build (published: false): the operator pushes it and re-derives the digest before the manifest merges", imageRecordPath)
	}

	repo, digest, ok := strings.Cut(rec.Image.Ref, "@")
	if !ok || !digestPinned.MatchString(rec.Image.Ref) || repo != recordRepoName {
		t.Fatalf("image.ref = %q, want %s@sha256:<64 hex>", rec.Image.Ref, recordRepoName)
	}
	arm64 := rec.Image.Platforms["darwin/arm64"]
	if len(rec.Image.Platforms) != 1 || !sha256Digest.MatchString(arm64) {
		t.Errorf("image.platforms = %v, want exactly darwin/arm64: sha256:<64 hex>", rec.Image.Platforms)
	}
	switch rec.Image.Index {
	case "":
		if digest != arm64 {
			t.Errorf("image.ref pins %s, but with no index it must pin the darwin/arm64 manifest %s", digest, arm64)
		}
	default:
		if !sha256Digest.MatchString(rec.Image.Index) || digest != rec.Image.Index {
			t.Errorf("image.ref pins %s, want the recorded index %s", digest, rec.Image.Index)
		}
	}
	if want := recordRepoName + ":" + rec.Source.Version; rec.Image.Tag != want {
		t.Errorf("image.tag = %q, want %q", rec.Image.Tag, want)
	}
	if rec.Source.Module != "sigs.k8s.io/metrics-server" || !gitCommit.MatchString(rec.Source.Commit) || !sumdbHash.MatchString(rec.Source.Sum) {
		t.Errorf("source = %+v, want the metrics-server module with a 40-hex commit and an h1: sumdb hash", rec.Source)
	}
	if !sha256Digest.MatchString("sha256:"+rec.Build.BinarySHA256) || !strings.HasPrefix(rec.Build.Toolchain, "go") {
		t.Errorf("build = %+v, want the toolchain and the binary's sha256", rec.Build)
	}

	manifest := manifestText(t)
	m := headerVersion.FindStringSubmatch(manifest)
	if m == nil {
		t.Fatal("the manifest header names no vendored upstream version")
	}
	if rec.Source.Version != m[1] {
		t.Errorf("image.yaml builds %s, the manifest vendors %s", rec.Source.Version, m[1])
	}
	if got := metricsServerDeployment(t).Spec.Template.Spec.Containers[0].Image; got != rec.Image.Ref {
		t.Errorf("the Deployment's image = %q, want the image.yaml record %q", got, rec.Image.Ref)
	}
}

// metricsServerDeployment decodes the shipped Deployment.
func metricsServerDeployment(t *testing.T) appsv1.Deployment {
	t.Helper()
	objs, errs := (&Reconciler{fsys: FS()}).load()
	for _, err := range errs {
		t.Fatalf("decode the embedded tree: %v", err)
	}
	var d appsv1.Deployment
	for _, o := range objs {
		if o.GetKind() == "Deployment" && o.GetName() == "metrics-server" {
			convert(t, o, &d)
			return d
		}
	}
	t.Fatal("no metrics-server Deployment in the embedded tree")
	return d
}

// manifestText is the shipped manifest file, verbatim.
func manifestText(t *testing.T) string {
	t.Helper()
	b, err := fs.ReadFile(FS(), "metrics-server.yaml")
	if err != nil {
		t.Fatalf("read the manifest: %v", err)
	}
	return string(b)
}

// upstreamObjectsDigest is the sha256 of every YAML document of the manifest
// except the Deployment, each with its leading comment lines removed, joined by
// "---\n" in file order.
func upstreamObjectsDigest(t *testing.T) string {
	t.Helper()
	var kept []string
	for _, doc := range strings.Split(manifestText(t), "\n---\n") {
		lines := strings.Split(doc, "\n")
		for len(lines) > 0 && strings.HasPrefix(lines[0], "#") {
			lines = lines[1:]
		}
		body := strings.TrimRight(strings.Join(lines, "\n"), "\n") + "\n"
		if strings.Contains(body, "\nkind: Deployment\n") {
			continue
		}
		kept = append(kept, body)
	}
	if len(kept) != len(wantMetricsServerObjects)-1 {
		t.Fatalf("%d non-Deployment documents, want %d", len(kept), len(wantMetricsServerObjects)-1)
	}
	sum := sha256.Sum256([]byte(strings.Join(kept, "---\n")))
	return hex.EncodeToString(sum[:])
}

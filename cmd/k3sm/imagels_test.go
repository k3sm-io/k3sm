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

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"

	"k3sm.io/k3sm/pkg/registryclient"
	"k3sm.io/k3sm/pkg/registryclient/registrytest"
	"k3sm.io/k3sm/pkg/registrysvc"
	"k3sm.io/k3sm/pkg/status"
)

var updateImageGolden = flag.Bool("update-image-golden", false, "rewrite testdata/image_ls.golden.json and image_df.golden.json")

// imageFixture is the gate's cluster: a registry with two repositories (one a
// multi-platform index), three nodes (two caching, one at the status.images
// cap) and Pods naming the images in every spelling a Pod spec may use.
type imageFixture struct {
	env              imageRegistryEnv
	appV1, multi     string
	registryHostPort string
}

func newImageFixture(t *testing.T, reachable bool) imageFixture {
	t.Helper()
	reg := registrytest.New()
	darwin := registryclient.Platform{OS: "darwin", Architecture: "arm64"}
	base := []byte("base layer")
	appV1 := reg.Image("app", "v1", darwin, base, []byte("app v1"))
	reg.Image("app", "v2", darwin, base, []byte("app v2"))
	a := reg.Image("tools/multi", "", registryclient.Platform{OS: "linux", Architecture: "arm64"}, base, []byte("arm"))
	b := reg.Image("tools/multi", "", registryclient.Platform{OS: "linux", Architecture: "amd64"}, []byte("amd base"), []byte("amd"))
	multi := reg.Index("tools/multi", "v1", a, b)

	// The registry is served in process (handlerTransport): no socket is opened.
	const port = "6450"
	var transport http.RoundTripper = handlerTransport{reg.Handler()}
	if !reachable {
		transport = refusedTransport{} // nothing answers on the published port
	}
	doc, err := registrysvc.HostingDocument(mustAtoi(t, port), "")
	if err != nil {
		t.Fatal(err)
	}
	hosting := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Namespace: registrysvc.HostingNamespace, Name: registrysvc.HostingConfigMapName},
		Data:       map[string]string{registrysvc.HostingDataKey: string(doc)},
	}

	cached := func(names ...string) corev1.ContainerImage {
		return corev1.ContainerImage{Names: names, SizeBytes: 1000}
	}
	full := make([]corev1.ContainerImage, nodeStatusImageCap)
	for i := range full {
		full[i] = cached(fmt.Sprintf("example.test/filler%d@sha256:%064d", i, i))
	}
	nodes := []corev1.Node{
		{ObjectMeta: metav1.ObjectMeta{Name: "node-b"}, Status: corev1.NodeStatus{Images: []corev1.ContainerImage{
			cached("localhost:"+port+"/app@"+appV1.Digest, "localhost:"+port+"/app:v1"),
		}}},
		{ObjectMeta: metav1.ObjectMeta{Name: "node-a"}, Status: corev1.NodeStatus{Images: []corev1.ContainerImage{
			cached("registry-k3sm:6450/app@"+appV1.Digest, "registry-k3sm:6450/app:v1"),
			cached("registry-k3sm:6450/tools/multi@" + multi.Digest),
		}}},
		{ObjectMeta: metav1.ObjectMeta{Name: "node-full"}, Status: corev1.NodeStatus{Images: full}},
	}
	pod := func(name, image, imageID string) *corev1.Pod {
		p := &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: name},
			Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "c", Image: image}}},
		}
		if imageID != "" {
			p.Status.ContainerStatuses = []corev1.ContainerStatus{{Name: "c", ImageID: imageID}}
		}
		return p
	}
	objs := []runtime.Object{
		hosting, &nodes[0], &nodes[1], &nodes[2],
		pod("canonical", "registry-k3sm:6450/app:v1", ""),
		pod("loopback-alias", "localhost:"+port+"/app:v1", ""),
		pod("by-digest", "registry-k3sm:6450/tools/multi@"+multi.Digest, ""),
		pod("by-image-id", "some.other/name:x", "registry-k3sm:6450/tools/multi@"+multi.Digest),
		pod("docker-hub", "app:v1", ""),
		pod("other-tag", "registry-k3sm:6450/app:v3", ""),
	}
	cs := fake.NewSimpleClientset(objs...)
	return imageFixture{
		env:              imageRegistryEnv{kube: cs, apiHost: "127.0.0.1", transport: transport},
		appV1:            appV1.Digest,
		multi:            multi.Digest,
		registryHostPort: "127.0.0.1:" + port,
	}
}

// refusedTransport fails every request the way a closed port does.
type refusedTransport struct{}

func (refusedTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	return nil, fmt.Errorf("dial tcp %s: connect: connection refused", r.URL.Host)
}

func mustAtoi(t *testing.T, s string) int {
	t.Helper()
	n, err := strconv.Atoi(s)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func runImageReport(t *testing.T, env imageRegistryEnv, args ...string) string {
	t.Helper()
	o, err := parseImageArgs(args, io.Discard)
	if err != nil {
		t.Fatalf("parseImageArgs(%v): %v", args, err)
	}
	var out bytes.Buffer
	if err := imageRegistryCommand(context.Background(), o, &out, env); err != nil {
		t.Fatalf("image %v: %v", args, err)
	}
	return out.String()
}

func checkGolden(t *testing.T, name, got string) {
	t.Helper()
	path := filepath.Join("testdata", name)
	if *updateImageGolden {
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read golden (run with -update-image-golden): %v", err)
	}
	if got != string(want) {
		t.Errorf("%s drifted:\n--- got\n%s\n--- want\n%s", name, got, want)
	}
}

// TestImageLsListsRegistryImagesWithCachedOn is the gate: `k3sm image ls`
// lists the registry's tags under the canonical name, joins each digest
// against the nodes' status.images and the Pods that use it, flags the node at
// the cap, and reports an unreachable registry in the document with exit 0.
func TestImageLsListsRegistryImagesWithCachedOn(t *testing.T) {
	f := newImageFixture(t, true)

	t.Run("json matches the golden document", func(t *testing.T) {
		got := runImageReport(t, f.env, "ls", "-o", "json")
		checkGolden(t, "image_ls.golden.json", got)

		var rep imageListReport
		if err := json.Unmarshal([]byte(got), &rep); err != nil {
			t.Fatal(err)
		}
		byRef := map[string]imageRow{}
		for _, r := range rep.Images {
			byRef[r.Reference] = r
		}
		app := byRef["registry-k3sm:6450/app:v1"]
		if app.Digest != f.appV1 || strings.Join(app.CachedOn, ",") != "node-a,node-b" || app.Pods != 2 {
			t.Errorf("app:v1 = %+v; want digest %s cached on node-a,node-b used by 2 pods", app, f.appV1)
		}
		multi := byRef["registry-k3sm:6450/tools/multi:v1"]
		if multi.Digest != f.multi || strings.Join(multi.Platforms, ",") != "linux/arm64,linux/amd64" ||
			strings.Join(multi.CachedOn, ",") != "node-a" || multi.Pods != 2 {
			t.Errorf("tools/multi:v1 = %+v; want both platforms, cached on node-a, used by 2 pods", multi)
		}
		if v2 := byRef["registry-k3sm:6450/app:v2"]; v2.Pods != 0 || len(v2.CachedOn) != 0 {
			t.Errorf("app:v2 = %+v; want no pods and no caches", v2)
		}
		if strings.Join(rep.CachedOnIncomplete, ",") != "node-full" {
			t.Errorf("cachedOnIncomplete = %v; want [node-full]", rep.CachedOnIncomplete)
		}
		if !strings.Contains(got, `"migration": null`) {
			t.Errorf("the migration key must be present and null:\n%s", got)
		}
	})

	t.Run("the table names every image and the capped node", func(t *testing.T) {
		got := runImageReport(t, f.env, "ls")
		for _, want := range []string{"REFERENCE", "registry-k3sm:6450/app:v1", "registry-k3sm:6450/tools/multi:v1",
			"node-a,node-b", "linux/arm64,linux/amd64", "node-full report 50 images"} {
			if !strings.Contains(got, want) {
				t.Errorf("ls table missing %q:\n%s", want, got)
			}
		}
	})

	t.Run("df json matches the golden document", func(t *testing.T) {
		checkGolden(t, "image_df.golden.json", runImageReport(t, f.env, "df", "-o", "json"))
	})

	t.Run("an unreachable registry is reported and exits 0", func(t *testing.T) {
		down := newImageFixture(t, false)
		got := runImageReport(t, down.env, "ls", "-o", "json")
		var rep imageListReport
		if err := json.Unmarshal([]byte(got), &rep); err != nil {
			t.Fatal(err)
		}
		if rep.Registry.Reachable || rep.Registry.Error == "" || rep.Registry.Name != canonicalRegistry {
			t.Errorf("registry = %+v; want unreachable with an error", rep.Registry)
		}
		if rep.Images == nil || len(rep.Images) != 0 || rep.SchemaVersion != 1 {
			t.Errorf("report = %+v; want schemaVersion 1 and an empty images array", rep)
		}
		if !strings.Contains(runImageReport(t, down.env, "ls"), "unreachable") {
			t.Error("the table does not say the registry is unreachable")
		}
		dfGot := runImageReport(t, down.env, "df", "-o", "json")
		if !strings.Contains(dfGot, `"reachable": false`) || !strings.Contains(dfGot, `"node-full"`) {
			t.Errorf("df on an unreachable registry must still report the node caches:\n%s", dfGot)
		}
	})

	t.Run("a cluster that publishes no registry is unreachable, not a failure", func(t *testing.T) {
		env := imageRegistryEnv{kube: fake.NewSimpleClientset(), apiHost: "127.0.0.1"}
		got := runImageReport(t, env, "ls", "-o", "json")
		if !strings.Contains(got, "publishes no registry") {
			t.Errorf("ls = %s; want the absent discovery document named", got)
		}
	})
}

func TestRegistryBases(t *testing.T) {
	tests := []struct {
		name, host, apiHost string
		want                string
		wantErr             bool
	}{
		{"the server reaches its own loopback listener", "localhost:6450", "127.0.0.1", "http://127.0.0.1:6450", false},
		{"localhost apiserver is loopback too", "registry-k3sm:6450", "localhost", "http://127.0.0.1:6450", false},
		{"an agent reaches the server's address, TLS first", "registry-k3sm:6450", "100.64.0.1", "https://100.64.0.1:6450 http://100.64.0.1:6450", false},
		{"a host with no port is refused", "localhost", "127.0.0.1", "", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := registryBases(hostingDoc{Host: tc.host}, tc.apiHost)
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v; wantErr %v", err, tc.wantErr)
			}
			if strings.Join(got, " ") != tc.want {
				t.Errorf("bases = %v; want %s", got, tc.want)
			}
		})
	}
}

func TestImageLsArgs(t *testing.T) {
	for _, tc := range []struct {
		args    []string
		wantErr string
	}{
		{[]string{"ls", "-o", "yaml"}, "json"},
		{[]string{"df", "-o", "out.tar"}, "json"},
		{[]string{"ls", "--socket", "/x.sock"}, "does not take --socket"},
	} {
		if _, err := parseImageArgs(tc.args, io.Discard); err == nil || !strings.Contains(err.Error(), tc.wantErr) {
			t.Errorf("%v: err = %v; want one containing %q", tc.args, err, tc.wantErr)
		}
	}
	if o, err := parseImageArgs([]string{"df", "-o", "json"}, io.Discard); err != nil || o.output != "json" {
		t.Errorf("df -o json = %+v, %v", o, err)
	}
}

// TestImageLsFallsBackToUserKubeconfig: `k3sm image ls` finds the cluster the
// way the other read verbs do. The role's credentials come first; on a worker
// whose node credential this account cannot read, the account's own
// kubeconfig for the server it joined is used instead, and only when neither
// gives a client does the verb fail, naming the first reason.
func TestImageLsFallsBackToUserKubeconfig(t *testing.T) {
	kubeAt := func(t *testing.T, host string) func() (status.Kube, string, error) {
		t.Helper()
		path := filepath.Join(t.TempDir(), "kubeconfig")
		cfg := "apiVersion: v1\nkind: Config\ncurrent-context: k3sm\n" +
			"clusters:\n- name: k3sm\n  cluster:\n    server: https://" + host + ":6444\n    insecure-skip-tls-verify: true\n" +
			"users:\n- name: k3sm\n  user:\n    token: test\n" +
			"contexts:\n- name: k3sm\n  context:\n    cluster: k3sm\n    user: k3sm\n"
		if err := os.WriteFile(path, []byte(cfg), 0o600); err != nil {
			t.Fatal(err)
		}
		return func() (status.Kube, string, error) { return buildStatusKube(kubectlConfig{kubeconfig: path}) }
	}
	failing := func(msg string) func() (status.Kube, string, error) {
		return func() (status.Kube, string, error) { return nil, "", fmt.Errorf("%s", msg) }
	}
	const unreadable = "node credential /var/lib/k3sm/agent/kubeconfig is not readable by this account (re-run with sudo)"
	cases := []struct {
		name     string
		primary  func(t *testing.T) func() (status.Kube, string, error)
		user     func(t *testing.T) func() (status.Kube, string, error)
		wantHost string
		wantErr  string
	}{
		{
			name:     "the role's credentials answer",
			primary:  func(t *testing.T) func() (status.Kube, string, error) { return kubeAt(t, "192.0.2.1") },
			user:     func(t *testing.T) func() (status.Kube, string, error) { return kubeAt(t, "192.0.2.2") },
			wantHost: "192.0.2.1",
		},
		{
			name:     "a worker's node credential is unreadable, the user's kubeconfig answers",
			primary:  func(*testing.T) func() (status.Kube, string, error) { return failing(unreadable) },
			user:     func(t *testing.T) func() (status.Kube, string, error) { return kubeAt(t, "192.0.2.2") },
			wantHost: "192.0.2.2",
		},
		{
			name:    "a worker with no usable kubeconfig either",
			primary: func(*testing.T) func() (status.Kube, string, error) { return failing(unreadable) },
			user: func(*testing.T) func() (status.Kube, string, error) {
				return failing("neither the k3sm context nor the current one points at the server this Mac joined")
			},
			wantErr: unreadable,
		},
		{
			name:    "a server has no fallback",
			primary: func(*testing.T) func() (status.Kube, string, error) { return failing("no kubeconfig") },
			user:    func(*testing.T) func() (status.Kube, string, error) { return nil },
			wantErr: "no kubeconfig",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env, err := imageRegistryEnvFrom(tc.primary(t), tc.user(t))
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("imageRegistryEnvFrom = %v, want an error naming %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("imageRegistryEnvFrom: %v", err)
			}
			if env.apiHost != tc.wantHost || env.kube == nil {
				t.Errorf("env apiHost = %q (kube %v), want %q with a client", env.apiHost, env.kube != nil, tc.wantHost)
			}
		})
	}
}

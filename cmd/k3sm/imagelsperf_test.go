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
	"context"
	"fmt"
	"io"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"

	"k3sm.io/k3sm/pkg/registryclient"
	"k3sm.io/k3sm/pkg/registryclient/registrytest"
	"k3sm.io/k3sm/pkg/registrysvc"
)

// slowTransport answers every request through h after a fixed delay, the
// round trip of a registry behind a relay. It counts the requests.
type slowTransport struct {
	h        http.Handler
	delay    time.Duration
	requests *atomic.Int64
}

func (t slowTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	t.requests.Add(1)
	select {
	case <-time.After(t.delay):
	case <-r.Context().Done():
		return nil, r.Context().Err()
	}
	return handlerTransport{t.h}.RoundTrip(r)
}

// largeRegistryEnv is a registry of repos repositories with tagsPerRepo tags
// each, every tag a two-platform index over the repository's two shared
// children (the shape of a mirrored image tagged under several names), served
// with delay per request.
func largeRegistryEnv(t *testing.T, repos, tagsPerRepo int, delay time.Duration) (imageRegistryEnv, *atomic.Int64) {
	t.Helper()
	reg := registrytest.New()
	for r := range repos {
		name := fmt.Sprintf("mirror/repo%02d", r)
		a := reg.Image(name, "", registryclient.Platform{OS: "linux", Architecture: "arm64"}, []byte(name+" base"), []byte(name+" arm"))
		b := reg.Image(name, "", registryclient.Platform{OS: "linux", Architecture: "amd64"}, []byte(name+" base"), []byte(name+" amd"))
		for i := range tagsPerRepo {
			reg.Index(name, fmt.Sprintf("v%d", i), a, b)
		}
	}
	doc, err := registrysvc.HostingDocument(6450, "")
	if err != nil {
		t.Fatal(err)
	}
	hosting := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Namespace: registrysvc.HostingNamespace, Name: registrysvc.HostingConfigMapName},
		Data:       map[string]string{registrysvc.HostingDataKey: string(doc)},
	}
	node := &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "node-a"}}
	requests := &atomic.Int64{}
	return imageRegistryEnv{
		kube:      fake.NewSimpleClientset([]runtime.Object{hosting, node}...),
		apiHost:   "127.0.0.1",
		transport: slowTransport{h: reg.Handler(), delay: delay, requests: requests},
	}, requests
}

// TestImageLsLargeRegistryIsFast is the listing's latency budget: 200 tags
// over 10 repositories, 20 ms per request. Reading the tag lists one by one
// and describing four tags at a time, fetching each index's children again
// for every tag, took about 3.6 s here (611 requests, 10 serial tag
// lists); the listing must finish well inside the app's 10 s deadline scaled
// to this registry, which the old code exceeded.
func TestImageLsLargeRegistryIsFast(t *testing.T) {
	env, requests := largeRegistryEnv(t, 10, 20, 20*time.Millisecond)
	o, err := parseImageArgs([]string{"ls", "-o", "json"}, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	var out countingWriter
	if err := imageRegistryCommand(context.Background(), o, &out, env); err != nil {
		t.Fatal(err)
	}
	took := time.Since(start)
	t.Logf("listed 200 tags in %v with %d registry requests", took, requests.Load())
	if out.n == 0 {
		t.Fatal("no output")
	}
	if took > 1500*time.Millisecond {
		t.Errorf("listing 200 tags took %v; want under 1.5s", took)
	}
}

// countingWriter discards what it is written and counts the bytes.
type countingWriter struct{ n int }

func (w *countingWriter) Write(p []byte) (int, error) { w.n += len(p); return len(p), nil }

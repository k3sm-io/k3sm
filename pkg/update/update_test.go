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

package update

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	"k3sm.io/k3sm/pkg/status"
	"k3sm.io/k3sm/pkg/version"
)

// index is a fake release index: a `latest` redirect (to /tag/<stable>, or to
// the index page when stable is empty), the releases list and the by-tag API,
// all under /releases as a non-GitHub BaseURL is read.
type index struct {
	stable   string
	releases []map[string]any
}

// indexURL is where a test index is served; no socket is opened (handlerClient).
const indexURL = "https://index.test"

// handlerClient is a client that serves every request from h in process,
// through httptest.NewRecorder, so no test opens a socket.
func handlerClient(h http.Handler) *http.Client {
	return &http.Client{Transport: roundTripper(func(req *http.Request) (*http.Response, error) {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		resp := rec.Result()
		resp.Request = req
		return resp, nil
	})}
}

// roundTripper adapts a function to http.RoundTripper.
type roundTripper func(*http.Request) (*http.Response, error)

func (f roundTripper) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

// client serves the index through handlerClient.
func (ix index) client() *http.Client {
	mux := http.NewServeMux()
	mux.HandleFunc("/releases/latest", func(w http.ResponseWriter, r *http.Request) {
		if ix.stable == "" {
			http.Redirect(w, r, "/releases", http.StatusFound)
			return
		}
		http.Redirect(w, r, "/releases/tag/"+ix.stable, http.StatusFound)
	})
	mux.HandleFunc("/releases/tag/", func(w http.ResponseWriter, r *http.Request) {})
	mux.HandleFunc("/releases", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("per_page") == "" {
			return // the HTML index page
		}
		_ = json.NewEncoder(w).Encode(ix.releases)
	})
	mux.HandleFunc("/releases/tags/", func(w http.ResponseWriter, r *http.Request) {
		tag := strings.TrimPrefix(r.URL.Path, "/releases/tags/")
		for _, rel := range ix.releases {
			if rel["tag_name"] == tag {
				_ = json.NewEncoder(w).Encode(rel)
				return
			}
		}
		http.NotFound(w, r)
	})
	return handlerClient(mux)
}

func rel(tag, published string, draft bool, body string) map[string]any {
	m := map[string]any{"tag_name": tag, "draft": draft, "body": body, "published_at": nil}
	if published != "" {
		m["published_at"] = published
	}
	return m
}

// TestLatestFollowsInstallSh pins the resolution install.sh does: the stable
// redirect wins, the newest non-draft of any kind by publication time is the
// pre-stable fallback, and the notes name the Kubernetes version.
func TestLatestFollowsInstallSh(t *testing.T) {
	releases := []map[string]any{
		rel("v0.1.0-rc.1", "2026-08-01T00:00:00Z", false, ""),
		rel("v0.3.0-rc.1", "2026-10-10T00:00:00Z", false, "The control plane runs Kubernetes v1.38.0."),
		rel("v0.2.0", "2026-10-01T00:00:00Z", false, "- **The control plane runs Kubernetes v1.37.1**, and more"),
		rel("v0.9.0", "", true, ""),
	}
	cases := []struct {
		name string
		ix   index
		want Release
	}{
		{"stable wins over a newer prerelease", index{stable: "v0.2.0", releases: releases},
			Release{Tag: "v0.2.0", Published: "2026-10-01T00:00:00Z", KubeVersion: "v1.37.1"}},
		{"pre-stable: the newest published release", index{releases: releases},
			Release{Tag: "v0.3.0-rc.1", Published: "2026-10-10T00:00:00Z", KubeVersion: "v1.38.0"}},
		{"stable tag whose API entry is missing keeps the tag", index{stable: "v0.2.1", releases: releases},
			Release{Tag: "v0.2.1"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Latest(context.Background(), Inputs{BaseURL: indexURL + "/releases", HTTP: tc.ix.client()})
			if err != nil {
				t.Fatal(err)
			}
			if got != tc.want {
				t.Errorf("Latest = %+v, want %+v", got, tc.want)
			}
		})
	}
}

// TestLatestRefuses pins the failures: no release at all, an unusable stable
// tag, an unreachable index, and a redirect off https.
func TestLatestRefuses(t *testing.T) {
	t.Run("no release", func(t *testing.T) {
		if _, err := Latest(context.Background(), Inputs{BaseURL: indexURL + "/releases", HTTP: index{}.client()}); err == nil || !strings.Contains(err.Error(), "no k3sm release") {
			t.Errorf("err = %v", err)
		}
	})
	t.Run("unusable stable tag", func(t *testing.T) {
		ix := index{stable: "v1;rm", releases: []map[string]any{rel("v0.2.0", "2026-10-01T00:00:00Z", false, "")}}
		if _, err := Latest(context.Background(), Inputs{BaseURL: indexURL + "/releases", HTTP: ix.client()}); err == nil || !strings.Contains(err.Error(), "unusable release tag") {
			t.Errorf("err = %v", err)
		}
	})
	t.Run("unreachable", func(t *testing.T) {
		down := &http.Client{Transport: roundTripper(func(*http.Request) (*http.Response, error) {
			return nil, errors.New("connect: connection refused")
		})}
		if _, err := Latest(context.Background(), Inputs{BaseURL: indexURL + "/releases", HTTP: down, Timeout: time.Second}); err == nil {
			t.Error("an unreachable index resolved a release")
		}
	})
	t.Run("https to http redirect", func(t *testing.T) {
		c := handlerClient(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "http://index.test/releases/tag/v0.2.0", http.StatusFound)
		}))
		if _, err := Latest(context.Background(), Inputs{BaseURL: indexURL + "/releases", HTTP: c}); err == nil {
			t.Error("a redirect from https to http was followed")
		} else if !strings.Contains(err.Error(), "refusing a redirect") {
			t.Errorf("err = %v, want the downgrade refusal", err)
		}
	})
}

func TestValidTag(t *testing.T) {
	for tag, want := range map[string]bool{
		"v0.1.7": true, "0.1.7": true, "v0.2.0-rc.1": true, "v1+meta_x": true,
		"": false, "-v1": false, "v1/../x": false, "v1 2": false, "v1;rm": false, "v1$(x)": false,
	} {
		if got := ValidTag(tag); got != want {
			t.Errorf("ValidTag(%q) = %v, want %v", tag, got, want)
		}
	}
}

// TestCheckComparesNodes pins the comparison: a node whose kubelet carries the
// latest release is current, any other k3sm release is behind, a kubelet with
// no k3sm part is unknown, and the binary itself is compared too.
func TestCheckComparesNodes(t *testing.T) {
	ix := index{stable: "v0.2.0", releases: []map[string]any{rel("v0.2.0", "2026-10-01T00:00:00Z", false, "")}}
	node := func(name, kubelet string) *corev1.Node {
		return &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: name}, Status: corev1.NodeStatus{NodeInfo: corev1.NodeSystemInfo{KubeletVersion: kubelet}}}
	}
	cs := fake.NewClientset(
		node("b", "v1.36.2+k3sm.0.1.7"),
		node("a", version.Info{KubeVersion: "v1.37.1", Version: "0.2.0"}.NodeVersion()),
		node("c", "v1.37.1"),
	)
	now := time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		installed version.Info
		want      string
	}{
		{version.Info{Version: "0.2.0"}, status.UpdateCurrent},
		{version.Info{Version: "v0.2.0"}, status.UpdateCurrent},
		{version.Info{Version: "0.2.0", Dirty: true}, status.UpdateBehind},
		{version.Info{Version: "0.1.7"}, status.UpdateBehind},
	} {
		rep, err := Check(context.Background(), Inputs{BaseURL: indexURL + "/releases", HTTP: ix.client(), Kube: cs, Installed: tc.installed, Now: func() time.Time { return now }})
		if err != nil {
			t.Fatal(err)
		}
		if rep.InstalledState != tc.want {
			t.Errorf("installed %+v: state %s, want %s", tc.installed, rep.InstalledState, tc.want)
		}
		want := []Node{
			{Name: "a", Version: "v1.37.1+k3sm.0.2.0", State: status.UpdateCurrent},
			{Name: "b", Version: "v1.36.2+k3sm.0.1.7", State: status.UpdateBehind},
			{Name: "c", Version: "v1.37.1", State: status.UpdateUnknown},
		}
		if len(rep.Nodes) != len(want) {
			t.Fatalf("nodes = %+v", rep.Nodes)
		}
		for i := range want {
			if rep.Nodes[i] != want[i] {
				t.Errorf("node %d = %+v, want %+v", i, rep.Nodes[i], want[i])
			}
		}
		if !rep.CheckedAt.Equal(now) || rep.Latest.Tag != "v0.2.0" {
			t.Errorf("report = %+v", rep)
		}
	}
}

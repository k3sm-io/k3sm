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
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestParseReleaseBase(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		raw  string
		want string // "" = refused
	}{
		{"https://mirror.example.com/k3sm/releases/", "https://mirror.example.com/k3sm/releases"},
		{"http://192.168.0.50:8080/releases", "http://192.168.0.50:8080/releases"},
		{"http://10.1.2.3/r", "http://10.1.2.3/r"},
		{"http://172.20.0.1/r", "http://172.20.0.1/r"},
		{"http://127.0.0.1:9000/r", "http://127.0.0.1:9000/r"},
		{"http://[::1]:9000/r", "http://[::1]:9000/r"},
		{"http://localhost:9000/r", "http://localhost:9000/r"},
		{"http://example.com/releases", ""},
		{"http://8.8.8.8/releases", ""},
		{"http://172.32.0.1/r", ""},
		{"http://100.64.0.1/r", ""},
		{"ftp://192.168.0.50/r", ""},
		{"https://user:pw@mirror.example.com/r", ""},
		{"https://mirror.example.com/r?x=1", ""},
		{"/releases", ""},
	} {
		u, err := ParseReleaseBase(tc.raw)
		switch {
		case tc.want == "" && err == nil:
			t.Errorf("ParseReleaseBase(%q) = %v, want refused", tc.raw, u)
		case tc.want != "" && (err != nil || u.String() != tc.want):
			t.Errorf("ParseReleaseBase(%q) = %v, %v; want %s", tc.raw, u, err, tc.want)
		}
	}
}

func TestHostPinAdmitsTheRecordedBase(t *testing.T) {
	t.Parallel()
	base, err := ParseReleaseBase("http://192.168.0.50:8080/releases")
	if err != nil {
		t.Fatal(err)
	}
	pin := HostPin{Base: base}
	for _, tc := range []struct {
		url string
		ok  bool
	}{
		{"http://192.168.0.50:8080/releases/download/v0.2.0/k3sm_0.2.0_darwin_arm64.tar.gz", true},
		{"https://github.com/k3sm-io/k3sm/releases/download/v0.2.0/a.tar.gz", true},
		{"https://192.168.0.50:8080/a", false},
		{"http://192.168.0.50:8081/a", false},
		{"http://192.168.0.51:8080/a", false},
		{"http://user@192.168.0.50:8080/a", false},
		{"https://evil.example/a", false},
	} {
		if err := pin.CheckRaw(tc.url); (err == nil) != tc.ok {
			t.Errorf("pin.CheckRaw(%q) = %v, want ok=%v", tc.url, err, tc.ok)
		}
	}
	if err := (HostPin{}).CheckRaw("http://192.168.0.50:8080/a"); !errors.Is(err, ErrRefused) {
		t.Errorf("a pin with no recorded base admitted the lab host: %v", err)
	}
	// The fetcher re-checks every hop against the same pin.
	client := &http.Client{Transport: rtFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.Path == "/start" {
			h := http.Header{}
			h.Set("Location", "https://evil.example/a")
			return &http.Response{StatusCode: http.StatusFound, Header: h, Body: http.NoBody, Request: r}, nil
		}
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader("ok")), Request: r}, nil
	})}
	f := HTTPFetcher{Client: client, Pin: pin}
	if _, err := f.Fetch(context.Background(), "http://192.168.0.50:8080/start"); !errors.Is(err, ErrRefused) {
		t.Errorf("a redirect from the lab base to a foreign host: Fetch = %v, want ErrRefused", err)
	}
	body, err := f.Fetch(context.Background(), "http://192.168.0.50:8080/releases/a.tar.gz")
	if err != nil {
		t.Fatalf("Fetch from the lab base = %v", err)
	}
	_ = body.Close()
}

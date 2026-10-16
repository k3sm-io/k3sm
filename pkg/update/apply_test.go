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

func TestCheckURL(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		url string
		ok  bool
	}{
		{"https://github.com/k3sm-io/k3sm/releases/download/v0.2.0/k3sm_0.2.0_darwin_arm64.tar.gz", true},
		{"https://objects.githubusercontent.com/github-production-release-asset/1?X-Amz-Signature=x", true},
		{"https://release-assets.githubusercontent.com/github-production-release-asset/1?sp=r", true},
		{"https://GitHub.com:443/a", true},
		{"https://assets.githubusercontent.com/a", false},
		{"http://github.com/a", false},
		{"https://github.com:8443/a", false},
		{"https://user:pw@github.com/a", false},
		{"https://github.com.evil.example/a", false},
		{"https://example.com/a", false},
		{"file:///etc/passwd", false},
	} {
		err := CheckURL(tc.url)
		if (err == nil) != tc.ok {
			t.Errorf("CheckURL(%q) = %v, want ok=%v", tc.url, err, tc.ok)
		}
		if err != nil && !errors.Is(err, ErrRefused) {
			t.Errorf("CheckURL(%q) = %v, want ErrRefused", tc.url, err)
		}
		if err != nil && strings.Contains(err.Error(), "X-Amz") {
			t.Errorf("CheckURL(%q) echoed the query: %v", tc.url, err)
		}
	}
}

func TestParsePayload(t *testing.T) {
	t.Parallel()
	sum := strings.Repeat("a", 64)
	url := "https://github.com/k3sm-io/k3sm/releases/download/v0.2.0/k3sm_0.2.0_darwin_arm64.tar.gz"
	for _, tc := range []struct {
		name, raw string
		ok        bool
		required  bool
	}{
		{"controller shape, if-signed", `{"version":"v0.2.0","url":"` + url + `","sha256":"` + sum + `","signature":"if-signed"}`, true, false},
		{"required with downgrade", `{"version":"v0.2.0","url":"` + url + `","sha256":"` + sum + `","signature":"required","allowDowngrade":true}`, true, true},
		{"empty policy", `{"version":"v0.2.0","url":"` + url + `","sha256":"` + sum + `","signature":""}`, true, false},
		{"unknown policy", `{"version":"v0.2.0","url":"` + url + `","sha256":"` + sum + `","signature":"maybe"}`, false, false},
		{"uppercase sha", `{"version":"v0.2.0","url":"` + url + `","sha256":"` + strings.Repeat("A", 64) + `","signature":"if-signed"}`, false, false},
		{"unknown field", `{"version":"v0.2.0","url":"` + url + `","sha256":"` + sum + `","signature":"if-signed","x":1}`, false, false},
		{"trailing value", `{"version":"v0.2.0","url":"` + url + `","sha256":"` + sum + `","signature":"if-signed"} {}`, false, false},
		{"not json", `nope`, false, false},
		{"no version", `{"url":"` + url + `","sha256":"` + sum + `","signature":"if-signed"}`, false, false},
	} {
		p, err := ParsePayload(tc.raw)
		if (err == nil) != tc.ok {
			t.Errorf("%s: ParsePayload = %v, want ok=%v", tc.name, err, tc.ok)
			continue
		}
		if err == nil && p.RequireTeamSignature() != tc.required {
			t.Errorf("%s: RequireTeamSignature = %v, want %v", tc.name, p.RequireTeamSignature(), tc.required)
		}
	}
}

func TestFormatPhase(t *testing.T) {
	t.Parallel()
	if got := FormatPhase("Downloading", ""); got != "Downloading" {
		t.Errorf("FormatPhase without a message = %q", got)
	}
	if got := FormatPhase("Failed", "bad\x00 thing\nhere\x1b"); got != "Failed: bad thing here" {
		t.Errorf("FormatPhase stripped to %q", got)
	}
	long := FormatPhase("Failed", strings.Repeat("é", 300))
	p, msg := ParsePhase(long)
	if p != "Failed" || len(msg) > MaxMessageBytes || !strings.HasPrefix(msg, "é") || strings.ContainsRune(msg, '�') {
		t.Errorf("clipped message is %d bytes (%q), phase %q", len(msg), msg[:8], p)
	}
}

type rtFunc func(*http.Request) (*http.Response, error)

func (f rtFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// TestHTTPFetcherPinsEveryRedirect: a redirect off the pinned hosts is
// refused, a redirect to the asset host is followed, and an oversized
// announced length is refused, all without the network.
func TestHTTPFetcherPinsEveryRedirect(t *testing.T) {
	t.Parallel()
	const start = "https://github.com/k3sm-io/k3sm/releases/download/v0.2.0/a.tar.gz"
	client := func(location string, length int64) *http.Client {
		return &http.Client{Transport: rtFunc(func(r *http.Request) (*http.Response, error) {
			if r.URL.Host == "github.com" {
				h := http.Header{}
				h.Set("Location", location)
				return &http.Response{StatusCode: http.StatusFound, Header: h, Body: http.NoBody, Request: r}, nil
			}
			return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader("ok")), ContentLength: length, Request: r}, nil
		})}
	}
	if _, err := (HTTPFetcher{Client: client("https://evil.example/a", 2)}).Fetch(context.Background(), start); !errors.Is(err, ErrRefused) {
		t.Errorf("redirect off the pin: Fetch = %v, want ErrRefused", err)
	}
	if _, err := (HTTPFetcher{Client: client("http://objects.githubusercontent.com/a", 2)}).Fetch(context.Background(), start); !errors.Is(err, ErrRefused) {
		t.Errorf("redirect to http: Fetch = %v, want ErrRefused", err)
	}
	if _, err := (HTTPFetcher{Client: client("https://objects.githubusercontent.com/a", MaxArchiveBytes+1)}).Fetch(context.Background(), start); !errors.Is(err, ErrRefused) {
		t.Errorf("oversized: Fetch = %v, want ErrRefused", err)
	}
	// Each hop is judged: github.com to release-assets is followed, but a
	// release-assets response that redirects off the pin is refused.
	hops := &http.Client{Transport: rtFunc(func(r *http.Request) (*http.Response, error) {
		h := http.Header{}
		switch r.URL.Host {
		case "github.com":
			h.Set("Location", "https://release-assets.githubusercontent.com/a")
		case "release-assets.githubusercontent.com":
			h.Set("Location", "https://evil.example/b")
		default:
			return &http.Response{StatusCode: http.StatusOK, Body: http.NoBody, Request: r}, nil
		}
		return &http.Response{StatusCode: http.StatusFound, Header: h, Body: http.NoBody, Request: r}, nil
	})}
	if _, err := (HTTPFetcher{Client: hops}).Fetch(context.Background(), start); !errors.Is(err, ErrRefused) {
		t.Errorf("second hop off the pin: Fetch = %v, want ErrRefused", err)
	}
	if b, err := (HTTPFetcher{Client: client("https://release-assets.githubusercontent.com/a?sp=r", 2)}).Fetch(context.Background(), start); err != nil {
		t.Errorf("redirect to release-assets: Fetch = %v", err)
	} else {
		_ = b.Close()
	}
	body, err := (HTTPFetcher{Client: client("https://objects.githubusercontent.com/a?sig=1", 2)}).Fetch(context.Background(), start)
	if err != nil {
		t.Fatalf("redirect to the asset host: Fetch = %v", err)
	}
	b, _ := io.ReadAll(body)
	_ = body.Close()
	if string(b) != "ok" {
		t.Errorf("body = %q", b)
	}
}

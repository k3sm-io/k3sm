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
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
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
		{"https://GitHub.com:443/a", true},
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
		{"controller shape, if-signed", `{"url":"` + url + `","sha256":"` + sum + `","signature":"if-signed"}`, true, false},
		{"required with downgrade", `{"url":"` + url + `","sha256":"` + sum + `","signature":"required","allowDowngrade":true}`, true, true},
		{"empty policy", `{"url":"` + url + `","sha256":"` + sum + `","signature":""}`, true, false},
		{"unknown policy", `{"url":"` + url + `","sha256":"` + sum + `","signature":"maybe"}`, false, false},
		{"uppercase sha", `{"url":"` + url + `","sha256":"` + strings.Repeat("A", 64) + `","signature":"if-signed"}`, false, false},
		{"unknown field", `{"url":"` + url + `","sha256":"` + sum + `","signature":"if-signed","x":1}`, false, false},
		{"trailing value", `{"url":"` + url + `","sha256":"` + sum + `","signature":"if-signed"} {}`, false, false},
		{"not json", `nope`, false, false},
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

type member struct {
	hdr  tar.Header
	body string
}

func setArchive(t *testing.T, extra ...member) string {
	t.Helper()
	var ms []member
	for _, m := range SetMembers() {
		ms = append(ms, member{hdr: tar.Header{Name: m, Typeflag: tar.TypeReg, Mode: 0o4755}, body: m})
	}
	ms = append(ms, extra...)
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(zw)
	for _, m := range ms {
		h := m.hdr
		if h.Typeflag == tar.TypeReg {
			h.Size = int64(len(m.body))
		}
		if err := tw.WriteHeader(&h); err != nil {
			t.Fatal(err)
		}
		if h.Size > 0 {
			if _, err := io.WriteString(tw, m.body); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "a.tar.gz")
	if err := os.WriteFile(p, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestExtractSet(t *testing.T) {
	t.Parallel()
	t.Run("the set is extracted without set-id bits", func(t *testing.T) {
		t.Parallel()
		dst := t.TempDir()
		m, err := ExtractSet(setArchive(t, member{hdr: tar.Header{Name: "./LICENSE", Typeflag: tar.TypeReg}, body: "legal"}), dst)
		if err != nil {
			t.Fatalf("ExtractSet = %v", err)
		}
		if len(m) != len(SetMembers()) {
			t.Fatalf("manifest has %d entries, want %d", len(m), len(SetMembers()))
		}
		fi, err := os.Lstat(filepath.Join(dst, "k3sm"))
		if err != nil || fi.Mode().Perm() != 0o755 || fi.Mode()&os.ModeSetuid != 0 {
			t.Errorf("k3sm mode = %v (%v), want 0755 and no setuid", fi.Mode(), err)
		}
		if _, err := os.Lstat(filepath.Join(dst, "LICENSE")); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("LICENSE was written: %v", err)
		}
	})
	for _, tc := range []struct {
		name string
		m    member
		want string
	}{
		{"absolute path", member{hdr: tar.Header{Name: "/k3sm", Typeflag: tar.TypeReg}, body: "x"}, "not a clean relative path"},
		{"parent component", member{hdr: tar.Header{Name: "cp-payload/../../x", Typeflag: tar.TypeReg}, body: "x"}, "not a clean relative path"},
		{"hard link", member{hdr: tar.Header{Name: "k3sm-netd", Typeflag: tar.TypeLink, Linkname: "k3sm"}}, "is a link"},
		{"symlink", member{hdr: tar.Header{Name: "x", Typeflag: tar.TypeSymlink, Linkname: "/"}}, "is a link"},
		{"device", member{hdr: tar.Header{Name: "x", Typeflag: tar.TypeChar}}, "not a regular file"},
		{"other directory", member{hdr: tar.Header{Name: "bin/", Typeflag: tar.TypeDir, Mode: 0o755}}, "not in the build set"},
		{"duplicate", member{hdr: tar.Header{Name: "k3sm", Typeflag: tar.TypeReg}, body: "again"}, "twice"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := ExtractSet(setArchive(t, tc.m), t.TempDir())
			if !errors.Is(err, ErrRefused) || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("ExtractSet = %v, want a refusal saying %q", err, tc.want)
			}
		})
	}
	t.Run("a missing member refuses", func(t *testing.T) {
		t.Parallel()
		var buf bytes.Buffer
		zw := gzip.NewWriter(&buf)
		tw := tar.NewWriter(zw)
		_ = tw.WriteHeader(&tar.Header{Name: "k3sm", Typeflag: tar.TypeReg, Size: 1})
		_, _ = tw.Write([]byte("x"))
		_ = tw.Close()
		_ = zw.Close()
		p := filepath.Join(t.TempDir(), "a.tar.gz")
		if err := os.WriteFile(p, buf.Bytes(), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := ExtractSet(p, t.TempDir()); !errors.Is(err, ErrRefused) || !strings.Contains(err.Error(), "does not carry") {
			t.Fatalf("ExtractSet = %v, want a missing-member refusal", err)
		}
	})
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

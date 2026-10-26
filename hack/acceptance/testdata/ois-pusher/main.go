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

// Command ois-pusher is the in-pod registry client of the one-image-store lab gate
// (hack/acceptance/one-image-store.sh, ois.4 and the ois.8 aged seed). It runs in a
// native pod from its own image: a platform binary such as /usr/bin/curl loses the
// path-rebase and DNS shims in a native pod, so the client ships in the image.
//
// It builds a one-layer image in memory whose layer carries the run id, and pushes
// its layer, config and manifest to registry-k3sm:6450/$OIS_REPO:$OIS_TAG over
// HTTPS, trusting the pod's service-account CA and presenting the projected
// k3sm-registry token as the HTTP Basic password. It reports `OIS key=value` lines
// between `OIS begin` and `OIS end`, the grammar the gate parses, and exits 0 only
// when the manifest PUT answered 201.
//
// stdlib only, built CGO_ENABLED=0 for darwin/arm64 by the gate.
package main

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

const (
	registry  = "registry-k3sm:6450"
	caPath    = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
	tokenPath = "/var/run/secrets/registry/token"
)

func emit(format string, a ...any) { fmt.Printf("OIS "+format+"\n", a...) }

func fail(reason string) {
	emit("error=%s", reason)
	emit("end")
	os.Exit(1)
}

func sha(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

type pusher struct {
	client *http.Client
	token  string
	repo   string
}

func (p *pusher) do(method, target, contentType string, body []byte) (*http.Response, error) {
	req, err := http.NewRequest(method, target, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.SetBasicAuth("pod", p.token)
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	resp, err := p.client.Do(req)
	if err != nil {
		return nil, err
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close() // the body was drained; only the status and headers matter
	return resp, nil
}

// upload pushes one blob by a monolithic POST-then-PUT upload.
func (p *pusher) upload(blob []byte, hexDigest string) bool {
	base := &url.URL{Scheme: "https", Host: registry}
	resp, err := p.do(http.MethodPost, base.String()+"/v2/"+p.repo+"/blobs/uploads/", "", nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ois-pusher: post %s: %v\n", hexDigest, err)
		return false
	}
	emit("post_status_%s=%d", hexDigest, resp.StatusCode)
	loc := resp.Header.Get("Location")
	if loc == "" {
		return false
	}
	rel, err := url.Parse(loc)
	if err != nil {
		return false
	}
	u := base.ResolveReference(rel)
	q := u.Query()
	q.Set("digest", "sha256:"+hexDigest)
	u.RawQuery = q.Encode()
	resp, err = p.do(http.MethodPut, u.String(), "application/octet-stream", blob)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ois-pusher: put %s: %v\n", hexDigest, err)
		return false
	}
	emit("put_status_%s=%d", hexDigest, resp.StatusCode)
	return resp.StatusCode == http.StatusCreated
}

func layer(content string) ([]byte, error) {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	hdr := &tar.Header{Name: "payload.txt", Mode: 0o644, Size: int64(len(content)), ModTime: time.Unix(0, 0), Format: tar.FormatPAX}
	if err := tw.WriteHeader(hdr); err != nil {
		return nil, err
	}
	if _, err := io.WriteString(tw, content); err != nil {
		return nil, err
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func main() {
	emit("begin")
	repo, tag := os.Getenv("OIS_REPO"), os.Getenv("OIS_TAG")
	if repo == "" || tag == "" {
		fail("no-repo")
	}
	ca, err := os.ReadFile(caPath)
	if err != nil {
		fail("no-ca")
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca) {
		fail("no-ca")
	}
	tok, err := os.ReadFile(tokenPath)
	if err != nil || len(bytes.TrimSpace(tok)) == 0 {
		fail("no-token")
	}
	p := &pusher{
		client: &http.Client{
			Timeout:   60 * time.Second,
			Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}},
		},
		token: strings.TrimSpace(string(tok)),
		repo:  repo,
	}

	l, err := layer(fmt.Sprintf("one-image-store %s %s\n", os.Getenv("OIS_RUN"), repo))
	if err != nil {
		fail("tar")
	}
	L := sha(l)
	config := []byte(fmt.Sprintf(`{"architecture":"%s","os":"%s","rootfs":{"type":"layers","diff_ids":["sha256:%s"]},"config":{}}`,
		os.Getenv("OIS_ARCH"), os.Getenv("OIS_OS"), L))
	C := sha(config)
	if !p.upload(l, L) {
		fail("layer-upload")
	}
	if !p.upload(config, C) {
		fail("config-upload")
	}
	manifest := []byte(fmt.Sprintf(`{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"sha256:%s","size":%d},"layers":[{"mediaType":"application/vnd.oci.image.layer.v1.tar","digest":"sha256:%s","size":%d}]}`,
		C, len(config), L, len(l)))
	emit("manifest_digest=sha256:%s", sha(manifest))
	resp, err := p.do(http.MethodPut, "https://"+registry+"/v2/"+repo+"/manifests/"+tag, "application/vnd.oci.image.manifest.v1+json", manifest)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ois-pusher: manifest put: %v\n", err)
		fail("manifest-put")
	}
	emit("manifest_status=%d", resp.StatusCode)
	emit("registry_digest=%s", resp.Header.Get("Docker-Content-Digest"))
	emit("end")
	if resp.StatusCode != http.StatusCreated {
		os.Exit(1)
	}
}

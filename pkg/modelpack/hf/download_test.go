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

package hf

import (
	"errors"
	"os"
	"strings"
	"testing"

	artifactv1 "k3sm.io/apis/artifact/v1"
)

// TestDownloadResumesWithRange: a transfer cut mid-body is resumed with a
// Range request from where it stopped, not restarted, and the file still
// verifies.
func TestDownloadResumesWithRange(t *testing.T) {
	hub := newFakeHub(t)
	hub.addCommit("main", commitA, tinyModel("a")...)
	hub.cutOnce["model.safetensors"] = 100 << 10
	res, err := hub.client(t).Import(testContext(t), mustRef(t, "hf://acme/tiny-model"), ImportOptions{ScratchDir: t.TempDir()})
	if err != nil {
		t.Fatalf("Import after a cut transfer: %v", err)
	}
	if res.Bytes == 0 {
		t.Error("Bytes = 0")
	}
	var cdn int
	for _, p := range hub.paths() {
		if strings.HasPrefix(p, "/blobs/") {
			cdn++
		}
	}
	if cdn != 2 {
		t.Errorf("%d CDN requests, want 2 (the cut transfer and one resume)", cdn)
	}
}

// TestDownloadRefusesRedirectOffTheHub: a redirect to plain http, or to a
// host that is neither the Hub nor a listed CDN host, is refused and not
// retried.
func TestDownloadRefusesRedirectOffTheHub(t *testing.T) {
	for _, to := range []string{"http://127.0.0.1:1/blobs/x", "https://attacker.example/blobs/x", "https://attacker.example/\x1b]0;owned\x07x", "ht\x1btp://attacker.example/x"} {
		t.Run(to, func(t *testing.T) {
			hub := newFakeHub(t)
			hub.addCommit("main", commitA, tinyModel("a")...)
			hub.redirectTo = to
			_, err := hub.client(t).Import(testContext(t), mustRef(t, "hf://acme/tiny-model"), ImportOptions{ScratchDir: t.TempDir()})
			if !errors.Is(err, ErrRedirectRefused) {
				t.Fatalf("Import = %v, want ErrRedirectRefused", err)
			}
			for _, c := range err.Error() {
				if c < 0x20 || c == 0x7f {
					t.Fatalf("refusal %q carries a control byte from the redirect target", err)
				}
			}
		})
	}
}

// TestImportRefusesCodeFileBeforeFetching: a repository with a code or
// pickle file is refused by the file's name, and no file is downloaded.
func TestImportRefusesCodeFileBeforeFetching(t *testing.T) {
	hub := newFakeHub(t)
	files := append(tinyModel("a"), hubFile{path: "pytorch_model.bin", data: []byte("pickle"), lfs: true})
	hub.addCommit("main", commitA, files...)
	_, err := hub.client(t).Import(testContext(t), mustRef(t, "hf://acme/tiny-model"), ImportOptions{ScratchDir: t.TempDir()})
	if !errors.Is(err, artifactv1.ErrCodeFile) || !strings.Contains(err.Error(), "pytorch_model.bin") {
		t.Fatalf("Import = %v, want ErrCodeFile naming pytorch_model.bin", err)
	}
	for _, p := range hub.paths() {
		if strings.Contains(p, "/resolve/") || strings.HasPrefix(p, "/blobs/") {
			t.Errorf("downloaded %s from a refused repository", p)
		}
	}
}

// TestImportRemovesItsScratchDirectory: the scratch directory is gone after
// an import, refused or not.
func TestImportRemovesItsScratchDirectory(t *testing.T) {
	hub := newFakeHub(t)
	hub.addCommit("main", commitA, tinyModel("a")...)
	scratch := t.TempDir()
	if _, err := hub.client(t).Import(testContext(t), mustRef(t, "hf://acme/tiny-model"), ImportOptions{ScratchDir: scratch}); err != nil {
		t.Fatal(err)
	}
	hub.corrupt["config.json"] = true
	if _, err := hub.client(t).Import(testContext(t), mustRef(t, "hf://acme/tiny-model"), ImportOptions{ScratchDir: scratch}); err == nil {
		t.Fatal("corrupt import succeeded")
	}
	left, err := os.ReadDir(scratch)
	if err != nil || len(left) != 0 {
		t.Errorf("scratch holds %v (%v), want nothing", left, err)
	}
}

func TestNewClientRefusesNonHTTPSEndpoint(t *testing.T) {
	for _, ep := range []string{"http://huggingface.co", "https://huggingface.co/api", "https://u@huggingface.co", "huggingface.co"} {
		if _, err := NewClient(Options{Endpoint: ep}); err == nil {
			t.Errorf("NewClient(%q) accepted", ep)
		}
	}
}

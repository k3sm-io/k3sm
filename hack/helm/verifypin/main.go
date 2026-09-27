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

// Command verifypin is the implementation behind hack/verify-helm-pin.sh: the
// re-pin-time check that the committed helm pin (pkg/helmchart.HelmSHA256) is the
// digest helm itself publishes for the pinned darwin-arm64 tarball.
//
// It takes the version, asset name, URLs and pin from k3sm.io/k3sm/pkg/helmchart,
// never from a copy here, so a run is a drift check against the committed
// constants by construction. With -download it also fetches the tarball once and
// hashes it, so the check covers the bytes and not only the published checksum.
//
// This is tooling, not enforcement: k3sm verifies the tarball against the pin
// every time `k3sm payload` (or the dev-shell fallback) downloads it.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"k3sm.io/k3sm/pkg/helmchart"
)

// Exit statuses, part of the script's contract.
const (
	exitPass     = 0
	exitError    = 1
	exitUsage    = 2
	exitMismatch = 3
)

func main() {
	var (
		download = flag.Bool("download", false, "also download the pinned tarball and hash it")
		timeout  = flag.Duration("timeout", 5*time.Minute, "overall deadline for the fetches")
	)
	flag.Parse()
	if flag.NArg() != 0 {
		fmt.Fprintf(os.Stderr, "verify-helm-pin: unexpected arguments: %q\n", flag.Args())
		os.Exit(exitUsage)
	}
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()
	os.Exit(run(ctx, *download))
}

// run performs the check and returns the exit status.
func run(ctx context.Context, download bool) int {
	if err := helmchart.ValidateHelmPin(); err != nil {
		return failf(exitError, "pin: %v", err)
	}
	body, _, err := fetch(ctx, helmchart.HelmChecksumURL(), true)
	if err != nil {
		return failf(exitError, "%v", err)
	}
	published, err := decide(string(body), helmchart.HelmAsset, helmchart.HelmSHA256)
	if err != nil {
		return failf(exitMismatch, "%v", err)
	}
	fmt.Printf("ok  published checksum %s matches the pin for %s\n", published, helmchart.HelmAsset)
	if download {
		_, sum, err := fetch(ctx, helmchart.HelmURL(), false)
		if err != nil {
			return failf(exitError, "%v", err)
		}
		if sum != helmchart.HelmSHA256 {
			return failf(exitMismatch, "downloaded %s has sha256 %s, pin is %s", helmchart.HelmAsset, sum, helmchart.HelmSHA256)
		}
		fmt.Printf("ok  downloaded %s hashes to the pin\n", helmchart.HelmAsset)
	}
	fmt.Printf("PASS helm %s pin verified\n", helmchart.HelmVersion)
	return exitPass
}

// fetch GETs url and returns its sha256; with keep it also returns the body
// (the checksum file is small; the tarball is hashed as it streams).
func fetch(ctx context.Context, url string, keep bool) ([]byte, string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, "", fmt.Errorf("request %s: %w", url, err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, "", fmt.Errorf("fetch %s: %w", url, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, "", fmt.Errorf("fetch %s: unexpected status %s", url, resp.Status)
	}
	h := sha256.New()
	var body []byte
	if keep {
		body, err = io.ReadAll(io.TeeReader(io.LimitReader(resp.Body, 1<<16), h))
	} else {
		_, err = io.Copy(h, resp.Body)
	}
	if err != nil {
		return nil, "", fmt.Errorf("read %s: %w", url, err)
	}
	return body, hex.EncodeToString(h.Sum(nil)), nil
}

func failf(code int, format string, args ...any) int {
	fmt.Fprintf(os.Stderr, "FAIL "+format+"\n", args...)
	return code
}

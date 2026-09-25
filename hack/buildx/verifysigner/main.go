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

// Command verifysigner is the implementation behind hack/verify-buildx-signer.sh:
// the re-pin-time check that the pinned darwin buildx asset is the bytes the
// committed sha256 names AND is signed by the one expected Developer ID.
//
// It is deliberately thin. The pin, the URL and the expected Team ID come from
// k3sm.io/k3sm/pkg/builder, never from a second copy here, so a run is a drift
// check against the committed constants by construction. The only decision this
// command makes is decide (signer.go), which the unit tests drive with recorded
// codesign output.
//
// This is tooling, not enforcement: at runtime k3sm verifies the host buildx
// binary by sha256 alone.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"k3sm.io/k3sm/pkg/builder"
)

func main() {
	var (
		file    = flag.String("file", "", "inspect this local file's signature instead of downloading the pinned asset (skips the sha256 check)")
		timeout = flag.Duration("timeout", 5*time.Minute, "overall deadline for the download and codesign runs")
	)
	flag.Usage = usage
	flag.Parse()
	if flag.NArg() != 0 {
		fmt.Fprintf(os.Stderr, "verify-buildx-signer: unexpected arguments: %q\n", flag.Args())
		os.Exit(exitUsage)
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()

	os.Exit(run(ctx, *file))
}

// run performs one check and returns the process exit status. It returns
// rather than exiting so the deferred cleanup of the download dir always runs.
func run(ctx context.Context, file string) int {
	path := file
	if path == "" {
		if err := builder.ValidateHostBuildxPin(); err != nil {
			return failf(exitError, "pin: %v", err)
		}
		dir, err := os.MkdirTemp("", "verify-buildx-signer-")
		if err != nil {
			return failf(exitError, "stage download: %v", err)
		}
		defer func() { _ = os.RemoveAll(dir) }()
		path = filepath.Join(dir, builder.HostBuildxAsset)
		if err := fetchPinned(ctx, path); err != nil {
			return failf(exitError, "%v", err)
		}
		fmt.Printf("ok  sha256: %s matches the pin %s\n", builder.HostBuildxAsset, builder.HostBuildxSHA256)
	} else {
		fmt.Printf("--  sha256 skipped: -file inspects a local file, not the pinned asset\n")
	}

	verifyExit, dvOut, err := inspect(ctx, path)
	if err != nil {
		return failf(exitError, "%v", err)
	}
	if verdict := decide(verifyExit, dvOut, builder.HostBuildxTeamID); verdict != nil {
		return failf(exitCode(verdict), "signer: %s: %v", path, verdict)
	}
	fmt.Printf("ok  signer: %s is strictly valid and signed by Team ID %s\n", filepath.Base(path), builder.HostBuildxTeamID)
	return exitOK
}

// fetchPinned downloads the pinned darwin asset to path exactly once, hashing the
// bytes on their way to disk and staging through a temp name so a cancelled run
// cannot leave a truncated file at path (the same discipline as builder's own
// unexported downloadTo/ensureVerifiedBinary pair, deliberately duplicated here:
// this is re-pin-time tooling, and importing it would widen pkg/builder's API for
// a non-runtime consumer). Fails unless the digest equals builder.HostBuildxSHA256;
// the file codesign inspects next is the same single copy whose digest was checked.
func fetchPinned(ctx context.Context, path string) error {
	url := builder.HostBuildxURL()
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o755)
	if err != nil {
		return fmt.Errorf("create %s: %w", tmp, err)
	}
	sum, err := downloadTo(ctx, f, url)
	if cerr := f.Close(); err == nil && cerr != nil {
		err = fmt.Errorf("close %s: %w", tmp, cerr)
	}
	if err != nil {
		return err
	}
	if sum != builder.HostBuildxSHA256 {
		return fmt.Errorf("sha256: %s from %s is %s, want %s", builder.HostBuildxAsset, url, sum, builder.HostBuildxSHA256)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("install %s: %w", path, err)
	}
	return nil
}

// downloadTo streams url into w and returns the lowercase hex sha256 of the
// bytes written.
func downloadTo(ctx context.Context, w io.Writer, url string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", fmt.Errorf("request %s: %w", url, err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("fetch %s: %w", url, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("fetch %s: unexpected status %s", url, resp.Status)
	}
	h := sha256.New()
	if _, err := io.Copy(io.MultiWriter(w, h), resp.Body); err != nil {
		return "", fmt.Errorf("download %s: %w", url, err)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// inspect runs `codesign --verify --strict` and `codesign -dv` on path and
// returns the verify exit status and the -dv output (codesign writes it to
// stderr, so both streams are captured). A codesign that cannot be started is an
// operational error, never a verdict.
func inspect(ctx context.Context, path string) (int, string, error) {
	verifyExit := 0
	if err := exec.CommandContext(ctx, "codesign", "--verify", "--strict", path).Run(); err != nil {
		var ee *exec.ExitError
		if !errors.As(err, &ee) {
			return 0, "", fmt.Errorf("run codesign --verify: %w", err)
		}
		verifyExit = ee.ExitCode()
	}
	out, err := exec.CommandContext(ctx, "codesign", "-dv", path).CombinedOutput()
	if err != nil {
		var ee *exec.ExitError
		if !errors.As(err, &ee) {
			return 0, "", fmt.Errorf("run codesign -dv: %w", err)
		}
		// A non-zero -dv exit (an unsigned file) still carries the diagnosis in
		// its output; decide reads it from there.
	}
	if ctx.Err() != nil {
		return 0, "", fmt.Errorf("codesign: %w", ctx.Err())
	}
	return verifyExit, string(out), nil
}

func failf(code int, format string, a ...any) int {
	fmt.Fprintf(os.Stderr, "verify-buildx-signer: "+format+"\n", a...)
	return code
}

func usage() {
	fmt.Fprint(flag.CommandLine.Output(), `verifysigner — re-pin-time check of the pinned darwin buildx asset.

Default: download the pinned asset once, assert its sha256 equals the committed
pin, then assert codesign --verify --strict passes and codesign -dv reports the
one expected TeamIdentifier. Network. With -file, only the signature stage runs,
against a local file (no network, no sha256).

Exit status: 0 pass; 1 operational error (download, sha256 mismatch, codesign
not runnable); 2 usage; 3 unsigned; 4 strict verify failed; 5 ad-hoc signed;
6 Team ID not set; 7 no TeamIdentifier line; 8 wrong Team ID.

Flags:
`)
	flag.PrintDefaults()
}

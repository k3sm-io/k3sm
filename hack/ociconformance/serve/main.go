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

// Command serve starts the k3sm registry server (pkg/ociregistry) on a
// loopback port for the OCI distribution-spec conformance run
// (hack/ociconformance.sh). It is test tooling and is never shipped.
//
// The server runs with the daemon's own access model (pkg/ociregistry/auth):
// the k3sm principal's secret is read from -secret-file, and the k3sm-gate
// principal gets a random secret that is never written anywhere, so no client
// can use it. The bound address is written to -addr-file once the listener is
// open. The server stops on SIGINT or SIGTERM.
package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"k3sm.io/k3sm/pkg/ociregistry/api"
	"k3sm.io/k3sm/pkg/ociregistry/auth"
	"k3sm.io/k3sm/pkg/ociregistry/store"
)

// minSecretBytes is the shortest k3sm secret accepted from -secret-file.
const minSecretBytes = 32

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "serve: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	var (
		workDir    = flag.String("work-dir", "", "absolute directory holding the store (registry, registry-state)")
		secretFile = flag.String("secret-file", "", "file holding the k3sm principal's secret")
		addrFile   = flag.String("addr-file", "", "file the bound host:port is written to")
		minFree    = flag.Uint64("min-free", 64<<20, "free bytes below which uploads get 507")
	)
	flag.Parse()
	if *workDir == "" || *secretFile == "" || *addrFile == "" || flag.NArg() != 0 {
		return errors.New("usage: serve -work-dir <dir> -secret-file <file> -addr-file <file>")
	}
	raw, err := os.ReadFile(*secretFile)
	if err != nil {
		return fmt.Errorf("read secret: %w", err)
	}
	secret := strings.TrimSpace(string(raw))
	if len(secret) < minSecretBytes || len(secret) > auth.MaxSecretBytes {
		return fmt.Errorf("secret in %s is %d bytes, want %d to %d", *secretFile, len(secret), minSecretBytes, auth.MaxSecretBytes)
	}
	gate := make([]byte, 32)
	if _, err := rand.Read(gate); err != nil {
		return fmt.Errorf("mint the gate secret: %w", err)
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
	access, err := auth.New(auth.Config{
		Principals: []auth.Principal{
			{User: auth.UserPush, SecretSHA256: auth.HashSecret(secret)},
			{User: auth.UserGate, SecretSHA256: auth.HashSecret(hex.EncodeToString(gate))},
		},
		Logger: log,
	})
	if err != nil {
		return err
	}
	st, err := store.OpenWorkDir(*workDir)
	if err != nil {
		return err
	}
	srv, err := api.New(api.Config{Store: st, Logger: log, Authorize: access.Authorize, MinFreeSpace: *minFree})
	if err != nil {
		return err
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	if err := writeAddr(*addrFile, ln.Addr().String()); err != nil {
		_ = ln.Close() // the write error is the one reported
		return err
	}
	hs := srv.HTTPServer(ln.Addr().String())
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	done := make(chan error, 1)
	go func() { done <- hs.Serve(ln) }()
	select {
	case err := <-done:
		return fmt.Errorf("serve: %w", err)
	case <-ctx.Done():
	}
	sctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := hs.Shutdown(sctx); err != nil {
		return fmt.Errorf("shutdown: %w", err)
	}
	if err := <-done; err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("serve: %w", err)
	}
	return nil
}

// writeAddr writes addr to path through a rename, so a reader never sees a
// partial address.
func writeAddr(path, addr string) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".addr-*")
	if err != nil {
		return fmt.Errorf("write address: %w", err)
	}
	if _, err := tmp.WriteString(addr + "\n"); err != nil {
		_ = tmp.Close()           // the write error is the one reported
		_ = os.Remove(tmp.Name()) // best effort
		return fmt.Errorf("write address: %w", err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmp.Name()) // best effort
		return fmt.Errorf("write address: %w", err)
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return fmt.Errorf("write address: %w", err)
	}
	return nil
}

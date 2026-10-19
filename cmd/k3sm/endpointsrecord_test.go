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
	"crypto/tls"
	"errors"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"k3sm.io/k3sm/pkg/certs"
	"k3sm.io/k3sm/pkg/status"
)

// pipeAPIServer is an apiserverLeafDial whose far end is an in-memory TLS
// server presenting certPEM/keyPEM, so the handshake runs with no socket. After
// the handshake the server reads until the client is gone: a net.Pipe write
// blocks until the far end reads, so a server that went straight to Close would
// leave the client's close_notify (and its own) blocked until crypto/tls's
// five-second close deadline.
func pipeAPIServer(t *testing.T, certPEM, keyPEM []byte) apiserverLeafDial {
	t.Helper()
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	return func(ctx context.Context, _ string) (net.Conn, error) {
		client, server := net.Pipe()
		go func() {
			srv := tls.Server(server, &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS12})
			if srv.HandshakeContext(ctx) == nil {
				_, _ = io.Copy(io.Discard, srv)
			}
			_ = srv.Close()
		}()
		return client, nil
	}
}

// TestAgentEndpointsRecordNamesTheMeshAndJoinHosts pins an agent's endpoints
// record: published 0644 in the status directory once a handshake verified
// against the pinned cluster CA answers, naming the join host, the apiserver
// URL's host and the presented certificate's SANs, at the URL's port; a
// certificate from another CA is never trusted for its SANs; no status
// directory, no record.
func TestAgentEndpointsRecordNamesTheMeshAndJoinHosts(t *testing.T) {
	ca, err := certs.NewCA("k3sm-cluster-ca")
	if err != nil {
		t.Fatal(err)
	}
	other, err := certs.NewCA("k3sm-cluster-ca")
	if err != nil {
		t.Fatal(err)
	}
	certPEM, keyPEM, err := ca.IssueServing("kube-apiserver", []string{"kubernetes.default.svc"}, []net.IP{net.ParseIP("100.64.0.1"), net.ParseIP("127.0.0.1")}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	logger := slog.New(slog.DiscardHandler)
	statusDir := filepath.Join(t.TempDir(), "status")
	if err := os.Mkdir(statusDir, 0o755); err != nil {
		t.Fatal(err)
	}

	runAgentEndpointsPublisher(context.Background(), statusDir, "https://100.64.0.1:6444", "192.0.2.50", ca.CertPEM, pipeAPIServer(t, certPEM, keyPEM), time.Millisecond, logger)
	path := status.EndpointsPath(statusDir)
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o644 {
		t.Fatalf("record mode = %v (err %v), want 0644", info.Mode().Perm(), err)
	}
	rec := status.ReadEndpointsRecord(os.ReadFile, path)
	if rec == nil || rec.Port != 6444 {
		t.Fatalf("record = %+v, want port 6444", rec)
	}
	for _, h := range []string{"192.0.2.50", "100.64.0.1", "127.0.0.1", "kubernetes.default.svc"} {
		if !slices.Contains(rec.Hosts, h) {
			t.Errorf("record hosts %v do not name %s", rec.Hosts, h)
		}
	}

	t.Run("a certificate the pinned CA did not issue is never trusted", func(t *testing.T) {
		dir := filepath.Join(t.TempDir(), "status")
		if err := os.Mkdir(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		forged, forgedKey, err := other.IssueServing("kube-apiserver", []string{"evil.example"}, []net.IP{net.ParseIP("100.64.0.1")}, time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()
		runAgentEndpointsPublisher(ctx, dir, "https://100.64.0.1:6444", "192.0.2.50", ca.CertPEM, pipeAPIServer(t, forged, forgedKey), 10*time.Millisecond, logger)
		if _, err := os.Stat(status.EndpointsPath(dir)); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("a record was published from an untrusted certificate: %v", err)
		}
	})
	t.Run("no status directory, no record", func(t *testing.T) {
		dir := filepath.Join(t.TempDir(), "status")
		if err := publishEndpoints(dir, 6444, []string{"127.0.0.1"}, time.Now()); err != nil {
			t.Fatalf("publish: %v", err)
		}
		if _, err := os.Stat(dir); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("the publisher created the status directory: %v", err)
		}
	})
}

// TestServerEndpointsRecordNamesTheServingSANs pins a server's endpoints record:
// its serving certificate's SANs, loopback, at the apiserver port it serves on,
// so a non-default --api-port is carried.
func TestServerEndpointsRecordNamesTheServingSANs(t *testing.T) {
	ca, err := certs.NewCA("k3sm-cluster-ca")
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	wd := filepath.Join(root, "server")
	if err := os.MkdirAll(filepath.Dir(certs.APIServerServingCertPath(wd)), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(status.Dir(wd), 0o755); err != nil {
		t.Fatal(err)
	}
	certPEM, _, err := ca.IssueServing("kube-apiserver", []string{"k3sm-studio"}, []net.IP{net.ParseIP("100.64.0.1")}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(certs.APIServerServingCertPath(wd), certPEM, 0o644); err != nil {
		t.Fatal(err)
	}
	publishServerEndpoints(wd, 7444, slog.New(slog.DiscardHandler))
	rec := status.ReadEndpointsRecord(os.ReadFile, status.EndpointsPath(status.Dir(wd)))
	if rec == nil || rec.Port != 7444 {
		t.Fatalf("record = %+v, want port 7444", rec)
	}
	for _, h := range []string{"k3sm-studio", "100.64.0.1", "127.0.0.1", "::1", "localhost"} {
		if !slices.Contains(rec.Hosts, h) {
			t.Errorf("record hosts %v do not name %s", rec.Hosts, h)
		}
	}
}

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
	"encoding/hex"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"k3sm.io/k3sm/pkg/bootstrap"
	"k3sm.io/k3sm/pkg/certs"
	"k3sm.io/k3sm/pkg/executor"
)

// failingTransport fails every request and counts them.
type failingTransport struct{ calls atomic.Int32 }

func (f *failingTransport) RoundTrip(*http.Request) (*http.Response, error) {
	f.calls.Add(1)
	return nil, errors.New("the --server is down")
}

// restoredJoinedServer lays down what a joined server holds after `k3sm snapshot
// restore`: its complete CA hierarchy (it imported it when it first joined) and an
// etcd member rebuilt on disk.
func restoredJoinedServer(t *testing.T) serverOptions {
	t.Helper()
	wd := t.TempDir()
	h, err := certs.EnsureHierarchy(wd, certs.RoleMintAuthority, certs.PostureEtcd)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := certs.EnsureEtcdCAs(wd); err != nil {
		t.Fatal(err)
	}
	if missing, err := certs.MissingOnDisk(wd, certs.PostureEtcd); err != nil || len(missing) != 0 {
		t.Fatalf("fixture hierarchy is missing %v (%v)", missing, err)
	}
	if err := os.MkdirAll(filepath.Join(executor.EtcdDataDir(wd), "member", "snap"), 0o700); err != nil {
		t.Fatal(err)
	}
	return serverOptions{
		serverJoin: true,
		// The recorded --server: down, and never to be dialled.
		joinServer: "192.0.2.10",
		etcdPeerIP: "192.0.2.20",
		nodeName:   "server-b",
		workDir:    wd,
		token:      bootstrap.FormatServerToken(h.Cluster.PinHash(), hex.EncodeToString([]byte("restored-server-secret-24"))),
	}
}

// TestRestoredJoinedServerStartsWithServerDown: a joined server restored from a
// snapshot (a complete hierarchy and a member on disk) starts with the --server its
// install recorded unreachable. The CA-bundle import fetches nothing, and the etcd
// member route is never asked: the member starts from its own data dir.
func TestRestoredJoinedServerStartsWithServerDown(t *testing.T) {
	opts := restoredJoinedServer(t)
	logger := slog.New(slog.DiscardHandler)
	rt := &failingTransport{}
	if err := importServerCABundleVia(t.Context(), opts, &http.Client{Transport: rt}, logger); err != nil {
		t.Fatalf("CA-bundle import on a restored joined server = %v, want nil with --server down", err)
	}
	if n := rt.calls.Load(); n != 0 {
		t.Errorf("the CA-bundle import dialled --server %d time(s); a complete hierarchy needs no fetch", n)
	}

	j := newServerEtcdJoin(opts)
	j.member = func(context.Context, bootstrap.EtcdMemberRequest) (bootstrap.EtcdMemberResponse, error) {
		t.Error("the member route was asked, but the restored member already exists on disk")
		return bootstrap.EtcdMemberResponse{}, errors.New("unreachable")
	}
	cfg, err := joinEtcdMember(t.Context(), j, opts.joinServer, executor.Config{WorkDir: opts.workDir, Etcd: opts.etcdConfig()}, logger)
	if err != nil {
		t.Fatalf("joinEtcdMember on a restored member = %v, want its own data dir", err)
	}
	if cfg.Etcd == nil || cfg.Etcd.InitialCluster != "" {
		t.Errorf("restored member's etcd config = %+v, want no initial cluster (a restart)", cfg.Etcd)
	}
}

// TestServerStartRefusesInterruptedRestore: an etcd server whose restore stopped
// between its renames refuses to start before any join or bootstrap, and the
// refusal says how to finish or undo the restore.
func TestServerStartRefusesInterruptedRestore(t *testing.T) {
	opts := restoredJoinedServer(t)
	bak := filepath.Join(opts.workDir, "etcd.restore-20261007T120000Z.bak")
	if err := os.Rename(executor.EtcdDataDir(opts.workDir), bak); err != nil {
		t.Fatal(err)
	}
	opts.token, opts.tokenFile = "", ""
	err := validateServerOptions(&opts, nil, slog.New(slog.DiscardHandler))
	if !errors.Is(err, executor.ErrEtcdRestoreInterrupted) {
		t.Fatalf("validateServerOptions = %v, want ErrEtcdRestoreInterrupted", err)
	}
	for _, want := range []string{"k3sm snapshot restore", "sudo mv " + bak + " " + executor.EtcdDataDir(opts.workDir)} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("refusal %q does not say %q", err, want)
		}
	}
	if _, serr := os.Stat(executor.EtcdDataDir(opts.workDir)); !os.IsNotExist(serr) {
		t.Error("the refusal created an etcd data dir")
	}
}

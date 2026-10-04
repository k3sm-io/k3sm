package bootstrap_test

import (
	"context"
	"testing"

	"k3sm.io/k3sm/pkg/bootstrap"
	"k3sm.io/k3sm/pkg/certs"
)

func TestB435RedReimport(t *testing.T) {
	wdA := t.TempDir()
	hA, _ := certs.EnsureHierarchy(wdA)
	hA.EtcdServer, hA.EtcdPeer, _ = certs.EnsureEtcdCAs(wdA)
	pt, _ := hA.Marshal()
	sealed, _ := bootstrap.SealBundle("s3cr3t-0123456789abcdef0123456789", pt)
	ts := bundleTestServer(t, sealed, false)
	defer ts.Close()
	wdB := t.TempDir()
	imp := func() error {
		return bootstrap.ImportCABundle(context.Background(), bootstrap.ServerJoinOptions{Server: ts.URL,
			Token: bootstrap.FormatServerToken(hA.Cluster.PinHash(), "s3cr3t-0123456789abcdef0123456789"), WorkDir: wdB, HTTPClient: ts.Client()})
	}
	if err := imp(); err != nil {
		t.Fatalf("first import: %v", err)
	}
	if err := imp(); err != nil {
		t.Fatalf("restart re-import: %v", err)
	}
}

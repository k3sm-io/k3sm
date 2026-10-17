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

package install

import (
	"bytes"
	"context"
	"fmt"
	"regexp"
	"strings"
	"testing"
	"time"

	"k8s.io/client-go/tools/clientcmd"

	"k3sm.io/k3sm/pkg/version"
)

// mintedAdminToken is generateToken's shape, spelled here rather than read
// from the package so the gate states the format it holds the installer to.
var mintedAdminToken = regexp.MustCompile(`^k3sm-[0-9a-f]{48}$`)

// adminCredential is what a copy of the admin kubeconfig authenticates with:
// the bearer token of its k3sm user and the CA it verifies the apiserver by.
func adminCredential(t *testing.T, f *fakeSystem) (token string, ca []byte) {
	t.Helper()
	kc, err := clientcmd.Load([]byte(f.kubeContent))
	if err != nil {
		t.Fatalf("parse the admin kubeconfig: %v", err)
	}
	au, cl := soleAuth(kc.AuthInfos), soleCluster(kc.Clusters)
	if au == nil || cl == nil || au.Token == "" {
		t.Fatal("the admin kubeconfig has no user token or cluster")
	}
	return au.Token, cl.CertificateAuthorityData
}

// TestServerRollKeepsTheAdminCredentialValid is the gate for B695: the server's
// turn in a managed roll (and Repair) runs the in-place update, and that update
// keeps the admin credential, so a copy of the admin kubeconfig taken before the
// roll (a worker's, a tool's) still authenticates after it. A fresh install still
// mints a credential of its own. An installed token the update cannot trust is
// not carried: the update mints, stages the new token in step with the
// kubeconfig, and reports the rotation.
func TestServerRollKeepsTheAdminCredentialValid(t *testing.T) {
	firstServer := func(t *testing.T) (*fakeSystem, Config, []byte) {
		t.Helper()
		shrinkRestartBudgets(t)
		f := &fakeSystem{}
		first := testConfig(t)
		first.MeshIP = "100.64.0.1"
		res, err := InstallWithResult(context.Background(), f, first)
		if err != nil {
			t.Fatalf("the first server install: %v", err)
		}
		if res.AdminTokenRotated {
			t.Error("a fresh install reported a rotated admin token: it has no token to rotate")
		}
		staged := f.files[first.withDefaults().serverTokenPath()]
		if !mintedAdminToken.MatchString(string(bytes.TrimSpace(staged))) {
			t.Fatalf("the first install staged %d bytes that are not a minted admin token", len(staged))
		}
		return f, first, staged
	}
	inPlace := func(first Config) Config {
		req := inPlaceRequest()
		req.DataRoot, req.ServerArgsRecord = first.DataRoot, first.ServerArgsRecord
		return req
	}
	alice := func(string) (string, error) { return "alice", nil }
	update := func(t *testing.T, f *fakeSystem, req Config) Result {
		t.Helper()
		cfg, err := ResolveInPlace(f, req, alice)
		if err != nil {
			t.Fatalf("ResolveInPlace = %v", err)
		}
		res, err := InstallWithResult(context.Background(), f, cfg)
		if err != nil {
			t.Fatalf("the in-place server install: %v", err)
		}
		return res
	}

	for _, tc := range []struct {
		name string
		req  func(Config) Config
	}{
		{"the roll's argv: the owner is read from the recorded kubeconfig", inPlace},
		{"the app's argv: --user names the owner", func(first Config) Config {
			req := inPlace(first)
			req.TargetUser = "alice"
			return req
		}},
	} {
		t.Run("an in-place update keeps the credential: "+tc.name, func(t *testing.T) {
			f, first, staged := firstServer(t)
			beforeTok, beforeCA := adminCredential(t, f)
			res := update(t, f, tc.req(first))
			afterTok, afterCA := adminCredential(t, f)
			if afterTok != beforeTok {
				t.Error("the in-place update rewrote the admin kubeconfig with a new token: every copy taken before the roll is now Unauthorized")
			}
			if !bytes.Equal(afterCA, beforeCA) {
				t.Error("the in-place update rewrote the admin kubeconfig with a different CA")
			}
			if got := f.files[first.withDefaults().serverTokenPath()]; !bytes.Equal(got, staged) {
				t.Error("the in-place update staged a different admin token for the server daemon than the one it served before")
			}
			if res.AdminTokenRotated {
				t.Error("the in-place update kept the token but reported it rotated")
			}
		})
	}

	t.Run("a fresh install mints a new credential", func(t *testing.T) {
		f1, _, _ := firstServer(t)
		f2, _, _ := firstServer(t)
		tok1, _ := adminCredential(t, f1)
		tok2, _ := adminCredential(t, f2)
		if tok1 == tok2 {
			t.Error("two fresh installs carry the same admin token: a fresh install must mint its own")
		}
	})

	for _, tc := range []struct {
		name  string
		plant func(f *fakeSystem, path string, staged []byte)
	}{
		{"a malformed staged token", func(f *fakeSystem, path string, _ []byte) {
			f.putFile(path, []byte("k3sm-x,admin,admin-uid,\"system:masters\"\n"))
		}},
		{"an empty staged token", func(f *fakeSystem, path string, _ []byte) { f.putFile(path, []byte("\n")) }},
		{"a missing staged token", func(f *fakeSystem, path string, _ []byte) { delete(f.files, path) }},
		{"a symlink in place of the staged token", func(f *fakeSystem, path string, _ []byte) { f.putSymlink(path) }},
		{"a staged token owned by another user", func(f *fakeSystem, path string, _ []byte) {
			f.putOwned(path, 501, 20, 0o600, EntryRegular)
		}},
		{"a group-writable staged token", func(f *fakeSystem, path string, _ []byte) {
			f.putOwned(path, 271, 271, 0o620, EntryRegular)
		}},
		{"a staged token larger than a token can be", func(f *fakeSystem, path string, staged []byte) {
			f.putFile(path, append(bytes.Repeat([]byte(" "), maxAdminTokenFile), staged...))
		}},
	} {
		t.Run(tc.name+" is not carried: the update mints one and reports it", func(t *testing.T) {
			f, first, staged := firstServer(t)
			path := first.withDefaults().serverTokenPath()
			beforeTok, _ := adminCredential(t, f)
			tc.plant(f, path, staged)
			res := update(t, f, inPlace(first))
			delete(f.kinds, path) // read back what the install staged over the plant
			tok, _ := adminCredential(t, f)
			if tok == beforeTok {
				t.Error("an untrusted staged token was carried into the admin kubeconfig")
			}
			if !mintedAdminToken.MatchString(tok) || string(bytes.TrimSpace(f.files[path])) != tok {
				t.Error("the update did not mint and stage a fresh admin token in lockstep with the kubeconfig")
			}
			if !res.AdminTokenRotated {
				t.Error("the update minted a new admin token without reporting the rotation")
			}
		})
	}
}

// TestAdminTokenRotationLeavesAMarker: an install that mints over an installed
// admin token leaves the server daemon a marker holding only the install's
// time, service-user-owned at the token's own modes; a fresh install leaves
// none, and an install that keeps the token leaves an existing marker in place
// (only the node removes it, once published).
func TestAdminTokenRotationLeavesAMarker(t *testing.T) {
	alice := func(string) (string, error) { return "alice", nil }
	setup := func(t *testing.T) (*fakeSystem, Config, string) {
		t.Helper()
		shrinkRestartBudgets(t)
		f := &fakeSystem{}
		first := testConfig(t)
		first.MeshIP = "100.64.0.1"
		if _, err := InstallWithResult(context.Background(), f, first); err != nil {
			t.Fatalf("the first server install: %v", err)
		}
		marker := AdminTokenRotatedMarkerPath(first.withDefaults().serverWorkDir())
		if _, ok := f.files[marker]; ok {
			t.Fatal("a fresh install left an admin token rotation marker")
		}
		return f, first, marker
	}
	update := func(t *testing.T, f *fakeSystem, first Config) Result {
		t.Helper()
		req := inPlaceRequest()
		req.DataRoot, req.ServerArgsRecord = first.DataRoot, first.ServerArgsRecord
		cfg, err := ResolveInPlace(f, req, alice)
		if err != nil {
			t.Fatalf("ResolveInPlace = %v", err)
		}
		res, err := InstallWithResult(context.Background(), f, cfg)
		if err != nil {
			t.Fatalf("the in-place server install: %v", err)
		}
		return res
	}

	t.Run("a rotation leaves the install time and nothing else", func(t *testing.T) {
		f, first, marker := setup(t)
		delete(f.files, first.withDefaults().serverTokenPath())
		before := time.Now().UTC().Truncate(time.Second)
		res := update(t, f, first)
		after := time.Now().UTC()
		if !res.AdminTokenRotated {
			t.Fatal("the update did not report the rotation")
		}
		raw, ok := f.files[marker]
		if !ok {
			t.Fatal("the rotation left no marker for the server daemon")
		}
		lines := strings.Split(string(raw), "\n")
		if len(lines) != 3 || lines[2] != "" {
			t.Fatalf("the marker is not two lines: %q", raw)
		}
		at, err := time.Parse(time.RFC3339, lines[0])
		if err != nil {
			t.Fatalf("the marker's first line is not an RFC 3339 time: %q (%v)", raw, err)
		}
		if lines[1] != version.Get().Version {
			t.Errorf("the marker names release %q, want the installing build's %q", lines[1], version.Get().Version)
		}
		if at.Before(before) || at.After(after) {
			t.Errorf("the marker says %s, want the install time in [%s, %s]", at, before, after)
		}
		tok, _ := adminCredential(t, f)
		if bytes.Contains(raw, []byte(tok)) || bytes.Contains(raw, []byte("k3sm-")) {
			t.Error("the marker carries the admin token")
		}
		want := fmt.Sprintf("WriteServiceUserFile:%s:%#o:%#o:", marker, ServerTokenFileMode, ServerTokenDirMode)
		found := false
		for _, c := range f.calls {
			if strings.HasPrefix(c, want) && !strings.HasSuffix(c, ":0") {
				found = true
			}
		}
		if !found {
			t.Errorf("the marker was not written service-user-owned at the token's modes (want a %q call): %v", want, f.calls)
		}
	})

	t.Run("an install that keeps the token leaves an existing marker in place", func(t *testing.T) {
		f, first, marker := setup(t)
		const earlier = "2026-01-01T00:00:00Z\n"
		f.putFile(marker, []byte(earlier))
		if res := update(t, f, first); res.AdminTokenRotated {
			t.Fatal("the update kept the token but reported it rotated")
		}
		if got, ok := f.files[marker]; !ok || string(got) != earlier {
			t.Errorf("an install that kept the admin token changed an unpublished rotation marker: %q (present %v)", got, ok)
		}
		for _, c := range f.calls {
			if strings.Contains(c, AdminTokenRotatedMarkerName) {
				t.Errorf("an install that kept the admin token touched the marker: %s", c)
			}
		}
	})
}

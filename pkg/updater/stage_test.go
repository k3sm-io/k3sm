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

package updater

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io/fs"
	"log/slog"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"k3sm.io/k3sm/pkg/updater/layout"
)

// stageRig is a temporary root with current 0.3.0, previous 0.2.0 and a
// delivered release in inbox/.
type stageRig struct {
	fs      *testFS
	l       layout.Layout
	s       *Stager
	payload *fakePayload
	code    *fakeCode
	log     *bytes.Buffer
	req     StageRequest
}

func newStageRig(t *testing.T) *stageRig {
	t.Helper()
	f := newTestFS(t)
	l := f.tree(t)
	installVersion(t, l, "0.2.0")
	installVersion(t, l, "0.3.0")
	link(t, f, l.PlanPrevious, "0.2.0")
	link(t, f, l.PlanCurrent, "0.3.0")
	r := &stageRig{fs: f, l: l, payload: &fakePayload{}, code: &fakeCode{refuse: map[string]bool{}}, log: &bytes.Buffer{}}
	r.s = &Stager{
		FS: f, Layout: l, Payload: r.payload, Code: r.code, Pods: fakePods(nil),
		Clock: &fakeClock{now: time.Date(2026, 11, 6, 0, 0, 0, 0, time.UTC), boot: "b1"}, SourceUID: k3smUID,
		Log:   slog.New(slog.NewTextHandler(r.log, nil)),
		Nonce: func() (string, error) { return "n1", nil },
	}
	return r
}

// deliver writes a release into inbox/, owned by the k3sm user.
func (r *stageRig) deliver(t *testing.T, rel release, sig string) {
	t.Helper()
	archive, manifest := rel.build(t)
	in := filepath.Join(r.fs.root, "inbox")
	r.req = StageRequest{
		Archive: filepath.Join(in, "a.tar"), Manifest: filepath.Join(in, "m.json"),
		Signature: filepath.Join(in, "m.sig"), Signer: filepath.Join(in, "s.pem"), Policy: PolicyRequired,
	}
	for p, body := range map[string]string{r.req.Archive: string(archive), r.req.Manifest: string(manifest), r.req.Signature: sig, r.req.Signer: "signer"} {
		writeFile(t, p, body, 0o644)
		r.fs.uid[p] = k3smUID
	}
}

func (r *stageRig) stage(t *testing.T) (string, error) {
	t.Helper()
	return r.s.Stage(context.Background(), r.req, "0.3.0")
}

func wantErr(t *testing.T, err, want error) {
	t.Helper()
	if !errors.Is(err, want) {
		t.Fatalf("err = %v, want %v", err, want)
	}
}

// TestStagePath is the stage path's table: the bounds, the source and trust
// checks, the manifest rules and the copy the verifier reads.
func TestStagePath(t *testing.T) {
	for _, tc := range []struct {
		name string
		run  func(t *testing.T, r *stageRig)
	}{
		{"stages a verified release into versions", func(t *testing.T, r *stageRig) {
			r.deliver(t, newRelease("0.4.0"), goodSig)
			ver, err := r.stage(t)
			if err != nil || ver != "0.4.0" {
				t.Fatalf("Stage = %q, %v", ver, err)
			}
			dir := filepath.Join(r.l.VersionsDir(), "0.4.0")
			for name, body := range newRelease("0.4.0").files {
				got, err := os.ReadFile(filepath.Join(dir, name))
				if err != nil || string(got) != body {
					t.Errorf("%s = %q, %v", name, got, err)
				}
			}
			if fi, _ := os.Stat(filepath.Join(dir, "k3sm")); fi.Mode().Perm() != 0o755 {
				t.Errorf("k3sm mode %s, want 0755", fi.Mode().Perm())
			}
			if fi, _ := os.Stat(filepath.Join(dir, "LICENSE")); fi.Mode().Perm() != 0o644 {
				t.Errorf("LICENSE mode %s, want 0644", fi.Mode().Perm())
			}
			if _, err := os.Lstat(dir + partialSuffix); !errors.Is(err, fs.ErrNotExist) {
				t.Errorf("partial left: %v", err)
			}
			if staged, err := r.s.state().staged(); staged != "0.4.0" || err != nil {
				t.Errorf("staged = %q, %v", staged, err)
			}
			if names, _ := os.ReadDir(r.l.WorkDir()); len(names) != 0 {
				t.Errorf("work dir not emptied: %v", names)
			}
			if len(r.code.checked) != len(RequiredMembers)+1 {
				t.Errorf("Apple leg ran on %d paths, want %d", len(r.code.checked), len(RequiredMembers)+1)
			}
			for _, p := range r.code.checked {
				if !strings.Contains(p, "/versions/0.4.0.partial/") {
					t.Errorf("Apple leg ran on %s, not the staged path", p)
				}
			}
		}},
		{"logs the accepted signer once per stage", func(t *testing.T, r *stageRig) {
			// The fake signer is not a certificate, so the log names nothing;
			// a parseable one is logged with CN, serial and not-after.
			r.deliver(t, newRelease("0.4.0"), goodSig)
			if _, err := r.stage(t); err != nil {
				t.Fatal(err)
			}
			r.s.logSigner(signerPEM(t), "0.4.0")
			if got := strings.Count(r.log.String(), "accepted the update signer"); got != 1 {
				t.Errorf("signer logged %d times:\n%s", got, r.log)
			}
			for _, want := range []string{"cn=", "serial=", "notAfter="} {
				if !strings.Contains(r.log.String(), want) {
					t.Errorf("log lacks %s:\n%s", want, r.log)
				}
			}
		}},
		{"a fourth staged version refused", func(t *testing.T, r *stageRig) {
			if err := r.s.state().writeStaged("0.3.5"); err != nil {
				t.Fatal(err)
			}
			r.deliver(t, newRelease("0.4.0"), goodSig)
			_, err := r.stage(t)
			wantErr(t, err, layout.ErrStagingFull)
		}},
		{"restaging the staged version is a retry", func(t *testing.T, r *stageRig) {
			r.deliver(t, newRelease("0.4.0"), goodSig)
			if _, err := r.stage(t); err != nil {
				t.Fatal(err)
			}
			if _, err := r.stage(t); err != nil {
				t.Fatalf("retry: %v", err)
			}
		}},
		{"source archive not a regular file owned by _k3sm", func(t *testing.T, r *stageRig) {
			r.deliver(t, newRelease("0.4.0"), goodSig)
			r.fs.uid[r.req.Archive] = 0
			_, err := r.stage(t)
			wantErr(t, err, ErrSource)
			r.fs.uid[r.req.Archive] = 502
			_, err = r.stage(t)
			wantErr(t, err, ErrSource)
			r.fs.uid[r.req.Archive] = k3smUID

			link := filepath.Join(r.fs.root, "inbox", "link.tar")
			if err := os.Symlink(r.req.Archive, link); err != nil {
				t.Fatal(err)
			}
			req := r.req
			req.Archive = link
			_, err = r.s.Stage(context.Background(), req, "0.3.0")
			wantErr(t, err, ErrSource)
			if !errors.Is(err, ErrSymlink) {
				t.Errorf("symlink: err = %v, want ErrSymlink", err)
			}

			fifo := filepath.Join(r.fs.root, "inbox", "fifo")
			if err := syscall.Mkfifo(fifo, 0o644); err != nil {
				t.Fatal(err)
			}
			r.fs.uid[fifo] = k3smUID
			req.Archive = fifo
			_, err = r.s.Stage(context.Background(), req, "0.3.0")
			wantErr(t, err, ErrSource)

			req.Archive = filepath.Join(r.fs.root, "inbox")
			_, err = r.s.Stage(context.Background(), req, "0.3.0")
			wantErr(t, err, ErrSource)
			r.fs.uid[r.req.Manifest] = 0
			_, err = r.stage(t)
			wantErr(t, err, ErrSource)
		}},
		{"source swapped after the copy", func(t *testing.T, r *stageRig) {
			rel := newRelease("0.4.0")
			r.deliver(t, rel, goodSig)
			want, _ := os.ReadFile(r.req.Archive)
			evil := newRelease("0.4.0")
			evil.files["k3sm"] = machO("evil")
			evilArchive, _ := evil.build(t)
			r.fs.onClose[r.req.Archive] = func() {
				if err := os.WriteFile(r.req.Archive, evilArchive, 0o644); err != nil {
					t.Error(err)
				}
			}
			if _, err := r.stage(t); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(r.payload.sawArchive, want) {
				t.Error("the verifier read bytes other than the copied ones")
			}
			if !strings.HasPrefix(r.payload.archiveName, r.l.WorkDir()+"/") {
				t.Errorf("the verifier read %s, not the root-only copy", r.payload.archiveName)
			}
			got, _ := os.ReadFile(filepath.Join(r.l.VersionsDir(), "0.4.0", "k3sm"))
			if string(got) != rel.files["k3sm"] {
				t.Errorf("staged k3sm = %q, want the copied bytes", got)
			}
		}},
		{"archive over its bound refused", func(t *testing.T, r *stageRig) {
			r.deliver(t, newRelease("0.4.0"), goodSig)
			r.s.lim = limits{archive: 64, extracted: MaxExtractedBytes, members: MaxMembers}
			_, err := r.stage(t)
			wantErr(t, err, ErrTooLarge)
		}},
		{"extraction over its bound refused", func(t *testing.T, r *stageRig) {
			r.deliver(t, newRelease("0.4.0"), goodSig)
			r.s.lim = limits{archive: MaxArchiveBytes, extracted: 40, members: MaxMembers}
			_, err := r.stage(t)
			wantErr(t, err, ErrTooLarge)
			if _, err := os.Lstat(filepath.Join(r.l.VersionsDir(), "0.4.0"+partialSuffix)); !errors.Is(err, fs.ErrNotExist) {
				t.Errorf("partial left after a refusal: %v", err)
			}
		}},
		{"more members than the bound refused", func(t *testing.T, r *stageRig) {
			r.deliver(t, newRelease("0.4.0"), goodSig)
			r.s.lim = limits{archive: MaxArchiveBytes, extracted: MaxExtractedBytes, members: 4}
			_, err := r.stage(t)
			wantErr(t, err, ErrTooLarge)
		}},
		{"unsigned or wrongly signed refused under every policy", func(t *testing.T, r *stageRig) {
			for _, p := range []SignaturePolicy{PolicyUnset, PolicyIfSigned, PolicyRequired} {
				r.deliver(t, newRelease("0.4.0"), "")
				r.req.Policy = p
				if _, err := r.stage(t); err == nil {
					t.Errorf("policy %q staged an unsigned release", p)
				}
				r.deliver(t, newRelease("0.4.0"), "forged")
				r.req.Policy = p
				if _, err := r.stage(t); err == nil {
					t.Errorf("policy %q staged a wrongly signed release", p)
				}
			}
			r.deliver(t, newRelease("0.4.0"), goodSig)
			r.req.Policy = "off"
			_, err := r.stage(t)
			wantErr(t, err, ErrPolicy)
		}},
		{"manifest version not a directory name refused", func(t *testing.T, r *stageRig) {
			for _, v := range []string{".", "..", "0.4.0/../x", "unknown-0123456789ab"} {
				r.deliver(t, newRelease(v), goodSig)
				_, err := r.stage(t)
				wantErr(t, err, layout.ErrBadVersion)
			}
		}},
		{"requiresInstaller refused", func(t *testing.T, r *stageRig) {
			rel := newRelease("0.4.0")
			rel.requiresInstaller = true
			r.deliver(t, rel, goodSig)
			_, err := r.stage(t)
			wantErr(t, err, layout.ErrRequiresInstaller)
		}},
		{"compatibleFrom above the installed version refused", func(t *testing.T, r *stageRig) {
			rel := newRelease("0.4.0")
			rel.compatibleFrom = "0.3.1"
			r.deliver(t, rel, goodSig)
			_, err := r.stage(t)
			wantErr(t, err, ErrIncompatible)
		}},
		{"a required top-level member missing refused", func(t *testing.T, r *stageRig) {
			rel := newRelease("0.4.0")
			delete(rel.files, "k3sm-vmhost")
			r.deliver(t, rel, goodSig)
			_, err := r.stage(t)
			wantErr(t, err, ErrManifest)
		}},
		{"extra member refused", func(t *testing.T, r *stageRig) {
			rel := newRelease("0.4.0")
			rel.extra = map[string]string{"cp-payload/extra": machO("extra")}
			r.deliver(t, rel, goodSig)
			_, err := r.stage(t)
			wantErr(t, err, ErrManifest)
		}},
		{"member whose bytes are not its declared kind refused", func(t *testing.T, r *stageRig) {
			rel := newRelease("0.4.0")
			rel.files["NOTICE"] = machO("hidden code")
			rel.kinds = map[string]MemberKind{"NOTICE": MemberData}
			r.deliver(t, rel, goodSig)
			_, err := r.stage(t)
			wantErr(t, err, ErrManifest)
		}},
		{"Apple leg refusal refused and the partial removed", func(t *testing.T, r *stageRig) {
			r.code.refuse["k3sm-vmhost"] = true
			r.deliver(t, newRelease("0.4.0"), goodSig)
			_, err := r.stage(t)
			wantErr(t, err, ErrCodeCheck)
			for _, n := range []string{"0.4.0", "0.4.0" + partialSuffix} {
				if _, err := os.Lstat(filepath.Join(r.l.VersionsDir(), n)); !errors.Is(err, fs.ErrNotExist) {
					t.Errorf("%s left: %v", n, err)
				}
			}
		}},
		{"bad version and downgrade refused", func(t *testing.T, r *stageRig) {
			if err := r.s.state().markBad("V0.4.0"); err != nil {
				t.Fatal(err)
			}
			r.deliver(t, newRelease("0.4.0"), goodSig)
			_, err := r.stage(t)
			wantErr(t, err, ErrVersionBad)
			r.deliver(t, newRelease("0.2.5"), goodSig)
			_, err = r.stage(t)
			wantErr(t, err, ErrDowngrade)
		}},
		{"the root CA copy must be root-owned and read-only to others", func(t *testing.T, r *stageRig) {
			r.deliver(t, newRelease("0.4.0"), goodSig)
			r.fs.uid[r.l.TrustCA()] = k3smUID
			_, err := r.stage(t)
			wantErr(t, err, ErrTrust)
			delete(r.fs.uid, r.l.TrustCA())
			if err := os.Chmod(r.l.TrustCA(), 0o664); err != nil {
				t.Fatal(err)
			}
			_, err = r.stage(t)
			wantErr(t, err, ErrTrust)
		}},
		{"ACL or immutable flag on a trusted directory refused", func(t *testing.T, r *stageRig) {
			r.deliver(t, newRelease("0.4.0"), goodSig)
			r.fs.acl[r.l.VersionsDir()] = true
			_, err := r.stage(t)
			wantErr(t, err, ErrACL)
			delete(r.fs.acl, r.l.VersionsDir())
			r.fs.flags[r.fs.root] = 0x2 // UF_IMMUTABLE
			_, err = r.stage(t)
			wantErr(t, err, ErrBSDFlags)
		}},
		{"updater-work and stale partials emptied at start", func(t *testing.T, r *stageRig) {
			writeFile(t, filepath.Join(r.l.WorkDir(), "old", "archive"), "110 MB of stale staging", 0o600)
			writeFile(t, filepath.Join(r.l.VersionsDir(), "0.4.0"+partialSuffix, "k3sm"), "half", 0o755)
			if err := r.s.Start(); err != nil {
				t.Fatal(err)
			}
			if names, _ := os.ReadDir(r.l.WorkDir()); len(names) != 0 {
				t.Errorf("work dir holds %v", names)
			}
			if _, err := os.Lstat(filepath.Join(r.l.VersionsDir(), "0.4.0"+partialSuffix)); !errors.Is(err, fs.ErrNotExist) {
				t.Errorf("partial left: %v", err)
			}
			if _, err := os.Lstat(filepath.Join(r.l.VersionsDir(), "0.3.0")); err != nil {
				t.Errorf("a real version removed: %v", err)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) { tc.run(t, newStageRig(t)) })
	}
}

// signerPEM is a throwaway self-signed certificate for the signer log line.
func signerPEM(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(42), Subject: pkix.Name{CommonName: "k3sm-update-signer"},
		NotBefore: time.Unix(0, 0), NotAfter: time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

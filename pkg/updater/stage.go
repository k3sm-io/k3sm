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
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"path"
	"path/filepath"
	"slices"
	"strings"

	"k3sm.io/k3sm/pkg/updater/layout"
)

// Bounds on what the stage path reads from a less privileged user (resolution
// 17). Every one is checked on the descriptor before a byte is copied.
const (
	// MaxArchiveBytes is the largest archive staged.
	MaxArchiveBytes int64 = 2 << 30
	// MaxExtractedBytes is the most a staged version may hold.
	MaxExtractedBytes int64 = 4 << 30
	// MaxMembers is the most files a release may carry.
	MaxMembers = 64
	// MaxManifestBytes is the largest signed manifest read.
	MaxManifestBytes int64 = 64 << 10
	// MaxSignatureBytes is the largest manifest signature read.
	MaxSignatureBytes int64 = 1 << 10
	// MaxSignerBytes is the largest signer certificate read.
	MaxSignerBytes int64 = 16 << 10
	// MaxClusterCABytes is the largest trust copy read.
	MaxClusterCABytes int64 = 1 << 20
)

// maxTreeEntries bounds the entries of a staged tree, directories included.
const maxTreeEntries = 2 * MaxMembers

// partialSuffix names a version directory being staged.
const partialSuffix = ".partial"

// RequiredMembers are the top-level files every release carries, each a
// Mach-O: the set netd's update path requires beside k3sm, and the updater.
var RequiredMembers = []string{
	layout.K3smBinary,
	"k3sm-execshim",
	"k3sm-vmhost",
	"libk3sm_getaddrinfo_shim.dylib",
	"libk3sm_pathrebase_shim.dylib",
	layout.UpdaterBinary,
}

// SignaturePolicy is the Update's signature field. The updater treats every
// value as required: no value turns either signature check off.
type SignaturePolicy string

// The policies an Update may name.
const (
	PolicyUnset    SignaturePolicy = ""
	PolicyIfSigned SignaturePolicy = "if-signed"
	PolicyRequired SignaturePolicy = "required"
)

var (
	// ErrSource reports a delivered file that is not a regular file owned by
	// the k3sm user, or that is over its bound.
	ErrSource = errors.New("the delivered file is not a regular file owned by _k3sm within its bound")
	// ErrTrust reports a trust copy that is not root-owned and read-only to
	// everyone else.
	ErrTrust = errors.New("the trust copy is not root-owned and read-only to others")
	// ErrPolicy reports a signature policy the updater does not know.
	ErrPolicy = errors.New("unknown signature policy")
	// ErrManifest reports a manifest the stage path refuses after the
	// signature verified, or a staged tree that does not match it.
	ErrManifest = errors.New("the release does not satisfy its manifest")
	// ErrIncompatible reports an installed version older than the release's
	// compatibleFrom.
	ErrIncompatible = errors.New("the installed version is older than the release's compatibleFrom")
	// ErrTooLarge reports an archive, an extraction or a member count over
	// its bound.
	ErrTooLarge = errors.New("the release is over a staging bound")
	// ErrCodeCheck reports a Mach-O the Apple leg refused.
	ErrCodeCheck = errors.New("the Apple code check refused a member")
)

// StageRequest names the files a stage reads. Every path is the delivered
// original; the stager copies each before it reads it.
type StageRequest struct {
	// Archive is the release archive.
	Archive string
	// Manifest is the signed manifest delivered beside it.
	Manifest string
	// Signature is the manifest signature.
	Signature string
	// Signer is the update signer's PEM certificate.
	Signer string
	// Policy is the Update's signature field; every value is required.
	Policy SignaturePolicy
}

// limits are the bounds a stage applies; a test lowers them.
type limits struct {
	archive, extracted int64
	members            int
}

var defaultLimits = limits{archive: MaxArchiveBytes, extracted: MaxExtractedBytes, members: MaxMembers}

// Stager stages verified releases into the versions directory of one root.
type Stager struct {
	// FS is the filesystem, OSFS in production.
	FS FS
	// Layout is the tree under the root.
	Layout layout.Layout
	// Payload is the k3sm leg.
	Payload PayloadVerifier
	// Code is the Apple leg.
	Code CodeVerifier
	// Pods reports the versions running pods hold.
	Pods PodUsage
	// Clock is the time the signer is checked at.
	Clock Clock
	// SourceUID is the uid that delivers archives (_k3sm).
	SourceUID uint32
	// Log receives the accepted signer once per stage.
	Log *slog.Logger
	// Nonce names a work directory; nil reads crypto/rand.
	Nonce func() (string, error)

	lim limits
}

func (s *Stager) limits() limits {
	if s.lim == (limits{}) {
		return defaultLimits
	}
	return s.lim
}

func (s *Stager) state() state { return state{fs: s.FS, dir: s.Layout.StateDir()} }

// Start empties updater-work and removes every versions/<ver>.partial a crash
// left, after checking the directories are root's. The resident updater runs
// it once at start, before it accepts a stage.
func (s *Stager) Start() error {
	l := s.Layout
	if err := checkTrustedDirs(s.FS, l.WorkDir(), l.VersionsDir(), l.StateDir()); err != nil {
		return err
	}
	if err := emptyDir(s.FS, l.WorkDir()); err != nil {
		return fmt.Errorf("empty %s: %w", l.WorkDir(), err)
	}
	names, err := s.FS.ReadDirNames(l.VersionsDir(), maxEmptyEntries)
	if err != nil {
		return err
	}
	for _, n := range names {
		if ver, ok := strings.CutSuffix(n, partialSuffix); ok && layout.ValidateVersion(ver) == nil {
			if err := s.FS.RemoveAll(filepath.Join(l.VersionsDir(), n)); err != nil {
				return err
			}
		}
	}
	return nil
}

// Stage copies, verifies and installs one release as versions/<ver> and
// records it as staged. installed is the version current points at. It returns
// the staged version.
func (s *Stager) Stage(ctx context.Context, req StageRequest, installed string) (string, error) {
	switch req.Policy {
	case PolicyUnset, PolicyIfSigned, PolicyRequired:
	default:
		return "", fmt.Errorf("%w %q", ErrPolicy, untrusted(string(req.Policy)))
	}
	l, lim := s.Layout, s.limits()
	if err := checkTrustedDirs(s.FS, l.WorkDir(), l.VersionsDir(), l.StateDir(), filepath.Dir(l.TrustCA())); err != nil {
		return "", err
	}
	ca, err := s.readTrusted(l.TrustCA(), MaxClusterCABytes)
	if err != nil {
		return "", err
	}
	nonce, err := s.nonce()
	if err != nil {
		return "", err
	}
	work := filepath.Join(l.WorkDir(), nonce)
	if err := s.FS.Mkdir(work, 0o700); err != nil {
		return "", err
	}
	defer func() { _ = s.FS.RemoveAll(work) }()

	// 1. Copy every delivered file into the root-only work directory and
	// close the source; only the copies are read from here on.
	var in SignedInput
	for _, c := range []struct {
		src, name string
		max       int64
		dst       *[]byte
	}{
		{req.Manifest, "manifest.json", MaxManifestBytes, &in.Manifest},
		{req.Signature, "manifest.sig", MaxSignatureBytes, &in.Signature},
		{req.Signer, "signer.pem", MaxSignerBytes, &in.SignerCertPEM},
	} {
		if *c.dst, err = s.copyIn(c.src, filepath.Join(work, c.name), c.max); err != nil {
			return "", err
		}
	}
	archiveCopy := filepath.Join(work, "archive")
	if _, err := s.copyIn(req.Archive, archiveCopy, lim.archive); err != nil {
		return "", err
	}
	in.ClusterCAPEM = ca
	in.Now = s.Clock.Now()

	// 2-3. Hash, verify and extract the copy.
	archive, err := s.FS.OpenRead(archiveCopy)
	if err != nil {
		return "", err
	}
	defer func() { _ = archive.Close() }()
	extract := filepath.Join(work, "x")
	if err := s.FS.Mkdir(extract, 0o700); err != nil {
		return "", err
	}
	m, err := s.Payload.VerifyPayload(ctx, in, archive, extract)
	if err != nil {
		return "", fmt.Errorf("k3sm signature check: %w", err)
	}
	ver, err := s.checkManifest(ctx, m, installed)
	if err != nil {
		return "", err
	}
	s.logSigner(in.SignerCertPEM, ver)

	// 4. Manifest check per file and Apple check per Mach-O, on the paths the
	// set will run from.
	partial := filepath.Join(l.VersionsDir(), ver+partialSuffix)
	if err := s.FS.RemoveAll(partial); err != nil {
		return "", err
	}
	if err := s.FS.Rename(extract, partial); err != nil {
		return "", err
	}
	if err := s.checkTree(ctx, partial, m, lim); err != nil {
		_ = s.FS.RemoveAll(partial)
		return "", err
	}

	// 5. Flush, rename into place, record the stage.
	final := filepath.Join(l.VersionsDir(), ver)
	if err := s.FS.FlushTree(partial); err != nil {
		return "", err
	}
	if err := s.FS.RemoveAll(final); err != nil {
		return "", err
	}
	if err := s.FS.Rename(partial, final); err != nil {
		return "", err
	}
	if err := s.state().writeStaged(ver); err != nil {
		return "", err
	}
	return ver, nil
}

// copyIn opens src no-follow, requires a regular file owned by SourceUID with
// no other link and within max bytes, copies it to dst (0600, flushed), closes
// the source and returns the copied bytes when they are small enough to hold;
// the archive's copy is returned as nil.
func (s *Stager) copyIn(src, dst string, max int64) ([]byte, error) {
	f, err := s.FS.OpenRead(src)
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %w", ErrSource, src, err)
	}
	defer func() { _ = f.Close() }()
	info, err := f.Info()
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %w", ErrSource, src, err)
	}
	switch {
	case !info.Mode.IsRegular():
		return nil, fmt.Errorf("%w: %s is %s", ErrSource, src, info.Mode.Type())
	case info.UID != s.SourceUID:
		return nil, fmt.Errorf("%w: %s is owned by uid %d", ErrSource, src, info.UID)
	case info.Size > max:
		return nil, fmt.Errorf("%w: %w: %s is %d bytes, over %d", ErrSource, ErrTooLarge, src, info.Size, max)
	}
	out, err := s.FS.CreateExcl(dst, 0o600)
	if err != nil {
		return nil, err
	}
	var keep []byte
	var sink io.Writer = out
	var buf strings.Builder
	if max <= MaxClusterCABytes {
		sink = io.MultiWriter(out, &buf)
	}
	n, err := io.Copy(sink, io.LimitReader(f, max+1))
	if err == nil && n > max {
		err = fmt.Errorf("%w: %w: %s grew past %d bytes while it was copied", ErrSource, ErrTooLarge, src, max)
	}
	if err == nil {
		err = out.Flush()
	}
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return nil, err
	}
	if max <= MaxClusterCABytes {
		keep = []byte(buf.String())
	}
	return keep, nil
}

// readTrusted reads a root-owned file no one else may write.
func (s *Stager) readTrusted(p string, max int64) ([]byte, error) {
	f, err := s.FS.OpenRead(p)
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %w", ErrTrust, p, err)
	}
	defer func() { _ = f.Close() }()
	info, err := f.Info()
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %w", ErrTrust, p, err)
	}
	switch {
	case !info.Mode.IsRegular(), info.UID != 0, info.Mode.Perm()&0o022 != 0, info.Size > max:
		return nil, fmt.Errorf("%w: %s (uid %d, mode %s, %d bytes)", ErrTrust, p, info.UID, info.Mode, info.Size)
	}
	if err := checkExtended(p, info); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrTrust, err)
	}
	data, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > max {
		return nil, fmt.Errorf("%w: %s grew past %d bytes", ErrTrust, p, max)
	}
	return data, nil
}

func (s *Stager) nonce() (string, error) {
	if s.Nonce != nil {
		n, err := s.Nonce()
		if err == nil && (n == "" || n != filepath.Base(n) || n == "." || n == "..") {
			err = fmt.Errorf("bad work directory name %q", n)
		}
		return n, err
	}
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// checkManifest applies the rules the verifier does not know: the version is a
// safe directory name, the release does not need the installer, the installed
// version is at least compatibleFrom, the version is not bad, not a downgrade
// and may be staged, and the required members are present.
func (s *Stager) checkManifest(ctx context.Context, m *Manifest, installed string) (string, error) {
	if m == nil {
		return "", fmt.Errorf("%w: the verifier returned no manifest", ErrManifest)
	}
	ver := m.Version
	if err := layout.CheckActivatable(ver, m.RequiresInstaller); err != nil {
		return "", err
	}
	if layout.IsUnknownVersion(ver) {
		return "", fmt.Errorf("%w: version %s", layout.ErrBadVersion, ver)
	}
	if len(m.Members) > s.limits().members {
		return "", fmt.Errorf("%w: the manifest lists %d members, over %d", ErrTooLarge, len(m.Members), s.limits().members)
	}
	if installed != "" {
		if err := layout.ValidateVersion(m.CompatibleFrom); err != nil {
			return "", fmt.Errorf("%w: compatibleFrom: %w", ErrManifest, err)
		}
		c, err := compareVersions(installed, m.CompatibleFrom)
		if err != nil {
			return "", fmt.Errorf("%w: installed %s: %w", ErrIncompatible, installed, err)
		}
		if c < 0 {
			return "", fmt.Errorf("%w: installed %s, compatibleFrom %s", ErrIncompatible, installed, m.CompatibleFrom)
		}
	}
	st := s.state()
	if err := st.checkTarget(ver, installed); err != nil {
		return "", err
	}
	r, err := s.retained()
	if err != nil {
		return "", err
	}
	if err := layout.CheckStage(r, ver); err != nil {
		return "", err
	}
	byPath := map[string]Member{}
	for _, mem := range m.Members {
		byPath[mem.Path] = mem
	}
	for _, req := range RequiredMembers {
		if mem, ok := byPath[req]; !ok || mem.Kind != MemberMachO {
			return "", fmt.Errorf("%w: the required member %s is missing or not a Mach-O", ErrManifest, req)
		}
	}
	return ver, nil
}

// retained is what the tree keeps: current, previous, the staged version and
// the versions running pods hold.
func (s *Stager) retained() (layout.Retained, error) {
	var r layout.Retained
	var err error
	if r.Current, err = resolveOptional(s.Layout.ResolveActive, s.FS); err != nil {
		return r, err
	}
	if r.Previous, err = resolveOptional(s.Layout.ResolvePrevious, s.FS); err != nil {
		return r, err
	}
	if r.Staged, err = s.state().staged(); err != nil {
		return r, err
	}
	if s.Pods != nil {
		if r.InUse, err = s.Pods.InUseVersions(context.Background()); err != nil {
			return r, err
		}
	}
	return r, nil
}

// resolveOptional resolves a layout link; an absent link is "".
func resolveOptional(resolve func(layout.Readlink) (string, error), fsys FS) (string, error) {
	ver, err := resolve(fsys.Readlink)
	if errors.Is(err, fs.ErrNotExist) {
		return "", nil
	}
	return ver, err
}

// checkTree re-reads the staged tree: exactly the manifest's members, each a
// regular file with its sha256 and kind, within the bounds, and every Mach-O
// passes the Apple leg at this path.
func (s *Stager) checkTree(ctx context.Context, dir string, m *Manifest, lim limits) error {
	entries, err := walkTree(s.FS, dir, maxTreeEntries)
	if err != nil {
		return err
	}
	want := map[string]Member{}
	for _, mem := range m.Members {
		want[mem.Path] = mem
	}
	var total int64
	files := 0
	for _, e := range entries {
		p := filepath.Join(dir, filepath.FromSlash(e.rel))
		if e.info.Mode.IsDir() {
			if err := s.FS.Chmod(p, 0o755); err != nil {
				return err
			}
			continue
		}
		mem, ok := want[e.rel]
		if !ok {
			return fmt.Errorf("%w: %s is not in the manifest", ErrManifest, untrusted(e.rel))
		}
		delete(want, e.rel)
		files++
		if total += e.info.Size; total > lim.extracted || files > lim.members {
			return fmt.Errorf("%w: the staged tree is over %d bytes or %d files", ErrTooLarge, lim.extracted, lim.members)
		}
		if err := s.checkMember(p, mem); err != nil {
			return err
		}
		mode := fs.FileMode(0o644)
		if mem.Kind == MemberMachO {
			mode = 0o755
		}
		if err := s.FS.Chmod(p, mode); err != nil {
			return err
		}
	}
	if len(want) != 0 {
		missing := slices.Sorted(func(yield func(string) bool) {
			for k := range want {
				if !yield(k) {
					return
				}
			}
		})
		return fmt.Errorf("%w: missing %s", ErrManifest, untrusted(strings.Join(missing, ",")))
	}
	for _, mem := range m.Members {
		if mem.Kind != MemberMachO {
			continue
		}
		p := filepath.Join(dir, filepath.FromSlash(mem.Path))
		if err := s.Code.VerifyCode(ctx, p, path.Base(mem.Path), m.Version); err != nil {
			return fmt.Errorf("%w: %s: %w", ErrCodeCheck, mem.Path, err)
		}
	}
	return nil
}

// checkMember hashes one staged file from its own descriptor and checks its
// kind by the 4-byte magic.
func (s *Stager) checkMember(p string, mem Member) error {
	f, err := s.FS.OpenRead(p)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	head := make([]byte, 4)
	n, err := io.ReadFull(f, head)
	if err != nil && !errors.Is(err, io.ErrUnexpectedEOF) && !errors.Is(err, io.EOF) {
		return err
	}
	head = head[:n]
	h.Write(head)
	if _, err := io.Copy(h, f); err != nil {
		return err
	}
	if hex.EncodeToString(h.Sum(nil)) != mem.SHA256 {
		return fmt.Errorf("%w: %s does not match its sha256", ErrManifest, untrusted(mem.Path))
	}
	if machOMagic(head) != (mem.Kind == MemberMachO) {
		return fmt.Errorf("%w: %s is not the kind %s the manifest declares", ErrManifest, untrusted(mem.Path), mem.Kind)
	}
	return nil
}

// logSigner records the accepted signer: CN, serial, not-after.
func (s *Stager) logSigner(signerPEM []byte, ver string) {
	if s.Log == nil {
		return
	}
	block, _ := pem.Decode(signerPEM)
	if block == nil {
		return
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return
	}
	s.Log.Info("accepted the update signer", "version", ver, "cn", cert.Subject.CommonName,
		"serial", cert.SerialNumber.String(), "notAfter", cert.NotAfter)
}

// untrusted quotes a string that came from a delivered file, bounded and
// with control characters escaped.
func untrusted(s string) string {
	const max = 128
	if len(s) > max {
		s = s[:max] + "..."
	}
	return fmt.Sprintf("%q", s)
}

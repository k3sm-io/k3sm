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

package binsign

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"golang.org/x/sys/unix"

	"k3sm.io/k3sm/internal/atomicfile"
	"k3sm.io/runtimed/pkg/image"
)

// HealMarkerName is the per-bin-dir record of binaries this k3sm has re-signed by
// replace once (see HealOnce). One line per binary: "<name>\t<stamp>".
const HealMarkerName = ".binsign-v1"

// Signer is the code-signing seam: verify a file's signature, or ad-hoc sign it.
// Codesign is the production implementation; tests fake it. A Signer that also
// implements Inspector gets the identity rule (see Inspector).
type Signer interface {
	// Verify reports whether path carries a valid AD-HOC signature, the k3sm
	// norm. A valid signature of any other kind reports false, so it is
	// re-signed ad hoc, as every staged binary always was.
	Verify(ctx context.Context, path string) (bool, error)
	// Sign ad-hoc signs the file at path under identifier, which is the
	// binary's final base name: path is only ever a temp no process can have
	// mapped, and its own name must not become the code identifier.
	Sign(ctx context.Context, path, identifier string) error
}

// Signature is what codesign reports about a file's code signature.
type Signature struct {
	// Valid reports that `codesign --verify --strict` passes.
	Valid bool
	// AdHoc reports a valid signature that carries no certificate identity.
	AdHoc bool
	// TeamID is the signing certificate's Team ID; empty when there is none.
	TeamID string
}

// IdentitySigned reports a valid signature made by a certificate identity (a
// Developer ID, say), the one kind of signature k3sm never replaces.
func (s Signature) IdentitySigned() bool { return s.Valid && !s.AdHoc }

// Inspector reads a file's signature and checks it against a designated
// requirement. When the Signer handed to EnsureSigned, SignIfInvalid or HealOnce
// also implements Inspector, those functions apply the identity rule: a binary
// whose signature verifies and is not ad hoc is never re-signed or replaced,
// whatever Verify says, because re-signing it ad hoc would strip its provenance.
// CodesignInspector is the production implementation; a caller opts into the rule
// by pairing it with Codesign, and a plain Codesign keeps the ad-hoc-only rule.
type Inspector interface {
	// Inspect reports path's signature. Only a failure to run the tool is an
	// error; an unsigned or invalid file is the zero Signature.
	Inspect(ctx context.Context, path string) (Signature, error)
	// Satisfies reports whether path's signature verifies strictly and
	// satisfies requirement, a designated-requirement source text.
	Satisfies(ctx context.Context, path, requirement string) (bool, error)
}

// teamIDLen is the length of an Apple Team ID.
const teamIDLen = 10

// ValidTeamID reports whether id has the shape of an Apple Team ID: ten
// characters of A-Z and 0-9. It is checked before an id is placed in a
// requirement source text, so the text cannot be extended through the id.
func ValidTeamID(id string) bool {
	if len(id) != teamIDLen {
		return false
	}
	for _, c := range id {
		if (c < 'A' || c > 'Z') && (c < '0' || c > '9') {
			return false
		}
	}
	return true
}

// TeamRequirement is the designated requirement a release payload binary must
// satisfy: a certificate chain anchored at Apple whose leaf is issued to teamID.
func TeamRequirement(teamID string) (string, error) {
	if !ValidTeamID(teamID) {
		return "", fmt.Errorf("binsign: %q is not a Team ID", teamID)
	}
	return `anchor apple generic and certificate leaf[subject.OU] = "` + teamID + `"`, nil
}

// DeveloperIDRequirement narrows TeamRequirement to a Developer ID Application
// certificate (the Developer ID intermediate and the Developer ID Application
// leaf marker), the only certificate a notarized release is signed with.
func DeveloperIDRequirement(teamID string) (string, error) {
	if !ValidTeamID(teamID) {
		return "", fmt.Errorf("binsign: %q is not a Team ID", teamID)
	}
	return `anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] and ` +
		`certificate leaf[field.1.2.840.113635.100.6.1.13] and ` +
		`certificate leaf[subject.OU] = "` + teamID + `"`, nil
}

// Codesign is the production Signer. Verify uses runtimed's image.CodesignTool
// (`codesign --verify --strict`, then `codesign -dv` for an ad-hoc signature).
// Sign runs `codesign -s - -f -i <identifier>`: an ad-hoc identity, no hardened
// runtime and no library validation (both would block a DYLD insert), the same
// flags as image.AdHocSign plus the identifier. The zero value is usable.
type Codesign struct{}

// Verify reports whether path's signature verifies and is ad hoc.
func (Codesign) Verify(ctx context.Context, path string) (bool, error) {
	ok, err := image.CodesignTool{}.Signed(ctx, path)
	if err != nil || !ok {
		return false, err
	}
	return image.CodesignTool{}.AdHoc(ctx, path)
}

// CodesignInspector is the production Inspector, over the codesign tool. The zero
// value is usable.
type CodesignInspector struct{}

// Inspect runs `codesign --verify --strict` and, on a valid signature,
// `codesign -dv` for its kind and Team ID.
func (CodesignInspector) Inspect(ctx context.Context, path string) (Signature, error) {
	ok, err := image.CodesignTool{}.Signed(ctx, path)
	if err != nil || !ok {
		return Signature{}, err
	}
	var stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, "codesign", "-dv", path)
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return Signature{}, nil
		}
		return Signature{}, fmt.Errorf("display signature of %s: %w", path, err)
	}
	return parseDisplay(stderr.String()), nil
}

// parseDisplay reads `codesign -dv` output of a file whose signature verified.
func parseDisplay(out string) Signature {
	sig := Signature{Valid: true}
	for _, line := range strings.Split(out, "\n") {
		key, val, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok {
			continue
		}
		switch key {
		case "Signature":
			if val == "adhoc" {
				sig.AdHoc = true
			}
		case "CodeDirectory v":
			if strings.Contains(val, "(adhoc") || strings.Contains(val, ",adhoc") {
				sig.AdHoc = true
			}
		case "TeamIdentifier":
			if val != "not set" {
				sig.TeamID = val
			}
		}
	}
	return sig
}

// Satisfies runs `codesign --verify --strict -R=<requirement>`; the leading "="
// makes codesign read the argument as requirement text, not a file path. Exit 0
// is true, any other exit false; only a failure to run the tool is an error.
func (CodesignInspector) Satisfies(ctx context.Context, path, requirement string) (bool, error) {
	err := exec.CommandContext(ctx, "codesign", "--verify", "--strict", "-R="+requirement, path).Run()
	if err == nil {
		return true, nil
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return false, nil
	}
	return false, fmt.Errorf("verify %s against a requirement: %w", path, err)
}

// identitySigned reports whether s can inspect signatures and path carries a
// valid signature that is not ad hoc (see Inspector).
func identitySigned(ctx context.Context, s Signer, path string) bool {
	in, ok := s.(Inspector)
	if !ok {
		return false
	}
	sig, err := in.Inspect(ctx, path)
	return err == nil && sig.IdentitySigned()
}

// Sign ad-hoc signs path under identifier.
func (Codesign) Sign(ctx context.Context, path, identifier string) error {
	if identifier == "" {
		return errors.New("binsign: empty signing identifier")
	}
	cmd := exec.CommandContext(ctx, "codesign", "-s", "-", "-f", "-i", identifier, path)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("ad-hoc sign %s as %s: %w: %s", path, identifier, err, bytes.TrimSpace(out))
	}
	return nil
}

// EnsureSigned leaves path untouched when its signature verifies and is ad hoc,
// or (when s is also an Inspector) verifies and is not ad hoc, and otherwise
// re-signs it on a new inode (ResignByReplace). It reports whether it replaced the
// file. A signing failure leaves path untouched and is returned.
func EnsureSigned(ctx context.Context, s Signer, path string) (bool, error) {
	if ok, err := s.Verify(ctx, path); err == nil && ok {
		return false, nil
	}
	if identitySigned(ctx, s, path) {
		return false, nil
	}
	if err := ResignByReplace(ctx, s, path); err != nil {
		return false, err
	}
	return true, nil
}

// ResignByReplace re-signs path unconditionally on a new inode: the bytes are
// copied to a temp beside it, the temp is signed under path's base name, and the
// temp is renamed over path (atomicfile.InstallReader, which keeps the owner when
// running as root). The copy keeps the permission bits. path must be a regular
// file; a symlink is refused rather than followed, so the copy's source is the
// very file that was named.
func ResignByReplace(ctx context.Context, s Signer, path string) error {
	f, err := os.OpenFile(path, os.O_RDONLY|unix.O_NOFOLLOW, 0)
	if err != nil {
		return fmt.Errorf("open %s for re-signing: %w", path, err)
	}
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	if err != nil {
		return fmt.Errorf("stat %s: %w", path, err)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("re-sign %s: not a regular file (%v)", path, info.Mode().Type())
	}
	id := filepath.Base(path)
	return atomicfile.InstallReader(f, path, info.Mode().Perm(), func(tmp string) error {
		return s.Sign(ctx, tmp, id)
	})
}

// Install installs a copy of src at dst with mode on a new inode, ad-hoc signing
// the temp under dst's base name before it is renamed into place, so dst never
// names unsigned bytes. Signing is best-effort, as it has always been for staged
// binaries: a host without codesign still installs the bytes, and a binary that
// truly cannot run fails loudly at exec.
func Install(ctx context.Context, s Signer, src, dst string, mode os.FileMode) error {
	return atomicfile.InstallFile(src, dst, mode, signTemp(ctx, s, filepath.Base(dst)))
}

// InstallReader is Install over a stream.
func InstallReader(ctx context.Context, s Signer, r io.Reader, dst string, mode os.FileMode) error {
	return atomicfile.InstallReader(r, dst, mode, signTemp(ctx, s, filepath.Base(dst)))
}

// signTemp is the atomicfile prepare hook that ad-hoc signs the temp under
// identifier. Best-effort: a signing failure still installs the bytes.
func signTemp(ctx context.Context, s Signer, identifier string) func(string) error {
	return func(tmp string) error {
		_ = s.Sign(ctx, tmp, identifier)
		return nil
	}
}

// SignIfInvalid returns the atomicfile prepare hook for bytes that normally arrive
// signed (a payload copy): the temp is signed under identifier only when it does
// not carry a valid ad-hoc signature, nor (when s is also an Inspector) a valid
// certificate-identity one. Best-effort, like signTemp.
func SignIfInvalid(ctx context.Context, s Signer, identifier string) func(string) error {
	return func(tmp string) error {
		if ok, err := s.Verify(ctx, tmp); err == nil && ok {
			return nil
		}
		if identitySigned(ctx, s, tmp) {
			return nil
		}
		_ = s.Sign(ctx, tmp, identifier)
		return nil
	}
}

// HealOnce re-signs by replace, once, each named binary present in dir whose line
// in dir's HealMarkerName does not carry stamp, and then records it. A k3sm older
// than this package re-signed live binaries in place, which can leave a vnode
// whose cached signature no longer matches its bytes, so every process that maps
// it is killed; a check of the file's signature cannot see that state, but a new
// inode clears it. stamp names what is staged (the version marker's content for a
// versioned set), so a re-stage at another version heals again once. A binary
// whose re-sign fails is not recorded and is retried on the next call. Absent
// names are skipped. When s is also an Inspector, a binary whose signature
// verifies and is not ad hoc is recorded without being replaced: the state the
// heal clears comes only from an ad-hoc `codesign -f`, which would have left an
// ad-hoc signature. Not safe to run concurrently for the same dir: a lost update
// only costs one more replace later.
func HealOnce(ctx context.Context, s Signer, dir, stamp string, names ...string) error {
	if strings.ContainsAny(stamp, "\t\n") || stamp == "" {
		return fmt.Errorf("binsign: invalid heal stamp %q", stamp)
	}
	marker := filepath.Join(dir, HealMarkerName)
	healed, err := readHealMarker(marker)
	if err != nil {
		return err
	}
	changed := false
	for _, name := range names {
		if healed[name] == stamp {
			continue
		}
		p := filepath.Join(dir, name)
		if fi, err := os.Lstat(p); err != nil || !fi.Mode().IsRegular() {
			continue
		}
		if !identitySigned(ctx, s, p) {
			if err := ResignByReplace(ctx, s, p); err != nil {
				continue
			}
		}
		healed[name] = stamp
		changed = true
	}
	if !changed {
		return nil
	}
	return writeHealMarker(marker, healed)
}

// RecordHealed records each named binary present in dir as healed at stamp in
// dir's HealMarkerName without touching any binary, so HealOnce never revisits
// it at that stamp. It is for a binary whose signature has just been verified and
// must stay byte-identical (a release payload binary).
func RecordHealed(dir, stamp string, names ...string) error {
	if strings.ContainsAny(stamp, "\t\n") || stamp == "" {
		return fmt.Errorf("binsign: invalid heal stamp %q", stamp)
	}
	marker := filepath.Join(dir, HealMarkerName)
	healed, err := readHealMarker(marker)
	if err != nil {
		return err
	}
	changed := false
	for _, name := range names {
		if healed[name] == stamp {
			continue
		}
		if fi, err := os.Lstat(filepath.Join(dir, name)); err != nil || !fi.Mode().IsRegular() {
			continue
		}
		healed[name] = stamp
		changed = true
	}
	if !changed {
		return nil
	}
	return writeHealMarker(marker, healed)
}

// writeHealMarker replaces the marker at path with healed, one sorted line per
// binary.
func writeHealMarker(marker string, healed map[string]string) error {
	keys := make([]string, 0, len(healed))
	for k := range healed {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, k := range keys {
		b.WriteString(k + "\t" + healed[k] + "\n")
	}
	if err := atomicfile.Replace(marker, []byte(b.String()), 0o644); err != nil {
		return fmt.Errorf("binsign: record healed binaries: %w", err)
	}
	return nil
}

// readHealMarker parses a HealMarkerName file; an absent file is empty.
func readHealMarker(path string) (map[string]string, error) {
	healed := map[string]string{}
	f, err := os.Open(path)
	if errors.Is(err, fs.ErrNotExist) {
		return healed, nil
	}
	if err != nil {
		return nil, fmt.Errorf("binsign: read %s: %w", path, err)
	}
	defer func() { _ = f.Close() }()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if name, stamp, ok := strings.Cut(sc.Text(), "\t"); ok && name != "" {
			healed[name] = stamp
		}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("binsign: read %s: %w", path, err)
	}
	return healed, nil
}

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

package shadow

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os/exec"
	"strconv"
	"strings"
)

// Code-signing flags (xnu cs_blobs.h) a copy's code directory is checked for.
const (
	csAdhoc    = 0x00000002
	csRestrict = 0x00000800
	csRuntime  = 0x00010000
)

// SFRestricted is the BSD file flag (sys/stat.h SF_RESTRICTED) the system
// volume carries. A copy that kept it would still be treated as a protected
// system file.
const SFRestricted = 0x00080000

// ErrUnsafeCopy is wrapped by every verification failure.
var ErrUnsafeCopy = errors.New("unsafe shadow copy")

// CheckCopyFile verifies a made copy's file properties: a regular file,
// without SF_RESTRICTED, no setuid or setgid bit, and writable by its owner
// only. mode is from lstat (a symlink is not regular); flags are st_flags.
func CheckCopyFile(mode fs.FileMode, flags uint32) error {
	switch {
	case !mode.IsRegular():
		return fmt.Errorf("%w: not a regular file (%v)", ErrUnsafeCopy, mode.Type())
	case flags&SFRestricted != 0:
		return fmt.Errorf("%w: carries SF_RESTRICTED", ErrUnsafeCopy)
	case mode&fs.ModeSetuid != 0:
		return fmt.Errorf("%w: setuid bit set", ErrUnsafeCopy)
	case mode&fs.ModeSetgid != 0:
		return fmt.Errorf("%w: setgid bit set", ErrUnsafeCopy)
	case mode.Perm()&0o020 != 0:
		return fmt.Errorf("%w: group-writable (%#o)", ErrUnsafeCopy, mode.Perm())
	case mode.Perm()&0o002 != 0:
		return fmt.Errorf("%w: world-writable (%#o)", ErrUnsafeCopy, mode.Perm())
	}
	return nil
}

// CheckCopySignature verifies a made copy's signature from `codesign -dvvv`
// output (dvvv) and `codesign -d --entitlements -` output (ents): ad hoc,
// without the hardened runtime or the restrict flag, and with no
// entitlements. Any of those would make dyld drop the shims again, or grant
// the copy something its source never had in a pod.
func CheckCopySignature(dvvv, ents []byte) error {
	flags, ok := codeDirectoryFlags(dvvv)
	if !ok {
		return fmt.Errorf("%w: no code directory flags in the codesign output", ErrUnsafeCopy)
	}
	switch {
	case flags&csAdhoc == 0 || !bytes.Contains(dvvv, []byte("Signature=adhoc")):
		return fmt.Errorf("%w: signature is not ad hoc (flags %#x)", ErrUnsafeCopy, flags)
	case flags&csRuntime != 0:
		return fmt.Errorf("%w: signature carries the hardened runtime flag", ErrUnsafeCopy)
	case flags&csRestrict != 0:
		return fmt.Errorf("%w: signature carries the restrict flag", ErrUnsafeCopy)
	}
	sc := bufio.NewScanner(bytes.NewReader(ents))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "Executable=") || strings.HasPrefix(line, "warning:") {
			continue
		}
		return fmt.Errorf("%w: signature carries entitlements", ErrUnsafeCopy)
	}
	return nil
}

// codeDirectoryFlags reads the flags=0x... value of the CodeDirectory line.
func codeDirectoryFlags(dvvv []byte) (uint64, bool) {
	sc := bufio.NewScanner(bytes.NewReader(dvvv))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if !strings.HasPrefix(line, "CodeDirectory ") {
			continue
		}
		for _, f := range strings.Fields(line) {
			v, ok := strings.CutPrefix(f, "flags=0x")
			if !ok {
				continue
			}
			if i := strings.IndexByte(v, '('); i >= 0 {
				v = v[:i]
			}
			n, err := strconv.ParseUint(v, 16, 64)
			return n, err == nil
		}
	}
	return 0, false
}

// VerifySignature runs codesign on a made copy and applies CheckCopySignature.
func VerifySignature(ctx context.Context, path string) error {
	dvvv, err := exec.CommandContext(ctx, "codesign", "-dvvv", path).CombinedOutput()
	if err != nil {
		return fmt.Errorf("codesign -dvvv %s: %w: %s", path, err, strings.TrimSpace(string(dvvv)))
	}
	ents, err := exec.CommandContext(ctx, "codesign", "-d", "--entitlements", "-", path).CombinedOutput()
	if err != nil {
		return fmt.Errorf("codesign -d --entitlements - %s: %w: %s", path, err, strings.TrimSpace(string(ents)))
	}
	return CheckCopySignature(dvvv, ents)
}

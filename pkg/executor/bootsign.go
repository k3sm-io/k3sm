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

package executor

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"k3sm.io/k3sm/internal/binsign"
	"k3sm.io/k3sm/pkg/helmchart"
)

// ErrPayloadSignature reports a release-path payload binary that is missing or
// whose signature does not satisfy the release requirement. The daemon refuses to
// start rather than run, or re-sign, a binary the signed release did not vouch for.
var ErrPayloadSignature = errors.New("payload binary fails release signature verification")

// codeSigner is the boot's signing seam: binsign's ad-hoc Signer plus its
// Inspector, so the identity rule applies wherever it signs.
type codeSigner interface {
	binsign.Signer
	binsign.Inspector
}

// codesignSigner is the production codeSigner: the ad-hoc signer paired with the
// inspector, which opts every boot signing step into the identity rule.
type codesignSigner struct {
	binsign.Codesign
	binsign.CodesignInspector
}

// bootCodeSigner is the codeSigner the boot uses. It is a var so a test drives
// both signing paths without codesign, the way runControlPlaneDownload stands in
// for the download.
var bootCodeSigner codeSigner = codesignSigner{}

// selfExecutable resolves the running k3sm binary, whose own signature decides
// the signing path. A var for the same reason as bootCodeSigner.
var selfExecutable = os.Executable

// signingPolicy is how a boot treats the payload binaries it runs.
//
// The RELEASE path holds when the running k3sm is itself signed with a Developer
// ID Application certificate: the signature verifies, is not ad hoc, and satisfies
// binsign.DeveloperIDRequirement for the Team ID it names. The Team ID is read from
// that signature, so no flag or environment variable selects the path. On it, the
// control-plane binaries are verified in place against binsign.TeamRequirement and
// used byte-identical, never healed and never re-signed; one that fails is refused.
//
// Every other k3sm (ad hoc, unsigned, signed by some other certificate, or one
// whose signature could not be read) is on the DEV path: the binaries are healed
// once per stamp and ad-hoc signed when they carry no valid signature, as before.
// On both paths a binary whose signature verifies and is not ad hoc is never
// re-signed (binsign's identity rule).
//
// The staged children kine, etcd and helm are outside the release check on both
// paths: they are built or fetched at boot and ad-hoc signed, and are not yet part
// of the signed payload, so they keep the dev signing (signBinaries).
type signingPolicy struct {
	s       codeSigner
	release bool
	teamID  string
}

// resolveSigningPolicy reads the running k3sm's own signature and returns the
// path it selects. Only a positive proof selects the release path; any failure to
// read or match the signature selects the dev path, where the identity rule still
// keeps every certificate-signed binary untouched.
func resolveSigningPolicy(ctx context.Context) signingPolicy {
	p := signingPolicy{s: bootCodeSigner}
	exe, err := selfExecutable()
	if err != nil {
		return p
	}
	sig, err := p.s.Inspect(ctx, exe)
	if err != nil || !sig.IdentitySigned() {
		return p
	}
	req, err := binsign.DeveloperIDRequirement(sig.TeamID)
	if err != nil {
		return p
	}
	if ok, err := p.s.Satisfies(ctx, exe, req); err != nil || !ok {
		return p
	}
	p.release, p.teamID = true, sig.TeamID
	return p
}

// verifyPayloadBinaries is the release path over a staged set: each named binary
// in dir must be a regular file whose signature satisfies the release requirement
// for p's Team ID. A pass leaves every binary byte-identical and records it at
// stamp in the heal marker, so the dev heal never revisits it; any failure,
// including an absent binary, an ad-hoc signature or another team's, is an
// ErrPayloadSignature naming the binary.
func verifyPayloadBinaries(ctx context.Context, p signingPolicy, dir, stamp string, names []string) error {
	req, err := binsign.TeamRequirement(p.teamID)
	if err != nil {
		return err
	}
	for _, n := range names {
		path := filepath.Join(dir, n)
		fi, err := os.Lstat(path)
		if err != nil || !fi.Mode().IsRegular() {
			return fmt.Errorf("%w: %s is not staged as a regular file; reinstall from the signed release", ErrPayloadSignature, path)
		}
		ok, err := p.s.Satisfies(ctx, path, req)
		if err != nil {
			return fmt.Errorf("verify the signature of %s: %w", path, err)
		}
		if !ok {
			return fmt.Errorf("%w: %s is not signed by team %s; refusing to start", ErrPayloadSignature, path, p.teamID)
		}
	}
	return binsign.RecordHealed(dir, stamp, names...)
}

// verifyTempHook is the atomicfile prepare hook for a release-path payload copy:
// the temp must satisfy the release requirement before it takes name, and is
// never signed. A refusal leaves the destination untouched.
func verifyTempHook(ctx context.Context, p signingPolicy, name string) func(string) error {
	return func(tmp string) error {
		req, err := binsign.TeamRequirement(p.teamID)
		if err != nil {
			return err
		}
		ok, err := p.s.Satisfies(ctx, tmp, req)
		if err != nil {
			return fmt.Errorf("verify the signature of the %s copy: %w", name, err)
		}
		if !ok {
			return fmt.Errorf("%w: the payload's %s is not signed by team %s", ErrPayloadSignature, name, p.teamID)
		}
		return nil
	}
}

// helmHealStamp is helm's heal stamp: its versioned binary name, which changes
// exactly when the pin does.
const helmHealStamp = helmchart.HelmBinaryName

// signHelm gives a staged helm the dev signing (see signingPolicy on why helm is
// outside the release check). It is the one place helm's heal stamp is chosen.
func signHelm(ctx context.Context, bd string) error {
	return signBinaries(ctx, bd, helmHealStamp, []string{helmchart.HelmBinaryName})
}

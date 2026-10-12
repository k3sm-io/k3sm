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
	"log/slog"
	"os"
	"path/filepath"

	"k3sm.io/k3sm/internal/binsign"
	"k3sm.io/k3sm/pkg/helmchart"
)

// ErrPayloadSignature reports a release-path payload binary that is missing or
// whose signature does not satisfy the release requirement. The daemon refuses to
// start rather than run, or re-sign, a binary the signed release did not vouch for.
var ErrPayloadSignature = errors.New("payload binary fails release signature verification")

// PayloadSignatureRemedy is the operator's fix for ErrPayloadSignature and
// ErrPayloadStamp: the staged payload is not the one this signed k3sm was released
// with, and only a reinstall from that release puts the right bytes in place.
const PayloadSignatureRemedy = "reinstall k3sm from a correctly signed release (`sudo k3sm install` from the release's own payload); the daemon runs only payload binaries signed with its own Developer ID and built at its pins, and never re-signs or rebuilds them"

// SelfSignatureRemedy is the operator's fix for ErrSelfSignatureUnreadable.
const SelfSignatureRemedy = "check that /usr/bin/codesign runs and that the installed k3sm binary is readable; if its signature is damaged, reinstall k3sm from a correctly signed release"

// ErrSelfSignatureUnreadable reports that the running k3sm's own signature could
// not be read or evaluated, so the signing path cannot be decided. The boot
// refuses rather than guess: the dev path would heal and ad-hoc sign binaries a
// release node must run untouched.
var ErrSelfSignatureUnreadable = errors.New("cannot read the running k3sm's own code signature")

// codeSigner is the boot's signing seam: binsign's ad-hoc Signer plus its
// Inspector, so the identity rule applies wherever it signs.
type codeSigner interface {
	binsign.Signer
	binsign.Inspector
}

// codesignSigner is the production codeSigner: the ad-hoc signer paired with the
// inspector (which runs /usr/bin/codesign by path), opting every boot signing
// step into the identity rule.
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
// control-plane binaries are verified in place against the same
// binsign.DeveloperIDRequirement and used byte-identical, never healed and never re-signed; one that fails is refused.
//
// A k3sm whose signature reads cleanly as ad hoc, unsigned, or signed by some
// other certificate is on the DEV path: the binaries are healed
// once per stamp and ad-hoc signed when they carry no valid signature, as before.
// On both paths a binary whose signature verifies and is not ad hoc is never
// re-signed (binsign's identity rule).
//
// The source-built children kine and etcd (and the offline etcdutl) are part of
// the signed payload: on the release path they are verified the same way and their
// build stamp, read from the verified bytes, must match the pins
// (stagedChild.ensureShipped); they are never built or signed there. helm stays
// outside the release check on both paths: it is fetched at boot and ad-hoc signed,
// and is not yet part of the signed payload, so it keeps the dev signing
// (signBinaries).
type signingPolicy struct {
	s       codeSigner
	release bool
	teamID  string
}

// resolveSigningPolicy reads the running k3sm's own signature and returns the
// path it selects. Only a positive proof selects the release path, and only a
// clean verdict selects the dev path: an ad-hoc or unsigned binary, or a
// certificate signature without a Team ID or that fails the Developer ID
// requirement. A failure to resolve the executable, read its signature, or
// evaluate the requirement is an ErrSelfSignatureUnreadable, logged here and
// returned so the boot refuses.
func resolveSigningPolicy(ctx context.Context, logger *slog.Logger) (signingPolicy, error) {
	p := signingPolicy{s: bootCodeSigner}
	refuse := func(what string, err error) (signingPolicy, error) {
		err = fmt.Errorf("%w: %s: %w", ErrSelfSignatureUnreadable, what, err)
		logger.Error("refusing to start: the signing path cannot be decided", "err", err,
			"remedy", "check that /usr/bin/codesign runs and that the k3sm binary is readable")
		return signingPolicy{}, err
	}
	exe, err := selfExecutable()
	if err != nil {
		return refuse("resolve the k3sm executable", err)
	}
	sig, err := p.s.Inspect(ctx, exe)
	if err != nil {
		return refuse("inspect "+exe, err)
	}
	if !sig.IdentitySigned() || sig.TeamID == "" {
		return p, nil
	}
	req, err := binsign.DeveloperIDRequirement(sig.TeamID)
	if err != nil {
		// A Team ID that is not an Apple Team ID cannot be a Developer ID.
		return p, nil
	}
	ok, err := p.s.Satisfies(ctx, exe, req)
	if err != nil {
		return refuse("evaluate the Developer ID requirement on "+exe, err)
	}
	if !ok {
		return p, nil
	}
	p.release, p.teamID = true, sig.TeamID
	return p, nil
}

// verifyPayloadBinaries is the release path over a staged set: each named binary
// in dir must be a regular file whose signature satisfies the Developer ID
// Application requirement for p's Team ID, the one the daemon itself met, so a
// development certificate of the same team is refused. A pass leaves every binary byte-identical and records it at
// stamp in the heal marker, so the dev heal never revisits it; any failure,
// including an absent binary, an ad-hoc signature, another team's or a
// non-Developer ID certificate, is an
// ErrPayloadSignature naming the binary.
func verifyPayloadBinaries(ctx context.Context, p signingPolicy, dir, stamp string, names []string) error {
	for _, n := range names {
		if err := verifyReleaseBinary(ctx, p, filepath.Join(dir, n)); err != nil {
			return err
		}
	}
	return binsign.RecordHealed(dir, stamp, names...)
}

// verifyReleaseBinary is the release check on one path: a regular file whose
// signature satisfies the Developer ID Application requirement for p's Team ID.
// Any failure, an absent file included, is an ErrPayloadSignature naming it.
func verifyReleaseBinary(ctx context.Context, p signingPolicy, path string) error {
	req, err := binsign.DeveloperIDRequirement(p.teamID)
	if err != nil {
		return err
	}
	fi, err := os.Lstat(path)
	if err != nil || !fi.Mode().IsRegular() {
		return fmt.Errorf("%w: %s is not staged as a regular file; reinstall from the signed release", ErrPayloadSignature, path)
	}
	ok, err := p.s.Satisfies(ctx, path, req)
	if err != nil {
		return fmt.Errorf("verify the signature of %s: %w", path, err)
	}
	if !ok {
		return fmt.Errorf("%w: %s is not signed with team %s's Developer ID Application certificate; refusing to start", ErrPayloadSignature, path, p.teamID)
	}
	return nil
}

// verifyTempHook is the atomicfile prepare hook for a release-path payload copy:
// the temp must satisfy the Developer ID requirement before it takes name, and
// is never signed. A refusal leaves the destination untouched.
func verifyTempHook(ctx context.Context, p signingPolicy, name string) func(string) error {
	return func(tmp string) error {
		req, err := binsign.DeveloperIDRequirement(p.teamID)
		if err != nil {
			return err
		}
		ok, err := p.s.Satisfies(ctx, tmp, req)
		if err != nil {
			return fmt.Errorf("verify the signature of the %s copy: %w", name, err)
		}
		if !ok {
			return fmt.Errorf("%w: the payload's %s is not signed with team %s's Developer ID Application certificate", ErrPayloadSignature, name, p.teamID)
		}
		return nil
	}
}

// helmHealStamp is helm's heal stamp: its versioned binary name, which changes
// exactly when the pin does.
const helmHealStamp = helmchart.HelmBinaryName

// signHelm gives a staged helm the dev signing (see signingPolicy on why helm is
// still outside the release check). It is the one place helm's heal stamp is chosen.
func signHelm(ctx context.Context, bd string) error {
	return signBinaries(ctx, bd, helmHealStamp, []string{helmchart.HelmBinaryName})
}

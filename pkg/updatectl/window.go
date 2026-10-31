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

package updatectl

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	updatesv1alpha1 "k3sm.io/apis/updates/v1alpha1"
	"k3sm.io/k3sm/pkg/certs"
	"k3sm.io/k3sm/pkg/update"
)

// The Failed condition reasons of the compatibility window, the manifest and
// a halting node report.
const (
	// ReasonOutsideCompatibilityWindow ends a roll, before any node is
	// cordoned, when a node runs a release older than the manifest's
	// compatibleFrom (or one that cannot be ordered against it).
	ReasonOutsideCompatibilityWindow = "OutsideCompatibilityWindow"
	// ReasonManifestMismatch ends a roll, before the next handover, when the
	// release's payload manifest is malformed or does not describe the
	// resolved archive.
	ReasonManifestMismatch = "ManifestMismatch"
	// ReasonNodeRolledBack, ReasonNodeRefused and ReasonDataRootUnmounted end
	// a roll at the first node that reports update.NodeReasonRolledBack,
	// NodeReasonRefused or NodeReasonDataRootUnmounted.
	ReasonNodeRolledBack    = "NodeRolledBack"
	ReasonNodeRefused       = "NodeRefused"
	ReasonDataRootUnmounted = "DataRootUnmounted"
)

// dataRootRemedy is appended to a node's message when it reports its data
// root unmounted.
const dataRootRemedy = "mount the node's data root and restart its k3sm daemons; do not reinstall"

// haltReasons maps each halting node reason code to its Failed reason.
var haltReasons = map[string]string{
	update.NodeReasonRolledBack:        ReasonNodeRolledBack,
	update.NodeReasonRefused:           ReasonNodeRefused,
	update.NodeReasonDataRootUnmounted: ReasonDataRootUnmounted,
}

// haltCode returns the halting reason code msg starts with: the whole message,
// or the text before its first ":" or ";" (the separator the controller adds
// a remedy with). ok is false for any other message.
func haltCode(msg string) (code string, ok bool) {
	code = msg
	if i := strings.IndexAny(msg, ":;"); i >= 0 {
		code = msg[:i]
	}
	code = strings.TrimSpace(code)
	_, ok = haltReasons[code]
	return code, ok
}

// haltMessage is the node message for a halting report.
func haltMessage(code, msg string) string {
	if code == update.NodeReasonDataRootUnmounted && !strings.Contains(msg, dataRootRemedy) {
		return msg + "; " + dataRootRemedy
	}
	return msg
}

// failedNodeReason is the Failed condition reason for a failed node entry:
// the halting reason its message carries, else ReasonFailed.
func failedNodeReason(e *updatesv1alpha1.UpdateNodeStatus) string {
	base, _ := splitProgress(e.Message)
	if code, ok := haltCode(base); ok {
		return haltReasons[code]
	}
	return ReasonFailed
}

// releaseManifest is the target release's payload manifest, checked against
// status.resolved: the exact bytes the controller signs and hands over, and
// their parse.
type releaseManifest struct {
	version string
	digest  string
	raw     []byte
	m       *certs.PayloadManifest
}

// ensureManifest returns the target's payload manifest, read once per
// controller and re-read after a restart. It requires status.resolved. The
// manifest must parse as the node's verifier parses it, be valid UTF-8 (it
// travels as an annotation string), name the Update's version and the
// resolved archive digest. A missing asset or a mismatch is a rollFailure; a
// transient read error is returned as is, to be retried.
//
// A transient read failure is retried for ResolveBound, counted from the
// first failure (the Manifest condition's transition time, so the bound
// survives a restart); past it the read is a rollFailure with
// ReasonManifestMismatch. The bound holds at the plan, before any cordon,
// and at a handover after a restart, where the node is failed in place.
//
// The resolved digest is what anchors a re-read manifest: the node checks
// every extracted file against the manifest and the archive against its
// digest, so a manifest swapped between two reads cannot change the bytes a
// node runs, only describe the same archive.
func (c *Controller) ensureManifest(ctx context.Context, u *updatesv1alpha1.Update, now time.Time) (*releaseManifest, error) {
	r := u.Status.Resolved
	if r == nil || !strings.HasPrefix(r.Digest, "sha256:") {
		return nil, errors.New("the release has not been resolved")
	}
	digest := strings.TrimPrefix(r.Digest, "sha256:")
	if m := c.manifest; m != nil && m.version == u.Spec.Version && m.digest == digest {
		return m, nil
	}
	raw, err := c.cfg.Resolver.Manifest(ctx, u.Spec.Version)
	if err != nil {
		err = fmt.Errorf("read the payload manifest of %s: %w", u.Spec.Version, err)
		if errors.Is(err, ErrReleasePinMismatch) {
			return nil, rollFailure{err: err, reason: ReasonReleasePinMismatch}
		}
		if errors.Is(err, ErrRelease) {
			return nil, rollFailure{err: err, reason: ReasonManifestMismatch}
		}
		since := c.manifestFailureStart(u, now)
		meta.SetStatusCondition(&u.Status.Conditions, metav1.Condition{
			Type: ConditionManifest, Status: metav1.ConditionFalse, Reason: ReasonRetrying, Message: clipMessage(err.Error()),
			ObservedGeneration: u.Generation, LastTransitionTime: metav1.NewTime(since),
		})
		// SetStatusCondition keeps a False condition's old transition time;
		// write the clamped one.
		meta.FindStatusCondition(u.Status.Conditions, ConditionManifest).LastTransitionTime = metav1.NewTime(since)
		if now.Sub(since) > ResolveBound {
			return nil, rollFailure{
				err:    fmt.Errorf("the payload manifest could not be read within %s; last error: %w", ResolveBound, err),
				reason: ReasonManifestMismatch,
			}
		}
		return nil, err
	}
	mismatch := func(format string, args ...any) error {
		return rollFailure{err: fmt.Errorf("the payload manifest of %s: "+format, append([]any{u.Spec.Version}, args...)...), reason: ReasonManifestMismatch}
	}
	if !utf8.Valid(raw) {
		return nil, mismatch("is not valid UTF-8")
	}
	m, err := certs.ParsePayloadManifest(raw)
	if err != nil {
		return nil, mismatch("%v", err)
	}
	if buildMetadata(m.Version) != buildMetadata(u.Spec.Version) {
		return nil, mismatch("names version %q", m.Version)
	}
	if m.ArchiveSHA256 != digest {
		return nil, mismatch("names archive sha256:%s, the release resolved to sha256:%s", m.ArchiveSHA256, digest)
	}
	if _, ok := parseKubeMinor(m.KubeMinor); !ok {
		return nil, mismatch("kubeMinor %q is not MAJOR.MINOR", m.KubeMinor)
	}
	if _, ok := parseSemver(m.CompatibleFrom); !ok {
		return nil, mismatch("compatibleFrom %q is not a release version", m.CompatibleFrom)
	}
	c.manifest = &releaseManifest{version: u.Spec.Version, digest: digest, raw: raw, m: m}
	c.manifestFailingSince = time.Time{}
	c.setCondition(u, ConditionManifest, metav1.ConditionTrue, ReasonManifestRead, "sha256:"+sha256Hex(raw))
	return c.manifest, nil
}

// manifestClockLimit is how old a persisted Manifest condition's transition
// time may be and still count as the start of a failure streak: a few
// bounds, so a streak a restart interrupted keeps counting while a stale or
// edited time does not end a roll at its first failure.
const manifestClockLimit = 3 * ResolveBound

// manifestFailureStart is when the current streak of transient manifest read
// failures started. Within one controller run it is the time this run
// fixed at its first failure. At that first failure it is the persisted
// Manifest condition's transition time when the condition is False and the
// time is neither in the future nor older than manifestClockLimit (a
// controller restarted mid-streak keeps the bound); any other value, the
// status being an input the controller does not vouch for, restarts the
// clock at now. With no False condition (a new Update, or a read that
// succeeded since) the streak starts now.
func (c *Controller) manifestFailureStart(u *updatesv1alpha1.Update, now time.Time) time.Time {
	prev := meta.FindStatusCondition(u.Status.Conditions, ConditionManifest)
	if prev == nil || prev.Status != metav1.ConditionFalse {
		// No streak recorded (a new Update, or the last read succeeded).
		c.manifestFailingSince = now
		return now
	}
	if !c.manifestFailingSince.IsZero() && !c.manifestFailingSince.After(now) {
		return c.manifestFailingSince
	}
	since := now
	if t := prev.LastTransitionTime.Time.UTC(); !t.After(now) && now.Sub(t) <= manifestClockLimit {
		since = t
	}
	c.manifestFailingSince = since
	return since
}

// sha256Hex is the lowercase hex sha256 of b.
func sha256Hex(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }

// signManifest is the manifest annotations of a handover, signed by signer.
func signManifest(signer *certs.UpdateSigner, m *releaseManifest) (raw, sig string, err error) {
	der, err := signer.SignManifest(m.raw)
	if err != nil {
		return "", "", err
	}
	return string(m.raw), base64.StdEncoding.EncodeToString(der), nil
}

// checkWindow refuses a roll the release cannot make in place: a release
// whose manifest requires the installer, a node to be updated that runs a
// release older than the manifest's compatibleFrom or one that does not parse
// as a release (it cannot be placed in the window, so it is refused), or a
// node whose Kubernetes minor the release raises by more than one (the
// upstream skew policy moves one minor at a time). It runs before any node is
// cordoned.
func checkWindow(m *certs.PayloadManifest, pending []*corev1.Node) error {
	if m.RequiresInstaller {
		return fmt.Errorf("requires the installer: %s cannot be applied in place; install it on each node with the installer", m.Version)
	}
	if err := checkKubeMinorStep(m, pending); err != nil {
		return err
	}
	floor, ok := parseSemver(m.CompatibleFrom)
	if !ok {
		return fmt.Errorf("the payload manifest's compatibleFrom %q is not a release version", m.CompatibleFrom)
	}
	var bad []string
	for _, n := range pending {
		from := fromRelease(n)
		v, ok := parseSemver(from)
		if !ok || compareSemver(v, floor) < 0 {
			bad = append(bad, fmt.Sprintf("%s runs %s", n.Name, from))
		}
	}
	if len(bad) > 0 {
		return fmt.Errorf("outside the compatibility window: %s accepts nodes from %s on, and %s; update those nodes with the installer first",
			m.Version, m.CompatibleFrom, strings.Join(bad, ", "))
	}
	return nil
}

// kubeMinor is a parsed Kubernetes MAJOR.MINOR.
type kubeMinor struct{ major, minor int }

func (a kubeMinor) less(b kubeMinor) bool {
	return a.major < b.major || a.major == b.major && a.minor < b.minor
}

// parseKubeMinor reads "1.35" or "v1.35", and the MAJOR.MINOR of a longer
// version ("v1.35.2", "v1.35.2+k3sm.0.3.0").
func parseKubeMinor(s string) (kubeMinor, bool) {
	s = strings.TrimPrefix(s, "v")
	if i := strings.IndexAny(s, "+-"); i >= 0 {
		s = s[:i]
	}
	parts := strings.Split(s, ".")
	if len(parts) < 2 || len(parts) > 3 {
		return kubeMinor{}, false
	}
	var v [2]int
	for i := range 2 {
		n, err := strconv.Atoi(parts[i])
		if err != nil || n < 0 {
			return kubeMinor{}, false
		}
		v[i] = n
	}
	return kubeMinor{v[0], v[1]}, true
}

// kubeMinorRises reports whether the release raises the Kubernetes minor of
// any node to be updated: one whose kubeletVersion carries an older minor, or
// whose minor cannot be read (then the server goes first, the order the
// upstream skew policy always allows; the plan has already refused such a
// node in checkKubeMinorStep, so this is a fail-safe default).
func kubeMinorRises(m *certs.PayloadManifest, pending []*corev1.Node) bool {
	target, ok := parseKubeMinor(m.KubeMinor)
	if !ok {
		return true
	}
	for _, n := range pending {
		cur, ok := parseKubeMinor(n.Status.NodeInfo.KubeletVersion)
		if !ok || cur.less(target) {
			return true
		}
	}
	return false
}

// checkKubeMinorStep refuses a release that raises the Kubernetes minor of a
// node to be updated by more than one, or moves it to another major, and a
// node whose kubeletVersion does not parse (its minor cannot be placed, so it
// is refused, as an unparseable manifest kubeMinor is).
func checkKubeMinorStep(m *certs.PayloadManifest, pending []*corev1.Node) error {
	target, ok := parseKubeMinor(m.KubeMinor)
	if !ok {
		return fmt.Errorf("unreadable manifest kubeMinor: the payload manifest's kubeMinor %q is not MAJOR.MINOR", m.KubeMinor)
	}
	var unreadable, bad []string
	for _, n := range pending {
		cur, ok := parseKubeMinor(n.Status.NodeInfo.KubeletVersion)
		if !ok {
			unreadable = append(unreadable, fmt.Sprintf("%s reports kubeletVersion %q", n.Name, n.Status.NodeInfo.KubeletVersion))
			continue
		}
		if cur.major != target.major || target.minor-cur.minor > 1 {
			bad = append(bad, fmt.Sprintf("%s runs Kubernetes %d.%d", n.Name, cur.major, cur.minor))
		}
	}
	if len(unreadable) > 0 {
		return fmt.Errorf("unreadable node Kubernetes version: %s; the release's Kubernetes step cannot be checked; repair the node so its kubelet reports a version, or remove it from the cluster, then create a new Update",
			strings.Join(unreadable, ", "))
	}
	if len(bad) > 0 {
		return fmt.Errorf("Kubernetes minor step too large: %s ships Kubernetes %d.%d, more than one minor above where %s; update through each minor in between first",
			m.Version, target.major, target.minor, strings.Join(bad, ", "))
	}
	return nil
}

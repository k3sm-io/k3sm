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
	"time"

	"k3sm.io/k3sm/pkg/certs"
)

// Rotation health-wait defaults. The control plane's own bring-up budget is up to
// ~120s (kine 30s + apiserver healthz 90s), so the post-restart wait must exceed it
// or a healthy-but-slow boot would be reported as a failure.
const (
	// DefaultRotateHealthTimeout bounds the post-restart health wait.
	DefaultRotateHealthTimeout = 150 * time.Second
	// DefaultRotateHealthPoll is the health-probe interval during that wait.
	DefaultRotateHealthPoll = 2 * time.Second
)

// Rotation failures. Each is a typed sentinel (errors.Is-comparable), never a string
// match — the CLI turns them into an actionable message and a non-zero exit.
var (
	// ErrRotateWorkDirRequired reports a rotation with no control-plane work dir.
	ErrRotateWorkDirRequired = errors.New("executor: certificate rotation requires a work dir")
	// ErrNoRestarter reports a --restart rotation with no injected daemon restarter.
	ErrNoRestarter = errors.New("executor: certificate rotation with a restart requires a daemon restarter")
	// ErrNoDaemonLabel reports a --restart rotation with no launchd label to kickstart.
	ErrNoDaemonLabel = errors.New("executor: certificate rotation with a restart requires a launchd daemon label")
	// ErrNoHealthProbe reports a --restart rotation with no way to verify the control
	// plane came back. It is fail-closed on purpose: a restart destroys every pod on
	// the node and takes the apiserver away for seconds to a minute, so performing one
	// blind — unable to tell a successful rotation from a crash-looping daemon — is
	// worse than refusing.
	ErrNoHealthProbe = errors.New("executor: certificate rotation with a restart requires a health probe (refusing to restart the control plane with no way to verify it came back)")
	// ErrCAPinChanged reports that a CA certificate changed across the rotation. This
	// must never happen — every node's join token pins K10<sha256(cluster CA)> and
	// every issued node/component cert chains to these CAs — so it is a loud failure,
	// not a warning.
	ErrCAPinChanged = errors.New("executor: the CA pin CHANGED across the rotation — every node's join-token pin is orphaned")
	// ErrRestartUnconfirmed reports that launchd never came to report a NEW instance
	// of the daemon within the wait budget. It is distinct from a health failure: the
	// health probe can be satisfied by the OLD instance, which keeps its listeners
	// while it drains, so "a new pid exists" is the precondition that makes every
	// later check mean anything. Hitting it means the daemon never respawned or is
	// crash-looping under launchd's KeepAlive.
	ErrRestartUnconfirmed = errors.New("executor: the control-plane daemon did not come back as a NEW launchd instance after the restart")
)

// DaemonRestarter restarts a launchd-managed k3sm daemon by label and reports the
// pid launchd currently has for it. It is declared HERE, at the consumer, and is
// satisfied by install.System (which shells out to `launchctl kickstart -k` and
// `launchctl print`); this package cannot import install, which imports it.
//
// The restart MUST go through launchd. A Supervised control plane is in-process state
// owned by the RUNNING server process; a CLI subcommand is a different process, so
// constructing a fresh Supervised and calling Start would boot a SECOND control plane
// against the same SQLite datastore and the same apiserver port — data corruption, not
// rotation.
//
// The pid accessor is what makes the verification honest. `launchctl kickstart -k`
// returns when the restart is REQUESTED; the old control plane then tears its
// components down serially (each with its own drain grace, inside the plist's
// ExitTimeOut), so the OLD apiserver holds its listener for seconds afterwards. A
// health probe run against that window is satisfied by the dying instance, which is
// exactly the invisible KeepAlive crash-loop this command exists to catch. Binding
// the wait to a CHANGED, non-zero pid is what makes "it came back" mean the new
// instance.
type DaemonRestarter interface {
	LaunchctlKickstart(label string) error
	// LaunchctlServicePID returns the pid launchd reports for the label, or 0 when
	// the job is loaded but not running. A not-loaded label is an error.
	LaunchctlServicePID(label string) (int, error)
}

// RotateOptions parametrizes RotateCertificates. Restarter/DaemonLabel/Health are
// required only when Restart is set.
type RotateOptions struct {
	// WorkDir is the control-plane state root holding the PKI dir. Required.
	WorkDir string
	// Restart performs the launchd kickstart. FALSE (report only) is the default: a
	// restart destroys every pod on the node, so the disruptive path is opt-in.
	Restart bool
	// DaemonLabel is the launchd label to kickstart (io.k3sm.server).
	DaemonLabel string
	// Restarter is the launchd seam the kickstart goes through.
	Restarter DaemonRestarter
	// Health reports whether the control plane is serving again; nil means "not
	// yet" is indistinguishable from "never", so it is required for a restart.
	Health func(ctx context.Context) error
	// HealthTimeout bounds the post-restart wait for a NEW, serving instance
	// (DefaultRotateHealthTimeout when zero); HealthPoll is the retry interval
	// (DefaultRotateHealthPoll).
	HealthTimeout time.Duration
	HealthPoll    time.Duration
}

// RotationArtifact is one on-disk credential a rotation report names.
type RotationArtifact struct {
	// Path is the artifact's location.
	Path string
	// Detail describes the credential — the identity it carries and its issuer — or,
	// for an out-of-scope entry, why rotation deliberately leaves it alone.
	Detail string
	// Present reports whether the artifact exists on disk today. A multi-node-only
	// artifact is legitimately absent on a single-node server.
	Present bool
}

// RotationReport is what a rotation observed and did. The caller renders it; this
// package prints nothing.
type RotationReport struct {
	// WorkDir is the control-plane state root the rotation inspected.
	WorkDir string
	// ClusterCAPin / SigningCAPin are the CA pins, verified UNCHANGED across the
	// rotation (a rotation re-issues leaves; it never re-mints a CA).
	ClusterCAPin string
	SigningCAPin string
	// Reissued are the leaf credentials the control-plane boot re-issues from those CAs.
	Reissued []RotationArtifact
	// OutOfScope are credentials this command deliberately does NOT rotate.
	OutOfScope []RotationArtifact
	// Restarted reports whether the daemon was actually kickstarted.
	Restarted bool
	// PriorPID / NewPID are the launchd pids of the instance that was replaced and
	// of the one that came back. NewPID is set ONLY once launchd reported a pid
	// that is non-zero and differs from PriorPID, so a non-zero NewPID is the
	// proof that the verified control plane is the new process, not the old one
	// still draining its listeners.
	PriorPID int
	NewPID   int
}

// RotateCertificates rotates the control plane's CA-signed leaf credentials by
// RESTARTING it, and verifies the CA hierarchy is untouched on both sides of the
// restart. It is deliberately NOT a second issuance path: every boot already re-issues
// the scheduler and controller-manager client certs (provisionComponentCerts →
// writeComponentKubeconfig, an unconditional write with no existence check) and, on a
// mesh server, the apiserver serving cert — so a second issuer here would diverge from
// the boot's validity/SAN/verify posture and be silently overwritten on the next boot.
// The command's content is therefore: verify the hierarchy → record the pins →
// [report | read the daemon's pid → restart → re-verify the pins → wait for a NEW
// launchd instance that serves → re-verify the pins] → report.
//
// Two invariants it maintains:
//
//   - It WRITES NOTHING under WorkDir. The daemon runs as the unprivileged _k3sm user
//     and re-opens those paths with os.WriteFile (O_CREAT|O_TRUNC, which does not
//     unlink), so a root-written file there would EACCES the next boot's provision
//     step — and launchd's KeepAlive would turn that into an invisible crash loop.
//   - It never opens a CA private key; certs.LoadCAPins reads only the certificates.
//
// A nil report is returned only for a configuration error (nothing was inspected); a
// non-nil report with an error means the rotation got as far as the report describes.
//
// Every post-restart check is bound to the NEW launchd instance: the pid is read
// BEFORE the kickstart and the wait does not accept a health answer until launchd
// reports a different, non-zero pid. Without that discriminator the old, still-
// draining apiserver answers the probe and the command reports success for a
// rotation whose new daemon may never have booted.
func RotateCertificates(ctx context.Context, opts RotateOptions) (*RotationReport, error) {
	if opts.WorkDir == "" {
		return nil, ErrRotateWorkDirRequired
	}
	if opts.Restart {
		// Validate the disruptive path's seams BEFORE touching anything: a rotation
		// that cannot verify its own outcome must not incur the blast radius.
		if opts.Restarter == nil {
			return nil, ErrNoRestarter
		}
		if opts.DaemonLabel == "" {
			return nil, ErrNoDaemonLabel
		}
		if opts.Health == nil {
			return nil, ErrNoHealthProbe
		}
	}

	// Fail closed on an absent or half-present hierarchy — LoadCAPins never mints one.
	clusterPin, signingPin, err := certs.LoadCAPins(opts.WorkDir)
	if err != nil {
		return nil, fmt.Errorf("verify CA hierarchy: %w", err)
	}

	rep := &RotationReport{
		WorkDir:      opts.WorkDir,
		ClusterCAPin: clusterPin,
		SigningCAPin: signingPin,
		Reissued:     reissuedArtifacts(opts.WorkDir),
		OutOfScope:   outOfScopeArtifacts(opts.WorkDir),
	}
	if !opts.Restart {
		return rep, nil
	}

	// Read the pid of the instance about to be replaced. A not-loaded label fails
	// HERE, before the blast radius — the same fail-closed refusal the kickstart
	// itself would give, reached one step earlier.
	priorPID, err := opts.Restarter.LaunchctlServicePID(opts.DaemonLabel)
	if err != nil {
		return rep, fmt.Errorf("read the launchd pid of %s before the restart: %w", opts.DaemonLabel, err)
	}
	rep.PriorPID = priorPID

	if err := opts.Restarter.LaunchctlKickstart(opts.DaemonLabel); err != nil {
		return rep, fmt.Errorf("restart %s: %w", opts.DaemonLabel, err)
	}
	rep.Restarted = true

	// Re-verify immediately: if the kickstart somehow disturbed the PKI, say so before
	// spending the wait budget.
	if err := verifyPinsUnchanged(opts.WorkDir, clusterPin, signingPin); err != nil {
		return rep, err
	}
	newPID, err := awaitRestartedInstance(ctx, opts, priorPID)
	if err != nil {
		return rep, err
	}
	rep.NewPID = newPID
	// Re-verify once more now that the NEW daemon is up and serving — it has
	// completed its provision step, so this is the check that proves the boot LOADED
	// the CA hierarchy (EnsureHierarchy's load arm) rather than minting a fresh,
	// cluster-orphaning one. It is only meaningful because the wait above refused to
	// accept an answer from the outgoing instance.
	if err := verifyPinsUnchanged(opts.WorkDir, clusterPin, signingPin); err != nil {
		return rep, err
	}
	return rep, nil
}

// verifyPinsUnchanged re-reads the CA pins and fails loudly if either moved.
func verifyPinsUnchanged(workDir, cluster, signing string) error {
	gotCluster, gotSigning, err := certs.LoadCAPins(workDir)
	if err != nil {
		return fmt.Errorf("re-verify CA hierarchy: %w", err)
	}
	if gotCluster != cluster {
		return fmt.Errorf("%w: cluster CA %s -> %s", ErrCAPinChanged, cluster, gotCluster)
	}
	if gotSigning != signing {
		return fmt.Errorf("%w: signing CA %s -> %s", ErrCAPinChanged, signing, gotSigning)
	}
	return nil
}

// awaitRestartedInstance polls until launchd reports a NEW instance of the daemon
// (a non-zero pid different from priorPID) that ALSO answers the health probe, and
// returns that pid. Both conditions must hold in the same iteration: a new pid alone
// is a process that exists, and a health answer alone can come from the outgoing
// instance, which keeps its listeners while it drains.
//
// A transient read error or a zero pid is the normal respawn window and is tolerated
// until the deadline; the LAST reason is wrapped into the timeout error so the caller
// can tell "never respawned" (ErrRestartUnconfirmed) from "respawned but never
// served" (the probe's own error).
func awaitRestartedInstance(ctx context.Context, opts RotateOptions, priorPID int) (int, error) {
	timeout := opts.HealthTimeout
	if timeout <= 0 {
		timeout = DefaultRotateHealthTimeout
	}
	poll := opts.HealthPoll
	if poll <= 0 {
		poll = DefaultRotateHealthPoll
	}
	deadline := time.Now().Add(timeout)
	var last error
	for {
		pid, err := opts.Restarter.LaunchctlServicePID(opts.DaemonLabel)
		switch {
		case err != nil:
			last = fmt.Errorf("%w: reading the launchd pid of %s: %w", ErrRestartUnconfirmed, opts.DaemonLabel, err)
		case pid == 0:
			last = fmt.Errorf("%w: %s is loaded but not running", ErrRestartUnconfirmed, opts.DaemonLabel)
		case pid == priorPID:
			last = fmt.Errorf("%w: %s still runs the pre-restart instance (pid %d)", ErrRestartUnconfirmed, opts.DaemonLabel, pid)
		default:
			herr := opts.Health(ctx)
			if herr == nil {
				return pid, nil
			}
			last = fmt.Errorf("the new %s instance (pid %d) is not serving: %w", opts.DaemonLabel, pid, herr)
		}
		if time.Now().After(deadline) {
			return 0, fmt.Errorf("control plane not healthy within %s of the restart: %w", timeout, last)
		}
		select {
		case <-ctx.Done():
			return 0, ctx.Err()
		case <-time.After(poll):
		}
	}
}

// reissuedArtifacts lists the CA-signed leaf credentials the control-plane boot
// re-issues — the actual content of a rotation.
func reissuedArtifacts(workDir string) []RotationArtifact {
	return []RotationArtifact{
		artifact(SchedulerKubeconfigPath(workDir),
			"client cert CN="+schedulerCN+", issued by the signing CA — re-issued on every boot"),
		artifact(ControllerManagerKubeconfigPath(workDir),
			"client cert CN="+controllerManagerCN+", issued by the signing CA — re-issued on every boot"),
		artifact(certs.APIServerServingCertPath(workDir),
			"apiserver serving cert, issued by the cluster CA — multi-node (--mesh-ip) servers only; re-issued on every boot"),
		artifact(certs.APIServerServingKeyPath(workDir),
			"apiserver serving key for the cert above — multi-node servers only"),
	}
}

// outOfScopeArtifacts lists control-plane credentials rotation deliberately leaves
// alone, with the reason. Reporting them is the honest half of the feature: an
// operator must not read "rotate" as "everything is new".
func outOfScopeArtifacts(workDir string) []RotationArtifact {
	return []RotationArtifact{
		artifact(certs.ClusterCACertPath(workDir),
			"the cluster CA itself — every join token pins K10<sha256(this cert)>; re-minting it orphans every node"),
		artifact(certs.SigningCACertPath(workDir),
			"the signing CA itself — every issued node and component client cert chains to it"),
		artifact(KubeconfigPath(workDir),
			"admin kubeconfig — it carries the static bearer token, not a CA-signed identity"),
		artifact(TokenFilePath(workDir),
			"apiserver static token file — the admin token is set at install time"),
		artifact(ServiceAccountKeyPath(workDir),
			"service-account signing key — replacing it invalidates every issued ServiceAccount token"),
		artifact(ServiceAccountPubPath(workDir),
			"service-account verification key for the signing key above"),
		artifact(APIServerCertDir(workDir),
			"the apiserver's own self-signed cert dir — also the controller-manager --root-ca-file and the source of every pod's projected kube-root-ca.crt; replacing it is a cluster-wide trust event"),
	}
}

// artifact builds a RotationArtifact, resolving Present with a stat. A stat error
// other than not-exist is reported as absent — the field is informational, and a
// rotation must never fail because it could not describe a file it does not touch.
func artifact(path, detail string) RotationArtifact {
	_, err := os.Stat(path)
	return RotationArtifact{Path: path, Detail: detail, Present: err == nil}
}

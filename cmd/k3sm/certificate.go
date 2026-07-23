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

package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"time"

	"k3sm.io/k3sm/pkg/bootstrap"
	"k3sm.io/k3sm/pkg/certs"
	"k3sm.io/k3sm/pkg/executor"
	"k3sm.io/k3sm/pkg/install"
)

// certificateUsage is the `k3sm certificate` help text. It states the three honesty
// caveats up front, because "rotate" invites all three wrong readings: that superseded
// certs stop working, that worker nodes are covered, and that the apiserver's own
// self-signed material is included.
const certificateUsage = `Usage: k3sm certificate rotate [--restart|--yes] [--work-dir <dir>]

Re-issue the control plane's CA-signed LEAF credentials over the EXISTING CA
hierarchy. Every boot already re-issues them, so a rotation is a restart plus a
verification that the CA hierarchy came through untouched — the cluster CA and the
signing CA are never re-minted (re-minting either would orphan every node).

Without --restart the command REPORTS ONLY: it prints the CA pins, the artifacts a
restart would re-issue, and the blast radius. --restart (alias --yes) performs it.

  --work-dir <dir>   control-plane state root (default: this posture's work dir)
  --restart, --yes   restart the control-plane daemon to perform the rotation
  --apiserver-port   port the post-restart health probe checks (default %d)

Caveats:
  * Rotation does NOT revoke. k3sm publishes no CRL/OCSP and --client-ca-file trust
    is CA-wide, so a superseded certificate stays valid until it expires. This is
    renewal hygiene, NOT a response to a compromised credential.
  * Worker/agent node certs are out of scope. They are re-issued when an agent
    restarts and re-runs its join, which needs a fresh join token (k3sm token create).
  * The apiserver's own self-signed cert dir is not rotated (it is also the
    controller-manager --root-ca-file and every pod's projected kube-root-ca.crt).
`

// runCertificate dispatches the `k3sm certificate` subcommands.
func runCertificate(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("%s", fmt.Sprintf(certificateUsage, executor.DefaultAPIServerPort))
	}
	switch args[0] {
	case "rotate":
		return runCertificateRotate(args[1:])
	case "rotate-ca":
		// Reserved as an explicit, informative refusal rather than an
		// unknown-subcommand error: an operator reaching for it has a specific,
		// unsupported intent and deserves to be told why k3sm will not do it.
		return errors.New("refusing to re-mint the cluster CA: every node pins it as K10<sha256(cluster CA)> in its join token, and every node and component client cert chains to the CA hierarchy — re-minting orphans the whole cluster and would require re-joining every node. k3sm ships no CA-replacement flow; recreate the cluster instead")
	default:
		return fmt.Errorf("unknown certificate subcommand %q (want: rotate)", args[0])
	}
}

// runCertificateRotate parses the flags and wires the real seams — the darwin launchd
// System and the loopback health probe — into certificateRotate.
func runCertificateRotate(args []string) error {
	fs := flag.NewFlagSet("certificate rotate", flag.ExitOnError)
	// Posture-aware default (the _k3sm control plane writes <home>/server, not the
	// root-only const); a resolve failure falls back to the const, overridable.
	defaultWorkDir, err := executor.ResolveWorkDir()
	if err != nil {
		defaultWorkDir = executor.DefaultWorkDir
	}
	workDir := fs.String("work-dir", defaultWorkDir, "control-plane state root (the CA hierarchy lives here)")
	restart := fs.Bool("restart", false, "restart the control-plane daemon to perform the rotation (destroys every pod on this node)")
	yes := fs.Bool("yes", false, "alias for --restart")
	port := fs.Int("apiserver-port", executor.DefaultAPIServerPort, "apiserver secure port the post-restart health probe checks")
	fs.Usage = func() { fmt.Fprintf(os.Stderr, certificateUsage, executor.DefaultAPIServerPort) }
	_ = fs.Parse(args)

	apiPort := *port
	return certificateRotate(context.Background(), os.Stdout, executor.RotateOptions{
		WorkDir:   *workDir,
		Restart:   *restart || *yes,
		Restarter: install.NewDarwinSystem(),
		Health:    func(ctx context.Context) error { return probeAPIServerServing(ctx, apiPort) },
	})
}

// certificateRotate runs the rotation and renders its report to out. It binds the
// launchd label (so the daemon identity lives in one place) and turns each typed
// failure into an actionable message; the orchestration itself is executor's.
func certificateRotate(ctx context.Context, out io.Writer, opts executor.RotateOptions) error {
	if opts.DaemonLabel == "" {
		opts.DaemonLabel = install.ServerLabel
	}
	rep, err := executor.RotateCertificates(ctx, opts)
	if rep != nil {
		// Append the credentials package main owns the layout of, so the out-of-scope
		// list is complete rather than only executor-owned.
		rep.OutOfScope = append(rep.OutOfScope,
			executor.RotationArtifact{
				Path:    serverSecretPath(opts.WorkDir),
				Detail:  "HA server-join secret — mint a new one by deleting it and re-running k3sm token create --server",
				Present: fileExists(serverSecretPath(opts.WorkDir)),
			},
			executor.RotationArtifact{
				Path:    bootstrap.TokensPath(opts.WorkDir),
				Detail:  "worker join-token store (bcrypt hashes) — tokens are TTL-bounded; mint a fresh one with k3sm token create",
				Present: fileExists(bootstrap.TokensPath(opts.WorkDir)),
			},
		)
		renderRotationReport(out, rep, opts, err)
	}
	if err != nil {
		return annotateRotateError(err, rep, opts)
	}
	return nil
}

// annotateRotateError turns a typed rotation failure into an actionable one. The
// wrapped error is preserved with %w so callers keep errors.Is.
func annotateRotateError(err error, rep *executor.RotationReport, opts executor.RotateOptions) error {
	switch {
	case errors.Is(err, certs.ErrNoHierarchy):
		return fmt.Errorf("%w — no CA hierarchy under %s; that state root is owned by the %s service user, so run `sudo k3sm certificate rotate` (or point --work-dir at the right state root). Nothing was created or restarted",
			err, opts.WorkDir, install.DefaultServiceUser)
	case errors.Is(err, certs.ErrIncompleteHierarchy):
		return fmt.Errorf("%w — the CA hierarchy under %s is damaged (a CA certificate without its private key); the control plane refuses to boot on it and rotation cannot repair it. Nothing was restarted",
			err, opts.WorkDir)
	case errors.Is(err, executor.ErrCAPinChanged):
		return fmt.Errorf("%w — every node's join token and every issued client cert are now orphaned; do NOT re-join nodes until the CA hierarchy under %s is restored from backup",
			err, opts.WorkDir)
	case rep != nil && rep.Restarted:
		return fmt.Errorf("%w — %s was restarted but did not come back healthy: inspect %s and `launchctl print system/%s`",
			err, opts.DaemonLabel, install.ServerLogPath(), opts.DaemonLabel)
	case opts.Restart:
		return fmt.Errorf("%w — is the daemon installed and loaded? check `launchctl print system/%s`, and run `sudo k3sm install` if it is absent",
			err, opts.DaemonLabel)
	}
	return err
}

// renderRotationReport prints the rotation report: the CA pins that did NOT change,
// what a boot re-issues, what stays untouched, the honesty caveats, and the blast
// radius of a restart. outcome (the rotation's error, or nil) decides the closing
// line — a failed rotation must never print the success sentence.
func renderRotationReport(w io.Writer, rep *executor.RotationReport, opts executor.RotateOptions, outcome error) {
	label := opts.DaemonLabel
	fmt.Fprintf(w, "k3sm certificate rotate — work dir %s\n\n", rep.WorkDir)

	fmt.Fprint(w, "CA hierarchy (never re-minted — these pins MUST NOT change):\n")
	fmt.Fprintf(w, "  cluster CA  sha256:%s\n", rep.ClusterCAPin)
	fmt.Fprintf(w, "  signing CA  sha256:%s\n\n", rep.SigningCAPin)

	fmt.Fprint(w, "Leaf credentials the control plane re-issues from those CAs on its next boot:\n")
	writeArtifacts(w, rep.Reissued)
	fmt.Fprint(w, "\nNOT rotated by this command:\n")
	writeArtifacts(w, rep.OutOfScope)

	fmt.Fprint(w, `
Rotation does not revoke. k3sm publishes no CRL/OCSP and --client-ca-file trust is
CA-wide, so a superseded certificate stays valid until it expires — this is renewal
hygiene, not a response to a compromised credential.

Worker/agent node certs are out of scope: they are re-issued when an agent restarts
and re-runs its join, which needs a fresh join token (k3sm token create).
`)

	fmt.Fprintf(w, `
BLAST RADIUS — a rotation restarts %s:
`, label)
	fmt.Fprint(w, `  * every pod on this node is destroyed. Pods are in-process children of the daemon
    with no durable podID->IP manifest, and startup reconciliation sweeps every
    k3sm-owned lo0 alias.
  * the apiserver is unavailable for roughly 5-90s while kine and the apiserver come
    back, and the watch cache is rebuilt from the datastore.
  * on an HA control plane the scheduler/controller-manager leader-election leases flap.
`)

	switch {
	case outcome != nil && rep.Restarted:
		fmt.Fprintf(w, "\n%s was restarted, but the rotation did NOT complete — see the error.\n", label)
	case outcome != nil:
		fmt.Fprint(w, "\nThe rotation did NOT complete and nothing was restarted — see the error.\n")
	case rep.Restarted:
		fmt.Fprintf(w, "\nRestarted %s; the control plane is serving again and both CA pins re-verified unchanged.\n", label)
	default:
		fmt.Fprint(w, "\nDry run — nothing was restarted. Re-run with --restart (or --yes) to perform the rotation.\n")
	}
}

// writeArtifacts prints one artifact per line with its presence and reason.
func writeArtifacts(w io.Writer, arts []executor.RotationArtifact) {
	for _, a := range arts {
		mark := "absent "
		if a.Present {
			mark = "present"
		}
		fmt.Fprintf(w, "  [%s] %s\n            %s\n", mark, a.Path, a.Detail)
	}
}

// probeAPIServerServing reports whether the local apiserver is serving again after a
// restart. It is deliberately CREDENTIAL-FREE: with --anonymous-auth=false the
// apiserver answers an unauthenticated /healthz with 401, which still proves the TLS
// listener, the HTTP server, and the authenticator are up — the "the control plane
// came back" signal a rotation needs. Reading the admin bearer token out of the 0600
// kubeconfig to earn a 200 would pull a live credential into a CLI process (and its
// terminal-visible error strings) for no extra liveness information.
//
// TLS verification is skipped for the same reason Supervised.Ready skips it: the
// single-node apiserver self-signs its serving cert, and this is a loopback liveness
// probe, not a trust decision — no data flows over the connection.
func probeAPIServerServing(ctx context.Context, port int) error {
	url := "https://127.0.0.1:" + strconv.Itoa(port) + "/healthz"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("build healthz request: %w", err)
	}
	client := &http.Client{
		Timeout:   3 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("apiserver not reachable on 127.0.0.1:%d: %w", port, err)
	}
	defer func() { _ = resp.Body.Close() }()
	switch resp.StatusCode {
	case http.StatusOK, http.StatusUnauthorized, http.StatusForbidden:
		// 200 is healthz ok; 401/403 mean the server answered and authenticated the
		// (credential-free) request — either way the control plane is serving.
		return nil
	default:
		return fmt.Errorf("apiserver on 127.0.0.1:%d answered healthz with HTTP %d", port, resp.StatusCode)
	}
}

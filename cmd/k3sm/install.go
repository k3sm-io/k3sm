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
	"flag"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"time"

	"k3sm.io/k3sm/pkg/datavol"
	"k3sm.io/k3sm/pkg/install"
	"k3sm.io/k3sm/pkg/version"
)

// runInstall lays down k3sm's two root LaunchDaemons (io.k3sm.netd as root,
// io.k3sm.server as the _k3sm user) via the install package's system seam. It is
// the single root step (run as `sudo k3sm install`): it copies THIS binary into
// the root-owned install dir, writes the plists, bootstraps both daemons, and
// writes the admin kubeconfig to the invoking human's home ($SUDO_USER), owned by
// them. The Homebrew formula that invokes this and the notarize/signing pipeline
// are the packaging follow-up.
func runInstall(args []string) error {
	opts, err := parseInstallFlags(args)
	if err != nil {
		return err
	}

	// Read-only introspection of the layout contract, deliberately BEFORE the
	// root check: the release tooling asserts an extracted archive's member set
	// against this output, and must be able to do so unprivileged. Paths are
	// printed relative so the caller can join them onto any directory.
	if opts.printRequired {
		for _, p := range install.RequiredSiblings("") {
			fmt.Println(p)
		}
		return nil
	}

	if os.Geteuid() != 0 {
		return fmt.Errorf("k3sm install must run as root — use 'sudo k3sm install'")
	}
	if opts.targetUser == "" || opts.targetUser == "root" {
		return fmt.Errorf("--user (or $SUDO_USER) must be a non-root human so the kubeconfig is not root-owned; run via 'sudo k3sm install'")
	}
	self, err := os.Executable()
	if err != nil {
		return fmt.Errorf("resolve own binary path: %w", err)
	}

	volume, err := opts.dataVolumeOptions(version.Get().Version)
	if err != nil {
		return err
	}
	// Said once, at the one moment it can still be acted on. The volume is
	// hardware-encrypted by the SEP either way; what --data-volume-encrypt adds
	// is a passphrase, and on a FileVault Mac an operator reasonably assumes
	// their data root inherited FileVault's protection. It did not.
	if volume != nil && !volume.Encrypt && fileVaultOn() {
		fmt.Fprintln(os.Stderr, fileVaultNote)
	}

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	ctx := context.Background()
	return install.Install(ctx, install.NewDarwinSystem(), install.Config{
		Role:              opts.role(),
		JoinServer:        opts.server,
		NodeIP:            opts.nodeIP,
		TokenFile:         opts.tokenFile,
		BinarySource:      self,
		TargetUser:        opts.targetUser,
		ServiceCIDR:       opts.serviceCIDR,
		DataVolume:        volume,
		RemoveOldDataRoot: opts.removeOldDataRoot,
		MeshIP:            opts.meshIP,
		Logger:            logger,
	})
}

// installFlags is the parsed `k3sm install` command line. It is a struct rather
// than a handful of pointers inside runInstall so the flag CONTRACT -- the
// defaults, the size floor, the flag that requires another flag -- is decidable
// in a unit test, where the install itself can never run.
type installFlags struct {
	// agent selects the WORKER role: this Mac joins an existing cluster and runs
	// the io.k3sm.agent LaunchDaemon instead of io.k3sm.server.
	agent     bool
	server    string
	nodeIP    string
	tokenFile string
	// set is the names of the flags the operator actually passed, from
	// flag.FlagSet.Visit. It is what makes "--agent with a server-only flag" a
	// decidable refusal: --service-cidr has a non-empty default, so its VALUE
	// cannot distinguish "the operator asked for this" from "nobody said
	// anything", and refusing on the value would refuse every agent install.
	set               map[string]bool
	targetUser        string
	serviceCIDR       string
	printRequired     bool
	dataVolume        bool
	dataVolumeName    string
	dataVolumeSize    string
	dataVolumeEncrypt bool
	removeOldDataRoot bool
	meshIP            string
}

// parseInstallFlags parses the install command line. It returns the parse error
// rather than exiting, so the caller (and a test) sees it.
func parseInstallFlags(args []string) (installFlags, error) {
	var o installFlags
	fs := flag.NewFlagSet("install", flag.ContinueOnError)
	fs.StringVar(&o.targetUser, "user", os.Getenv("SUDO_USER"), "the human whose ~/.kube/config receives the admin kubeconfig (default $SUDO_USER)")
	fs.StringVar(&o.serviceCIDR, "service-cidr", install.DefaultServiceCIDR, "cluster Service CIDR")
	fs.BoolVar(&o.agent, "agent", false, "install this Mac as a WORKER that joins an existing cluster (the io.k3sm.agent daemon) instead of as the control plane; needs --server")
	fs.StringVar(&o.server, "server", "", "with --agent: the control-plane host to join, an UNDERLAY address (a LAN IP or DNS name, no scheme, no port) because the join dials <host>:9345 before this node has any mesh")
	fs.StringVar(&o.nodeIP, "node-ip", "", "with --agent: optional; the join assigns this Mac's mesh address, pass it only to assert the expected value (a value that differs from the assignment fails the join instead of minting a certificate for an address this node does not hold)")
	fs.StringVar(&o.tokenFile, "token-file", "", "with --agent: a file holding the join token, read once at each daemon start (a joined node needs none). It must not be group- or world-readable, and it is yours to delete once the node is Ready")
	fs.BoolVar(&o.printRequired, "print-required-artifacts", false, "print the artifacts that must sit beside this binary (one per line, relative) and exit; needs no privilege")
	fs.BoolVar(&o.dataVolume, "data-volume", false, "keep the data root on a dedicated, size-capped APFS volume: create it, adopt an existing one, or migrate onto it")
	fs.StringVar(&o.dataVolumeName, "data-volume-name", defaultDataVolumeName, "the APFS volume label to create or adopt")
	fs.StringVar(&o.dataVolumeSize, "data-volume-size", defaultDataVolumeSize, "the data volume's quota (m, g or t suffix). APFS fixes it at creation: changing it later means delete, reinstall and restore")
	fs.BoolVar(&o.dataVolumeEncrypt, "data-volume-encrypt", false, "encrypt the data volume with a random passphrase kept in the System keychain (a volume k3sm creates only)")
	fs.BoolVar(&o.removeOldDataRoot, "remove-old-data-root", false, "after a verified migration, delete the .pre-volume copy of the old data root instead of keeping it")
	fs.StringVar(&o.meshIP, "mesh-ip", "", "this node's wireguard mesh address, written into the server daemon's arguments; needed on every Mac that serves the control plane in a multi-node cluster")
	if err := fs.Parse(args); err != nil {
		return installFlags{}, err
	}
	if o.meshIP != "" {
		if err := validateMeshIP(o.meshIP); err != nil {
			return installFlags{}, err
		}
	}
	o.set = map[string]bool{}
	fs.Visit(func(f *flag.Flag) { o.set[f.Name] = true })
	if err := o.validateRole(); err != nil {
		return installFlags{}, err
	}
	return o, nil
}

// validateMeshIP refuses a --mesh-ip this install can never serve from: an
// address that fails to parse at all, and the three IP shapes that are always
// wrong for a server's own bind address — unspecified (0.0.0.0/::), loopback,
// and multicast. It runs at flag-parse time, before root/privilege checks, so a
// typo is reported immediately rather than after `sudo` and the rest of a
// (possibly slow) install has already run.
func validateMeshIP(raw string) error {
	addr, err := netip.ParseAddr(raw)
	if err != nil {
		return fmt.Errorf("--mesh-ip %q is not an IP address: %w", raw, err)
	}
	switch {
	case !addr.Is4():
		return fmt.Errorf("--mesh-ip %q is not an IPv4 address; the mesh is IPv4 only (100.64.0.0/10 by default)", raw)
	case addr.IsLinkLocalUnicast():
		return fmt.Errorf("--mesh-ip %q is a link-local address; give this Mac's own wireguard mesh address, not an interface's self-assigned one", raw)
	case addr.IsUnspecified():
		return fmt.Errorf("--mesh-ip %q is the unspecified address and cannot be bound; give this Mac's own wireguard mesh address", raw)
	case addr.IsLoopback():
		return fmt.Errorf("--mesh-ip %q is a loopback address; give the mesh address other nodes reach this Mac at", raw)
	case addr.IsMulticast():
		return fmt.Errorf("--mesh-ip %q is a multicast address and cannot be bound", raw)
	}
	return nil
}

// serverOnlyInstallFlags configure the CONTROL PLANE and mean nothing on a
// worker: the Service CIDR the control plane pins, the mesh address its
// apiserver binds, and the data volume the datastore lives on. Passing one with
// --agent is a misunderstanding worth stopping rather than silently ignoring,
// because every one of them would otherwise look configured and do nothing.
var serverOnlyInstallFlags = []string{
	"service-cidr",
	"mesh-ip",
	"data-volume",
	"data-volume-name",
	"data-volume-size",
	"data-volume-encrypt",
	"remove-old-data-root",
}

// agentOnlyInstallFlags describe a JOIN and mean nothing on a control plane.
var agentOnlyInstallFlags = []string{"server", "node-ip", "token-file"}

// role is the install role these flags select.
func (o installFlags) role() install.Role {
	if o.agent {
		return install.RoleAgent
	}
	return install.RoleServer
}

// validateRole is the flag-level contract of the two roles, decided before any
// privilege is taken: an agent install must say where to join, and neither role
// may be given the other's flags.
//
// It does NOT require --node-ip. The address this Mac holds inside the mesh is
// the control plane's to assign, and the join returns it; requiring it here made
// every agent install start by guessing at a value only the server's allocator
// knew. It stays accepted as an assertion, which the server checks.
//
// The refusals are separate sentences rather than one "invalid combination"
// because each names a different mistake, and the operator is at a terminal
// with a machine they are about to change.
func (o installFlags) validateRole() error {
	if !o.agent {
		for _, name := range agentOnlyInstallFlags {
			if o.set[name] {
				return fmt.Errorf("--%s needs --agent: it configures a node joining an existing cluster, and without --agent this Mac is being installed as the control plane", name)
			}
		}
		return nil
	}
	if o.server == "" {
		return fmt.Errorf("--agent needs --server (the control-plane host to join, an underlay address)")
	}
	for _, name := range serverOnlyInstallFlags {
		if o.set[name] {
			return fmt.Errorf("--%s cannot be combined with --agent: it configures the control plane, and a worker runs none of it", name)
		}
	}
	return nil
}

// The data-volume flag defaults.
const (
	// defaultDataVolumeName is the APFS volume label k3sm creates or adopts.
	defaultDataVolumeName = "k3sm"
	// defaultDataVolumeSize is the quota a volume is created with when the
	// operator names no size. It is large enough for a real workload's images,
	// datastore and PersistentVolumes, and small enough to be a bound rather
	// than a formality on the 512 GB and 1 TB Macs k3sm runs on.
	defaultDataVolumeSize = "100g"
)

// dataVolumeOptions turns the flags into the install package's request, or nil
// when no volume was asked for. It is where the two flag-level refusals live:
// a quota below the supported floor, and an encryption flag with no volume to
// apply it to.
func (o installFlags) dataVolumeOptions(k3smVersion string) (*datavol.Options, error) {
	if !o.dataVolume {
		// An encryption flag on its own is a misunderstanding worth stopping:
		// APFS cannot encrypt a volume in place, so it can only ever mean "and
		// also make me a volume", which is not something an install should infer.
		if o.dataVolumeEncrypt {
			return nil, fmt.Errorf("--data-volume-encrypt needs --data-volume: encryption is applied when the volume is created, and APFS cannot encrypt one in place")
		}
		return nil, nil
	}
	quota, err := datavol.ParseSize(o.dataVolumeSize)
	if err != nil {
		return nil, fmt.Errorf("--data-volume-size: %w", err)
	}
	if quota < datavol.MinQuotaBytes {
		return nil, fmt.Errorf("--data-volume-size %s is below the supported minimum of %s: runtimed's reclaim ladder and the node's DiskPressure floor are absolute byte counts, and a volume near them lives permanently inside the band that triggers reclamation",
			datavol.FormatSize(quota), datavol.FormatSize(datavol.MinQuotaBytes))
	}
	return &datavol.Options{
		Name:       o.dataVolumeName,
		Mountpoint: install.DefaultDataRoot,
		QuotaBytes: quota,
		Encrypt:    o.dataVolumeEncrypt,
		CreatedBy:  "k3sm " + k3smVersion,
	}, nil
}

// fileVaultOn reports whether FileVault is enabled on this Mac.
//
// It is advisory and tolerant: fdesetup(8) can fail for reasons that say
// nothing about FileVault (a managed Mac, a policy, a missing binary), and a
// note printed beside an install is not worth failing that install over. An
// unanswerable probe reports false and prints nothing.
func fileVaultOn() bool {
	out, err := exec.Command("fdesetup", "status").CombinedOutput()
	if err != nil {
		return false
	}
	return strings.Contains(string(out), "FileVault is On")
}

// fileVaultNote is the one line `k3sm install --data-volume` prints on a
// FileVault Mac when the volume is not passphrase-protected. The distinction is
// real and easy to miss: a k3sm volume is hardware-encrypted by the SEP whether
// or not FileVault is on, but without --data-volume-encrypt it is not gated on
// a passphrase, so it unlocks with the machine rather than with the user.
const fileVaultNote = "FileVault is on and the data volume is not passphrase-protected; see docs/user/storage.md"

// runUninstall boots out both LaunchDaemons (the netd helper flushes lo0/pf/utun
// on SIGTERM) and removes the install dir. It requires root and is idempotent.
//
// On a WORKER it first asks the cluster to forget this node, presenting the
// node's own certificate to the control plane's deregistration verb, so the Macs
// it leaves behind stop carrying a wireguard entry for it (see
// uninstalldereg.go). The closure is built here, where the credential store and
// the bootstrap client live; install decides when to call it and never lets it
// block the teardown. A worker with nothing to deregister with says so once, in
// one line, and the uninstall carries on.
func runUninstall(args []string) error {
	fs := flag.NewFlagSet("uninstall", flag.ExitOnError)
	_ = fs.Parse(args)

	if os.Geteuid() != 0 {
		return fmt.Errorf("k3sm uninstall must run as root — use 'sudo k3sm uninstall'")
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	sys := install.NewDarwinSystem()
	deregister, why := agentDeregister(sys, install.DefaultDataRoot, time.Now())
	if deregister == nil && why != "" {
		logger.Warn("not asking the cluster to forget this node: "+why,
			"remedy", "on the control plane: kubectl delete meshpeer/<node> node/<node>")
	}
	return install.Uninstall(context.Background(), sys, install.Config{
		Logger:     logger,
		Deregister: deregister,
	})
}

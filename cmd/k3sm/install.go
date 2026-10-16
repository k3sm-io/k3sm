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
	"io"
	"log/slog"
	"math"
	"net/netip"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"k3sm.io/k3sm/pkg/dataroot"
	"k3sm.io/k3sm/pkg/datavol"
	"k3sm.io/k3sm/pkg/executor"
	"k3sm.io/k3sm/pkg/install"
	"k3sm.io/k3sm/pkg/netdsvc"
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
	env := installEnv{
		euid:        os.Geteuid(),
		executable:  install.Executable,
		stagingFS:   install.NewDarwinStagingFS(),
		stagingRoot: install.DefaultStagingRoot,
	}
	opts, self, volume, err := env.prepare(args)
	if err != nil {
		return err
	}

	// Read-only introspection of the layout contract, deliberately BEFORE the
	// root check (prepare returns before it): the release tooling asserts an
	// extracted archive's member set against this output, and must be able to
	// do so unprivileged. Paths are printed relative so the caller can join
	// them onto any directory.
	if opts.printRequired {
		for _, p := range install.RequiredSiblings("") {
			fmt.Println(p)
		}
		return nil
	}

	// Said once, at the one moment it can still be acted on. The volume is
	// hardware-encrypted by the SEP either way; what --data-volume-encrypt adds
	// is a passphrase, and on a FileVault Mac an operator reasonably assumes
	// their data root inherited FileVault's protection. It did not.
	if volume != nil && !volume.Encrypt && fileVaultOn() {
		fmt.Fprintln(os.Stderr, fileVaultNote)
	}

	logger := newDaemonLogger(os.Stderr, slog.LevelInfo)
	ctx := context.Background()
	sys := install.NewDarwinSystem()
	cfg := opts.installConfig(self, volume, logger)
	if cfg.TLSSANs, err = opts.resolveTLSSANs(os.ReadFile, installedPlistPath(install.ServerLabel), dataroot.DefaultServerArgsRecordPath); err != nil {
		return err
	}
	if opts.fromStaging != "" {
		// The seams the --from-staging predicate and the signing continuity
		// check read through, and the version the downgrade rule compares.
		cfg.StagingFS = install.NewDarwinStagingFS()
		cfg.Signer = install.CodesignTeamID{}
		cfg.StagedVersion = version.Get().Version
	}
	if cfg, err = opts.resolveInPlace(cfg, func(c install.Config) (install.Config, error) {
		return install.ResolveInPlace(sys, c, kubeconfigOwner)
	}); err != nil {
		return err
	}
	// Only an install --start over a stopped node calls it: the uncordon.
	cfg.MarkNode = nodeMarker(sys, install.DefaultDataRoot)
	return install.Install(ctx, sys, cfg)
}

// inPlace reports the in-place update shape: --from-staging with no role flag
// (--agent, --server-join) and no --token-file, the argv the k3sm-netd root
// helper runs for a managed update. The role comes from the disk
// (install.ResolveInPlace).
func (o installFlags) inPlace() bool {
	return o.fromStaging != "" && !o.agent && !o.serverJoin && o.tokenFile == ""
}

// resolveInPlace runs resolve (install.ResolveInPlace in production) for an
// in-place update, and returns cfg unchanged otherwise. A worker resolved from
// the disk refuses the control-plane flags, as an explicit --agent install
// does.
func (o installFlags) resolveInPlace(cfg install.Config, resolve func(install.Config) (install.Config, error)) (install.Config, error) {
	if !o.inPlace() {
		return cfg, nil
	}
	cfg, err := resolve(cfg)
	if err != nil {
		return cfg, err
	}
	if cfg.Role == install.RoleAgent {
		for _, name := range serverOnlyInstallFlags {
			if o.set[name] {
				return cfg, fmt.Errorf("--%s cannot be used to update this Mac in place: it is installed as a worker, which runs no control plane", name)
			}
		}
	}
	return cfg, nil
}

// kubeconfigOwner is the production install.FileOwner: the user name owning
// the regular file at path (the recorded admin kubeconfig), never through a
// symlink.
func kubeconfigOwner(path string) (string, error) {
	fi, err := os.Lstat(path)
	if err != nil {
		return "", err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || !fi.Mode().IsRegular() {
		return "", fmt.Errorf("%s is not a regular file", path)
	}
	u, err := user.LookupId(strconv.FormatUint(uint64(st.Uid), 10))
	if err != nil {
		return "", err
	}
	return u.Username, nil
}

// installEnv is what runInstall reads from the process before it builds the
// install's Config: the effective uid, the resolved executable, and the
// staging seams a refused --from-staging run uses to discard its token file.
// It is a struct so those refusals are testable without root.
type installEnv struct {
	euid        int
	executable  func() (string, error)
	stagingFS   install.StagingFS
	stagingRoot string
}

// prepare parses the flags and makes every refusal that comes before the
// install itself: a flag that fails validation, the root check, the --user
// check, an unresolvable executable and the data-volume flags. Under
// --from-staging with --token-file, each of those refusals also discards the
// staged token file, unread (install.DiscardStagedToken), so a refused run
// never leaves a token behind. --print-required-artifacts returns before the
// root check.
func (e installEnv) prepare(args []string) (opts installFlags, self string, volume *datavol.Options, err error) {
	defer func() {
		if err != nil && opts.fromStaging != "" && opts.tokenFile != "" {
			install.DiscardStagedToken(e.stagingFS, e.stagingRoot, opts.tokenFile)
		}
	}()
	opts, err = parseInstallFlags(args)
	if err != nil || opts.printRequired {
		return opts, "", nil, err
	}
	if e.euid != 0 {
		return opts, "", nil, fmt.Errorf("k3sm install must run as root — use 'sudo k3sm install'")
	}
	// An in-place update may name no user: the root helper runs it with no
	// $SUDO_USER, and install.ResolveInPlace finds the kubeconfig's owner.
	if (opts.targetUser == "" && !opts.inPlace()) || opts.targetUser == "root" {
		return opts, "", nil, fmt.Errorf("--user (or $SUDO_USER) must be a non-root human so the kubeconfig is not root-owned; run via 'sudo k3sm install'")
	}
	if self, err = e.executable(); err != nil {
		return opts, "", nil, err
	}
	if volume, err = opts.dataVolumeOptions(version.Get().Version); err != nil {
		return opts, "", nil, err
	}
	return opts, self, volume, nil
}

// installConfig is the install package's Config these flags describe. It is
// split out of runInstall so the mapping from flag to Config, and through it to
// the rendered daemon arguments, is assertable without root.
func (o installFlags) installConfig(self string, volume *datavol.Options, logger *slog.Logger) install.Config {
	return install.Config{
		Role:              o.role(),
		JoinServer:        o.server,
		NodeIP:            o.nodeIP,
		ClusterInit:       o.clusterInit,
		ServerJoin:        o.serverJoin,
		TokenFile:         o.tokenFile,
		BinarySource:      self,
		TargetUser:        o.targetUser,
		ServiceCIDR:       o.serviceCIDR,
		DataVolume:        volume,
		RemoveOldDataRoot: o.removeOldDataRoot,
		MeshIP:            o.meshIP,
		TLSSANs:           o.tlsSANs,
		KubeconfigName:    o.recordedKubeconfigName(),
		NodePortAddresses: o.recordedNodePortAddresses(),
		LAN:               o.recordedLAN(),
		SecretsEncryption: o.secretsEncryption,
		EtcdSnapshots:     o.etcdSnapshotFlags(),
		Start:             o.start,
		Logger:            logger,
		StagingOptions: install.StagingOptions{
			FromStagingDir:       o.fromStaging,
			AllowDowngrade:       o.allowDowngrade,
			RequireTeamSignature: o.requireTeamSignature,
			Executable:           self,
		},
	}
}

// resolveTLSSANs is the install-time judgement of --tls-san, made before
// anything is written: nil when the flag was not passed (the recorded list is
// kept), else the list in canonical spelling, which replaces the recorded one.
// The server's effective mesh IP is --mesh-ip when passed, else the installed
// one (read the way install.InstalledMeshIP reads it); without one the server
// is single-node, which issues the same cluster-CA leaf, so the list is judged
// the same way with no mesh IP (checkInstallTLSSANs).
func (o installFlags) resolveTLSSANs(read func(string) ([]byte, error), plistPath, recordPath string) ([]string, error) {
	if len(o.tlsSANs) == 0 {
		return nil, nil
	}
	meshIP := o.meshIP
	if meshIP == "" {
		installed, err := install.InstalledMeshIP(read, plistPath, recordPath)
		if err != nil {
			return nil, fmt.Errorf("--%s: read the installed --mesh-ip: %w", install.TLSSANFlag, err)
		}
		meshIP = installed
	}
	return checkInstallTLSSANs(o.tlsSANs, meshIP, o.serviceCIDR)
}

// recordedKubeconfigName is --kubeconfig-name when the operator passed it, and
// "" otherwise so an unpassed flag keeps the carried name.
func (o installFlags) recordedKubeconfigName() string {
	if o.set["kubeconfig-name"] {
		return o.kubeconfigName
	}
	return ""
}

// recordedNodePortAddresses is the install package's request for
// --nodeport-addresses: the passed value (an empty one clears a carried
// setting back to every interface), or nil when the flag was not passed so a
// carried value is kept.
func (o installFlags) recordedNodePortAddresses() *string {
	if !o.set[nodePortAddressesFlag] {
		return nil
	}
	v := o.nodePortAddresses
	return &v
}

// recordedLAN is the install package's request for --lan: the passed value,
// or nil when the flag was not passed (keep the recorded value, or decide by
// whether k3sm ran here before).
func (o installFlags) recordedLAN() *install.LAN {
	if !o.set["lan"] {
		return nil
	}
	v := o.lan
	return &v
}

// etcdSnapshotFlags is the install package's request for the scheduled-snapshot
// flags: only the ones the operator passed, so an unpassed one keeps its carried
// value (or the daemon's default).
func (o installFlags) etcdSnapshotFlags() install.EtcdSnapshotFlags {
	var f install.EtcdSnapshotFlags
	if o.set["etcd-snapshot-schedule-cron"] {
		f.Cron = strings.Join(strings.Fields(o.etcdSnapshotCron), " ")
	}
	if o.set["etcd-snapshot-retention"] {
		f.Retention = o.etcdSnapshotRetention
	}
	if o.set["etcd-disable-snapshots"] {
		v := o.etcdDisableSnapshots
		f.Disable = &v
	}
	if o.set["etcd-snapshot-compress"] {
		v := o.etcdSnapshotCompress
		f.Compress = &v
	}
	return f
}

// validateEtcdSnapshotFlags refuses, before anything is written, a schedule the
// daemon would refuse at every start.
func (o installFlags) validateEtcdSnapshotFlags() error {
	if o.set["etcd-snapshot-schedule-cron"] {
		if _, err := executor.ParseCron(o.etcdSnapshotCron); err != nil {
			return fmt.Errorf("--etcd-snapshot-schedule-cron: %w", err)
		}
	}
	if o.set["etcd-snapshot-retention"] && o.etcdSnapshotRetention < 1 {
		return fmt.Errorf("--etcd-snapshot-retention %d: %w", o.etcdSnapshotRetention, executor.ErrEtcdSnapshotRetention)
	}
	return nil
}

// installFlags is the parsed `k3sm install` command line. It is a struct rather
// than a handful of pointers inside runInstall so the flag CONTRACT -- the
// defaults, the size floor, the flag that requires another flag -- is decidable
// in a unit test, where the install itself can never run.
type installFlags struct {
	// agent selects the WORKER role: this Mac joins an existing cluster and runs
	// the io.k3sm.agent LaunchDaemon instead of io.k3sm.server.
	agent bool
	// clusterInit and serverJoin select the embedded-etcd HA role of a SERVER
	// install: form a new HA control plane, or join an existing one.
	clusterInit bool
	serverJoin  bool
	// server, nodeIP and tokenFile are shared by the two roles, with a
	// different meaning on each (see their help text).
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
	// tlsSANs is --tls-san, as passed; resolveTLSSANs validates it against
	// the effective mesh IP and this Mac's addresses.
	tlsSANs           tlsSANList
	kubeconfigName    string
	nodePortAddresses string
	lan               install.LAN
	lanRaw            string
	secretsEncryption bool
	// etcdSnapshotCron, etcdSnapshotRetention and etcdDisableSnapshots are the
	// scheduled etcd snapshot flags, rendered into the server daemon's arguments
	// only when passed (see etcdSnapshotFlags).
	etcdSnapshotCron      string
	etcdSnapshotRetention int
	etcdDisableSnapshots  bool
	etcdSnapshotCompress  bool
	// start is --start: start a node the user stopped (install.Config.Start).
	start bool
	// fromStaging is --from-staging: the k3sm.app staging directory this
	// binary runs from (install.StagingOptions.FromStagingDir).
	fromStaging string
	// allowDowngrade is --allow-downgrade, with --from-staging only.
	allowDowngrade bool
	// requireTeamSignature is --require-team-signature, with --from-staging
	// only (install.StagingOptions.RequireTeamSignature).
	requireTeamSignature bool
}

// parseInstallFlags parses the install command line. It returns the parse error
// rather than exiting, so the caller (and a test) sees it. A validation error
// after a successful parse comes back with the parsed flags, so the caller can
// still discard a staged token file (installEnv.prepare).
func parseInstallFlags(args []string) (installFlags, error) {
	var o installFlags
	fs := flag.NewFlagSet("install", flag.ContinueOnError)
	fs.StringVar(&o.targetUser, "user", os.Getenv("SUDO_USER"), "the human whose ~/.kube/config receives the admin kubeconfig (default $SUDO_USER)")
	fs.StringVar(&o.serviceCIDR, "service-cidr", install.DefaultServiceCIDR, "cluster Service CIDR")
	fs.BoolVar(&o.agent, "agent", false, "install this Mac as a WORKER that joins an existing cluster (the io.k3sm.agent daemon) instead of as the control plane; needs --server")
	fs.BoolVar(&o.clusterInit, "cluster-init", false, "form a new embedded etcd HA control plane on this server; needs --node-ip")
	fs.BoolVar(&o.serverJoin, "server-join", false, "join this server to an existing embedded etcd HA control plane; needs --server, --token-file and --node-ip")
	fs.StringVar(&o.server, "server", "", "with --agent: the control-plane host to join; with --server-join: an existing server's LAN address (the --node-ip it was installed with). Either way an UNDERLAY address (a LAN IP or DNS name, no scheme, no port), because the join dials <host>:9345 before this node has any mesh")
	fs.StringVar(&o.nodeIP, "node-ip", "", "with --agent: optional; the join assigns this Mac's mesh address, pass it only to assert the expected value (a value that differs from the assignment fails the join instead of minting a certificate for an address this node does not hold). With --cluster-init or --server-join: required; this Mac's LAN address, which the etcd peer listener binds and every other server dials (not loopback). The server daemon receives it as --etcd-peer-ip; the node itself advertises its --mesh-ip")
	fs.StringVar(&o.tokenFile, "token-file", "", "with --agent: a file holding the join token (a joined node needs none). With --server-join: required; a file holding the server token `k3sm token create --server` printed on an existing server. Read once by this install and copied for the daemon; it must not be group- or world-readable, and it is yours to delete afterwards")
	fs.StringVar(&o.fromStaging, "from-staging", "", "install from a k3sm.app staging directory: the directory directly inside "+install.DefaultStagingRoot+" that this k3sm runs from. Every file is installed from that directory, which must be owned by root and writable by nobody else. A --token-file must sit directly inside it, owned by root with mode 600, and is removed once read. Without --agent, --server-join and --token-file it updates whatever is installed in place: the role, the join target and every configured argument are read from the installed daemon, and nothing installed is refused unless --user names a first install. Refuses an older version than the installed one, and a build signed by a different team")
	fs.BoolVar(&o.allowDowngrade, "allow-downgrade", false, "with --from-staging: install even when the installed k3sm is newer, or its version cannot be read")
	fs.BoolVar(&o.requireTeamSignature, "require-team-signature", false, "with --from-staging: refuse the install unless every Mach-O in the staging directory carries a Developer ID team signature, whatever the installed k3sm is signed with")
	fs.BoolVar(&o.start, "start", false, "on a node stopped with 'k3sm stop', start it after installing (without it the node is updated and stays stopped)")
	fs.BoolVar(&o.printRequired, "print-required-artifacts", false, "print the artifacts that must sit beside this binary (one per line, relative) and exit; needs no privilege")
	fs.BoolVar(&o.dataVolume, "data-volume", false, "keep the data root on a dedicated, size-capped APFS volume: create it, adopt an existing one, or migrate onto it")
	fs.StringVar(&o.dataVolumeName, "data-volume-name", defaultDataVolumeName, "the APFS volume label to create or adopt")
	fs.StringVar(&o.dataVolumeSize, "data-volume-size", defaultDataVolumeSize, "the data volume's quota (m, g or t suffix). APFS fixes it at creation: changing it later means delete, reinstall and restore")
	fs.BoolVar(&o.dataVolumeEncrypt, "data-volume-encrypt", false, "encrypt the data volume with a random passphrase kept in the System keychain (a volume k3sm creates only)")
	fs.BoolVar(&o.removeOldDataRoot, "remove-old-data-root", false, "after a verified migration, delete the .pre-volume copy of the old data root instead of keeping it")
	fs.StringVar(&o.meshIP, "mesh-ip", "", "this node's wireguard mesh address, written into the server daemon's arguments; needed on every Mac that serves the control plane in a multi-node cluster")
	fs.Var(&o.tlsSANs, install.TLSSANFlag, tlsSANUsage)
	fs.StringVar(&o.kubeconfigName, "kubeconfig-name", install.DefaultKubeconfigName, "the cluster, user and context name the admin kubeconfig is merged under in your ~/.kube/config (the k3s --write-kubeconfig-name analog). It is recorded with the other install arguments, so k3sm kubectl, k3sm kubeconfig and uninstall --purge use it; a name already used by an entry k3sm did not create is refused")
	fs.StringVar(&o.nodePortAddresses, nodePortAddressesFlag, "", nodePortAddressesUsage+". Written into the node daemon's arguments and kept across reinstalls; pass an empty value to go back to every interface")
	fs.StringVar(&o.lanRaw, "lan", "", "LAN access for this node's NodePort, LoadBalancer and ingress listeners: off answers only on this Mac and the cluster mesh, on answers on every network this Mac is on. Not passed, a new install records off and an existing install keeps what it has (on, if it predates the setting). Change it later with 'sudo k3sm network lan on|off'. The apiserver, the worker join port and the mesh port do not follow it")
	fs.BoolVar(&o.secretsEncryption, "secrets-encryption", false, "encrypt Secrets at rest with a key generated on this Mac; a new single-server cluster only (back up <data root>/server/cred with every datastore backup)")
	fs.StringVar(&o.etcdSnapshotCron, "etcd-snapshot-schedule-cron", executor.DefaultEtcdSnapshotCron, "when the server takes a scheduled etcd snapshot, as a five-field cron expression in local time (embedded etcd HA servers only); written into the server daemon's arguments when passed")
	fs.IntVar(&o.etcdSnapshotRetention, "etcd-snapshot-retention", executor.DefaultEtcdSnapshotRetention, "how many of this server's scheduled etcd snapshots to keep (embedded etcd HA servers only); written into the server daemon's arguments when passed")
	fs.BoolVar(&o.etcdDisableSnapshots, "etcd-disable-snapshots", false, "take no scheduled etcd snapshots on this server (embedded etcd HA servers only); written into the server daemon's arguments when passed")
	fs.BoolVar(&o.etcdSnapshotCompress, "etcd-snapshot-compress", false, "write this server's scheduled etcd snapshots as zip archives (embedded etcd HA servers only); written into the server daemon's arguments when passed")
	if err := fs.Parse(args); err != nil {
		return installFlags{}, err
	}
	if o.meshIP != "" {
		if err := validateMeshIP(o.meshIP); err != nil {
			return o, err
		}
	}
	o.set = map[string]bool{}
	fs.Visit(func(f *flag.Flag) { o.set[f.Name] = true })
	if o.set["kubeconfig-name"] {
		if err := install.ValidateKubeconfigName(o.kubeconfigName); err != nil {
			return o, fmt.Errorf("--kubeconfig-name: %w", err)
		}
	}
	if o.set["lan"] {
		lan, err := install.ParseLAN(o.lanRaw)
		if err != nil {
			return o, fmt.Errorf("--lan: %w", err)
		}
		o.lan = lan
	}
	o.nodePortAddresses = strings.TrimSpace(o.nodePortAddresses) // whitespace-only clears, like ""
	if err := validateNodePortAddresses(o.nodePortAddresses); err != nil {
		return o, err
	}
	if err := o.validateRole(); err != nil {
		return o, err
	}
	if err := o.validateFromStaging(); err != nil {
		return o, err
	}
	if err := o.validateEtcdSnapshotFlags(); err != nil {
		return o, err
	}
	return o, nil
}

// validateFromStaging is the flag-level half of --from-staging: an absolute,
// clean directory, and --allow-downgrade and --require-team-signature only
// beside it. The install package
// judges the directory itself on disk, before anything is written.
func (o installFlags) validateFromStaging() error {
	if o.fromStaging == "" {
		if o.allowDowngrade {
			return fmt.Errorf("--allow-downgrade needs --from-staging: it relaxes the version check of an install from a k3sm.app staging directory, and a plain install makes none")
		}
		if o.requireTeamSignature {
			return fmt.Errorf("--require-team-signature needs --from-staging: it tightens the signature check of an install from a staging directory, and a plain install makes none")
		}
		return nil
	}
	if !filepath.IsAbs(o.fromStaging) || filepath.Clean(o.fromStaging) != o.fromStaging {
		return fmt.Errorf("--from-staging %q must be a clean absolute path", o.fromStaging)
	}
	return nil
}

// validateMeshIP refuses a --mesh-ip this install can never serve from: an
// address that fails to parse at all, the IP shapes that are always wrong for a
// server's own bind address — unspecified (0.0.0.0/::), loopback, and multicast
// — and any address that is not the mesh-egress address of a node pod range
// inside the cluster pod range (install.MeshNodePodCIDR). It runs at flag-parse time, before root/privilege checks, so a
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
	// A server's mesh address is the mesh-egress address of its own node pod
	// range: the install seeds netd's node range from it, so an address that
	// names no range would leave netd refusing the server's own mesh alias.
	if _, err := install.MeshNodePodCIDR(raw); err != nil {
		return err
	}
	return nil
}

// serverOnlyInstallFlags configure the CONTROL PLANE and mean nothing on a
// worker: the Service CIDR the control plane pins, the mesh address its
// apiserver binds, the data volume the datastore lives on, and the embedded-etcd
// HA role. Passing one with --agent is a misunderstanding worth stopping rather
// than silently ignoring, because every one of them would otherwise look
// configured and do nothing.
var serverOnlyInstallFlags = []string{
	"cluster-init",
	"server-join",
	"service-cidr",
	"mesh-ip",
	install.TLSSANFlag,
	"kubeconfig-name",
	"data-volume",
	"data-volume-name",
	"data-volume-size",
	"data-volume-encrypt",
	"remove-old-data-root",
	"secrets-encryption",
	"etcd-snapshot-schedule-cron",
	"etcd-snapshot-retention",
	"etcd-disable-snapshots",
	"etcd-snapshot-compress",
}

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
//
// A server install takes the embedded-etcd HA flags: --cluster-init alone, or
// --server-join with --server and --token-file, and either with a non-loopback
// --node-ip, rendered as the daemon's --etcd-peer-ip; the predicate is the one
// `k3sm server` itself applies to that flag.
func (o installFlags) validateRole() error {
	if !o.agent {
		return o.validateServerRole()
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

// validateServerRole is validateRole for a control-plane install. It is the
// install package's ValidateHARequest over the Config these flags become, the
// same validator install.Install runs before it writes anything, so the CLI
// and the installer refuse exactly one set of HA shapes.
func (o installFlags) validateServerRole() error {
	return install.ValidateHARequest(o.installConfig("", nil, nil))
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
//
// With --purge --yes it also removes everything a plain uninstall keeps. The
// flags are judged before anything else, so a purge that was not confirmed
// refuses without touching the system.
func runUninstall(args []string) error {
	fs := flag.NewFlagSet("uninstall", flag.ExitOnError)
	purgeFlag := fs.Bool("purge", false, "also remove everything a plain uninstall keeps: the cluster data (and the data volume with its keychain item), the daemon logs, the _k3sm user, the k3sm context in your kubeconfig, the /etc/fstab line and the recorded arguments. Irreversible; requires --yes")
	yes := fs.Bool("yes", false, "confirm --purge")
	purgeUser := fs.String("user", "", "with --purge, the human whose ~/.kube/config holds the k3sm context, for a caller with no sudo environment (looked up by name; root and service accounts are refused). Default: $SUDO_USER")
	_ = fs.Parse(args)
	if err := checkPurgeFlags(*purgeFlag, *yes); err != nil {
		return err
	}

	if os.Geteuid() != 0 {
		return fmt.Errorf("k3sm uninstall must run as root — use 'sudo k3sm uninstall'")
	}
	cfg := uninstallConfig(os.Stdout, os.Stderr)
	// Who is running: the k3sm.app root step runs a staged copy of this
	// binary while its copy-out holds the staging lock, and the uninstall
	// tells that case from a copy-out it would race by this path.
	if self, err := install.Executable(); err == nil {
		cfg.Executable = self
	}
	cfg.StagingFS = install.NewDarwinStagingFS()
	logger := cfg.Logger
	sys := install.NewDarwinSystem()
	deregister, why := agentDeregister(sys, install.DefaultDataRoot, time.Now())
	if deregister == nil && why != "" {
		logger.Warn("not asking the cluster to forget this node: "+why,
			"remedy", "on the control plane: kubectl delete meshpeer/<node> node/<node>")
	}
	cfg.Deregister = deregister
	// On an embedded-etcd HA server, remove its etcd member first (install decides
	// whether the installed plist is one; see uninstalletcd.go).
	cfg.DeregisterServer = serverMemberDeregister(filepath.Join(install.DefaultDataRoot, "server"), dialLocalEtcdAdmin, logger)
	if *purgeFlag {
		human, home, err := resolvePurgeTarget(*purgeUser, os.Getenv("SUDO_USER"), os.Getenv("SUDO_UID"))
		if err != nil {
			return err
		}
		cfg.Purge, cfg.PurgeConfirmed = true, true
		cfg.TargetUser, cfg.TargetHome = human, home
	}
	if err := install.Uninstall(context.Background(), sys, cfg); err != nil {
		return err
	}
	removeNodeResolverEntry(logger)
	return nil
}

// uninstallConfig is the uninstall's output wiring: result lines (what a purge
// removed, and an account it could not delete with how to finish by hand) to
// stdout, progress and diagnostics through the logger to stderr.
func uninstallConfig(stdout, stderr io.Writer) install.Config {
	return install.Config{
		// Not newDaemonLogger: called with injected writers, and install_test.go asserts on an isolated buffer; setting the process default here would leak test state.
		Logger: slog.New(slog.NewTextHandler(stderr, &slog.HandlerOptions{Level: slog.LevelInfo})),
		Out:    stdout,
	}
}

// purgeWarning names what `k3sm uninstall --purge` destroys, for the refusal
// an unconfirmed purge prints.
const purgeWarning = "k3sm uninstall --purge permanently deletes this Mac's cluster: the datastore and every image and volume under " +
	install.DefaultDataRoot + " (and the data volume, if there is one, with its keychain item), the daemon logs in " +
	install.LogDir + ", the " + install.DefaultServiceUser + " user (deletion attempted; macOS may need an approval at the screen), the k3sm context in your kubeconfig, the /etc/fstab line and the recorded arguments"

// checkPurgeFlags judges --purge and --yes together: --yes confirms a purge
// and nothing else, and a purge is never run unconfirmed.
func checkPurgeFlags(purge, yes bool) error {
	switch {
	case yes && !purge:
		return fmt.Errorf("--yes only confirms --purge; a plain 'sudo k3sm uninstall' needs no confirmation")
	case purge && !yes:
		return fmt.Errorf("%s. Nothing was changed. Re-run as 'sudo k3sm uninstall --purge --yes' to do it", purgeWarning)
	}
	return nil
}

// lookupUser resolves an account by name; tests replace it.
var lookupUser = user.Lookup

// minHumanUID is the first uid macOS gives a human account; below it are
// root and the system and service accounts.
const minHumanUID = 501

// resolvePurgeTarget picks the purge's human: an explicit --user wins over
// the sudo environment, which is consulted only when --user is empty.
func resolvePurgeTarget(userFlag, sudoUser, sudoUID string) (name, home string, err error) {
	if userFlag != "" {
		return explicitPurgeTarget(userFlag)
	}
	return purgeTarget(sudoUser, sudoUID)
}

// explicitPurgeTarget resolves --user. The uid and home come only from the
// account lookup, never from SUDO_UID. It refuses root, a uid below 501, a
// service account (a leading underscore, nobody, daemon; nobody's uid is
// above any human range, so it is named), and a home that is "/" or a prefix of the data root,
// which the purge could not protect. The returned home is symlink-resolved.
func explicitPurgeTarget(name string) (string, string, error) {
	if name == "" || name == "root" || name == "nobody" || name == "daemon" || strings.HasPrefix(name, "_") {
		return "", "", fmt.Errorf("--user %q is not a human account; name the account whose kubeconfig holds the k3sm context", name)
	}
	u, err := lookupUser(name)
	if err != nil {
		return "", "", fmt.Errorf("look up --user %s: %w", name, err)
	}
	uid, err := strconv.ParseUint(u.Uid, 10, 32)
	if err != nil {
		return "", "", fmt.Errorf("--user %s has uid %q, which is not a 32-bit number: %w", name, u.Uid, err)
	}
	if uid < minHumanUID || uid > math.MaxInt32 {
		return "", "", fmt.Errorf("--user %s has uid %s, below %d: refusing a system or service account", name, u.Uid, minHumanUID)
	}
	if u.HomeDir == "" {
		return "", "", fmt.Errorf("--user %s has no home directory", name)
	}
	home, err := filepath.EvalSymlinks(u.HomeDir)
	if err != nil {
		return "", "", fmt.Errorf("resolve the home of --user %s: %w", name, err)
	}
	home = filepath.Clean(home)
	dataRoot := filepath.Clean(install.DefaultDataRoot)
	if resolved, err := filepath.EvalSymlinks(dataRoot); err == nil {
		dataRoot = resolved
	}
	if home == "/" || dataRoot == home || strings.HasPrefix(dataRoot, home+"/") {
		return "", "", fmt.Errorf("--user %s has home %s, which contains the cluster data; refusing", name, home)
	}
	return u.Username, home, nil
}

// purgeTarget is the human a purge cleans the kubeconfig of, and that
// human's home, which the purge never deletes into. It must be a real,
// non-root account: run through sudo from it.
//
// sudo sets both SUDO_USER and SUDO_UID; either alone is just an environment
// variable a caller can set. The account the name looks up must carry the uid
// sudo recorded, so a SUDO_USER pointed at someone else's account is refused
// rather than trusted with whose home is protected and whose kubeconfig is
// edited.
func purgeTarget(sudoUser, sudoUID string) (name, home string, err error) {
	if sudoUser == "" || sudoUser == "root" {
		return "", "", fmt.Errorf("run 'sudo k3sm uninstall --purge --yes' from your own account, so k3sm knows whose kubeconfig holds the k3sm context")
	}
	if sudoUID == "" {
		return "", "", fmt.Errorf("SUDO_USER is set but SUDO_UID is not; run 'sudo k3sm uninstall --purge --yes' through sudo")
	}
	u, err := lookupUser(sudoUser)
	if err != nil {
		return "", "", fmt.Errorf("look up %s: %w", sudoUser, err)
	}
	if u.Uid != sudoUID {
		return "", "", fmt.Errorf("SUDO_USER %s has uid %s, but SUDO_UID is %s; refusing to purge on behalf of a user sudo did not record", sudoUser, u.Uid, sudoUID)
	}
	return u.Username, u.HomeDir, nil
}

// removeNodeResolverEntry deletes netd's node resolver entry from the dynamic
// store after the daemons are gone. netd removes it itself on SIGTERM, so this
// is the backstop for a netd that crashed or was killed first: configd keeps a
// State: key after its writer exits, and an entry left behind would route svc
// and the cluster domain to a DNS VIP nothing serves. An absent key is not an
// error; a failure is a warning with the manual remedy, never an uninstall
// failure.
func removeNodeResolverEntry(logger *slog.Logger) {
	store, err := netdsvc.OpenSystemStore()
	if err == nil {
		err = store.Remove(netdsvc.NodeResolverKey)
		_ = store.Close() // the removal above is the only thing that mattered
	}
	if err != nil {
		logger.Warn("could not remove the node resolver entry", "key", netdsvc.NodeResolverKey, "err", err,
			"remedy", "printf 'remove "+netdsvc.NodeResolverKey+"\\n' | sudo scutil")
	}
}

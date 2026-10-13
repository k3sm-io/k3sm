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
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"k3sm.io/darwin-net/pkg/proxy"

	"k3sm.io/k3sm/internal/atomicfile"
	"k3sm.io/k3sm/pkg/ingresshost"
	"k3sm.io/k3sm/pkg/install"
	"k3sm.io/k3sm/pkg/netserve"
	"k3sm.io/k3sm/pkg/svclb"
)

// lanApplyTimeout bounds one live apply of the LAN switch: every family binds
// its new addresses inside it, or the apply fails and nothing changes.
const lanApplyTimeout = 20 * time.Second

// lanSets is what the LAN switch resolves to for the listener families: the
// NodePort address set (nil is the wildcard) and the set the LoadBalancer and
// ingress listeners bind.
type lanSets struct {
	lan       install.LAN
	nodePorts []netip.Addr
	listeners []netip.Addr
}

// lanFamily is one kind of workload listener the switch moves.
type lanFamily interface {
	// name is the family's name in status and in an error.
	name() string
	// prepare binds the family's listeners on sets beside the current ones,
	// all or nothing; the returned step commits or undoes that.
	prepare(ctx context.Context, sets lanSets) (lanStep, error)
}

// lanStep is a prepared family move: commit closes the old addresses (never
// an accepted connection), abort closes what prepare opened.
type lanStep struct {
	commit func() error
	abort  func()
}

// lanSwitch is the node daemon's half of `k3sm network lan`: it holds the LAN
// state in force, the families it moves, and applies the recorded value on
// SIGHUP as ONE all-or-nothing change across the families.
//
// Locking discipline: mu guards every field below it and is held for a whole
// apply and for a family's attach, so a family can never be built on one
// state and miss the apply that changes it. Families' prepare calls run under
// mu; none of them calls back into the switch.
type lanSwitch struct {
	recordPath  string
	appliedPath string
	readFile    func(string) ([]byte, error)
	writeFile   func(path string, data []byte) error
	hostAddrs   func() ([]netip.Addr, error)
	log         *slog.Logger

	mu       sync.Mutex
	lan      install.LAN
	serial   string
	spec     string
	node     netip.Addr
	families []lanFamily
}

// newLANSwitch reads the record at recordPath and returns a switch in that
// state. An absent record is LAN access on (an install from before the switch
// served every interface). An unusable one is off, the narrower exposure, and
// the error is reported in the applied file and the log.
func newLANSwitch(recordPath, appliedPath string, log *slog.Logger) *lanSwitch {
	s := &lanSwitch{
		recordPath:  recordPath,
		appliedPath: appliedPath,
		readFile:    os.ReadFile,
		writeFile:   func(path string, data []byte) error { return atomicfile.Replace(path, data, 0o644) },
		hostAddrs:   nodePortHostAddrs,
		log:         log,
	}
	s.load()
	return s
}

// load reads the record into the switch's state (startup only).
func (s *lanSwitch) load() {
	rec, _, err := install.ReadNetworkRecord(s.readFile, s.recordPath)
	if err != nil {
		s.log.Error("the LAN access record cannot be used; serving workload listeners on this Mac and the mesh only until it is fixed (sudo k3sm network lan on|off)", "err", err)
		s.lan = install.LANOff
		return
	}
	s.lan, s.serial = rec.LAN, rec.Serial
}

// resolve turns lan into the families' address sets, against this Mac's
// addresses and the node's own address. Off is the "local" preset for every
// family; on is every interface, except that NodePorts keep an explicit
// --nodeport-addresses.
func (s *lanSwitch) resolve(lan install.LAN) (lanSets, error) {
	spec := strings.TrimSpace(s.spec)
	if lan == install.LANOff {
		spec = proxy.NodePortPresetLocal
	}
	nodePorts, err := resolveNodePortAddresses(spec, s.node, s.hostAddrs)
	if err != nil {
		return lanSets{}, err
	}
	if lan == install.LANOff {
		return lanSets{lan: lan, nodePorts: nodePorts, listeners: nodePorts}, nil
	}
	return lanSets{lan: install.LANOn, nodePorts: nodePorts, listeners: []netip.Addr{wildcardBindAddr}}, nil
}

// attach builds a family on the state in force and registers it for later
// applies, under the switch's lock. spec (--nodeport-addresses) and node (the
// node's own address) are remembered when non-empty. A nil switch (a node with
// no LAN switch, such as the standalone `k3sm node`) builds the family on LAN
// access on and registers nothing.
func (s *lanSwitch) attach(spec, node string, build func(lanSets) (lanFamily, error)) error {
	if s == nil {
		tmp := &lanSwitch{hostAddrs: nodePortHostAddrs, spec: spec, node: parseNodeAddr(node)}
		sets, err := tmp.resolve(install.LANOn)
		if err != nil {
			return err
		}
		_, err = build(sets)
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if spec != "" {
		s.spec = spec
	}
	if a := parseNodeAddr(node); a.IsValid() {
		s.node = a
	}
	sets, err := s.resolve(s.lan)
	if err != nil {
		return err
	}
	f, err := build(sets)
	if err != nil {
		return err
	}
	if f != nil {
		s.families = append(s.families, f)
	}
	return nil
}

// parseNodeAddr parses a node address, or returns the zero Addr.
func parseNodeAddr(node string) netip.Addr {
	a, err := netip.ParseAddr(node)
	if err != nil {
		return netip.Addr{}
	}
	return a.Unmap()
}

// apply reads the record and moves every family to it, all or nothing: each
// family binds its new addresses beside the old ones, and only when every one
// has done so are the old addresses closed. If any family fails, everything
// prepared is undone, the previous state stays in force everywhere, and the
// failure is reported. The outcome is written to the applied file either way.
func (s *lanSwitch) apply(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, _, err := install.ReadNetworkRecord(s.readFile, s.recordPath)
	if err != nil {
		s.report(rec.Serial, err)
		return err
	}
	sets, err := s.resolve(rec.LAN)
	if err != nil {
		err = fmt.Errorf("resolve LAN access %s: %w", rec.LAN, err)
		s.report(rec.Serial, err)
		return err
	}
	steps := make([]lanStep, 0, len(s.families))
	for _, f := range s.families {
		st, err := f.prepare(ctx, sets)
		if err != nil {
			for i := len(steps) - 1; i >= 0; i-- {
				steps[i].abort()
			}
			err = fmt.Errorf("%s: %w", f.name(), err)
			s.report(rec.Serial, err)
			return err
		}
		steps = append(steps, st)
	}
	for i, st := range steps {
		if err := st.commit(); err != nil {
			s.log.Warn("a listener family did not take the new LAN access state", "family", s.families[i].name(), "err", err)
		}
	}
	s.lan, s.serial = rec.LAN, rec.Serial
	s.report(rec.Serial, nil)
	return nil
}

// report writes the applied file: the state in force and the serial of the
// record acted on, plus err when the record could not be applied. A write
// failure is logged; the CLI then falls back to a restart.
func (s *lanSwitch) report(serial string, err error) {
	a := install.NetworkApplied{LAN: s.lan, Serial: serial, At: time.Now().UTC()}
	if err != nil {
		a.Error = err.Error()
	}
	data, merr := json.Marshal(a)
	if merr != nil {
		s.log.Error("encode the LAN access report", "err", merr)
		return
	}
	if werr := s.writeFile(s.appliedPath, append(data, '\n')); werr != nil {
		s.log.Warn("could not write the LAN access report", "path", s.appliedPath, "err", werr)
	}
}

// watch applies the record on every signal from hup until ctx ends.
func (s *lanSwitch) watch(ctx context.Context, hup <-chan os.Signal) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-hup:
		}
		actx, cancel := context.WithTimeout(ctx, lanApplyTimeout)
		err := s.apply(actx)
		cancel()
		if err != nil {
			s.log.Error("LAN access change refused; the previous state stays in force", "err", err)
			continue
		}
		s.log.Info("LAN access applied", "lan", string(s.state()))
	}
}

// state returns the LAN state in force.
func (s *lanSwitch) state() install.LAN {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lan
}

// startDaemonLAN is the node daemon's LAN switch: it reads the record, takes
// SIGHUP (so the signal never terminates the daemon), writes the applied file
// for the state it starts in, and applies the record on every SIGHUP until
// ctx ends. workDir is the daemon's own work dir, where the applied file goes.
func startDaemonLAN(ctx context.Context, workDir string, log *slog.Logger) *lanSwitch {
	s := newLANSwitch(install.DefaultNetworkRecordPath, filepath.Join(workDir, install.NetworkAppliedName), log)
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	s.mu.Lock()
	s.report(s.serial, nil)
	s.mu.Unlock()
	log.Info("LAN access", "lan", string(s.lan), "record", s.recordPath)
	go func() {
		defer signal.Stop(hup)
		s.watch(ctx, hup)
	}()
	return s
}

// proxyLANFamily moves the Service proxy's NodePort listeners.
type proxyLANFamily struct{ srv *netserve.Server }

func (proxyLANFamily) name() string { return install.LANFamilyNodePorts }

func (f proxyLANFamily) prepare(_ context.Context, sets lanSets) (lanStep, error) {
	sw, err := f.srv.PrepareNodePortAddresses(sets.nodePorts...)
	if err != nil {
		return lanStep{}, err
	}
	return lanStep{commit: sw.Commit, abort: func() { _ = sw.Abort() }}, nil
}

// hosterLANFamily moves the svclb hoster's LoadBalancer listeners.
type hosterLANFamily struct{ h *svclb.Hoster }

func (hosterLANFamily) name() string { return install.LANFamilyLoadBalancers }

func (f hosterLANFamily) prepare(ctx context.Context, sets lanSets) (lanStep, error) {
	rb, err := f.h.PrepareBindAddrs(ctx, sets.listeners)
	if errors.Is(err, svclb.ErrHosterStopped) {
		// A hoster that is no longer running holds no listener to move.
		return lanStep{commit: func() error { return nil }, abort: func() {}}, nil
	}
	if err != nil {
		return lanStep{}, err
	}
	return lanStep{commit: rb.Commit, abort: func() { _ = rb.Abort() }}, nil
}

// ingressLANFamily moves the ingress host's HTTP/HTTPS listeners.
type ingressLANFamily struct{ h *ingresshost.Host }

func (ingressLANFamily) name() string { return install.LANFamilyIngress }

func (f ingressLANFamily) prepare(ctx context.Context, sets lanSets) (lanStep, error) {
	rb, err := f.h.PrepareBindAddrs(ctx, sets.listeners)
	if err != nil {
		return lanStep{}, err
	}
	return lanStep{commit: func() error { rb.Commit(); return nil }, abort: rb.Abort}, nil
}

package executor

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync"
	"syscall"
	"time"

	"crypto/tls"
)

// kcmDisabledControllers are the node-side controllers k3sm DROPS because they
// assume real Linux kubelets / cloud providers and would fight the Virtual
// Kubelet node or churn against absent infrastructure. Names match k8s v1.36.2's
// "-controller" suffix convention (kube-controller-manager --help → "All
// controllers").
//
// The --controllers value is rendered as "*,-<each>" — enable every
// on-by-default controller, then disable just these. That is robust across kube
// versions (no brittle allow-list to keep in sync) AND keeps the
// endpointslice-controller ON, which M1.4's Service proxy reconciles off.
var kcmDisabledControllers = []string{
	"persistentvolume-attach-detach-controller", // attach-detach: no real volumes to (de)attach
	"cloud-node-lifecycle-controller",           // cloud provider lifecycle: not a cloud node
	"node-route-controller",                     // route: no cloud routes
	"service-lb-controller",                     // service load-balancer: no cloud LB
	"node-ipam-controller",                      // nodeipam: podCIDR is assigned by darwin-net, not here
}

// healthTimeout bounds how long Start waits for the apiserver to report healthz.
const healthTimeout = 90 * time.Second

// drainGrace is how long Stop waits for a component to exit after SIGTERM before
// escalating to SIGKILL.
const drainGrace = 5 * time.Second

// component is one supervised control-plane child process.
type component struct {
	name string
	cmd  *exec.Cmd
	log  *os.File
}

// Supervised is the child-process control-plane executor: it os/exec-supervises
// kine, the apiserver, the scheduler, and the controller-manager as child
// processes, each in its own process group for clean teardown.
//
// Concurrency: mu guards comps + started. The components run until Stop, which
// tears them down in reverse dependency order. No Context is stored.
type Supervised struct {
	cfg    Config
	client *http.Client

	mu      sync.Mutex
	comps   []*component // in start order; Stop walks it in reverse
	started bool
	token   string
}

// NewSupervised returns a Supervised executor for cfg, filling defaults.
func NewSupervised(cfg Config) *Supervised {
	cfg = cfg.withDefaults()
	return &Supervised{
		cfg:   cfg,
		token: cfg.Token,
		// The apiserver self-signs its serving cert in M1; skip verification on the
		// loopback healthz probe (the kubeconfig does the same).
		client: &http.Client{
			Timeout:   3 * time.Second,
			Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
		},
	}
}

// Compile-time check that Supervised satisfies the Executor contract.
var _ Executor = (*Supervised)(nil)

// Kubeconfig returns the admin kubeconfig path.
func (s *Supervised) Kubeconfig() string { return kubeconfigPath(s.cfg.WorkDir) }

// RESTConfigToken returns the apiserver URL and static token.
func (s *Supervised) RESTConfigToken() (string, string) {
	return apiServerURL(s.cfg.APIServerPort), s.token
}

// Start provisions the workdir (binaries, kine, SA keys, token, kubeconfig),
// then brings the control plane up in dependency order (kine → apiserver →
// scheduler → controller-manager) and blocks until the apiserver reports healthz
// ok. On any failure it tears down whatever started.
func (s *Supervised) Start(ctx context.Context) error {
	s.mu.Lock()
	if s.started {
		s.mu.Unlock()
		return nil
	}
	s.mu.Unlock()

	if s.token == "" {
		tok, err := generateToken()
		if err != nil {
			return err
		}
		s.token = tok
	}

	if err := s.provision(ctx); err != nil {
		return err
	}

	if err := s.bringUp(ctx); err != nil {
		_ = s.Stop(context.WithoutCancel(ctx))
		return err
	}

	s.mu.Lock()
	s.started = true
	s.mu.Unlock()
	return nil
}

// provision lays down everything the components need on disk.
func (s *Supervised) provision(ctx context.Context) error {
	if err := ensureWorkDirs(s.cfg.WorkDir); err != nil {
		return err
	}
	if err := ensureControlPlaneBinaries(ctx, s.cfg.WorkDir, s.cfg.KubeVersion); err != nil {
		return err
	}
	if err := ensureKine(ctx, s.cfg.WorkDir, s.cfg.KineVersion); err != nil {
		return err
	}
	if err := writeServiceAccountKeys(ctx, s.cfg.WorkDir); err != nil {
		return err
	}
	if err := writeTokenFile(s.cfg.WorkDir, s.token); err != nil {
		return err
	}
	if err := writeKubeconfig(s.cfg.WorkDir, s.cfg.APIServerPort, s.token); err != nil {
		return err
	}
	return nil
}

// bringUp starts the components in order and waits for the apiserver to be
// healthy before starting scheduler + controller-manager.
func (s *Supervised) bringUp(ctx context.Context) error {
	if err := s.startKine(ctx); err != nil {
		return fmt.Errorf("start kine: %w", err)
	}
	if err := waitTCP(ctx, s.cfg.KinePort, 30*time.Second); err != nil {
		return fmt.Errorf("kine not listening: %w", err)
	}
	if err := s.startAPIServer(ctx); err != nil {
		return fmt.Errorf("start apiserver: %w", err)
	}
	if err := s.waitHealthz(ctx); err != nil {
		return fmt.Errorf("apiserver not healthy: %w", err)
	}
	if err := s.startScheduler(ctx); err != nil {
		return fmt.Errorf("start scheduler: %w", err)
	}
	if err := s.startControllerManager(ctx); err != nil {
		return fmt.Errorf("start controller-manager: %w", err)
	}
	return nil
}

// startKine launches the kine etcd shim over the workdir SQLite DB (WAL).
func (s *Supervised) startKine(ctx context.Context) error {
	endpoint := "sqlite://" + filepath.Join(dbDir(s.cfg.WorkDir), "state.db") + "?_journal=WAL&_busy_timeout=30000"
	return s.spawn(ctx, "kine",
		"--listen-address", "127.0.0.1:"+strconv.Itoa(s.cfg.KinePort),
		"--endpoint", endpoint,
	)
}

// startAPIServer launches kube-apiserver against kine on the secure port. It
// keeps the spike's AlwaysAllow + static-token posture (so the M0 node still
// registers) and sets --kubelet-preferred-address-types=InternalIP so kubectl
// logs/exec reach the node by IP (closing the M0.3 gap).
//
// NOTE: the DESIGN's --feature-gates=ConsistentListFromCache=false (the kine#577
// watch-staleness mitigation) is NOT passed: in the pinned kwok-ci/k8s build
// (k8s v1.36.2) that gate is GA-LOCKED to true and the apiserver refuses to
// start if it is set false ("feature is locked to true"). It is left at its
// locked default; the soak is revisited if k3sm ever pins a kube version where
// the gate is still settable.
func (s *Supervised) startAPIServer(ctx context.Context) error {
	wd := s.cfg.WorkDir
	return s.spawn(ctx, "kube-apiserver",
		"--etcd-servers", "http://127.0.0.1:"+strconv.Itoa(s.cfg.KinePort),
		"--service-cluster-ip-range", "10.43.0.0/16",
		"--service-account-key-file", saPubPath(wd),
		"--service-account-signing-key-file", saKeyPath(wd),
		"--service-account-issuer", "https://kubernetes.default.svc.cluster.local",
		"--token-auth-file", tokenFilePath(wd),
		"--authorization-mode", "AlwaysAllow",
		"--bind-address", "127.0.0.1",
		"--advertise-address", s.cfg.NodeIP,
		"--secure-port", strconv.Itoa(s.cfg.APIServerPort),
		"--cert-dir", certDir(wd),
		"--kubelet-preferred-address-types", "InternalIP",
		"--allow-privileged",
	)
}

// startScheduler launches kube-scheduler against the admin kubeconfig.
func (s *Supervised) startScheduler(ctx context.Context) error {
	kc := kubeconfigPath(s.cfg.WorkDir)
	return s.spawn(ctx, "kube-scheduler",
		"--kubeconfig", kc,
		"--authentication-kubeconfig", kc,
		"--authorization-kubeconfig", kc,
		"--leader-elect=false",
		"--bind-address", "127.0.0.1",
		"--secure-port", "10259",
	)
}

// startControllerManager launches kube-controller-manager with the SCOPED
// controller set (node-side controllers dropped; endpointslice kept).
func (s *Supervised) startControllerManager(ctx context.Context) error {
	wd := s.cfg.WorkDir
	kc := kubeconfigPath(wd)
	args := []string{
		"--kubeconfig", kc,
		"--authentication-kubeconfig", kc,
		"--authorization-kubeconfig", kc,
		"--leader-elect=false",
		"--service-account-private-key-file", saKeyPath(wd),
		"--root-ca-file", filepath.Join(certDir(wd), "apiserver.crt"),
		"--bind-address", "127.0.0.1",
		"--secure-port", "10257",
		"--controllers", controllersFlag(),
	}
	return s.spawn(ctx, "kube-controller-manager", args...)
}

// controllersFlag renders the scoped --controllers value: "*" (all on-by-default
// controllers) followed by "-<name>" for each dropped node-side controller.
func controllersFlag() string {
	out := "*"
	for _, c := range kcmDisabledControllers {
		out += ",-" + c
	}
	return out
}

// spawn starts a control-plane binary from the workdir bin as a child process in
// its own process group, redirecting its output to a per-component log file, and
// records it for teardown. It does NOT wait — components run until Stop.
func (s *Supervised) spawn(ctx context.Context, name string, args ...string) error {
	bin := filepath.Join(binDir(s.cfg.WorkDir), name)
	logPath := filepath.Join(s.cfg.WorkDir, name+".log")
	lf, err := os.Create(logPath)
	if err != nil {
		return fmt.Errorf("create %s log: %w", name, err)
	}
	cmd := exec.Command(bin, args...)
	cmd.Stdout, cmd.Stderr = lf, lf
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		_ = lf.Close()
		return fmt.Errorf("start %s: %w", name, err)
	}
	s.cfg.Logger.Info("started control-plane component", "component", name, "pid", cmd.Process.Pid, "log", logPath)

	s.mu.Lock()
	s.comps = append(s.comps, &component{name: name, cmd: cmd, log: lf})
	s.mu.Unlock()
	return nil
}

// waitHealthz polls the apiserver /healthz endpoint until it returns ok or the
// timeout/ctx elapses.
func (s *Supervised) waitHealthz(ctx context.Context) error {
	deadline := time.Now().Add(healthTimeout)
	for {
		if s.Ready(ctx) {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("healthz not ok within %s", healthTimeout)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(500 * time.Millisecond):
		}
	}
}

// Ready reports whether the apiserver /healthz returns "ok".
func (s *Supervised) Ready(ctx context.Context) bool {
	url := apiServerURL(s.cfg.APIServerPort) + "/healthz"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return false
	}
	req.Header.Set("Authorization", "Bearer "+s.token)
	resp, err := s.client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	buf := make([]byte, 2)
	n, _ := resp.Body.Read(buf)
	return resp.StatusCode == http.StatusOK && string(buf[:n]) == "ok"
}

// Stop tears the control plane down in REVERSE dependency order: the components
// were appended in start order (kine, apiserver, scheduler, controller-manager),
// so walking the slice in reverse stops the apiserver and the controllers first
// and kine LAST, after which the SQLite DB is no longer in use. Idempotent.
func (s *Supervised) Stop(ctx context.Context) error {
	s.mu.Lock()
	comps := s.comps
	s.comps = nil
	s.started = false
	s.mu.Unlock()

	// Reverse start order = correct shutdown order, but kine (index 0) must die
	// LAST. Build the explicit order: apiserver, scheduler, controller-manager,
	// then kine.
	for _, c := range shutdownOrder(comps) {
		s.stopComponent(c)
	}
	return nil
}

// shutdownOrder returns comps ordered for a clean teardown: the apiserver drains
// FIRST (it stops writing), then scheduler + controller-manager, then kine LAST
// (so no component loses its datastore mid-shutdown). Components arrive in start
// order [kine, apiserver, scheduler, controller-manager]; this pulls kine to the
// end and keeps the rest in start order (apiserver before the controllers).
func shutdownOrder(comps []*component) []*component {
	var kine *component
	out := make([]*component, 0, len(comps))
	for _, c := range comps {
		if c.name == "kine" {
			kine = c
			continue
		}
		out = append(out, c)
	}
	if kine != nil {
		out = append(out, kine)
	}
	return out
}

// stopComponent SIGTERMs a component's process group, waits drainGrace, then
// SIGKILLs if it has not exited, and closes its log file.
func (s *Supervised) stopComponent(c *component) {
	if c == nil || c.cmd == nil || c.cmd.Process == nil {
		return
	}
	pid := c.cmd.Process.Pid
	_ = syscall.Kill(-pid, syscall.SIGTERM)

	done := make(chan struct{})
	go func() { _, _ = c.cmd.Process.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(drainGrace):
		_ = syscall.Kill(-pid, syscall.SIGKILL)
		<-done
	}
	if c.log != nil {
		_ = c.log.Close()
	}
	s.cfg.Logger.Info("stopped control-plane component", "component", c.name)
}

// waitTCP blocks until 127.0.0.1:port accepts a connection or the timeout/ctx
// elapses.
func waitTCP(ctx context.Context, port int, timeout time.Duration) error {
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	deadline := time.Now().Add(timeout)
	d := &net.Dialer{Timeout: time.Second}
	for {
		conn, err := d.DialContext(ctx, "tcp", addr)
		if err == nil {
			_ = conn.Close()
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("%s not accepting connections within %s", addr, timeout)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(300 * time.Millisecond):
		}
	}
}

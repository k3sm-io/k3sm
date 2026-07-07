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

package ingresshost

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"sync/atomic"
	"time"

	"golang.org/x/sync/errgroup"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"k3sm.io/darwin-net/pkg/ingress"
	"k3sm.io/darwin-net/pkg/netbind"

	"k3sm.io/k3sm/pkg/svclb"
)

const (
	// ClassName is the k3sm IngressClass; the Watcher reconciles ONLY Ingresses
	// whose spec.ingressClassName names it.
	ClassName = "k3sm"
	// ControllerName is the IngressClass spec.controller identifying this host.
	ControllerName = "k3sm.io/ingress"
	// ServiceNamespace/ServiceName locate the canonical ingress LoadBalancer
	// Service — the DECLARING SUBJECT the netd port authorizer confirms a
	// privileged node-address 80/443 bind against (netdsvc.PortPolicy).
	ServiceNamespace = "kube-system"
	// ServiceName is the canonical ingress LoadBalancer Service name.
	ServiceName = "k3sm-ingress"
)

// httpPortDefault / httpsPortDefault are the production listener ports — the
// ports the canonical LoadBalancer Service declares. Any other configured pair
// is the explicit high-port mode (integration tier): served, but never
// advertised on the LB Service status (it would claim 80/443 reachability).
const (
	httpPortDefault  = 80
	httpsPortDefault = 443
)

// bindRetrySchedule bounds the ErrBind retry (the SRE posture): the netd
// helper or the node address may not be ready at bring-up, so a bind failure
// is non-fatal to the server and retried — boundedly, and NEVER by silently
// falling back to different ports. After the last attempt the ingress is
// loudly disabled until the server restarts.
var bindRetrySchedule = []time.Duration{5 * time.Second, 10 * time.Second, 20 * time.Second, 40 * time.Second, 80 * time.Second}

// Config configures the in-process ingress Host.
type Config struct {
	// Client is the server's in-process ADMIN client: it feeds the Watcher, the
	// targeted TLS-Secret fetches, and the status writes. Keys fetched under it
	// only ever live in the control-plane process (no RBAC widening).
	Client kubernetes.Interface
	// NodeIP is the SPECIFIC node InternalIP the listeners bind (never a
	// wildcard) and the address written into Ingress/LB statuses.
	NodeIP netip.Addr
	// HTTPPort / HTTPSPort are the listener ports; 0 disables that listener.
	// 80/443 is the production posture (netd-authorized via the canonical LB
	// Service); anything else is the EXPLICIT high-port mode — a config choice,
	// never a fallback.
	HTTPPort  uint16
	HTTPSPort uint16
	// Binder opens the listeners: netbind.Netd in the unprivileged helper
	// posture, nil for netbind.Direct (run-as-root, tests).
	Binder netbind.Binder
	// Logger is the structured log sink; nil means slog.Default.
	Logger *slog.Logger
}

// Host assembles and runs the server-process ingress: RouteTable + CertStore +
// class-filtered Watcher + Server, the k3sm IngressClass + canonical LB
// Service provisioning, and the single auditable status writer.
type Host struct {
	cfg   Config
	log   *slog.Logger
	table *ingress.RouteTable
	certs *ingress.CertStore

	// serving reports whether every enabled listener of the CURRENT run attempt
	// is bound; statuses are advertised only while it is true (bind-then-
	// advertise — never a dead address). boundCount counts the attempt's binds.
	serving    atomic.Bool
	boundCount atomic.Int32
	// statusKick coalesces status-sync triggers (reconcile events + listener
	// transitions). Buffered 1; sends are non-blocking.
	statusKick chan struct{}
}

// New validates cfg and builds the Host. It starts nothing; call Run.
func New(cfg Config) (*Host, error) {
	if cfg.Client == nil {
		return nil, errors.New("ingresshost: config requires a client")
	}
	if !cfg.NodeIP.IsValid() || cfg.NodeIP.IsUnspecified() {
		return nil, fmt.Errorf("ingresshost: config requires a specific node address, got %q", cfg.NodeIP)
	}
	if cfg.HTTPPort == 0 && cfg.HTTPSPort == 0 {
		return nil, errors.New("ingresshost: config enables no listener (both ports zero)")
	}
	log := cfg.Logger
	if log == nil {
		log = slog.Default()
	}
	return &Host{
		cfg:        cfg,
		log:        log,
		table:      ingress.NewRouteTable(),
		certs:      ingress.NewCertStore(),
		statusKick: make(chan struct{}, 1),
	}, nil
}

// Run provisions the IngressClass + canonical LB Service (idempotent,
// log-and-continue like the sibling policy provisioners) and hosts the
// Watcher, the status writer, and the listener serve-loop until ctx is
// cancelled. It returns nil on clean shutdown.
func (h *Host) Run(ctx context.Context) error {
	if err := h.ensureIngressClass(ctx); err != nil {
		h.log.Error("provision k3sm ingressclass", "err", err)
	}
	if err := h.ensureLBService(ctx); err != nil {
		h.log.Error("provision canonical ingress loadbalancer service", "err", err)
	}

	g, gctx := errgroup.WithContext(ctx)
	// The Watcher surfaces tls[] Secret NAMES after every reconcile; the host
	// fetches + installs them (see installCertificates) and re-syncs statuses.
	// The callback runs outside the watcher's lock, so the synchronous fetch is
	// safe (darwin-net's documented contract).
	watcher := ingress.NewWatcher(h.cfg.Client, h.table, ingress.WatcherConfig{
		ClassName: ClassName,
		OnTLSSecrets: func(refs []ingress.SecretRef) {
			h.installCertificates(gctx, refs)
			h.kickStatus()
		},
	}, h.log)
	g.Go(func() error { return watcher.Run(gctx) })
	g.Go(func() error { h.statusLoop(gctx); return nil })
	g.Go(func() error { h.serveLoop(gctx); return nil })

	err := g.Wait()
	if ctx.Err() != nil {
		return nil // clean shutdown
	}
	return err
}

// binder returns the configured binder, defaulting to the direct in-process
// bind (run-as-root, tests).
func (h *Host) binder() netbind.Binder {
	if h.cfg.Binder != nil {
		return h.cfg.Binder
	}
	return netbind.Direct{}
}

// listenerCount is the number of enabled listeners (New rejects zero).
func (h *Host) listenerCount() int {
	n := 0
	if h.cfg.HTTPPort != 0 {
		n++
	}
	if h.cfg.HTTPSPort != 0 {
		n++
	}
	return n
}

// countingBinder wraps the configured binder so the Host observes successful
// binds: once every enabled listener of the current run attempt is bound, the
// Host flips serving=true and kicks the status writer (bind-then-advertise —
// the status IP is only ever written for live listeners).
type countingBinder struct{ h *Host }

// Listen binds through the Host's binder and counts the success.
func (b countingBinder) Listen(ctx context.Context, network string, addr netip.AddrPort) (net.Listener, error) {
	ln, err := b.h.binder().Listen(ctx, network, addr)
	if err != nil {
		return nil, err
	}
	if int(b.h.boundCount.Add(1)) >= b.h.listenerCount() {
		b.h.serving.Store(true)
		b.h.kickStatus()
	}
	return ln, nil
}

// serveLoop runs the ingress Server, retrying a bind failure on the bounded
// schedule. A bind failure is NON-FATAL to the server process: the helper may
// be absent or the LB-Service authorization not yet visible to netd — but
// there is NO silent port fallback; exhausted retries disable the ingress
// loudly until restart.
func (h *Host) serveLoop(ctx context.Context) {
	srv, err := ingress.NewServer(h.table, ingress.Config{
		Addr:      h.cfg.NodeIP,
		HTTPPort:  h.cfg.HTTPPort,
		HTTPSPort: h.cfg.HTTPSPort,
		Binder:    countingBinder{h: h},
		Certs:     h.certs,
		Logger:    h.log,
	})
	if err != nil {
		h.log.Error("ingress server construction (misconfiguration, not retried)", "err", err)
		return
	}
	for attempt := 0; ; {
		h.boundCount.Store(0)
		err := srv.Run(ctx)
		h.serving.Store(false)
		if ctx.Err() != nil {
			return
		}
		if !errors.Is(err, ingress.ErrBind) {
			h.log.Error("ingress server stopped", "err", err)
			return
		}
		if attempt >= len(bindRetrySchedule) {
			h.log.Error("ingress bind retries exhausted; ingress listeners DISABLED until the server restarts (no port fallback — check the netd helper and the k3sm-ingress LoadBalancer authorization)", "err", err)
			return
		}
		delay := bindRetrySchedule[attempt]
		attempt++
		h.log.Error("ingress listener bind failed; retrying", "attempt", attempt, "retry-in", delay, "err", err)
		select {
		case <-ctx.Done():
			return
		case <-time.After(delay):
		}
	}
}

// installCertificates enforces the M10.3 TLS-Secret discipline
// (SECURITY-BINDING):
//
//   - every referenced Secret is fetched BY NAME via a targeted
//     Secrets(ns).Get — deliberately NO Secret informer/lister (the
//     pkg/provider resolver.go imagePullSecret precedent), so this process
//     never holds a cache of the cluster's Secrets, only the ones an Ingress
//     tls[] block names;
//   - a Secret whose type is not kubernetes.io/tls is REJECTED (logged by
//     name, skipped);
//   - parsing is IN MEMORY ONLY via ingress.ParseKeyPair — no temp files, and
//     its errors carry the secret NAME, never certificate or key bytes;
//   - SetCertificates atomically replaces the WHOLE snapshot, and this runs on
//     every reconcile callback — so rotation is an event-driven re-read.
//
// NOTHING here (or downstream of it) may ever write key bytes to disk, logs,
// or object status: keys live exclusively in the in-process CertStore.
func (h *Host) installCertificates(ctx context.Context, refs []ingress.SecretRef) {
	certs := make(map[string]*tls.Certificate, len(refs))
	for _, ref := range refs {
		name := ref.Namespace + "/" + ref.Name
		s, err := h.cfg.Client.CoreV1().Secrets(ref.Namespace).Get(ctx, ref.Name, metav1.GetOptions{})
		if err != nil {
			h.log.Warn("ingress tls secret fetch failed; its hosts stay unserved", "secret", name, "err", err)
			continue
		}
		if s.Type != corev1.SecretTypeTLS {
			h.log.Warn("ingress tls secret rejected: type is not kubernetes.io/tls", "secret", name, "type", string(s.Type))
			continue
		}
		cert, err := ingress.ParseKeyPair(name, s.Data[corev1.TLSCertKey], s.Data[corev1.TLSPrivateKeyKey])
		if err != nil {
			// The error names the secret and echoes NO key material (ParseKeyPair's
			// contract) — safe to log.
			h.log.Warn("ingress tls secret parse failed; its hosts stay unserved", "err", err)
			continue
		}
		if len(ref.Hosts) == 0 {
			h.log.Debug("ingress tls secret has no hosts in its tls[] entry; skipped (SNI-keyed store)", "secret", name)
			continue
		}
		for _, host := range ref.Hosts {
			certs[host] = cert
		}
	}
	h.certs.SetCertificates(certs)
}

// ensureIngressClass idempotently provisions the k3sm IngressClass
// (controller k3sm.io/ingress). Create-if-absent: AlreadyExists is success.
func (h *Host) ensureIngressClass(ctx context.Context) error {
	ic := &networkingv1.IngressClass{
		ObjectMeta: metav1.ObjectMeta{
			Name:   ClassName,
			Labels: map[string]string{"k3sm.io/managed": "true"},
		},
		Spec: networkingv1.IngressClassSpec{Controller: ControllerName},
	}
	if _, err := h.cfg.Client.NetworkingV1().IngressClasses().Create(ctx, ic, metav1.CreateOptions{}); err != nil && !apierrors.IsAlreadyExists(err) {
		return fmt.Errorf("create ingressclass %s: %w", ClassName, err)
	}
	return nil
}

// ensureLBService idempotently provisions kube-system/k3sm-ingress: the
// canonical type=LoadBalancer Service declaring ports 80+443 — the DECLARING
// SUBJECT the netd port authorizer confirms the privileged node-address bind
// against (an explicit policy chain, never allowed-by-coincidence). It has NO
// selector: the in-process ingress Server IS the implementation. It carries
// svclb.IgnoreLabel so the svclb controller neither races the ingress' own
// listeners for 80/443 nor splices them to a backendless ClusterIP; this host
// writes its status instead (only when actually serving 80/443).
func (h *Host) ensureLBService(ctx context.Context) error {
	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      ServiceName,
			Namespace: ServiceNamespace,
			Labels: map[string]string{
				"k3sm.io/managed": "true",
				svclb.IgnoreLabel: "true",
			},
		},
		Spec: corev1.ServiceSpec{
			Type: corev1.ServiceTypeLoadBalancer,
			Ports: []corev1.ServicePort{
				{Name: "http", Port: httpPortDefault, Protocol: corev1.ProtocolTCP},
				{Name: "https", Port: httpsPortDefault, Protocol: corev1.ProtocolTCP},
			},
		},
	}
	if _, err := h.cfg.Client.CoreV1().Services(ServiceNamespace).Create(ctx, svc, metav1.CreateOptions{}); err != nil && !apierrors.IsAlreadyExists(err) {
		return fmt.Errorf("create loadbalancer service %s/%s: %w", ServiceNamespace, ServiceName, err)
	}
	return nil
}

// kickStatus coalesces a status-sync trigger (non-blocking).
func (h *Host) kickStatus() {
	select {
	case h.statusKick <- struct{}{}:
	default:
	}
}

// statusLoop serializes status syncs behind the coalescing trigger.
func (h *Host) statusLoop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-h.statusKick:
		}
		h.syncStatus(ctx)
	}
}

// syncStatus writes status.loadBalancer.ingress = [{ip: nodeIP}] onto every
// Ingress of the k3sm class (own-class ONLY — a foreign or classless Ingress
// is never touched) and onto the canonical LB Service. It is the SINGLE
// auditable status author, and it writes only while the listeners are
// actually bound (h.serving — bind-then-advertise); the LB Service is
// additionally advertised only when the bound ports ARE the declared 80/443
// (the explicit high-port integration mode must not claim ports it does not
// serve).
func (h *Host) syncStatus(ctx context.Context) {
	if !h.serving.Load() {
		return
	}
	ip := h.cfg.NodeIP.String()
	ings, err := h.cfg.Client.NetworkingV1().Ingresses(metav1.NamespaceAll).List(ctx, metav1.ListOptions{})
	if err != nil {
		h.log.Warn("list ingresses for status sync", "err", err)
	} else {
		for i := range ings.Items {
			ing := &ings.Items[i]
			if ing.Spec.IngressClassName == nil || *ing.Spec.IngressClassName != ClassName {
				continue
			}
			if ingressStatusHas(ing, ip) {
				continue
			}
			upd := ing.DeepCopy()
			upd.Status.LoadBalancer.Ingress = []networkingv1.IngressLoadBalancerIngress{{IP: ip}}
			if _, err := h.cfg.Client.NetworkingV1().Ingresses(ing.Namespace).UpdateStatus(ctx, upd, metav1.UpdateOptions{}); err != nil {
				h.log.Warn("update ingress status", "ingress", ing.Namespace+"/"+ing.Name, "err", err)
			}
		}
	}

	if h.cfg.HTTPPort != httpPortDefault || h.cfg.HTTPSPort != httpsPortDefault {
		return // high-port mode: the 80/443-declaring LB Service status stays empty
	}
	svc, err := h.cfg.Client.CoreV1().Services(ServiceNamespace).Get(ctx, ServiceName, metav1.GetOptions{})
	if err != nil {
		h.log.Warn("get canonical ingress loadbalancer service for status sync", "err", err)
		return
	}
	for _, lbi := range svc.Status.LoadBalancer.Ingress {
		if lbi.IP == ip {
			return
		}
	}
	upd := svc.DeepCopy()
	upd.Status.LoadBalancer.Ingress = []corev1.LoadBalancerIngress{{IP: ip}}
	if _, err := h.cfg.Client.CoreV1().Services(ServiceNamespace).UpdateStatus(ctx, upd, metav1.UpdateOptions{}); err != nil {
		h.log.Warn("update canonical ingress loadbalancer service status", "err", err)
	}
}

// ingressStatusHas reports whether ing's LB status already carries ip.
func ingressStatusHas(ing *networkingv1.Ingress, ip string) bool {
	for _, lbi := range ing.Status.LoadBalancer.Ingress {
		if lbi.IP == ip {
			return true
		}
	}
	return false
}

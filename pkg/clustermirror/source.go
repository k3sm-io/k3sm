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

package clustermirror

import (
	"context"
	"log/slog"
	"sort"
	"strings"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"

	"k3sm.io/runtimed/pkg/image"

	"k3sm.io/k3sm/pkg/registrysvc"
)

// resyncPeriod is the informer's full re-list interval. It is long because the
// watch carries every real change; the re-list only repairs a cache that silently
// diverged, and the cost of a stale entry here is one refused dial on a peer that
// has gone away — which the puller already treats as "this mirror does not have
// it" and moves past.
const resyncPeriod = 10 * time.Minute

// advertisementLister is the slice of the informer cache Source reads, declared
// HERE at the consumer so this package depends on one method rather than on
// client-go's lister types. The generated ConfigMapNamespaceLister satisfies it,
// and a test satisfies it with a slice.
type advertisementLister interface {
	List(selector labels.Selector) ([]*corev1.ConfigMap, error)
}

// Source is the k3sm-side implementation of runtimed's cluster-mirror seam. The
// assertion is here so a change to that interface fails THIS package's build
// rather than silently leaving the node with no mirrors at runtime.
var _ image.MirrorSource = (*Source)(nil)

// Config configures a Source.
type Config struct {
	// NodeName is THIS node. Its own advertisement is never returned as a mirror:
	// falling back from a node's registry to the same registry is a second
	// request for the answer it just gave.
	NodeName string
	// Client is the apiserver client the advertisements are watched with.
	Client kubernetes.Interface
	// Logger receives sync and skip events. nil discards.
	Logger *slog.Logger
}

// Source resolves this node's cluster-mirror candidates from the per-node
// registry advertisements. It implements runtimed's image.MirrorSource.
//
// The zero value is not usable — construct one with New.
type Source struct {
	node string
	log  *slog.Logger
	cs   kubernetes.Interface

	// mu guards the two fields below. It is a read/write lock because Mirrors is
	// on the pull path and Start writes once: readers must never serialize behind
	// each other, and neither may observe a lister without the sync verdict that
	// makes it meaningful.
	mu     sync.RWMutex
	lister advertisementLister
	synced bool
}

// New returns a Source. It performs no I/O: the watch starts at Start.
func New(cfg Config) *Source {
	log := cfg.Logger
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &Source{node: cfg.NodeName, log: log, cs: cfg.Client}
}

// Start begins watching the advertisements and returns IMMEDIATELY.
//
// It does not block on the initial cache sync, and that is the contract rather
// than an optimisation: this runs during node bring-up, ahead of the first Pod,
// and a node that waited on an apiserver round trip to learn about mirrors it may
// never need would be trading pod-scheduling latency for a fallback path. Until
// the cache syncs, Mirrors reports no candidates — which is the single-node
// behavior, not a degraded one.
//
// It NEVER FAILS. A nil client, an unsynced cache, or an apiserver that refuses
// the watch all leave a Source that answers "no candidates" forever; none of them
// can fail a pull that would otherwise have worked, because a pull that reaches
// the fallback has already failed against its own registry.
//
// The watch stops when ctx is done.
func (s *Source) Start(ctx context.Context) {
	if s.cs == nil {
		s.log.Debug("cluster image mirrors disabled: this node has no apiserver client")
		return
	}
	factory := informers.NewSharedInformerFactoryWithOptions(s.cs, resyncPeriod,
		informers.WithNamespace(registrysvc.AdvertisementNamespace))
	informer := factory.Core().V1().ConfigMaps()
	// A watch this node is not permitted to make is the one failure worth naming
	// in the log rather than leaving as a silent absence of mirrors: the reflector
	// retries forever, so without this the operator sees an image that will not
	// pull and no reason anywhere. Reported ONCE — the retry is unbounded, and a
	// per-attempt line would bury the log it is supposed to inform.
	var once sync.Once
	if err := informer.Informer().SetWatchErrorHandlerWithContext(
		func(_ context.Context, _ *cache.Reflector, err error) {
			once.Do(func() {
				s.log.Warn("cannot watch the cluster's node registry advertisements, so this node will not fall back to a peer's registry (pods pulling from public registries are unaffected)",
					"namespace", registrysvc.AdvertisementNamespace, "err", err)
			})
		}); err != nil {
		s.log.Warn("cluster image mirrors: install the watch error handler", "err", err)
	}

	lister := informer.Lister().ConfigMaps(registrysvc.AdvertisementNamespace)
	factory.Start(ctx.Done())

	s.mu.Lock()
	s.lister = lister
	s.mu.Unlock()

	go func() {
		if !cache.WaitForCacheSync(ctx.Done(), informer.Informer().HasSynced) {
			return // ctx ended, or the watch never came up; either way, no candidates
		}
		s.mu.Lock()
		s.synced = true
		s.mu.Unlock()
		s.log.Info("watching the cluster's node registry advertisements for image mirrors",
			"namespace", registrysvc.AdvertisementNamespace, "node", s.node)
	}()
}

// Mirrors returns every OTHER node's ingest registry, ordered by node name.
//
// ref is ignored, and that is a truthful answer rather than an unimplemented
// one: a node advertises its registry, not an inventory of what is in it, so
// every candidate is a candidate for every reference. The puller has already
// established that the reference is node-relative and that its own registry
// missed before it asks — see runtimed/pkg/image's mirrorCandidates.
//
// The order is by PEER NODE NAME, so the candidate list is stable across pulls
// and across nodes. Any order would be correct (the puller tries them in turn and
// each is digest-verified), but an unstable one makes a failure that depends on
// which peer answered impossible to reproduce.
//
// A malformed advertisement SKIPS that peer and never fails the call: one node
// writing nonsense must not cost every other node its mirror.
func (s *Source) Mirrors(string) []image.Mirror {
	s.mu.RLock()
	lister, synced := s.lister, s.synced
	s.mu.RUnlock()
	if lister == nil || !synced {
		return nil
	}
	cms, err := lister.List(labels.Everything())
	if err != nil {
		// A read from a synced informer cache does not do I/O, so this is not a
		// transient apiserver fault; log it and answer with no candidates.
		s.log.Warn("listing the cluster's node registry advertisements", "err", err)
		return nil
	}
	peers := make([]registrysvc.Peer, 0, len(cms))
	for _, cm := range cms {
		if cm == nil || !isAdvertisement(cm.Name) {
			continue
		}
		p, perr := registrysvc.ParseAdvertisement(cm)
		if perr != nil {
			s.log.Warn("skipping a malformed node registry advertisement", "configmap", cm.Name, "err", perr)
			continue
		}
		if p.Node == s.node {
			continue // this node's own registry is the one that just missed
		}
		peers = append(peers, p)
	}
	sort.Slice(peers, func(i, j int) bool { return peers[i].Node < peers[j].Node })
	out := make([]image.Mirror, 0, len(peers))
	for _, p := range peers {
		out = append(out, image.Mirror{Host: p.MeshHost, PlainHTTP: p.PlainHTTP})
	}
	return out
}

// isAdvertisement reports whether a ConfigMap name is in the advertisement set.
// The namespace is shared with the KEP-1755 hosting document and with whatever
// else a cluster puts in a world-readable namespace, so the prefix is the
// membership test — and ParseAdvertisement re-checks it, because a reader that
// trusted the name alone would accept any object an operator named to look like
// one.
func isAdvertisement(name string) bool {
	return strings.HasPrefix(name, registrysvc.AdvertisementPrefix)
}

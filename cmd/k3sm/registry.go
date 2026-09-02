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
	"log/slog"
	"time"

	"k3sm.io/k3sm/pkg/registrysvc"
)

// registryShutdownGrace bounds the ingest registry's teardown. It is shorter than
// the control plane's 30s because the registry holds no datastore and has nothing
// to drain — the only thing worth waiting for is the port coming free.
const registryShutdownGrace = 10 * time.Second

// registryService is the lifetime seam `k3sm server` drives the node-local ingest
// registry through.
//
// It is declared HERE, at the consumer, and not in pkg/registrysvc: what the
// server needs is three methods, and an interface owned by the caller is what
// lets this file's wiring be tested — start ordering, the never-fatal contract,
// the KEP-1755 publish, the teardown — without a zot binary, a Go toolchain, or a
// bound port anywhere in the test.
type registryService interface {
	Start(ctx context.Context) error
	Addr() string
	Shutdown(ctx context.Context) error
}

// registryConfig renders the ingest registry's configuration from the parsed
// server flags. It is PURE, so the flag-to-config mapping — most of all "0 means
// disabled", which is checked by the caller, and the payload dir a packaged
// install seeds the binary from — is assertable without a bring-up.
func registryConfig(opts serverOptions, payloadBinDir string, logger *slog.Logger) registrysvc.Config {
	return registrysvc.Config{
		WorkDir:       opts.workDir,
		PayloadBinDir: payloadBinDir,
		Port:          opts.registryPort,
		Logger:        logger,
	}
}

// startIngestRegistry brings the registry up and publishes the KEP-1755 discovery
// ConfigMap, and returns the teardown closure the caller defers. The closure is
// never nil, so the caller's `defer stop()` is unconditional.
//
// NOTHING HERE IS FATAL. A registry that cannot build, bind or serve leaves a
// cluster that cannot ingest images; a bring-up that aborted over it leaves a
// cluster that does nothing at all. This is the same log-and-continue posture the
// ingress listeners and svclb are started under, and the opposite of the
// fail-closed RBAC and MeshPeer-CRD steps, which decide whether there is a
// working control plane at all.
//
// The discovery ConfigMap is published only AFTER the registry is serving. A
// document naming a port nothing answers on is worse than no document: a reader
// that finds it stops looking and then fails at the push.
func startIngestRegistry(ctx context.Context, svc registryService, port int, cms registrysvc.ConfigMapClient, logger *slog.Logger) func() {
	if err := svc.Start(ctx); err != nil {
		logger.Error("ingest registry disabled", "err", err)
		return func() {}
	}
	if err := registrysvc.PublishHosting(ctx, cms, port); err != nil {
		// The registry is serving and pushes to it work; only the DISCOVERY of it
		// failed. Reporting and continuing keeps the working half working.
		logger.Error("publish the local-registry-hosting ConfigMap", "err", err,
			"namespace", registrysvc.HostingNamespace, "name", registrysvc.HostingConfigMapName)
	} else {
		logger.Info("published local-registry-hosting for discovery",
			"namespace", registrysvc.HostingNamespace, "name", registrysvc.HostingConfigMapName, "addr", svc.Addr())
	}
	return func() {
		// WithoutCancel: this runs from a defer during shutdown, when ctx is already
		// cancelled, and a teardown that inherited the cancellation would SIGKILL
		// the child immediately instead of letting it close its storage.
		stopCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), registryShutdownGrace)
		defer cancel()
		if err := svc.Shutdown(stopCtx); err != nil {
			logger.Error("ingest registry shutdown", "err", err)
		}
	}
}

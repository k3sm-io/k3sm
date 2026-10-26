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
	"errors"
	"fmt"
	"log/slog"
	"time"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"k3sm.io/k3sm/pkg/certs"
	"k3sm.io/k3sm/pkg/executor"
	"k3sm.io/k3sm/pkg/netserve"
	"k3sm.io/k3sm/pkg/nodecred"
	"k3sm.io/k3sm/pkg/registrysvc"
)

// serverRegistryGateAuth builds the push gate's three apiserver clients under
// the gate's own identity, or returns the zero GateAuth (every write refused,
// reads served) when that identity cannot be minted. The failure is logged here
// and never fatal: the registry's reads are worth keeping on a node whose gate
// cannot authorize anything.
func serverRegistryGateAuth(ctx context.Context, opts serverOptions, admin *rest.Config, logger *slog.Logger) registrysvc.GateAuth {
	cs, err := serverRegistryGateClient(ctx, opts, admin, logger)
	if err != nil {
		logger.Error("in-pod pushes to the ingest registry are disabled: the push gate has no apiserver identity", "err", err)
		return registrysvc.GateAuth{}
	}
	return registrysvc.GateAuth{
		Tokens:     cs.AuthenticationV1().TokenReviews(),
		Access:     cs.AuthorizationV1().SubjectAccessReviews(),
		Namespaces: cs.CoreV1().Namespaces(),
	}
}

// serverRegistryGateClient builds the client the push gate runs on: its
// registry-gate identity (certs.RegistryGateSubject(nodeName)), minted in memory
// from the signing CA on every boot and re-minted before it expires, exactly as
// serverNetserveClient does for the datapath. Its grant is pkg/rbac's
// k3sm:registry-gate role and nothing more.
func serverRegistryGateClient(ctx context.Context, opts serverOptions, admin *rest.Config, logger *slog.Logger) (kubernetes.Interface, error) {
	h, err := certs.EnsureHierarchy(opts.workDir, opts.role(), opts.posture())
	if err != nil {
		return nil, fmt.Errorf("load the CA hierarchy for the registry push gate's identity: %w", err)
	}
	cfg, err := serverRegistryGateRESTConfig(admin, h, opts.nodeName)
	if err != nil {
		return nil, err
	}
	if cn, notAfter, err := clientCertIdentity(cfg.CertData); err == nil {
		logger.Info("minted the registry push gate's identity (in memory, never written to disk)", "cn", cn, "groups", certs.RegistryGateGroup, "not_after", notAfter.UTC().Format(time.RFC3339))
	} else {
		return nil, fmt.Errorf("read back the registry push gate's identity: %w", err)
	}
	cred, err := netserve.NewRotatingCredential(cfg.CertData, cfg.KeyData, nil)
	if err != nil {
		return nil, fmt.Errorf("hold the registry push gate's identity: %w", err)
	}
	rot := &netserve.Rotator{
		Credential: cred,
		Margin:     nodecred.ExpiryMargin,
		Renew: func(context.Context) ([]byte, []byte, error) {
			return h.Signing.IssueRegistryGateClient(opts.nodeName, executor.ComponentCertValidity)
		},
		Logger: logger,
	}
	client, err := startNetserveClient(ctx, cred, rest.AnonymousClientConfig(cfg), rot)
	if err != nil {
		return nil, fmt.Errorf("build the registry push gate's client: %w", err)
	}
	return client, nil
}

// serverRegistryGateRESTConfig is serverNetserveRESTConfig for the push gate:
// the admin config's apiserver address and trust, none of its credentials, and
// the minted pair as the only one. The admin rate limiter is dropped so the
// gate's reviews do not share the admin client's budget. It fails closed on a hierarchy without a
// usable signing CA and never falls back to the admin identity.
func serverRegistryGateRESTConfig(admin *rest.Config, h *certs.Hierarchy, nodeName string) (*rest.Config, error) {
	if admin == nil {
		return nil, errors.New("mint the registry push gate's identity: no admin client config to take the apiserver address from")
	}
	if nodeName == "" {
		return nil, errors.New("mint the registry push gate's identity: empty node name")
	}
	if h == nil || h.Signing == nil || h.Signing.Cert == nil || h.Signing.Key == nil {
		return nil, errors.New("mint the registry push gate's identity: no usable signing CA (the work dir's PKI must carry the signing half of the CA hierarchy)")
	}
	certPEM, keyPEM, err := h.Signing.IssueRegistryGateClient(nodeName, executor.ComponentCertValidity)
	if err != nil {
		return nil, fmt.Errorf("mint the registry push gate's identity: %w", err)
	}
	cfg := rest.AnonymousClientConfig(admin)
	cfg.RateLimiter = nil
	cfg.TLSClientConfig.CertData = certPEM
	cfg.TLSClientConfig.KeyData = keyPEM
	return cfg, nil
}

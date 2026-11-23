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
	"log/slog"
	"os"
	"path/filepath"

	"k8s.io/client-go/kubernetes"

	"k3sm.io/k3sm/pkg/executor"
	"k3sm.io/k3sm/pkg/keystore"
	keydeliver "k3sm.io/k3sm/pkg/keystore/deliver"
)

// keystoreDeliveryIDs are the process facts the server's keystore identity is
// taken from, so a test can fake them.
type keystoreDeliveryIDs struct {
	euid, egid func() int
	// service resolves the installed service user, for a server run as root.
	service func() (uid, gid uint32, err error)
}

// keystoreDeliveryConfig is the reconciler's Config for this server: the
// declaration in the data root above workDir, the store the keys verbs open
// there, opened as the user that owns it (this process, or the service user
// when the server runs as root), the admin client, the start-time encryption
// verdict and the override flag.
func keystoreDeliveryConfig(workDir string, encryptionOn, allowPlaintext bool, cs kubernetes.Interface, ids keystoreDeliveryIDs, logger *slog.Logger) (keydeliver.Config, error) {
	work := filepath.Clean(workDir)
	if !filepath.IsAbs(work) {
		return keydeliver.Config{}, errors.New("the work dir is not absolute")
	}
	storeCfg := keystoreLayout(work)
	// A root server's work dir is the service user's, so the state file's
	// directory may be owned by it too; an unresolved service user fails
	// closed, building no reconciler.
	var stateDirOwners []uint32
	if euid := ids.euid(); euid != 0 {
		storeCfg.UID, storeCfg.GID = uint32(euid), uint32(ids.egid())
	} else {
		uid, gid, err := ids.service()
		if err != nil {
			return keydeliver.Config{}, err
		}
		storeCfg.UID, storeCfg.GID = uid, gid
		stateDirOwners = []uint32{uid}
	}
	cfg := keydeliver.Config{
		Path:           filepath.Join(executor.RuntimeRoot(work), keydeliver.FileName),
		StatePath:      filepath.Join(work, keydeliver.StateFileName),
		StateOwner:     uint32(ids.euid()),
		StateDirOwners: stateDirOwners,
		Client:         cs,
		Store:          keystore.New(storeCfg),
		EncryptionOn:   encryptionOn,
		AllowPlaintext: allowPlaintext,
		Logger:         logger,
	}
	return cfg, cfg.Validate()
}

// keystoreDeliveryGate is what plan hands the reconciler about plaintext:
// whether this start passes the apiserver an encryption provider
// configuration (an empty EncryptionProviderConfig is encryption off), and
// whether --allow-plaintext-secrets-delivery is set.
func keystoreDeliveryGate(plan serverPlan) (encryptionOn, allowPlaintext bool) {
	return plan.cfg.EncryptionProviderConfig != "", plan.opts.allowPlaintextSecretsDelivery
}

// startKeystoreDelivery is step 3c”': the keystore delivery reconciler
// (pkg/keystore/deliver), beside the add-on reconcilers and on the same
// system:masters admin client, adding no role, binding or ServiceAccount. It
// is handed the encryption verdict this start already made
// (executor.EncryptionAtStart, carried as the executor's
// EncryptionProviderConfig), so it cannot disagree with the apiserver. It runs
// in its own goroutine, logs every failure itself, and the returned stop
// cancels it and waits for it; runServer defers it so LIFO drains it before
// the control plane stops. It is never nil.
func startKeystoreDelivery(ctx context.Context, plan serverPlan, cs kubernetes.Interface, logger *slog.Logger) (stop func()) {
	encryptionOn, allowPlaintext := keystoreDeliveryGate(plan)
	cfg, err := keystoreDeliveryConfig(plan.opts.workDir, encryptionOn, allowPlaintext, cs,
		keystoreDeliveryIDs{euid: func() int { return euidSeam() }, egid: os.Getegid, service: lookupServiceIDs}, logger)
	if err != nil {
		logger.Error("keystore delivery disabled", "err", err)
		return noStop
	}
	if cfg.AllowPlaintext && !cfg.EncryptionOn {
		logger.Warn("keystore delivery: --" + keydeliver.AllowPlaintextFlag + " is set and secrets encryption is off; delivered Secrets are stored in plaintext in the datastore")
	}
	r := keydeliver.New(cfg)
	dCtx, dCancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		r.Run(dCtx)
	}()
	return func() {
		dCancel()
		<-done
	}
}

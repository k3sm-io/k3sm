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
	"sync"

	"github.com/google/go-containerregistry/pkg/v1/remote"

	"k3sm.io/k3sm/pkg/provider"
	"k3sm.io/k3sm/pkg/registrysvc"
	"k3sm.io/runtimed/pkg/guestartifacts"
)

// errNoGuestPublishCredential is an attempt made before this server's
// registry has written a push credential this process can use.
var errNoGuestPublishCredential = errors.New("this server's registry push credential is not readable yet")

// startGuestPublication returns the hook the node hands its verified guest
// boot pair to, and the stop that ends the publication. The hook starts, once,
// a background publish of the pair to this server's own registry
// (registrysvc.GuestPublisher), retried with backoff until it lands. It never
// blocks: the node's bring-up does not wait on its own registry, and a server
// whose publish keeps failing still serves everything else, logging why.
func startGuestPublication(ctx context.Context, workDir string, logger *slog.Logger) (publish func(provider.EnsuredGuestArtifacts), stop func()) {
	ctx, cancel := context.WithCancel(ctx)
	var (
		once sync.Once
		wg   sync.WaitGroup
	)
	pub := registrysvc.GuestPublisher{Access: guestPublishAccess(workDir), Logger: logger}
	publish = func(art provider.EnsuredGuestArtifacts) {
		once.Do(func() {
			set, err := guestSet(art)
			if err != nil {
				logger.Warn("guest boot artifacts not published to the cluster registry: the pin names no store artifact", "guest_kernel", guestartifacts.ActiveGuestKernel, "err", err)
				return
			}
			wg.Go(func() { pub.Run(ctx, set) })
		})
	}
	stop = func() {
		cancel()
		wg.Wait()
	}
	return publish, stop
}

// guestPublishAccess reaches this server's registry with its per-boot push
// credential, read again on every attempt because a registry restart rewrites
// it.
func guestPublishAccess(workDir string) func(context.Context) (string, []remote.Option, error) {
	return func(ctx context.Context) (string, []remote.Option, error) {
		acc, ok, err := credentialAccess(ctx, workDir)
		if !ok {
			return "", nil, errNoGuestPublishCredential
		}
		if err != nil {
			return "", nil, err
		}
		return acc.authority, acc.opts, nil
	}
}

// guestSet is the publishable form of an ensured guest pair: the store
// artifact the runtime derives from the in-code pin (the one a worker fetches
// by), and the verified files.
func guestSet(art provider.EnsuredGuestArtifacts) (registrysvc.GuestSet, error) {
	a, err := guestartifacts.ClusterStoreArtifact(guestartifacts.ActiveGuestKernel)
	if err != nil {
		return registrysvc.GuestSet{}, err
	}
	return registrysvc.GuestSet{Artifact: a, Files: map[string]string{
		guestartifacts.ImageFileName:     art.Artifacts.KernelPath,
		guestartifacts.InitramfsFileName: art.Artifacts.InitramfsPath,
	}}, nil
}

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

package policy

import (
	"errors"
	"fmt"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

// NewClient returns the clientset the server provisions this package's objects
// through: cfg's identity and address, with client-go's request rate limiter
// switched off.
//
// The limiter is the cost it removes. A rest.Config that leaves QPS at zero gets
// client-go's default token bucket (5 requests a second, a burst of 10) on every
// API group client, and one Ensure* is up to six requests (create, then get and
// update, for the policy and again for its binding) when the stored object has
// drifted. Once the burst was spent the server paid about a second per object at
// every start, 9 s for the set, all of it in front of the RBAC graph and the
// worker-join listener.
//
// No limiter is safe here because the request count is bounded by the set this
// package provisions (a handful of objects, each a create-or-update with a
// bounded conflict retry), it runs once at server start, and the apiserver's own
// priority-and-fairness still governs the requests. A QPS of -1 is client-go's
// spelling of "no limiter"; a zero QPS would bring the default back.
//
// cfg is copied, never modified: the caller's other clients keep their budget.
func NewClient(cfg *rest.Config) (*kubernetes.Clientset, error) {
	if cfg == nil {
		return nil, errors.New("build the policy provisioning client: no client config")
	}
	c := rest.CopyConfig(cfg)
	c.RateLimiter = nil
	c.QPS = -1
	cs, err := kubernetes.NewForConfig(c)
	if err != nil {
		return nil, fmt.Errorf("build the policy provisioning client: %w", err)
	}
	return cs, nil
}

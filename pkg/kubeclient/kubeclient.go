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

package kubeclient

import (
	"crypto/x509"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"

	"k3sm.io/k3sm/pkg/defaults"
)

// ErrCredentialsNotInline marks a FromCheckedPath refusal: the kubeconfig has a
// user or cluster entry that keeps its credentials anywhere but in the file.
var ErrCredentialsNotInline = errors.New("only inline credentials are accepted")

// ErrCAUnusable marks a PinCA refusal: the bytes it was given hold no PEM
// certificate.
var ErrCAUnusable = errors.New("holds no PEM certificate")

// apiServerName is the first address of the cluster's Service range.
var apiServerName = netip.MustParsePrefix(defaults.ServiceCIDR).Masked().Addr().Next().String()

// APIServerName is the name a client holding the cluster CA verifies the apiserver's
// serving certificate against: the kubernetes Service IP, the first address of
// defaults.ServiceCIDR. Every apiserver certificate k3sm has issued carries it, and
// the apiserver's range is fixed (`--service-cluster-ip-range` in pkg/executor, which
// no k3sm command changes), so it is a constant of the cluster. An address is used
// because a node's serving certificate can carry a DNS name equal to the node's name
// but only the IP address the join assigned, and that assignment never comes from
// the Service range.
//
// Being an address, it goes out as no SNI, and it decides only what the certificate
// must name: the connection still dials the kubeconfig's server.
func APIServerName() string { return apiServerName }

// FromPath loads the kubeconfig at path and returns both the rest.Config it
// resolved and a typed clientset built from it. path is used verbatim, and
// nothing else is consulted: an empty path reaches client-go's in-cluster
// fallback, which on a macOS host always fails, rather than quietly resolving to
// whatever KUBECONFIG or ~/.kube/config names (see the package comment).
//
// A load failure is returned EXACTLY as clientcmd produced it, with no context
// added. The caller names its own site — "load kubeconfig", "load node
// kubeconfig for node-local datapath", "build client config from <path>" — and
// those messages are what operators have been reading; a wrap here would either
// stutter with the caller's or silently reword it. The helper names nothing.
// (The NewForConfig failure is the one exception: it cannot be reached through
// a config this function itself just loaded successfully, so no caller has a
// distinguishable message for it and one canonical wrap is clearer than none.)
//
// Neither call dials: BuildConfigFromFlags reads a file and NewForConfig only
// constructs a client, so a returned client proves nothing about reachability.
// Timeouts and rate limits are the caller's to set on the returned config before
// it builds anything else from it.
func FromPath(path string) (*rest.Config, kubernetes.Interface, error) {
	cfg, err := clientcmd.BuildConfigFromFlags("", path)
	if err != nil {
		return nil, nil, err
	}
	return clientFor(cfg)
}

// FromCheckedPath is FromPath for a caller that accepts only inline credentials:
// certificate-authority-data, client-certificate-data, client-key-data, token,
// username and password. Every user and cluster entry in the file is checked, not
// only the ones the current context names, and a refusal wraps
// ErrCredentialsNotInline.
//
// The rest.Config is built from the checked object, and the path is read once,
// so what was checked is exactly what is used.
//
// A load failure comes back as clientcmd produced it, as FromPath's does. A
// refusal names the entry and its fields but no field's value, and leaves the
// path to the caller, whose own wrap or log attribute already carries it. Entries
// and fields are in a fixed order, so one file always gives the same message and
// a caller can recognise a repeat.
func FromCheckedPath(path string) (*rest.Config, kubernetes.Interface, error) {
	cfg, err := checkedConfig(path)
	if err != nil {
		return nil, nil, err
	}
	return clientFor(cfg)
}

// FromCheckedPathWithCA is FromCheckedPath for a caller that holds the cluster's
// CA itself: the kubeconfig gives the address and the client credential, and
// caPEM alone decides which CA, and APIServerName which name, a server certificate
// is accepted for (PinCA). A refusal from PinCA wraps ErrCAUnusable.
func FromCheckedPathWithCA(path string, caPEM []byte) (*rest.Config, kubernetes.Interface, error) {
	cfg, err := checkedConfig(path)
	if err != nil {
		return nil, nil, err
	}
	if err := PinCA(cfg, caPEM); err != nil {
		return nil, nil, err
	}
	return clientFor(cfg)
}

// FromCheckedWorkerPath is FromCheckedPath for a worker's node credential where
// the caller holds no CA of its own: the file's CA stays, the certificate must name
// APIServerName, and insecure-skip-tls-verify does not apply.
func FromCheckedWorkerPath(path string) (*rest.Config, kubernetes.Interface, error) {
	cfg, err := checkedConfig(path)
	if err != nil {
		return nil, nil, err
	}
	cfg.Insecure = false
	cfg.ServerName = apiServerName
	return clientFor(cfg)
}

// PinCA makes caPEM and APIServerName the only trust cfg has in its server: every
// other trust setting a kubeconfig can carry is replaced, a CA file or inline CA,
// insecure-skip-tls-verify and tls-server-name. The address is left alone, since
// it can legitimately differ from the one the CA was first seen at. Its callers are
// all root on a k3sm node, whose server is always a k3sm apiserver.
func PinCA(cfg *rest.Config, caPEM []byte) error {
	if !x509.NewCertPool().AppendCertsFromPEM(caPEM) {
		return fmt.Errorf("cluster CA %w", ErrCAUnusable)
	}
	cfg.CAData = caPEM
	cfg.CAFile = ""
	cfg.Insecure = false
	cfg.ServerName = apiServerName
	return nil
}

// CheckedConfig is FromCheckedPath for a caller that sets its own client up from
// the config: the same refusals, and no clientset built.
func CheckedConfig(path string) (*rest.Config, error) {
	return checkedConfig(path)
}

// checkedConfig reads path once, checks it, and resolves its current context.
func checkedConfig(path string) (*rest.Config, error) {
	raw, err := clientcmd.LoadFromFile(path)
	if err != nil {
		return nil, err
	}
	if err := checkInline(raw); err != nil {
		return nil, err
	}
	return restConfigFrom(raw)
}

// clientFor builds the clientset of a config this package resolved.
func clientFor(cfg *rest.Config) (*rest.Config, kubernetes.Interface, error) {
	cs, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return nil, nil, fmt.Errorf("build kubernetes client: %w", err)
	}
	return cfg, cs, nil
}

// restConfigFrom resolves raw's current context with no overrides. It reads no
// file and no environment.
func restConfigFrom(raw *clientcmdapi.Config) (*rest.Config, error) {
	return clientcmd.NewDefaultClientConfig(*raw, &clientcmd.ConfigOverrides{}).ClientConfig()
}

// checkInline returns an error naming every user and cluster entry whose
// credentials are not all inline.
func checkInline(raw *clientcmdapi.Config) error {
	var refused []string
	for _, name := range sortedKeys(raw.AuthInfos) {
		if fields := userFieldsNotInline(raw.AuthInfos[name]); len(fields) > 0 {
			refused = append(refused, fmt.Sprintf("user %q sets %s", name, strings.Join(fields, ", ")))
		}
	}
	for _, name := range sortedKeys(raw.Clusters) {
		if c := raw.Clusters[name]; c != nil && c.CertificateAuthority != "" {
			refused = append(refused, fmt.Sprintf("cluster %q sets certificate-authority", name))
		}
	}
	if len(refused) == 0 {
		return nil
	}
	return fmt.Errorf("%s: %w", strings.Join(refused, "; "), ErrCredentialsNotInline)
}

// userFieldsNotInline returns the kubeconfig keys u sets that checkInline refuses.
func userFieldsNotInline(u *clientcmdapi.AuthInfo) []string {
	if u == nil {
		return nil
	}
	var fields []string
	for _, f := range []struct {
		key string
		set bool
	}{
		{"exec", u.Exec != nil},
		{"auth-provider", u.AuthProvider != nil},
		{"tokenFile", u.TokenFile != ""},
		{"client-certificate", u.ClientCertificate != ""},
		{"client-key", u.ClientKey != ""},
		{"as", u.Impersonate != ""},
		{"as-uid", u.ImpersonateUID != ""},
		{"as-groups", len(u.ImpersonateGroups) > 0},
		{"as-user-extra", len(u.ImpersonateUserExtra) > 0},
	} {
		if f.set {
			fields = append(fields, f.key)
		}
	}
	return fields
}

// sortedKeys returns m's keys in order.
func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}

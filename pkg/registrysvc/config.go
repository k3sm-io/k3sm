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

package registrysvc

import (
	"encoding/json"
	"fmt"
	"strconv"
)

// The garbage-collection cadence. zot's own defaults are one hour for both; the
// interval is stretched to six because an ingest registry's write pattern is a
// human pushing a handful of images, not a fleet churning tags, and an hourly
// full walk of the blob store buys nothing on that pattern. The DELAY stays at an
// hour: it is the window during which a just-uploaded but not yet referenced blob
// is protected from collection, and shortening it would let GC race a slow push.
const (
	gcDelay    = "1h"
	gcInterval = "6h"
)

// authFailDelay is the seconds zot waits before answering a failed
// authentication. One second is enough to make online password guessing against
// a 256-bit secret pointless without making a mistyped credential feel broken.
const authFailDelay = 1

// dockerCompat asks zot to accept Docker Schema-2 manifests and config media
// types in addition to the OCI ones.
//
// `k3sm build --format oci` writes OCI media types, so k3sm's own path does not
// need this. Everything else does: a `docker save`/`docker buildx` artifact and
// the overwhelming majority of images on public registries are still Schema 2,
// and a node-local ingest registry that answers MANIFEST_INVALID to them is not a
// generic registry. Verified accepted by the pinned minimal build.
const dockerCompat = "docker2s2"

// zotConfig is the subset of zot's configuration k3sm renders.
//
// It is a HAND-WRITTEN subset rather than zot's own config struct because zot is
// not a Go dependency of this module — it is a child process — so the schema is
// reproduced here and validated by the child at boot. That validation is strict
// in the direction that matters: zot's loader UnmarshalExacts the file and fails
// on any key it does not know, so a field renamed upstream produces a refusal at
// boot with the offending key named, not a silently ignored setting.
type zotConfig struct {
	Storage zotStorage `json:"storage"`
	HTTP    zotHTTP    `json:"http"`
	Log     zotLog     `json:"log"`
}

type zotStorage struct {
	RootDirectory string `json:"rootDirectory"`
	Dedupe        bool   `json:"dedupe"`
	GC            bool   `json:"gc"`
	GCDelay       string `json:"gcDelay"`
	GCInterval    string `json:"gcInterval"`
}

type zotHTTP struct {
	Address       string           `json:"address"`
	Port          string           `json:"port"`
	Compat        []string         `json:"compat"`
	Auth          zotAuth          `json:"auth"`
	AccessControl zotAccessControl `json:"accessControl"`
}

type zotAuth struct {
	FailDelay int         `json:"failDelay"`
	HTPasswd  zotHTPasswd `json:"htpasswd"`
}

type zotHTPasswd struct {
	Path string `json:"path"`
}

type zotAccessControl struct {
	Repositories map[string]zotPolicyGroup `json:"repositories"`
}

type zotPolicyGroup struct {
	Policies        []zotPolicy `json:"policies"`
	DefaultPolicy   []string    `json:"defaultPolicy"`
	AnonymousPolicy []string    `json:"anonymousPolicy"`
}

type zotPolicy struct {
	Users   []string `json:"users"`
	Actions []string `json:"actions"`
}

// allRepositories is zot's glob for every repository. It is the only key k3sm
// writes: the ingest registry has one policy for its whole namespace, and a
// per-repository policy would be a second authorization model to keep correct.
const allRepositories = "**"

// renderConfig renders the zot configuration for a work dir, bind address and
// port. It is PURE — it reads no environment and touches no filesystem — so the
// exact document that reaches the child is assertable in a unit test.
//
// The access-control shape is the whole security posture in four lines:
// anonymousPolicy grants "read" to an unauthenticated caller, defaultPolicy is
// EMPTY (an authenticated caller gets nothing by being authenticated), and the
// one policy entry grants the push user read+create+update+delete. So the node's
// runtime pulls with no credential, and only the holder of the per-boot password
// can put an image into the store the cluster runs out of.
func renderConfig(workDir, bindAddress string, port int) ([]byte, error) {
	if err := validateBind(bindAddress, port); err != nil {
		return nil, err
	}
	cfg := zotConfig{
		Storage: zotStorage{
			RootDirectory: StateDir(workDir),
			Dedupe:        true,
			GC:            true,
			GCDelay:       gcDelay,
			GCInterval:    gcInterval,
		},
		HTTP: zotHTTP{
			Address: bindAddress,
			// zot's HTTP port is a STRING in its own schema, and its loader is
			// strict, so rendering it as a JSON number is a boot failure rather
			// than a coercion.
			Port:   strconv.Itoa(port),
			Compat: []string{dockerCompat},
			Auth: zotAuth{
				FailDelay: authFailDelay,
				HTPasswd:  zotHTPasswd{Path: HTPasswdPath(workDir)},
			},
			AccessControl: zotAccessControl{
				Repositories: map[string]zotPolicyGroup{
					allRepositories: {
						Policies: []zotPolicy{{
							Users:   []string{pushUser},
							Actions: []string{"read", "create", "update", "delete"},
						}},
						DefaultPolicy:   []string{},
						AnonymousPolicy: []string{"read"},
					},
				},
			},
		},
		// Output empty is stdout, which the spawn redirects to the 0600
		// registry.log beside the control plane's other component logs.
		Log: zotLog{Level: "info"},
	}
	b, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("render the registry config: %w", err)
	}
	return append(b, '\n'), nil
}

type zotLog struct {
	Level string `json:"level"`
}

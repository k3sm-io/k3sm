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

package helmchart

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"

	helmv1 "k3sm.io/apis/helm/v1"
)

// ConfigHash is the digest of everything the install Job's behaviour depends on
// from the API: the HelmChart's spec and the HelmChartConfig's values overlay.
// It is stamped on the install Job (AnnotationConfigHash), and a Job carrying a
// different hash is replaced, which is how an edited spec or overlay reaches
// helm.
//
// "sha256:" + hex of sha256(JSON(spec) || 0x00 || overlay). encoding/json sorts
// map keys, so the digest is stable across processes; the NUL separator keeps a
// spec/overlay pair from colliding with another split of the same bytes. Only
// the overlay's valuesContent is hashed, because it is the only
// HelmChartConfig field the controller applies.
func ConfigHash(spec helmv1.HelmChartSpec, cfg *helmv1.HelmChartConfig) string {
	// A HelmChartSpec is plain data (strings, bools, ints, a map, a Duration), so
	// its encoding does not fail. Were it ever to, the error text is hashed in its
	// place: the digest then still differs from every real spec's, where hashing
	// an empty encoding would collide with the zero spec.
	raw, err := json.Marshal(spec)
	if err != nil {
		raw = []byte("unencodable:" + err.Error())
	}
	h := sha256.New()
	h.Write(raw)
	h.Write([]byte{0})
	h.Write([]byte(configValues(cfg)))
	return "sha256:" + hex.EncodeToString(h.Sum(nil))
}

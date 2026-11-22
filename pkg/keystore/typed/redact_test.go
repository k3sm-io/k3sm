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

package typed

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"
)

// TestSecretTypesRedactWhenFormatted is U149's formatting case: an Envelope
// and a Credential print the kind, field names, presence and lengths, and
// never a byte of RefreshToken, AccessToken, Value or Seed, under every fmt
// verb, through slog and inside a wrapped error.
func TestSecretTypesRedactWhenFormatted(t *testing.T) {
	markers := map[string][]byte{
		"refresh": []byte("MARKERrefreshQ7"),
		"access":  []byte("MARKERaccessW3"),
		"value":   []byte("MARKERvalueZ9"),
		"seed":    bytes.Repeat([]byte("SEEDMRK!"), 4),
	}
	now := time.Unix(1_800_000_000, 0).UTC()
	cases := map[string]Envelope{
		"oauth": {Credential: Credential{AccessToken: markers["access"], AccessExpiresAt: now, RefreshOwner: "local"}, RefreshToken: markers["refresh"]},
		"token": {Credential: Credential{Value: markers["value"], ExpiresAt: now}},
		"ssh":   {Credential: Credential{Algorithm: SSHAlgorithmEd25519, Seed: markers["seed"]}},
		// Every secret field at once, as no valid envelope holds.
		"all": {Credential: Credential{Value: markers["value"], Seed: markers["seed"], AccessToken: markers["access"]}, RefreshToken: markers["refresh"]},
	}
	forms := func(secret []byte) []string {
		return []string{
			string(secret), hex.EncodeToString(secret), strings.ToUpper(hex.EncodeToString(secret)),
			base64.StdEncoding.EncodeToString(secret), base64.RawURLEncoding.EncodeToString(secret),
			fmt.Sprintf("%v", secret), fmt.Sprintf("%q", secret), fmt.Sprintf("% x", secret),
		}
	}
	verbs := []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%X", "%d", "%10.3v"}
	for name, e := range cases {
		var outs []string
		for i, v := range []any{e, &e, e.Credential, &e.Credential, []Envelope{e}, map[string]Credential{"c": e.Credential}} {
			for _, verb := range verbs {
				outs = append(outs, fmt.Sprintf(verb, v))
			}
			outs = append(outs, fmt.Errorf("wrapped: %v", v).Error(), fmt.Sprint(v), fmt.Sprintln(v))
			var buf bytes.Buffer
			slog.New(slog.NewTextHandler(&buf, nil)).Info("msg", "credential", v, slog.Group("g", "c", v))
			// The JSON handler resolves a LogValuer it is handed; a slice or
			// map of them it hands to encoding/json, which no formatting
			// method reaches.
			if i < 4 {
				slog.New(slog.NewJSONHandler(&buf, nil)).Info("msg", "credential", v, slog.Group("g", "c", v))
			}
			outs = append(outs, buf.String())
		}
		outs = append(outs, e.String(), e.GoString(), e.Credential.String(), e.Credential.GoString(),
			e.LogValue().String(), e.Credential.LogValue().String())
		for _, out := range outs {
			for m, secret := range markers {
				for _, f := range forms(secret) {
					if strings.Contains(out, f) {
						t.Fatalf("%s: the %s marker appears as %q in %q", name, m, f, out)
					}
				}
			}
		}
	}
	got := fmt.Sprint(cases["oauth"])
	for _, want := range []string{"oauth", "accessToken", "14 bytes", "refreshToken", "15 bytes", "refreshOwner"} {
		if !strings.Contains(got, want) {
			t.Errorf("redacted oauth envelope %q does not show %q", got, want)
		}
	}
	if got := fmt.Sprint(cases["ssh"].Credential); !strings.Contains(got, "ssh") || !strings.Contains(got, "seed") || !strings.Contains(got, "32 bytes") {
		t.Errorf("redacted ssh credential %q does not name its kind, field and length", got)
	}
}

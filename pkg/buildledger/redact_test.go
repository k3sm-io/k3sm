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

package buildledger

import "testing"

// TestRedact pins the credential shapes a stored build error loses.
func TestRedact(t *testing.T) {
	cases := []struct{ name, in, want string }{
		{"plain text is untouched", "COPY app: no such file", "COPY app: no such file"},
		{"url user and password", "GET https://user:hunter2@registry.example.com/v2/: 401", "GET https://registry.example.com/v2/: 401"},
		{"url user only", "pull oci://token@ghcr.io/org/img", "pull oci://ghcr.io/org/img"},
		{"url without userinfo", "GET https://registry.example.com/v2/a@sha256:ab", "GET https://registry.example.com/v2/a@sha256:ab"},
		{"two urls", "http://a:b@x/ and ftp://c@y/", "http://x/ and ftp://y/"},
		{"authorization basic", "header Authorization: Basic dXNlcjpwYXNz rejected", "header Authorization: [redacted] rejected"},
		{"authorization bearer", "authorization: Bearer abc.def.ghi", "authorization: [redacted]"},
		{"authorization bare value", "Authorization:abc123", "Authorization:[redacted]"},
		{"bare bearer", `token "Bearer eyJhbGciOi" expired`, `token "Bearer [redacted]" expired`},
		{"secret with keys", "buildx --secret id=npm,src=/Users/me/.npmrc failed", "buildx --secret id=[redacted],src=[redacted] failed"},
		{"secret with equals", "--secret=id=gh,env=GH_TOKEN", "--secret=id=[redacted],env=[redacted]"},
		{"secret bare value", "--secret hunter2", "--secret [redacted]"},
		{"secret-file is a different flag", "--secret-file x", "--secret-file x"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := redact(tc.in); got != tc.want {
				t.Errorf("redact(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

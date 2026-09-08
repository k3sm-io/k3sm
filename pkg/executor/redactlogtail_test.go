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

package executor

import (
	"strings"
	"testing"
)

// A component log is opened 0600 because, in spawnEnv's own words, it "can carry
// bearer tokens and the kine datastore endpoint". The crash callback hands a tail
// of it to the daemon logger, which launchd captures into
// /var/log/k3sm/server.log — mode 0644 on an installed cluster. These pin what
// may cross that boundary.
func TestRedactLogTailRemovesCredentialMaterial(t *testing.T) {
	tests := []struct {
		name   string
		in     string
		leaked string // must NOT appear in the output
		keeps  string // must still appear: redaction that eats the diagnosis is useless
	}{
		{
			name:   "bearer header",
			in:     `E0908 apiserver: request failed, Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9`,
			leaked: "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9",
			keeps:  "request failed",
		},
		{
			name:   "postgres DSN password in the kine endpoint",
			in:     `kine: --endpoint=postgres://k3sm:sup3r-s3cret@db.internal:5432/kine failed to connect`,
			leaked: "sup3r-s3cret",
			keeps:  "db.internal:5432", // WHICH datastore is diagnostics
		},
		{
			name:   "token flag echoed on a fatal flag error",
			in:     `flag provided but not defined: --agent-token=abcdef0123456789`,
			leaked: "abcdef0123456789",
			keeps:  "flag provided but not defined",
		},
		{
			name:   "structured log field",
			in:     `time=2026-09-08T10:00:00Z level=ERROR msg="join rejected" token=abcdef0123456789 peer=node-2`,
			leaked: "abcdef0123456789",
			keeps:  "node-2",
		},
		{
			name:   "k3sm-minted join token, on shape alone",
			in:     `could not verify k3sm-A1b2C3d4E5f6G7h8 against the cluster`,
			leaked: "k3sm-A1b2C3d4E5f6G7h8",
			keeps:  "could not verify",
		},
		{
			name:   "CA-pinned bootstrap token, on shape alone",
			in:     `bootstrap failed for K10deadbeefcafef00d::server:xyz`,
			leaked: "K10deadbeefcafef00d",
			keeps:  "bootstrap failed",
		},
		{
			name:   "password query parameter",
			in:     `dial postgres://db.internal/kine?sslmode=require&password=hunter2 refused`,
			leaked: "hunter2",
			keeps:  "refused",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := redactLogTail(tc.in)
			if strings.Contains(got, tc.leaked) {
				t.Errorf("credential %q survived redaction into a world-readable sink:\n%s", tc.leaked, got)
			}
			if !strings.Contains(got, tc.keeps) {
				t.Errorf("redaction ate the diagnostic %q, leaving:\n%s", tc.keeps, got)
			}
			if !strings.Contains(got, redactedTokenPlaceholder) {
				t.Errorf("nothing was marked as redacted, so the reader cannot tell material was removed:\n%s", got)
			}
		})
	}
}

// A prefix-preserving mask is not redaction: the first characters of a token are
// still part of the token.
func TestRedactLogTailKeepsNoPrefixOfASecret(t *testing.T) {
	const secret = "abcdefghijklmnop0123456789"
	got := redactLogTail("token=" + secret)
	for n := 4; n <= len(secret); n++ {
		if strings.Contains(got, secret[:n]) {
			t.Fatalf("output keeps the first %d characters of the secret: %s", n, got)
		}
	}
}

// The line cap does not bound the tail on its own: one marshalled object or one
// stack trace is a single enormous line, and this value goes into a structured
// log record.
func TestRedactLogTailIsByteCappedKeepingTheEnd(t *testing.T) {
	// The fatal line is the LAST one, so the cap must drop the head.
	tail := strings.Repeat("x", exitLogTailBytes*2) + "THE-FATAL-LINE"
	got := redactLogTail(tail)
	if len(got) > exitLogTailBytes+len("<truncated>") {
		t.Errorf("tail is %d bytes, want at most %d", len(got), exitLogTailBytes+len("<truncated>"))
	}
	if !strings.Contains(got, "THE-FATAL-LINE") {
		t.Error("the byte cap dropped the END of the log, which is where the fatal line is")
	}
	if !strings.HasPrefix(got, "<truncated>") {
		t.Error("a truncated tail does not say so, so the reader cannot tell lines are missing")
	}
}

// An unreadable log must not turn into an empty tail that reads as "the component
// said nothing on its way out".
func TestRedactedLogTailReportsAnUnreadableLog(t *testing.T) {
	got := redactedLogTail("/nonexistent/k3sm-component.log")
	if !strings.Contains(got, "unreadable log") {
		t.Errorf("an unreadable log produced %q, which does not say the log could not be read", got)
	}
}

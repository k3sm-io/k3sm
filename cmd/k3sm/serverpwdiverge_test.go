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
	"strings"
	"testing"

	"k3sm.io/k3sm/pkg/bootstrap"
	"k3sm.io/k3sm/pkg/hostnet"
)

// genericBringUpFailure is the wording every NON-mismatch bring-up failure keeps.
const genericBringUpFailure = "server mesh bring-up failed; this node is NOT on its own mesh"

// TestSelfNodePasswordMismatchNamesTheRemedy is B354: when this control-plane
// node's own node-password no longer matches the binding the store holds for its
// name (a reinstall or restore that lost the password file), the survivable log
// line says so, names the file and the name, and points at restoring the file —
// without spelling out how to mutate the datastore.
func TestSelfNodePasswordMismatchNamesTheRemedy(t *testing.T) {
	ctx := context.Background()
	const nodeName = "k3sm-host"
	mode := hostnet.Mode{Backend: hostnet.BackendNone}

	t.Run("a mismatch is diagnosed with the file, the name and the restore-first remedy", func(t *testing.T) {
		e, _ := enrollerOverStub(t)
		passwords := bootstrap.NewMemoryNodePasswords()
		if err := passwords.Ensure(ctx, nodeName, "a-previous-installs-password"); err != nil {
			t.Fatalf("seed the binding: %v", err)
		}
		workDir := t.TempDir()
		opts := selfEnrollOptions(workDir, nodeName)

		_, _, err := enrollSelfAndBringUpMesh(ctx, e, passwords, opts, mode, "", quietLogger())
		if !errors.Is(err, bootstrap.ErrNodePasswordMismatch) {
			t.Fatalf("self-enroll error = %v, want ErrNodePasswordMismatch", err)
		}
		sink := &syncBuffer{}
		msg, attrs := serverMeshBringUpFailure(opts, err)
		slog.New(slog.NewTextHandler(sink, nil)).Error(msg, attrs...)
		out := sink.String()

		path := filepath.Join(workDir, serverNodePasswordRef)
		for _, want := range []string{
			path,
			nodeName,
			"no longer matches",
			"restore the original",
		} {
			if !strings.Contains(out, want) {
				t.Errorf("diagnosis does not contain %q:\n%s", want, out)
			}
		}
		if strings.Contains(out, genericBringUpFailure) {
			t.Errorf("a mismatch still logged the generic wording:\n%s", out)
		}

		// Never the recovery mechanics, never the credential.
		stored, rerr := os.ReadFile(path)
		if rerr != nil {
			t.Fatalf("read the persisted node-password: %v", rerr)
		}
		for _, banned := range []string{
			"kubectl",
			"kube-system",
			"Secret",
			nodeName + nodePasswordSecretSuffix,
			nodePasswordSecretSuffix,
			"$2a$",
			strings.TrimSpace(string(stored)),
		} {
			if strings.Contains(out, banned) {
				t.Errorf("diagnosis contains %q, which it must never print:\n%s", banned, out)
			}
		}
	})

	t.Run("a non-mismatch failure keeps the generic wording", func(t *testing.T) {
		e, _ := enrollerOverStub(t)
		opts := selfEnrollOptions(t.TempDir(), nodeName)

		_, _, err := enrollSelfAndBringUpMesh(ctx, e, nil, opts, mode, "", quietLogger())
		if err == nil || errors.Is(err, bootstrap.ErrNodePasswordMismatch) {
			t.Fatalf("self-enroll error = %v, want a non-mismatch failure", err)
		}
		sink := &syncBuffer{}
		msg, attrs := serverMeshBringUpFailure(opts, err)
		slog.New(slog.NewTextHandler(sink, nil)).Error(msg, attrs...)
		out := sink.String()
		if !strings.Contains(out, genericBringUpFailure) {
			t.Errorf("a non-mismatch failure lost the generic wording:\n%s", out)
		}
		if strings.Contains(out, "restore the original") {
			t.Errorf("a non-mismatch failure was diagnosed as a divergence:\n%s", out)
		}
	})

	t.Run("the join path's rejection line is unchanged", func(t *testing.T) {
		src, err := os.ReadFile(filepath.Join("..", "..", "pkg", "bootstrap", "server.go"))
		if err != nil {
			t.Fatalf("read the join handler source: %v", err)
		}
		const joinLine = `s.cfg.Logger.Warn("join rejected", "reason", "node-password", "node", req.NodeName, "err", err)`
		if !strings.Contains(string(src), joinLine) {
			t.Errorf("the join path's node-password rejection line changed; want it byte-for-byte:\n%s", joinLine)
		}
		const joinReply = `http.Error(w, "node-password rejected", http.StatusForbidden)`
		if !strings.Contains(string(src), joinReply) {
			t.Errorf("the join path's node-password reply changed; want it byte-for-byte:\n%s", joinReply)
		}
	})
}

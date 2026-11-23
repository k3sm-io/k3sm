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
	"fmt"
	"path/filepath"

	"k3sm.io/k3sm/pkg/executor"
	keydeliver "k3sm.io/k3sm/pkg/keystore/deliver"
)

// keysUndeliverHint is what undeliver prints after withdrawing a target: the
// reconciler is converge-only, so the Secret it delivered is not deleted.
const keysUndeliverHint = "the Secret stays; delete it with kubectl, and rotate the entry to revoke"

// keysEncryptionOffNote is what deliver prints on a data root where secrets
// encryption is off. The CLI reads the files only and cannot see a running
// server's flags, so it says "unless the server was started with the override".
const keysEncryptionOffNote = "secrets encryption is off on this data root, so the server refuses this delivery " +
	"unless the server was started with the override (--" + keydeliver.AllowPlaintextFlag + "): " +
	"a delivered Secret would be stored in plaintext in the datastore. See docs/user/keys.md"

// encryptionOnAt reports whether the server would start workDir's apiserver
// with secrets encryption, by the server's own start verdict. A refused
// verdict (the server would not start) is not "off", so it prints no note.
func encryptionOnAt(workDir string) bool {
	p, err := executor.EncryptionAtStart(executor.OSEncryptionStore{}, workDir, false, daemonUID(workDir))
	return err != nil || p != ""
}

// deliveryPath is the declaration's path in the data root --work-dir names.
// It sets v.roots, as store does, so failf scrubs the paths.
func (v *keysVerb) deliveryPath() (string, error) {
	work := filepath.Clean(*v.workDir)
	if !filepath.IsAbs(work) {
		return "", errors.New("--work-dir is not an absolute path (the value given is not echoed)")
	}
	if v.roots == nil {
		v.roots = []string{work, filepath.Join(executor.CredDir(work), keystoreMasterSubdir), executor.RuntimeRoot(work)}
	}
	return filepath.Join(executor.RuntimeRoot(work), keydeliver.FileName), nil
}

// lockDeclaration takes the writers' lock beside the declaration at path,
// so a concurrent deliver or undeliver cannot lose this one's change.
func (v *keysVerb) lockDeclaration(ctx context.Context, path string) (func(), error) {
	unlock, err := keydeliver.Lock(ctx, filepath.Join(filepath.Dir(path), keydeliver.LockName), v.env.deliveryCheck, v.env.deliveryLockBusy)
	if err != nil {
		return nil, fmt.Errorf("the delivery declaration's lock (<data-root>/%s): %w", keydeliver.LockName, err)
	}
	return unlock, nil
}

// readDeclaration reads the declaration at path as the reconciler does, so a
// file the server would refuse is refused here too rather than rewritten.
func (v *keysVerb) readDeclaration(path string) (keydeliver.Declaration, error) {
	d, _, _, err := keydeliver.Read(path, keydeliver.OpenNoFollow, v.env.deliveryCheck)
	if err != nil {
		return keydeliver.Declaration{}, fmt.Errorf("the delivery declaration (<data-root>/%s): %w", keydeliver.FileName, err)
	}
	if v.env.deliveryRead != nil {
		v.env.deliveryRead()
	}
	return d, nil
}

// warnDeclared warns, after rm deleted entry name, about each target still
// declaring it for delivery: the reconciler can no longer read the entry, but
// the Secret it delivered keeps the value. It prints the namespace and
// Secret, never a path or a value, and only warns: rm has already succeeded.
func (v *keysVerb) warnDeclared(name string) {
	path, err := v.deliveryPath()
	if err == nil {
		var d keydeliver.Declaration
		if d, _, _, err = keydeliver.Read(path, keydeliver.OpenNoFollow, v.env.deliveryCheck); err == nil {
			for _, t := range d.Targets {
				if t.Entry == qualify(name) {
					fmt.Fprintf(v.env.stderr, "k3sm keys rm: warning: %s is still declared for delivery to %s/%s; "+
						"the Secret keeps its value: run `k3sm keys undeliver` and delete the Secret\n",
						qualify(name), t.Namespace, t.Secret())
				}
			}
			return
		}
	}
	fmt.Fprintf(v.env.stderr, "k3sm keys rm: warning: cannot read the delivery declaration to check whether %s is still declared for delivery\n", qualify(name))
}

func keysDeliver(ctx context.Context, args []string, env keysEnv) int {
	v := newKeysVerb("deliver", env)
	ns := v.fs.String("namespace", "", "the namespace the Secret is delivered into (required)")
	secretName := v.fs.String("secret", "", "the Secret's name (default: the entry name without system/)")
	dataKey := v.fs.String("data-key", "", "the Secret data key the value is delivered under (default: "+keydeliver.DefaultDataKey+")")
	pos, err := v.parse(args)
	if err != nil {
		return keysBadUsage
	}
	name, code := v.nameArg(pos)
	if code != keysOK {
		return code
	}
	if *ns == "" {
		return v.failf(keysBadUsage, "--namespace is required")
	}
	t := keydeliver.Target{Entry: qualify(name), Namespace: *ns, SecretName: *secretName, DataKey: *dataKey}
	if err := t.Check(); err != nil {
		return v.failf(keysBadUsage, "%v (the value given is not echoed)", err)
	}
	// The file states both, so a later default change moves no Secret.
	t.SecretName, t.DataKey = t.Secret(), t.Key()
	if code := v.requireRoot(); code != keysOK {
		return code
	}
	s, err := v.store()
	if err != nil {
		return v.failf(keysRefused, "%v", err)
	}
	if _, err := showMetadata(ctx, s, name, 0); err != nil {
		return v.failf(keysRefused, "%v; deliver only an existing entry", err)
	}
	path, err := v.deliveryPath()
	if err != nil {
		return v.failf(keysBadUsage, "%v", err)
	}
	unlock, err := v.lockDeclaration(ctx, path)
	if err != nil {
		return v.failf(keysRefused, "%v", err)
	}
	defer unlock()
	d, err := v.readDeclaration(path)
	if err != nil {
		return v.failf(keysRefused, "%v", err)
	}
	replaced := d.Upsert(t)
	if len(d.Targets) > keydeliver.MaxTargets {
		return v.failf(keysRefused, "the declaration already holds %d targets, the limit", keydeliver.MaxTargets)
	}
	if err := keydeliver.Write(path, d, env.deliveryCheck, env.deliveryChown); err != nil {
		return v.failf(keysRefused, "write the delivery declaration: %v", err)
	}
	verb := "declared"
	if replaced {
		verb = "replaced the declaration for"
	}
	fmt.Fprintf(env.stdout, "%s delivery of %s as Secret %s/%s (data key %s)\n", verb, qualify(name), t.Namespace, t.SecretName, t.DataKey)
	if !env.encryptionOn(filepath.Clean(*v.workDir)) {
		fmt.Fprintf(env.stderr, "k3sm keys deliver: warning: %s\n", keysEncryptionOffNote)
	}
	return keysOK
}

func keysUndeliver(ctx context.Context, args []string, env keysEnv) int {
	v := newKeysVerb("undeliver", env)
	ns := v.fs.String("namespace", "", "the namespace the delivery is withdrawn from (required)")
	secret := v.fs.String("secret", "", "withdraw only the delivery into this Secret (default: every one in the namespace)")
	pos, err := v.parse(args)
	if err != nil {
		return keysBadUsage
	}
	name, code := v.nameArg(pos)
	if code != keysOK {
		return code
	}
	if *ns == "" {
		return v.failf(keysBadUsage, "--namespace is required")
	}
	if code := v.requireRoot(); code != keysOK {
		return code
	}
	// The store is opened only for the verb's audit line (runKeysWith); one
	// that cannot be opened has no log to write it to, and the withdrawal
	// goes ahead.
	_, _ = v.store()
	path, err := v.deliveryPath()
	if err != nil {
		return v.failf(keysBadUsage, "%v", err)
	}
	unlock, err := v.lockDeclaration(ctx, path)
	if err != nil {
		return v.failf(keysRefused, "%v", err)
	}
	defer unlock()
	d, err := v.readDeclaration(path)
	if err != nil {
		return v.failf(keysRefused, "%v", err)
	}
	n := d.Remove(qualify(name), *ns, *secret)
	if n == 0 {
		// The namespace and Secret are not echoed: they were not found, so
		// they were never checked as names.
		return v.failf(keysRefused, "no delivery of %s is declared in that namespace (and Secret, with --secret)", qualify(name))
	}
	if err := keydeliver.Write(path, d, env.deliveryCheck, env.deliveryChown); err != nil {
		return v.failf(keysRefused, "write the delivery declaration: %v", err)
	}
	fmt.Fprintf(env.stdout, "withdrew %d delivery target(s) of %s in namespace %s; %s\n", n, qualify(name), *ns, keysUndeliverHint)
	return keysOK
}

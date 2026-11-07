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
	"maps"
	"testing"
)

const modelType = "application/vnd.cncf.model.manifest.v1+json"

// TestQuotaFlag pins the --registry-quota grammar: <artifactType>=<bytes>, once
// per type, a media type with no parameters and a positive decimal count.
func TestQuotaFlag(t *testing.T) {
	var q QuotaFlag
	for _, v := range []string{modelType + "=1073741824", "application/wasm=10"} {
		if err := q.Set(v); err != nil {
			t.Fatalf("Set(%q): %v", v, err)
		}
	}
	want := QuotaFlag{modelType: 1 << 30, "application/wasm": 10}
	if !maps.Equal(q, want) {
		t.Fatalf("quota %v, want %v", q, want)
	}
	if got := q.String(); got != modelType+"=1073741824,application/wasm=10" {
		t.Errorf("String() = %q", got)
	}
	for _, v := range []string{
		modelType + "=5",        // given twice
		modelType,               // no bytes
		"application/x=0",       // not positive
		"application/x=-1",      // not positive
		"application/x=1k",      // not decimal
		"=10",                   // no type
		"not a type=10",         // not a media type
		"application/x; v=1=10", // parameters
		"Application/X=10",      // not canonical
	} {
		if err := q.Set(v); err == nil {
			t.Errorf("Set(%q) accepted", v)
		}
	}
}

// TestServeConfigRendersQuota: the quota the daemon is given is rendered into
// serve.json and read back as the server reads it, and a quota the server
// would refuse is refused by New and by the serve config check.
func TestServeConfigRendersQuota(t *testing.T) {
	work := t.TempDir()
	quota := map[string]int64{modelType: 1 << 30}
	s, err := New(Config{WorkDir: work, Port: 6450, Quota: quota})
	if err != nil {
		t.Fatal(err)
	}
	quota[modelType] = 1 // the service holds its own copy
	if err := s.provision(); err != nil {
		t.Fatal(err)
	}
	cfg, err := ReadServeConfig(ServeConfigPath(work))
	if err != nil {
		t.Fatal(err)
	}
	if want := map[string]int64{modelType: 1 << 30}; !maps.Equal(cfg.Quota, want) {
		t.Fatalf("serve config quota %v, want %v", cfg.Quota, want)
	}
	if err := cfg.validateForServing(); err != nil {
		t.Fatalf("validateForServing: %v", err)
	}

	for _, bad := range []map[string]int64{{modelType: 0}, {"": 1}, {"not a type": 1}} {
		if _, err := New(Config{WorkDir: work, Port: 6450, Quota: bad}); err == nil {
			t.Errorf("New accepted quota %v", bad)
		}
		c := ServeConfig{Listen: "127.0.0.1:6450", Quota: bad}
		if err := c.validateForServing(); err == nil {
			t.Errorf("validateForServing accepted quota %v", bad)
		}
	}

	// No quota renders no field, so a config written before quotas reads the same.
	plain := t.TempDir()
	p, err := New(Config{WorkDir: plain, Port: 6450})
	if err != nil {
		t.Fatal(err)
	}
	if err := p.provision(); err != nil {
		t.Fatal(err)
	}
	if cfg, err := ReadServeConfig(ServeConfigPath(plain)); err != nil || cfg.Quota != nil {
		t.Fatalf("a config without a quota read %v, %v", cfg.Quota, err)
	}
}

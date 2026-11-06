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
	"bytes"
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestVMPodFitAuditReportsEachRowShape(t *testing.T) {
	podSpec := func(runtimeClass string, images ...string) string {
		var cs []string
		for i, img := range images {
			cs = append(cs, fmt.Sprintf(`{"name":"c%d","image":%q}`, i, img))
		}
		rc := ""
		if runtimeClass != "" {
			rc = fmt.Sprintf(`"runtimeClassName":%q,`, runtimeClass)
		}
		return fmt.Sprintf(`{%s"containers":[%s]}`, rc, strings.Join(cs, ","))
	}
	meta := func(name string) string { return fmt.Sprintf(`"metadata":{"name":%q,"namespace":"ns"}`, name) }
	input := fmt.Sprintf(`{"apiVersion":"v1","kind":"List","items":[
	  {"apiVersion":"v1","kind":"Pod",%s,"spec":%s},
	  {"apiVersion":"apps/v1","kind":"Deployment",%s,"spec":{"template":{"spec":%s}}},
	  {"apiVersion":"v1","kind":"Pod",%s,"spec":%s},
	  {"apiVersion":"v1","kind":"Pod",%s,"spec":%s},
	  {"apiVersion":"batch/v1","kind":"CronJob",%s,"spec":{"jobTemplate":{"spec":{"template":{"spec":%s}}}}}
	]}`,
		meta("two"), podSpec("vm", "alpine", "busybox"),
		meta("host"), podSpec("vm", "native"),
		meta("legal"), podSpec("vm", "alpine"),
		meta("plain"), podSpec("", "native"),
		meta("cron"), podSpec("vm", "alpine"))

	var out bytes.Buffer
	err := AuditVMPodFit(strings.NewReader(input), &out)
	if !errors.Is(err, ErrVMPodFitRefused) {
		t.Fatalf("err = %v, want ErrVMPodFitRefused", err)
	}
	want := strings.Join([]string{
		"Pod ns/two\tR1\tk3sm: this vm pod names images alpine and busybox, and the vm runtime starts every container from one image, so the second command would run against the first image's files. Use one image, or separate Pods.",
		"Deployment ns/host\tR2\tk3sm: image native names a host binary, and a vm pod runs in a Linux guest. Use a Linux image, or remove runtimeClassName: vm.",
		"",
	}, "\n")
	if out.String() != want {
		t.Errorf("rows:\n%s\nwant:\n%s", out.String(), want)
	}

	t.Run("clean", func(t *testing.T) {
		var out bytes.Buffer
		clean := fmt.Sprintf(`{"kind":"List","items":[{"kind":"Pod",%s,"spec":%s}]}`, meta("ok"), podSpec("vm", "alpine"))
		if err := AuditVMPodFit(strings.NewReader(clean), &out); err != nil || out.Len() != 0 {
			t.Errorf("err=%v out=%q, want none", err, out.String())
		}
	})
	t.Run("unparsable is an input error", func(t *testing.T) {
		for _, in := range []string{"", "not json", `{"kind":"List","items":[{"kind":"Pod","spec":7}]}`} {
			err := AuditVMPodFit(strings.NewReader(in), &bytes.Buffer{})
			if err == nil || errors.Is(err, ErrVMPodFitRefused) {
				t.Errorf("input %q: err = %v, want an input error", in, err)
			}
		}
	})
}

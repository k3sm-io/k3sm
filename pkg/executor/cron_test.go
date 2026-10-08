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
	"errors"
	"testing"
	"time"
)

// TestParseCron is the cron parser's table: the k3s default and the shapes the
// snapshot docs name fire when cron would, and malformed or never-firing expressions
// are refused.
func TestParseCron(t *testing.T) {
	t.Parallel()
	// A Friday.
	from := time.Date(2026, 10, 2, 13, 7, 30, 0, time.UTC)
	at := func(mo time.Month, d, h, mi int) time.Time { return time.Date(2026, mo, d, h, mi, 0, 0, time.UTC) }
	for _, tc := range []struct {
		name string
		spec string
		want []time.Time // the next firings after from, in order
	}{
		{"the k3s default, every 12 hours", "0 */12 * * *", []time.Time{at(10, 3, 0, 0), at(10, 3, 12, 0), at(10, 4, 0, 0)}},
		{"every minute", "* * * * *", []time.Time{at(10, 2, 13, 8), at(10, 2, 13, 9)}},
		{"a list", "15,45 13 * * *", []time.Time{at(10, 2, 13, 15), at(10, 2, 13, 45), at(10, 3, 13, 15)}},
		{"a range", "0 9-10 * * *", []time.Time{at(10, 3, 9, 0), at(10, 3, 10, 0), at(10, 4, 9, 0)}},
		{"a stepped range", "0 1-7/3 * * *", []time.Time{at(10, 3, 1, 0), at(10, 3, 4, 0), at(10, 3, 7, 0)}},
		{"a start with a step", "50/5 * * * *", []time.Time{at(10, 2, 13, 50), at(10, 2, 13, 55), at(10, 2, 14, 50)}},
		{"extra whitespace", "  0   */12  *  *  * ", []time.Time{at(10, 3, 0, 0)}},
		{"day of week only (Monday)", "30 2 * * 1", []time.Time{at(10, 5, 2, 30), at(10, 12, 2, 30)}},
		{"Sunday as 7", "0 0 * * 7", []time.Time{at(10, 4, 0, 0), at(10, 11, 0, 0)}},
		{"day of month only", "0 0 1 * *", []time.Time{at(11, 1, 0, 0), at(12, 1, 0, 0)}},
		{"both day fields: either matches", "0 0 10 * 0", []time.Time{at(10, 4, 0, 0), at(10, 10, 0, 0), at(10, 11, 0, 0)}},
		{"a month", "0 0 1 1 *", []time.Time{time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)}},
		{"leap day", "0 0 29 2 *", []time.Time{time.Date(2028, 2, 29, 0, 0, 0, 0, time.UTC)}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			c, err := ParseCron(tc.spec)
			if err != nil {
				t.Fatalf("ParseCron(%q) = %v", tc.spec, err)
			}
			cur := from
			for i, want := range tc.want {
				got := c.Next(cur)
				if !got.Equal(want) {
					t.Fatalf("firing %d after %s = %s, want %s", i+1, cur, got, want)
				}
				cur = got
			}
		})
	}

	for _, tc := range []struct{ name, spec string }{
		{"empty", ""},
		{"four fields", "0 */12 * *"},
		{"six fields", "0 0 */12 * * *"},
		{"a name", "0 0 * * MON"},
		{"a descriptor", "@daily"},
		{"minute out of range", "60 * * * *"},
		{"hour out of range", "0 24 * * *"},
		{"day of month zero", "0 0 0 * *"},
		{"month thirteen", "0 0 1 13 *"},
		{"day of week eight", "0 0 * * 8"},
		{"zero step", "*/0 * * * *"},
		{"negative step", "*/-1 * * * *"},
		{"backwards range", "0 10-9 * * *"},
		{"empty list element", "0,,5 * * * *"},
		{"the 30th of February never fires", "0 0 30 2 *"},
	} {
		t.Run("refuses "+tc.name, func(t *testing.T) {
			t.Parallel()
			if c, err := ParseCron(tc.spec); !errors.Is(err, ErrCronSpec) {
				t.Fatalf("ParseCron(%q) = %v, %v; want ErrCronSpec", tc.spec, c, err)
			}
		})
	}

	t.Run("String is the normalised expression", func(t *testing.T) {
		t.Parallel()
		c, err := ParseCron(" 0  */12 * * * ")
		if err != nil {
			t.Fatal(err)
		}
		if c.String() != "0 */12 * * *" {
			t.Fatalf("String() = %q", c.String())
		}
	})

	t.Run("Next is strictly after a matching minute", func(t *testing.T) {
		t.Parallel()
		c, err := ParseCron("0 */12 * * *")
		if err != nil {
			t.Fatal(err)
		}
		on := at(10, 3, 12, 0)
		if got := c.Next(on); !got.Equal(at(10, 4, 0, 0)) {
			t.Fatalf("Next(%s) = %s, want the following firing", on, got)
		}
	})

	t.Run("Next keeps the input's location across a daylight-saving change", func(t *testing.T) {
		t.Parallel()
		loc, err := time.LoadLocation("America/Los_Angeles")
		if err != nil {
			t.Skip("no zoneinfo:", err)
		}
		c, err := ParseCron("30 2 * * *")
		if err != nil {
			t.Fatal(err)
		}
		// 2:30 does not exist on 2026-03-08 in Los Angeles; the next firing is after
		// the gap and every firing moves forward.
		cur := time.Date(2026, 3, 7, 3, 0, 0, 0, loc)
		for range 3 {
			next := c.Next(cur)
			if !next.After(cur) || next.Location() != loc {
				t.Fatalf("Next(%s) = %s", cur, next)
			}
			cur = next
		}
	})
}

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
	"fmt"
	"strconv"
	"strings"
	"time"
)

// The standard five-field cron expression the etcd snapshot schedule is written in:
//
//	minute hour day-of-month month day-of-week
//
// Each field is `*`, a number, a range `a-b`, a step `*/n` or `a-b/n`, or a comma
// list of those. Day-of-week is 0-6 with Sunday as 0 (7 is accepted as Sunday too).
//
// The two day fields combine by Vixie cron's rule: a day field whose text starts
// with `*` (so `*` and `*/n` alike) counts as unrestricted; when either day field is
// unrestricted a day must match both, and when both are restricted a day matching
// either one fires. k3s's default schedule restricts neither day field, so the
// rule does not change when it fires.
//
// Names (JAN, MON), the `@daily` descriptors and a seconds field are not accepted;
// k3s's own default and documented examples need none of them.

// ErrCronSpec reports a cron expression that does not parse or never fires.
var ErrCronSpec = errors.New("executor: invalid cron expression")

// cronSearchYears bounds Next: a schedule that names no reachable minute in this many
// years ("0 0 30 2 *", the 30th of February) never fires, and ParseCron refuses it.
const cronSearchYears = 5

// CronSchedule is a parsed five-field cron expression. The zero value is not usable;
// build one with ParseCron.
type CronSchedule struct {
	spec                          string
	minute, hour, dom, month, dow uint64
	// domStar and dowStar record a day field that starts with `*`, which decides
	// how the two day fields combine (Vixie cron's rule).
	domStar, dowStar bool
}

// cronField is one field's name and inclusive bounds.
type cronField struct {
	name     string
	min, max int
}

var cronFields = [5]cronField{
	{"minute", 0, 59},
	{"hour", 0, 23},
	{"day-of-month", 1, 31},
	{"month", 1, 12},
	{"day-of-week", 0, 7},
}

// ParseCron parses a standard five-field cron expression.
func ParseCron(spec string) (*CronSchedule, error) {
	fields := strings.Fields(spec)
	if len(fields) != len(cronFields) {
		return nil, fmt.Errorf("%w %q: want 5 fields (minute hour day-of-month month day-of-week), got %d", ErrCronSpec, spec, len(fields))
	}
	var bits [5]uint64
	for i, f := range fields {
		b, err := parseCronField(f, cronFields[i])
		if err != nil {
			return nil, fmt.Errorf("%w %q: %s field %q: %w", ErrCronSpec, spec, cronFields[i].name, f, err)
		}
		bits[i] = b
	}
	// Day-of-week 7 is Sunday: fold it onto 0.
	if bits[4]&(1<<7) != 0 {
		bits[4] = bits[4]&^(1<<7) | 1
	}
	c := &CronSchedule{
		spec:   strings.Join(fields, " "),
		minute: bits[0], hour: bits[1], dom: bits[2], month: bits[3], dow: bits[4],
		domStar: strings.HasPrefix(fields[2], "*"), dowStar: strings.HasPrefix(fields[4], "*"),
	}
	probe := time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)
	if c.Next(probe).IsZero() {
		return nil, fmt.Errorf("%w %q: it names no date that exists, so it would never fire", ErrCronSpec, spec)
	}
	return c, nil
}

// parseCronField parses one comma list into a bit set over f's bounds.
func parseCronField(s string, f cronField) (uint64, error) {
	var bits uint64
	for part := range strings.SplitSeq(s, ",") {
		if part == "" {
			return 0, errors.New("empty list element")
		}
		rng, stepStr, hasStep := strings.Cut(part, "/")
		step := 1
		if hasStep {
			n, err := strconv.Atoi(stepStr)
			if err != nil || n < 1 {
				return 0, fmt.Errorf("step %q is not a positive number", stepStr)
			}
			step = n
		}
		lo, hi := f.min, f.max
		switch {
		case rng == "*":
		case strings.Contains(rng, "-"):
			a, b, _ := strings.Cut(rng, "-")
			var err error
			if lo, err = cronNumber(a, f); err != nil {
				return 0, err
			}
			if hi, err = cronNumber(b, f); err != nil {
				return 0, err
			}
			if lo > hi {
				return 0, fmt.Errorf("range %q runs backwards", rng)
			}
		default:
			n, err := cronNumber(rng, f)
			if err != nil {
				return 0, err
			}
			lo, hi = n, n
			if hasStep {
				// "5/15" is "5-max/15", as in every cron that accepts it.
				hi = f.max
			}
		}
		for v := lo; v <= hi; v += step {
			bits |= 1 << v
		}
	}
	return bits, nil
}

// cronNumber parses one value and checks it against f's bounds.
func cronNumber(s string, f cronField) (int, error) {
	n, err := strconv.Atoi(s)
	if err != nil {
		return 0, fmt.Errorf("%q is not a number", s)
	}
	if n < f.min || n > f.max {
		return 0, fmt.Errorf("%d is outside %d-%d", n, f.min, f.max)
	}
	return n, nil
}

// String returns the expression as parsed (fields single-spaced).
func (c *CronSchedule) String() string { return c.spec }

// Next returns the first minute strictly after t that the schedule matches, in t's
// location, or the zero time when none exists within cronSearchYears.
func (c *CronSchedule) Next(t time.Time) time.Time {
	loc := t.Location()
	start := t
	t = time.Date(t.Year(), t.Month(), t.Day(), t.Hour(), t.Minute(), 0, 0, loc).Add(time.Minute)
	limit := start.Year() + cronSearchYears
	// advance moves to next, unless a wall-clock normalisation (a daylight-saving
	// change) would not move forward, in which case it steps one minute.
	advance := func(next time.Time) time.Time {
		if !next.After(t) {
			return t.Add(time.Minute)
		}
		return next
	}
	for t.Year() <= limit {
		switch {
		case c.month&(1<<uint(t.Month())) == 0:
			t = advance(time.Date(t.Year(), t.Month()+1, 1, 0, 0, 0, 0, loc))
		case !c.dayMatches(t):
			t = advance(time.Date(t.Year(), t.Month(), t.Day()+1, 0, 0, 0, 0, loc))
		case c.hour&(1<<uint(t.Hour())) == 0:
			t = advance(time.Date(t.Year(), t.Month(), t.Day(), t.Hour()+1, 0, 0, 0, loc))
		case c.minute&(1<<uint(t.Minute())) == 0:
			t = t.Add(time.Minute)
		default:
			return t
		}
	}
	return time.Time{}
}

// dayMatches applies the two day fields the way cron does.
func (c *CronSchedule) dayMatches(t time.Time) bool {
	dom := c.dom&(1<<uint(t.Day())) != 0
	dow := c.dow&(1<<uint(t.Weekday())) != 0
	if c.domStar || c.dowStar {
		return dom && dow
	}
	return dom || dow
}

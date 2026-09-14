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

package datavol

import (
	"fmt"
	"strconv"
	"strings"
)

const (
	// MinQuotaBytes is the smallest quota k3sm will create a data volume with.
	//
	// It is several times runtimed's reclaim target (10 GiB), so that the
	// reclaim ladder's band -- and the provider's 2 GiB DiskPressure floor,
	// which are all absolute byte counts -- stay a small fraction of the
	// volume rather than half of it. A volume near the floor would live
	// permanently inside the band that triggers reclamation.
	MinQuotaBytes uint64 = 32 << 30
	// DefaultQuotaBytes is the quota k3sm install --data-volume uses when the
	// operator names no size.
	DefaultQuotaBytes uint64 = 100 << 30
)

// ParseSize parses a size written the way the install flag takes it: a decimal
// count with an optional m, g or t suffix, case-insensitive. The suffixes are
// BINARY units, so 100g is 100 * 2^30 bytes, matching what diskutil reports
// back and what FormatSize prints. A bare number is a byte count.
func ParseSize(s string) (uint64, error) {
	t := strings.TrimSpace(s)
	if t == "" {
		return 0, fmt.Errorf("size is empty")
	}
	mult := uint64(1)
	switch last := t[len(t)-1]; last {
	case 'm', 'M':
		mult = 1 << 20
	case 'g', 'G':
		mult = 1 << 30
	case 't', 'T':
		mult = 1 << 40
	default:
		if last < '0' || last > '9' {
			return 0, fmt.Errorf("size %q: unknown unit %q, want m, g or t", s, string(last))
		}
	}
	digits := t
	if mult != 1 {
		digits = t[:len(t)-1]
	}
	n, err := strconv.ParseUint(digits, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("size %q: %w", s, err)
	}
	if n != 0 && n > ^uint64(0)/mult {
		return 0, fmt.Errorf("size %q: overflows 64 bits", s)
	}
	return n * mult, nil
}

// FormatSize renders a byte count the way status and the install log print it:
// the largest binary unit that fits, one decimal place unless the value is an
// exact multiple ("100G", "29.9G", "512M").
func FormatSize(b uint64) string {
	units := []struct {
		name string
		size uint64
	}{
		{"T", 1 << 40},
		{"G", 1 << 30},
		{"M", 1 << 20},
		{"K", 1 << 10},
	}
	for _, u := range units {
		if b < u.size {
			continue
		}
		if b%u.size == 0 {
			return fmt.Sprintf("%d%s", b/u.size, u.name)
		}
		return fmt.Sprintf("%.1f%s", float64(b)/float64(u.size), u.name)
	}
	return fmt.Sprintf("%dB", b)
}

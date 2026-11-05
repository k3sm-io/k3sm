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

package api

import (
	"errors"
	"strconv"
)

// Bounds of a chunk range. maxOffset keeps end-start+1 and every offset sum
// inside int64; no blob is that large.
const (
	maxOffset      = int64(1) << 62
	maxRangeDigits = 19
	maxRangeLen    = 2*maxRangeDigits + 1
)

// errBadRange is a Content-Range value outside the grammar.
var errBadRange = errors.New("malformed chunk range")

// parseChunkRange parses the Content-Range value of an OCI chunked upload:
// "<start>-<end>", two decimal numbers without sign, space, unit or leading
// zero (a lone "0" excepted), with start <= end <= maxOffset. Both bounds are
// inclusive. Anything else is refused.
func parseChunkRange(s string) (start, end int64, err error) {
	if len(s) < 3 || len(s) > maxRangeLen {
		return 0, 0, errBadRange
	}
	dash := -1
	for i := 0; i < len(s); i++ {
		if s[i] == '-' {
			if dash >= 0 {
				return 0, 0, errBadRange
			}
			dash = i
		}
	}
	if dash < 0 {
		return 0, 0, errBadRange
	}
	if start, err = parseOffset(s[:dash]); err != nil {
		return 0, 0, err
	}
	if end, err = parseOffset(s[dash+1:]); err != nil {
		return 0, 0, err
	}
	if start > end {
		return 0, 0, errBadRange
	}
	return start, end, nil
}

// parseOffset parses one bound: 1 to maxRangeDigits decimal digits, no leading
// zero unless the value is 0, at most maxOffset.
func parseOffset(s string) (int64, error) {
	if s == "" || len(s) > maxRangeDigits || (len(s) > 1 && s[0] == '0') {
		return 0, errBadRange
	}
	var v int64
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < '0' || c > '9' {
			return 0, errBadRange
		}
		d := int64(c - '0')
		if v > (maxOffset-d)/10 {
			return 0, errBadRange
		}
		v = v*10 + d
	}
	return v, nil
}

// formatRange is the Range header of a session holding size bytes:
// "0-<size-1>", and "0-0" for an empty session, as clients expect.
func formatRange(size int64) string {
	if size <= 0 {
		return "0-0"
	}
	return "0-" + strconv.FormatInt(size-1, 10)
}

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

import (
	"io"
	"sync"
)

// plainState is where a PlainWriter is inside a terminal control sequence.
type plainState int

const (
	plainText   plainState = iota
	plainEsc               // after ESC
	plainCSI               // inside ESC [ ... final byte
	plainString            // inside an OSC/DCS/APC/PM/SOS string
	plainStrEsc            // ESC inside a string: ESC \ ends it
)

// PlainWriter removes terminal control from what it writes through: escape
// sequences (CSI such as colours, cursor moves and line clears; OSC and the
// other string sequences; two-byte escapes), carriage returns, and every other
// C0 control byte except newline and tab. What is left is the text a terminal
// would have shown, one redraw after another, which is what a stored log
// should hold. A sequence split across writes is handled, so give each stream
// its own writer. Bytes from 0x80 up pass through, so UTF-8 text is kept.
type PlainWriter struct {
	mu    sync.Mutex // guards state
	w     io.Writer
	state plainState
}

// NewPlainWriter returns a PlainWriter over w.
func NewPlainWriter(w io.Writer) *PlainWriter { return &PlainWriter{w: w} }

// Write filters p and writes the rest to the underlying writer, reporting all
// of p consumed unless that write fails.
func (p *PlainWriter) Write(b []byte) (int, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]byte, 0, len(b))
	for _, c := range b {
		switch p.state {
		case plainText:
			switch {
			case c == 0x1b:
				p.state = plainEsc
			case c == '\n' || c == '\t' || (c >= 0x20 && c != 0x7f):
				out = append(out, c)
			}
		case plainEsc:
			switch c {
			case '[':
				p.state = plainCSI
			case ']', 'P', 'X', '^', '_':
				p.state = plainString
			default:
				p.state = plainText
			}
		case plainCSI:
			if c >= 0x40 && c <= 0x7e {
				p.state = plainText
			}
		case plainString:
			switch c {
			case 0x07:
				p.state = plainText
			case 0x1b:
				p.state = plainStrEsc
			}
		case plainStrEsc:
			if c == '\\' {
				p.state = plainText
			} else {
				p.state = plainString
			}
		}
	}
	if len(out) > 0 {
		if _, err := p.w.Write(out); err != nil {
			return 0, err
		}
	}
	return len(b), nil
}

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

package oci

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/google/go-containerregistry/pkg/name"
)

// Verb is an accepted Dockerfile instruction. The set is closed: see the
// package comment for the full grammar.
type Verb string

// The accepted verbs.
const (
	VerbFrom       Verb = "FROM"
	VerbCopy       Verb = "COPY"
	VerbAdd        Verb = "ADD"
	VerbEnv        Verb = "ENV"
	VerbEntrypoint Verb = "ENTRYPOINT"
	VerbCmd        Verb = "CMD"
	VerbWorkdir    Verb = "WORKDIR"
	VerbLabel      Verb = "LABEL"
	VerbExpose     Verb = "EXPOSE"
)

// Parse rejects these with ErrUnsupportedInstruction rather than
// ErrUnknownInstruction: they are real Dockerfile verbs a user may reasonably
// write, so the error should say "not supported" and not "unknown". Silently
// ignoring any of them would produce an image whose behavior diverges from the
// recipe with no signal at build time.
var knownUnsupported = map[string]bool{
	"RUN":         true, // handled separately — ErrRunUnsupported names the vm builder
	"USER":        true,
	"VOLUME":      true,
	"HEALTHCHECK": true,
	"SHELL":       true,
	"STOPSIGNAL":  true,
	"ONBUILD":     true,
	"ARG":         true,
	"MAINTAINER":  true,
}

// Parse errors. Compare with errors.Is; the wrapped message names the offending
// line and construct.
var (
	// ErrRunUnsupported reports a RUN instruction. Its message names the
	// vm-backed builder as the RUN-capable path — a build step that executes
	// code is the security boundary this subset exists to draw, so the refusal
	// is total and never a warning.
	ErrRunUnsupported = errors.New("oci: RUN is not supported by the native builder")

	// ErrUnsupportedInstruction reports a standard Dockerfile verb outside the
	// accepted subset.
	ErrUnsupportedInstruction = errors.New("oci: unsupported Dockerfile instruction")

	// ErrUnknownInstruction reports a token that is not a Dockerfile verb at all.
	ErrUnknownInstruction = errors.New("oci: unknown Dockerfile instruction")

	// ErrUnsupportedSyntax reports a construct a subset parser would otherwise
	// mis-read: a heredoc, a parser directive, a per-instruction flag, a
	// variable reference in a path, or a second FROM.
	ErrUnsupportedSyntax = errors.New("oci: unsupported Dockerfile syntax")

	// ErrMissingFrom reports a Dockerfile whose first instruction is not FROM.
	ErrMissingFrom = errors.New("oci: Dockerfile must begin with FROM")

	// ErrUnsupportedBase reports a FROM whose base cannot be used by this build.
	// The parser accepts any well-formed reference; it is Build that returns this
	// when a named base was requested and no BaseResolver was configured, because
	// resolving one is a network operation the library never performs on its own.
	ErrUnsupportedBase = errors.New("oci: this build cannot resolve a named FROM base")

	// ErrRemoteSource reports an ADD whose source is a URL. This builder performs
	// no network reads.
	ErrRemoteSource = errors.New("oci: ADD does not fetch remote sources")

	// ErrArchiveAutoExtract reports an ADD whose source is an archive. Docker
	// would auto-extract it; this builder refuses rather than silently copying,
	// because a silent downgrade produces content the recipe did not describe.
	ErrArchiveAutoExtract = errors.New("oci: ADD does not auto-extract archives")

	// ErrBadInstruction reports a syntactically malformed instruction (missing
	// operands, unterminated quoting, malformed JSON array).
	ErrBadInstruction = errors.New("oci: malformed instruction")
)

// Instruction is one parsed Dockerfile instruction.
type Instruction struct {
	Verb Verb
	Line int    // 1-based line of the instruction's first physical line
	Raw  string // the logical source line, recorded verbatim as History.CreatedBy

	// Args holds the operands, already word-split and unquoted for shell forms,
	// or the JSON array elements for exec forms.
	Args []string
	// JSON reports whether the operands were given in JSON-array (exec) form.
	// ENTRYPOINT and CMD are wrapped in a shell invocation when this is false.
	JSON bool
}

// Dockerfile is a parsed, validated Dockerfile in the accepted subset.
type Dockerfile struct {
	Instructions []Instruction
}

// maxDockerfileBytes bounds the parser's input. A Dockerfile is a recipe, not a
// payload; anything larger is a mistake or an attempt to exhaust memory.
const maxDockerfileBytes = 1 << 20

// Parse reads a Dockerfile and returns its instructions, or an error naming the
// first rejected construct. It is a strict allowlist: see the package comment.
//
// Parsing is complete before any caller opens an output — a Dockerfile whose RUN
// sits on the last line is rejected without a single byte having been written.
func Parse(r io.Reader) (*Dockerfile, error) {
	lines, err := logicalLines(io.LimitReader(r, maxDockerfileBytes+1))
	if err != nil {
		return nil, err
	}

	df := &Dockerfile{}
	for _, ln := range lines {
		inst, err := parseInstruction(ln)
		if err != nil {
			return nil, err
		}
		if inst.Verb == VerbFrom && len(df.Instructions) > 0 {
			return nil, fmt.Errorf("line %d: a second FROM (multi-stage build): %w", ln.num, ErrUnsupportedSyntax)
		}
		if inst.Verb != VerbFrom && len(df.Instructions) == 0 {
			return nil, fmt.Errorf("line %d: first instruction is %s: %w", ln.num, inst.Verb, ErrMissingFrom)
		}
		df.Instructions = append(df.Instructions, *inst)
	}
	if len(df.Instructions) == 0 {
		return nil, fmt.Errorf("no instructions: %w", ErrMissingFrom)
	}
	return df, nil
}

// logicalLine is a source line with continuations already joined.
type logicalLine struct {
	num  int    // 1-based line number of the first physical line
	text string // the joined, comment-stripped instruction text
}

// logicalLines splits input into instruction lines, honoring line continuations
// and full-line comments. A parser directive ("# syntax=", "# escape=") is
// rejected rather than ignored, so an operator never believes a custom frontend
// or a non-default escape character took effect.
func logicalLines(r io.Reader) ([]logicalLine, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), maxDockerfileBytes+1)

	var (
		out       []logicalLine
		pending   strings.Builder
		startLine int
		seenInst  bool
		n         int
		total     int
	)
	for sc.Scan() {
		n++
		raw := strings.TrimRight(sc.Text(), "\r")
		total += len(raw) + 1
		if total > maxDockerfileBytes {
			return nil, fmt.Errorf("Dockerfile exceeds %d bytes: %w", maxDockerfileBytes, ErrBadInstruction)
		}
		trimmed := strings.TrimSpace(raw)

		if pending.Len() == 0 {
			if trimmed == "" {
				continue
			}
			if strings.HasPrefix(trimmed, "#") {
				// Directives are only meaningful before the first instruction,
				// but reject them anywhere: honoring neither and ignoring them
				// silently are different failures, and only one is legible.
				body := strings.ToLower(strings.TrimSpace(strings.TrimPrefix(trimmed, "#")))
				if !seenInst && (strings.HasPrefix(body, "syntax=") || strings.HasPrefix(body, "escape=")) {
					return nil, fmt.Errorf("line %d: parser directive %q: %w", n, trimmed, ErrUnsupportedSyntax)
				}
				continue
			}
			startLine = n
		}

		if strings.Contains(raw, "<<") {
			return nil, fmt.Errorf("line %d: heredoc: %w", n, ErrUnsupportedSyntax)
		}

		if cont, ok := strings.CutSuffix(trimmed, `\`); ok {
			pending.WriteString(cont)
			pending.WriteString(" ")
			continue
		}
		pending.WriteString(trimmed)
		out = append(out, logicalLine{num: startLine, text: strings.TrimSpace(pending.String())})
		pending.Reset()
		seenInst = true
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("read Dockerfile: %w", err)
	}
	if pending.Len() > 0 {
		return nil, fmt.Errorf("line %d: unterminated line continuation: %w", startLine, ErrBadInstruction)
	}
	return out, nil
}

// parseInstruction validates one logical line against the accepted subset.
func parseInstruction(ln logicalLine) (*Instruction, error) {
	verb, rest, _ := strings.Cut(ln.text, " ")
	upper := strings.ToUpper(verb)
	rest = strings.TrimSpace(rest)

	if upper == "RUN" {
		return nil, fmt.Errorf(
			"line %d: %w — this builder packages files, it does not execute them; "+
				"the RUN-capable path is the vm-backed builder (a BuildKit builder inside a "+
				"vm-RuntimeClass micro-VM), which is not available yet",
			ln.num, ErrRunUnsupported)
	}
	if knownUnsupported[upper] {
		return nil, fmt.Errorf("line %d: %s: %w", ln.num, upper, ErrUnsupportedInstruction)
	}

	inst := &Instruction{Line: ln.num, Raw: ln.text}
	switch Verb(upper) {
	case VerbFrom, VerbCopy, VerbAdd, VerbEnv, VerbEntrypoint, VerbCmd, VerbWorkdir, VerbLabel, VerbExpose:
		inst.Verb = Verb(upper)
	default:
		return nil, fmt.Errorf("line %d: %q: %w", ln.num, verb, ErrUnknownInstruction)
	}
	if rest == "" {
		return nil, fmt.Errorf("line %d: %s has no operands: %w", ln.num, upper, ErrBadInstruction)
	}

	// A per-instruction flag changes what the instruction means (--from selects a
	// stage rather than the context; --chown/--chmod perturb the tar metadata the
	// layer digest is computed over). Ignoring one silently would build a
	// different image than the recipe describes.
	if strings.HasPrefix(rest, "--") {
		flag, _, _ := strings.Cut(rest, " ")
		return nil, fmt.Errorf("line %d: %s flag %q: %w", ln.num, upper, flag, ErrUnsupportedSyntax)
	}

	switch inst.Verb {
	case VerbFrom:
		return inst, parseFrom(inst, rest)
	case VerbCopy, VerbAdd:
		return inst, parseCopy(inst, rest)
	case VerbEntrypoint, VerbCmd:
		return inst, parseExecOrShell(inst, rest)
	case VerbEnv:
		return inst, parseEnv(inst, rest)
	case VerbLabel:
		return inst, parseKeyValues(inst, rest)
	case VerbWorkdir:
		return inst, parseWorkdir(inst, rest)
	case VerbExpose:
		return inst, parseExpose(inst, rest)
	}
	return inst, nil
}

func parseFrom(inst *Instruction, rest string) error {
	words, err := splitWords(rest)
	if err != nil {
		return fmt.Errorf("line %d: FROM: %w", inst.Line, err)
	}
	// "FROM scratch AS name" names a single stage; the name is inert here.
	if len(words) == 3 && strings.EqualFold(words[1], "AS") {
		words = words[:1]
	}
	if len(words) != 1 {
		return fmt.Errorf("line %d: FROM takes one base image: %w", inst.Line, ErrBadInstruction)
	}
	if strings.EqualFold(words[0], "scratch") {
		inst.Args = []string{ScratchBase}
		return nil
	}
	// A named base is parsed, not fetched. Validating the reference here keeps a
	// typo a PARSE error — reported with its line, before any output is opened,
	// like every other rejection in this file — rather than a network error
	// surfacing later with no line number attached.
	if _, err := name.ParseReference(words[0]); err != nil {
		return fmt.Errorf("line %d: FROM %s: %w: %v", inst.Line, words[0], ErrBadInstruction, err)
	}
	inst.Args = []string{words[0]}
	return nil
}

// ScratchBase is the FROM operand naming the empty base. It is the one base the
// builder can assemble with no I/O beyond the build context.
const ScratchBase = "scratch"

// Base returns the FROM operand, and whether it names something other than
// scratch. A parsed Dockerfile always begins with FROM (ErrMissingFrom), so the
// zero case here means the caller built a Dockerfile value by hand.
func (d *Dockerfile) Base() (ref string, named bool) {
	for _, inst := range d.Instructions {
		if inst.Verb == VerbFrom {
			if len(inst.Args) == 0 || inst.Args[0] == ScratchBase {
				return ScratchBase, false
			}
			return inst.Args[0], true
		}
	}
	return ScratchBase, false
}

// archiveSuffixes are the extensions Docker's ADD would auto-extract.
var archiveSuffixes = []string{
	".tar", ".tar.gz", ".tgz", ".tar.bz2", ".tbz2", ".tar.xz", ".txz", ".tar.zst", ".tzst",
}

func parseCopy(inst *Instruction, rest string) error {
	args, jsonForm, err := operands(rest)
	if err != nil {
		return fmt.Errorf("line %d: %s: %w", inst.Line, inst.Verb, err)
	}
	if len(args) < 2 {
		return fmt.Errorf("line %d: %s needs at least one source and a destination: %w", inst.Line, inst.Verb, ErrBadInstruction)
	}
	for _, a := range args {
		// Variable expansion is not implemented. Treating "$VAR" as a literal
		// path component would be an invisible divergence from Docker, and a
		// containment check is only sound AFTER expansion — so refuse instead.
		if strings.Contains(a, "$") {
			return fmt.Errorf("line %d: %s path %q contains a variable reference: %w", inst.Line, inst.Verb, a, ErrUnsupportedSyntax)
		}
	}
	if inst.Verb == VerbAdd {
		for _, src := range args[:len(args)-1] {
			if strings.Contains(src, "://") {
				return fmt.Errorf("line %d: ADD %s: %w", inst.Line, src, ErrRemoteSource)
			}
			lower := strings.ToLower(src)
			for _, sfx := range archiveSuffixes {
				if strings.HasSuffix(lower, sfx) {
					return fmt.Errorf("line %d: ADD %s: %w (use COPY to add the archive verbatim)", inst.Line, src, ErrArchiveAutoExtract)
				}
			}
		}
	}
	inst.Args, inst.JSON = args, jsonForm
	return nil
}

func parseExecOrShell(inst *Instruction, rest string) error {
	args, jsonForm, err := operands(rest)
	if err != nil {
		return fmt.Errorf("line %d: %s: %w", inst.Line, inst.Verb, err)
	}
	if jsonForm && len(args) == 0 {
		return fmt.Errorf("line %d: %s has an empty exec form: %w", inst.Line, inst.Verb, ErrBadInstruction)
	}
	if !jsonForm {
		// Shell form: the whole remainder is one command string, wrapped at
		// build time. Keep it verbatim rather than word-splitting it.
		args = []string{rest}
	}
	inst.Args, inst.JSON = args, jsonForm
	return nil
}

func parseEnv(inst *Instruction, rest string) error {
	words, err := splitWords(rest)
	if err != nil {
		return fmt.Errorf("line %d: ENV: %w", inst.Line, err)
	}
	if len(words) == 0 {
		return fmt.Errorf("line %d: ENV has no operands: %w", inst.Line, ErrBadInstruction)
	}
	// Legacy form "ENV key value rest of value" — only when the first word
	// carries no '='.
	if !strings.Contains(words[0], "=") {
		if len(words) < 2 {
			return fmt.Errorf("line %d: ENV %s has no value: %w", inst.Line, words[0], ErrBadInstruction)
		}
		inst.Args = []string{words[0] + "=" + strings.Join(words[1:], " ")}
		return nil
	}
	return parseKeyValues(inst, rest)
}

func parseKeyValues(inst *Instruction, rest string) error {
	words, err := splitWords(rest)
	if err != nil {
		return fmt.Errorf("line %d: %s: %w", inst.Line, inst.Verb, err)
	}
	if len(words) == 0 {
		return fmt.Errorf("line %d: %s has no operands: %w", inst.Line, inst.Verb, ErrBadInstruction)
	}
	pairs := make([]string, 0, len(words))
	for _, w := range words {
		k, _, ok := strings.Cut(w, "=")
		if !ok || k == "" {
			return fmt.Errorf("line %d: %s operand %q is not key=value: %w", inst.Line, inst.Verb, w, ErrBadInstruction)
		}
		pairs = append(pairs, w)
	}
	inst.Args = pairs
	return nil
}

func parseWorkdir(inst *Instruction, rest string) error {
	words, err := splitWords(rest)
	if err != nil {
		return fmt.Errorf("line %d: WORKDIR: %w", inst.Line, err)
	}
	if len(words) != 1 {
		return fmt.Errorf("line %d: WORKDIR takes one path: %w", inst.Line, ErrBadInstruction)
	}
	if strings.Contains(words[0], "$") {
		return fmt.Errorf("line %d: WORKDIR %q contains a variable reference: %w", inst.Line, words[0], ErrUnsupportedSyntax)
	}
	inst.Args = words
	return nil
}

func parseExpose(inst *Instruction, rest string) error {
	words, err := splitWords(rest)
	if err != nil {
		return fmt.Errorf("line %d: EXPOSE: %w", inst.Line, err)
	}
	ports := make([]string, 0, len(words))
	for _, w := range words {
		port, proto, ok := strings.Cut(w, "/")
		if !ok {
			proto = "tcp"
		}
		proto = strings.ToLower(proto)
		if proto != "tcp" && proto != "udp" {
			return fmt.Errorf("line %d: EXPOSE %q has protocol %q: %w", inst.Line, w, proto, ErrBadInstruction)
		}
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 {
			return fmt.Errorf("line %d: EXPOSE %q is not a port: %w", inst.Line, w, ErrBadInstruction)
		}
		ports = append(ports, port+"/"+proto)
	}
	if len(ports) == 0 {
		return fmt.Errorf("line %d: EXPOSE has no ports: %w", inst.Line, ErrBadInstruction)
	}
	inst.Args = ports
	return nil
}

// operands returns an instruction's operands, reporting whether they were given
// in JSON-array (exec) form.
func operands(rest string) ([]string, bool, error) {
	if strings.HasPrefix(rest, "[") {
		var arr []string
		if err := json.Unmarshal([]byte(rest), &arr); err != nil {
			return nil, true, fmt.Errorf("malformed JSON array: %w", ErrBadInstruction)
		}
		return arr, true, nil
	}
	w, err := splitWords(rest)
	return w, false, err
}

// splitWords splits on unquoted whitespace, honoring double and single quotes
// and backslash escapes, and strips one level of quoting.
func splitWords(s string) ([]string, error) {
	var (
		out   []string
		cur   strings.Builder
		quote rune
		esc   bool
		open  bool
	)
	for _, r := range s {
		switch {
		case esc:
			cur.WriteRune(r)
			esc = false
			open = true
		case r == '\\' && quote != '\'':
			esc = true
			open = true
		case quote != 0:
			if r == quote {
				quote = 0
			} else {
				cur.WriteRune(r)
			}
		case r == '"' || r == '\'':
			quote = r
			open = true
		case r == ' ' || r == '\t':
			if open {
				out = append(out, cur.String())
				cur.Reset()
				open = false
			}
		default:
			cur.WriteRune(r)
			open = true
		}
	}
	if quote != 0 || esc {
		return nil, fmt.Errorf("unterminated quoting: %w", ErrBadInstruction)
	}
	if open {
		out = append(out, cur.String())
	}
	return out, nil
}

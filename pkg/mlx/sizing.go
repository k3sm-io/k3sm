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

package mlx

import (
	"fmt"
	"strconv"

	"k8s.io/apimachinery/pkg/api/resource"
)

// The serving engine, its MEASURED command-line surface, and the two facts about
// it that this file encodes.
//
// The engine is vllm-mlx 0.4.1 (the version hack/images/mlx-serve/build.sh
// installs). Its `serve` surface was measured on the rig and reproduced
// host-side; this is the whole of it:
//
//	model                   POSITIONAL — a repository reference or a local path.
//	                        There is NO --model option.
//	--models-config <path>
//	--max-kv-size <tokens>  the KV-cache ceiling: the term that grows.
//	--max-num-seqs <n>      the concurrent-sequence ceiling.
//	--max-tokens <n>        the per-response generation ceiling.
//	--continuous-batching   boolean; see below.
//	--host <addr>           supplied by the image ENTRYPOINT.
//	--port <n>              supplied by the ENTRYPOINT and re-supplied here.
//
// ABSENT, and each absent differently: --model, --revision, --quantization,
// --max-model-len.
//
// THE SILENT-PREFIX-MATCH LESSON. This block previously recorded --max-model-len
// and --max-num-seqs as unmeasured vLLM spellings and argued the risk was
// acceptable because "the failure is loud — the engine exits on an unknown flag".
// Half of that was true and the important half was false. --revision,
// --quantization and --max-model-len did exit argparse loudly. `--model <repo>`
// did NOT: Python's argparse abbreviates options by default, `--model` is an
// unambiguous prefix of `--models-config`, and the repository reference was
// therefore bound SILENTLY to the models-config option — a healthy-looking
// process serving nothing anyone asked for. So an argument surface is never
// assumed from a sibling project's spelling, and the accepted set is pinned by a
// test against the measurement (TestEngineArgsMatchTheMeasuredSurface), with
// EXACT membership, because a prefix-tolerant check would have accepted the very
// bug it exists to catch.
//
// Two properties of the engine are contract, not tuning:
//
//   - --continuous-batching is REQUIRED in argv. It is not the default, and
//     without it the engine serves exactly one request at a time and answers
//     HTTP 503 to every other concurrent client (S5 measured 1 of 8 requests
//     served, with `waiters=0` in the 503 body — a rejection, not a queue).
//     Nothing else catches this: /health stays healthy and the readiness probe
//     stays green, so the pod presents as a broken load balancer. S5 measured
//     the flag as a win on every axis including single-stream (219 -> 279
//     tok/s), so there is no case in which omitting it is right. The image's
//     ENTRYPOINT carries it too; a boolean repeated is still true, and neither
//     copy is load bearing on the other.
//
//   - The KV cache must be PINNED. It grows with every generated token, so a pod
//     sized at load time against an unpinned cache is a deterministic
//     mid-generation kill: S3 measured the working set climbing from 1960.6 MB
//     at load to ~2132 MB after 1200 tokens and found NO backstop under it — the
//     Metal wired limit is a residency hint that allocation ignored 8x over, and
//     jetsam never fired. k3sm's own sampler is the only killer, so the only way
//     a memory limit is honest is if the engine cannot grow past it.
const (
	// argMaxKVSize pins the KV cache in tokens, per sequence. It is the measured
	// spelling of the ceiling this file derives; --max-model-len, the vLLM
	// spelling this package used to render, does not exist on this engine.
	argMaxKVSize = "--max-kv-size"
	// argMaxNumSeqs pins how many sequences the engine batches concurrently.
	// Under continuous batching each in-flight sequence carries its OWN KV
	// cache, so this is the multiplier on the term that grows.
	argMaxNumSeqs = "--max-num-seqs"
	// argContinuousBatching is the S5-binding flag (see above).
	argContinuousBatching = "--continuous-batching"
	// argPort is the port the engine listens on. The image's ENTRYPOINT already
	// names its own default, so this is rendered to make the SPEC's port win.
	argPort = "--port"
)

// The sizing formula's constants.
//
//	spec.memory = weights + KV cache + compile/scratch + headroom
//
// The operator states spec.memory; this package derives the KV term's ceiling
// back out of it, because the KV term is the only one that grows at runtime.
// Every constant below carries the measurement it comes from — a number here
// without a basis is a guess that becomes a SIGKILL on someone's node.
const (
	// kvBytesPerToken is the KV-cache growth per generated token, per sequence.
	//
	// S3 (hack/spike/m8/findings-s3.md §2) measured a 3B-4bit model growing
	// 1960.6 MB -> ~2132 MB over 1200 tokens = ~0.145 MB/token, linear. This
	// rounds that UP to a full 0.15 MiB so the derivation errs toward a smaller
	// context.
	//
	// RESIDUAL, stated rather than hidden: KV geometry scales with the model's
	// layer count, head count and head dimension, and the spec carries no
	// per-model geometry — so this constant is calibrated for the 3B-4bit class
	// and is generous for a smaller model and optimistic for a much larger one.
	// A per-model geometry input (a spec field, or a fact read from the model's
	// config at load) is the seam that would fix it; until then the sampler's
	// N-consecutive-sample OOM kill remains the backstop, which is exactly the
	// posture S3 §4 leaves k3sm in.
	kvBytesPerToken = 157_286

	// compileScratchBytes is the fixed, model-independent overhead: the Python
	// interpreter, the MLX runtime, kernel compilation, and the allocator's own
	// buffer cache.
	//
	// S3 §1 measured ~500 MB of interpreter/runtime footprint underneath a
	// 24 GiB allocation ramp, and §2 watched MLX's buffer cache spike to 131 MB
	// mid-generation and fall back to 2.8 MB. 512 MiB covers the measured
	// baseline; the churn on top of it is what headroomPercent covers.
	compileScratchBytes = 512 << 20

	// headroomPercent is the slice of spec.memory left unallocated for transient
	// peaks.
	//
	// S3 §2: the footprint oscillates ABOVE its own steady state by ~60-130 MB
	// on a ~2100 MB working set — ~6% — because the allocator returns and
	// re-takes cache between samples. A budget fitted to the steady state is
	// tripped by that churn alone, so the formula sizes against the peak.
	headroomPercent = 6

	// kvSharePercent is the share of the usable budget the KV cache may claim.
	// The remainder is the weights, whose size this package cannot know: the
	// spec names a model repository, not a byte count.
	//
	// S3 §2's model held 1960 MB of weights against ~172 MB of KV over 1200
	// tokens — the KV term was 8% of that pod. A quarter is therefore generous
	// for the measured class while still BOUNDING the growing term, which is the
	// property that matters: whatever the weights turn out to be, the KV cache
	// cannot consume the memory they need.
	kvSharePercent = 25

	// defaultMaxSequences is the concurrent-sequence ceiling, and so the
	// multiplier on the KV term.
	//
	// S5's scoreboard: 4 concurrent requests reached 720.9 tok/s aggregate and 8
	// reached 775.1 — +7.5% for twice the KV cache. Four buys nearly all of the
	// batching win at half the memory that grows, so four is the pin. An
	// operator who wants eight states --max-num-seqs in spec.runtime.args and
	// must raise spec.memory to match.
	defaultMaxSequences = 4

	// minContextTokens is the smallest context worth serving. Below it the
	// engine cannot hold a system prompt and a useful reply in one sequence, so
	// a spec that cannot fund it has not under-configured the context — it has
	// under-sized the pod, and saying so is better than serving a model that
	// truncates every conversation.
	minContextTokens = 512

	// maxContextTokens caps the derived context regardless of how much memory
	// the spec states.
	//
	// It exists because the cap is not free in the other direction either. The
	// KV cache is budgeted for the ceiling it is given, and no sequence reaches
	// past the model's own trained window, so a ceiling above that window buys
	// nothing and reserves memory the weights need. 32768 is the native window
	// of the model classes M8 targets. A model with a SMALLER window is not an
	// error here — --max-kv-size bounds the cache, it does not promise the model
	// can fill it — but an operator who wants the tighter pin states
	// --max-kv-size in spec.runtime.args, which is why those args are appended
	// last. (The previous rationale, that an engine refuses to start when the
	// pin exceeds the trained window, belonged to --max-model-len, which this
	// engine does not have.)
	maxContextTokens = 32768

	// contextGranularityTokens rounds the derived context DOWN to a round
	// number. Rounding down never spends memory the formula did not grant, and a
	// pin of 9216 is legible where 9412 invites someone to wonder what it means.
	contextGranularityTokens = 256
)

// Sizing is the engine's memory-derived configuration for one MLXModel: the
// values that make spec.memory a real bound rather than a hope.
//
// It is a value, not a pointer, and every field is derived — nothing here comes
// from the spec except through DeriveSizing.
type Sizing struct {
	// MaxContextTokens is the per-sequence KV-cache ceiling in tokens, rendered
	// as --max-kv-size.
	MaxContextTokens int64
	// MaxSequences is the concurrent-sequence ceiling, rendered as
	// --max-num-seqs.
	MaxSequences int64
	// KVCacheBytes is what those two cost at full occupancy —
	// MaxSequences * MaxContextTokens * kvBytesPerToken. It is the number the
	// formula actually bounds, carried so a caller (a status condition, a
	// validation report) can show the operator where their memory went.
	KVCacheBytes int64
}

// DeriveSizing derives the engine's context and concurrency pins from the
// unified memory an MLXModel asks for. It is pure: same quantity in, same
// Sizing out, no IO and no clock.
//
// The derivation is the sizing formula solved for its one growing term:
//
//	usable   = memory - compile/scratch - headroom
//	kvBudget = usable * kvSharePercent     (the rest is weights)
//	context  = kvBudget / maxSequences / kvBytesPerToken, capped and rounded down
//
// It is MONOTONE by construction — every step is multiplication by a positive
// constant, subtraction of a constant, or integer division, so more memory never
// yields a smaller context. That property is load bearing: an operator who
// raises spec.memory and gets a shorter context would have no way to reason
// about the knob at all.
//
// A memory value that cannot fund minContextTokens returns ErrMemoryTooSmall
// rather than a tiny context, because a 128-token pin serves nothing and hides
// the real problem (the pod is too small for the weights) behind a symptom that
// looks like a truncation bug.
func DeriveSizing(memory resource.Quantity) (Sizing, error) {
	total := memory.Value()
	if total <= 0 {
		return Sizing{}, ErrNoMemory
	}

	usable := total - compileScratchBytes - total*headroomPercent/100
	var kvBudget int64
	if usable > 0 {
		kvBudget = usable * kvSharePercent / 100
	}

	context := kvBudget / defaultMaxSequences / kvBytesPerToken
	if context > maxContextTokens {
		context = maxContextTokens
	}
	context -= context % contextGranularityTokens

	if context < minContextTokens {
		return Sizing{}, fmt.Errorf("%w: %s funds %d context tokens across %d sequences, below the %d-token minimum",
			ErrMemoryTooSmall, memory.String(), context, defaultMaxSequences, minContextTokens)
	}

	return Sizing{
		MaxContextTokens: context,
		MaxSequences:     defaultMaxSequences,
		KVCacheBytes:     context * defaultMaxSequences * kvBytesPerToken,
	}, nil
}

// Args renders the sizing as engine arguments, with --continuous-batching
// beside them because the three are one decision: the flag is what makes
// concurrent requests batch instead of 503, and the concurrency it enables is
// exactly what MaxSequences bounds. Splitting them across two call sites is how
// one of them later goes missing.
func (s Sizing) Args() []string {
	return []string{
		argMaxKVSize, strconv.FormatInt(s.MaxContextTokens, 10),
		argMaxNumSeqs, strconv.FormatInt(s.MaxSequences, 10),
		argContinuousBatching,
	}
}

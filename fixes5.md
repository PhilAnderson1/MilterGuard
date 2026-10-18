# Close remaining fork loop and allocation guard gaps

## Scope and status

Implemented on 2026-10-18. The plan below is retained as the implementation
record; results and limitations appear in the completion record at the end.
Existing working-tree changes, including fixes4, were preserved.

Keep the shared monotonic allocation budget, existing structural limits and
sampled CPU callbacks. Prefer eliminating unnecessary work or allocation over
adding accounting machinery. Do not add timeout goroutines, another budget,
caches, or a general-purpose allocation framework.

Cancellation remains cooperative, and allocation accounting is not a hard heap
or RSS ceiling. The objective is bounded work between checkpoints and admission
before owned allocations, not exact agreement with Go allocator statistics.

## Evidence and implementation order

The standalone reproducer is `local-testing/fork-loop-audit/main.go`. Input
construction is outside its measured operations. Allocation figures describe
cumulative allocation; timings are illustrative wall time, not thread CPU or
end-to-end email measurements.

| Finding | Evidence | Exposure |
| --- | --- | --- |
| Selector traversal continues after cancellation | A 200-combinator general-sibling chain over 50,000 siblings ran about 53 ms after the callback returned true | Current guarded matching path |
| Function-name recognition copies without admission | A 1 MiB function name allocated about 1 MiB with a one-byte budget and zero charge | CSS parser and guarded lexer |
| Fallback bypasses selector length and allocation controls | A 1 MiB uppercase fallback source allocated about 2 MiB | Current selector planning path |
| `:checked` lowercases an unrestricted attribute | 32 matches on a 1 MiB uppercase value allocated about 64 MiB without increasing the budget | Guarded fork API; currently unsupported by email planning |
| `:lang` repeatedly constructs a prefix string | 32 matches with an 8 KiB language argument allocated about 297 KiB | Guarded fork API; currently unsupported by email planning |
| CSS error formatting scans and converts whole lines | Formatting an error on a roughly 1 MiB line allocated about 6.3 MiB | Guarded fork API; current extraction avoids this syntax-error path |

Additional static findings concern HTML child reparenting, formatting-element
attribute comparisons, CSS post-tokenization loops, HTML NUL replacement and
whitespace scans. Existing size limits bound these operations; significant
overrun was not demonstrated experimentally. Close their checkpoints with focused
tests without presenting them as confirmed production exploits.

Implement sections 1–3 first, then 4–5, then the bounded-work corrections in
section 6. Before implementation:

1. Record the working-tree state and read fork provenance/update instructions.
2. Capture processed-body corpus outputs from the current tree, including fixes4.
3. Rerun the reproducer and retain its output. Save ordinary corpus performance
   measurements before making changes.
4. Trace affected callers, error boundaries and allocation ownership. Confirm
   that unsupported pseudo-classes remain excluded from executable email plans.

Put new temporary artifacts under `local-testing/tmp/fixes5`. Set `TMPDIR` and
`GOTMPDIR` to `/root/ai_milter/local-testing/tmp` for Go commands; `/tmp` is not
suitable for executing Go build artifacts in this environment. Reuse the
workspace-local socket-test overlay approach from fixes4 when needed.

## 1. Stop selector traversal promptly after cancellation

Relevant files: `cascadia/selector.go`, `pseudo_classes.go`, `resource.go`.

### Changes

- In `descendantMatchResource`, the general-sibling branch of
  `siblingMatchResource`, `hasChildMatchResource`, and selector-group iteration,
  stop traversal when the shared control becomes stopped. A failed nested match
  must not trigger continued traversal after cancellation.
- Prefer a direct nil-safe read of the sticky stopped state at loop boundaries,
  or immediately after nested matching. Do not add a clock callback per sibling.
  Existing calls to `matchResource` already advance sampling during active work.
- Review other composite matchers for cancellation propagation, especially
  negation. Cancellation must not become an accepted match because a nested
  false result was inverted. Preserve the public matched/stopped contract and
  ordinary matching semantics.

### Verification

- Reproduce cancellation inside nested descendant and general-sibling chains,
  child searches and selector groups. Include cancellation after useful work,
  not just a control that is stopped before matching begins.
- Assert bounded traversal after cancellation using deterministic test fixtures
  or test-only visitation accounting; avoid wall-time thresholds in unit tests.
  A callback-count assertion alone is insufficient because stopped controls
  deliberately stop calling the callback.
- Confirm the control remains stopped for subsequent calls and callers discard
  cancelled results, including results involving `:not`.
- Repeat the 50,000-sibling probe and measure time after the callback separately
  from time spent finding the cancellation checkpoint.

Completion: recursive unwinding does not scan the remaining ancestor/sibling
lists at every level after cancellation.

## 2. Recognize CSS URL function names without copying

Relevant symbol: `consumeIdentlike` in `tdewolffparse/css/lex.go`.

### Changes

- Replace `bytes.Replace` followed by `parse.EqualFold` with an allocation-free
  comparison against `url`, preserving the existing behavior of ignoring
  backslashes for this recognition step and folding ASCII letters.
- Reject on the first mismatching non-backslash byte or a fourth such byte.
  Do not decode escapes differently or change lexer grammar as part of this fix.
- Sample long runs of skipped bytes using the existing cancellation mechanism.
  Ensure both `NewLexerWithLimits` and `NewParserWithLimits` reach this check:
  the parser currently installs input progress checking but constructs its
  internal lexer through `NewLexer`. Merely consulting the lexer's guard would
  leave the parser path uncovered.
- Preserve existing error propagation and unguarded compatibility behavior.

### Verification

- Cover `url`, mixed case, currently accepted escaped spellings, ordinary
  functions, long names, and long backslash-heavy identifiers.
- Verify long ordinary function names no longer allocate a transformed name.
  Exclude input construction and retained consumer copies from measurements.
- Exercise cancellation in the recognition scan itself through both guarded
  constructors, rather than allowing earlier tokenization to mask the gap.
- Run lexer/parser compatibility tests and compare emitted tokens and grammar.

Completion: function recognition creates no input-sized temporary buffer and
cannot perform a long recognition scan without cancellation sampling.

## 3. Bound selector fallback and make list scanning cancellable

Relevant files: `cascadia/fallback.go`, `split.go`, and
`htmlextract/selector_plan.go` plus its caller in `css_parser.go`.

### Changes

- Apply the existing `maxSelectorBytes` bound before fallback scans or casing.
  Oversized input must produce unconstrained conservative uncertainty, not be
  silently discarded or treated as an exact non-match.
- Determine generated-pseudo handling conservatively for oversized input. An
  empty fallback must not accidentally suppress uncertainty for generated
  content. Lock the intended planner behavior down with integration tests.
- Replace whole-compound lowercasing used only to detect `:before`/`:after`
  with a bounded suffix comparison preserving existing case semantics.
- Remove avoidable temporary casing in positive-prefix validation. For owned
  normalized index keys that remain necessary, pass the existing memory budget
  to a resource-aware fallback path and reserve before allocation. Keep any
  unguarded wrapper small and share the implementation.
- Add sampled cancellation to selector-list scanning, including quoted,
  bracketed, parenthesized and empty/whitespace-only branches. Compilation's
  branch-size check occurs too late to protect this scan.
- Thread cancellation through planning without confusing it with normal end of
  iteration or a branch-count limit. Propagate it to the existing stopped or
  incomplete-cascade behavior. Preserve valid branch splitting and escape rules.

### Verification

- Cover oversized uppercase selectors, long unsupported compounds, namespace
  prefixes, generated pseudo-elements and selectors with no safe positive scope.
- Verify no input-sized fallback casing allocation occurs after length rejection.
- Test cancellation within one long branch and while skipping empty branches;
  test separators inside strings, escapes and nested component values.
- Verify budget failure before owned fallback-key construction and no duplicate
  charge for borrowed source slices.
- Add email-planning tests proving rejected or interrupted selectors preserve
  conservative uncertainty rather than incorrectly making content visible or
  declaring a selector irrelevant.

Completion: rejected selectors do not bypass compilation's resource controls
through fallback, and list iteration has bounded cancellation checkpoints.

## 4. Remove matching-time copies in `:checked` and `:lang`

Relevant file: `cascadia/pseudo_classes.go`.

### Changes

- In `:checked`, replace `toLowerASCII(val)` with existing allocation-free
  `equalAttribute` comparisons against `checkbox` and `radio`, using ASCII
  case-insensitive matching. Oversized values then fail at the length check.
- In `:lang`, replace `strings.HasPrefix(val, s.lang+"-")` with a length check,
  comparison against `s.lang`, and inspection of the following hyphen. Use the
  existing guarded string comparison where appropriate; preserve current case
  semantics rather than changing the pseudo-class's behavior incidentally.
- Keep both pseudo-classes unsupported in email planning. Do not broaden the
  product's supported-selector set as a side effect of fixing library matching.

### Verification

- Test mixed-case input types, exact matches, nonmatches and oversized values.
- Test exact language matches, hyphen suffixes, unrelated values and inherited
  language matches, including long arguments and cancellation during traversal.
- Measure repeated matching after compilation/input setup; neither operation
  should allocate temporary strings proportional to the attribute or argument.
- Retain planner tests that exclude these executable matchers.

Completion: these matching loops have no per-visit casing/prefix allocations.

## 5. Keep guarded CSS diagnostics bounded

Relevant files: `tdewolffparse/css/parse.go`, `error.go`, `position.go`.

### Changes

- For parsers constructed with resource limits, prefer a lightweight syntax
  error containing the existing message and byte offset. Do not call the
  whole-input line/context formatter on that path.
- Review callers and error-type compatibility before choosing the precise
  representation. Keep legacy rich diagnostics for unguarded callers where
  compatibility requires them; resource-stop errors remain unchanged.
- If a guarded caller actually requires line/context output, implement a bounded
  context window with sampled scanning and admitted storage instead. Do not
  convert the full line into runes just to display a short excerpt.
- Preserve the extraction caller's existing `HasParseError` handling; do not
  introduce diagnostic construction into recovery loops.

### Verification

- Test errors near the start/end of a long line and after many lines, including
  non-ASCII text and repeated `Err()` calls.
- Confirm guarded diagnostics allocate bounded storage and do not rescan input.
- Confirm unguarded diagnostic compatibility and typed resource-error behavior.

Completion: requesting a guarded syntax error cannot allocate or scan in
proportion to an arbitrarily long source line.

## 6. Close bounded-work checkpoint blind spots

Use package-local helpers and existing guard/error boundaries. Sample operations
with `stop()`/`step()` where appropriate, but use direct checks at byte-chunk
boundaries: sampling an already chunked loop again every 256 iterations can
accidentally create a much larger unchecked interval.

### HTML child reparenting

Pass the parser guard into `reparentChildren` or add a guarded internal variant.
Call the existing sampled operation check for each moved child. Preserve linked
list invariants and existing recovery semantics. Test a broad child list through
the adoption-agency path and a focused helper test with mid-loop cancellation.

### Formatting-element attribute sorting and equality

In `addFormattingElement`, sample comparisons/search iterations. Replace
whole-attribute equality with a guarded equivalent where long string comparisons
can dominate work; compare long strings in chunks while preserving exact
lexicographic and equality semantics. A checkpoint only before a long comparison
does not bound the comparison itself.

Confirm that the two sorted attribute slices alias the same storage before
removing the redundant second sort. Preserve Noah's Ark behavior and attribute
ordering. Test many attributes, long common prefixes, nonidentical final bytes,
formatting recovery and cancellation inside comparisons.

### CSS post-tokenization processing

Add byte-chunk checkpoints to `appendCustomCommentSpace` and the lowercasing of
property names and at-keywords. Sample the token compaction and whitespace loops
in `parseDeclaration`. Retain existing allocation admission and buffer reuse.
Ensure recovery does not swallow cancellation or emit a successful declaration
after stopping. Test token-dense declarations, long comments and names, with
cancellation targeted after tokenization has completed.

### HTML NUL replacement and whitespace scans

Replace whole-token `bytes.Contains`/`Count`/`Replace` sequences in tokenizer
accessors with a guarded byte-oriented helper. Sample sizing and output passes,
reserve the entire replacement buffer before allocation, and preserve invalid
UTF-8 bytes and the unchanged-input path. Do not introduce extra string copies
by routing byte tokens through a string-only helper.

Use guarded ASCII-whitespace scanning for tree-builder trimming and relevant
doctype scans. Preserve each call site's whitespace set and substring behavior;
do not substitute Unicode whitespace semantics. Review adjacent doctype
delimiter searches for the same whole-token scan issue.

Test long NUL-heavy text, comments, tag names and attribute keys/values, plus
whitespace-only text in relevant insertion modes. Exercise standalone tokenizer
accessors and tree parsing. Assert typed cancellation and admission before output
allocation. Keep ordinary text, invalid bytes and HTML recovery outputs unchanged.

Completion: these loops sample within their work rather than depending solely
on a check before or after a complete token, attribute set or child list.

## Final validation and acceptance

1. Run focused regressions, `go test ./internal/fork/...`, affected extraction
   and message tests, then `go test ./cmd/... ./internal/...`. Use the established
   socket overlay if required by the environment.
2. Run `go vet ./cmd/... ./internal/...`. Run targeted race tests if shared state
   or ownership changes warrant them; this plan should not add concurrent state.
3. Compare the saved processed-body corpus without replacing expected outputs
   to conceal differences. Explain any intended fallback/diagnostic difference.
4. Repeat standalone probes and ordinary corpus benchmarks sequentially under
   comparable conditions. Record allocated bytes, budget charges, callback gaps
   and post-cancellation work separately. Use thread CPU for CPU-limit claims;
   retain wall time only as clearly labelled supporting measurements.
5. Update fork README/provenance notes for actual implementation changes. Do not
   change upstream version identifiers without an upstream update.
6. Review the diff for accidental changes to prior work and run `git diff --check`.
   Append a completion record here with changes, results and remaining limits.

Acceptance requires preventing unadmitted input-sized allocations and stopping
within the corrected loops, not merely observing an error at a later caller
checkpoint. Do not claim that finite input caps eliminate cancellation latency,
or that standalone fork probes establish an end-to-end exploit for unsupported
email selectors.


## Completion record — 2026-10-18

### Implemented

- Selector ancestor, general-sibling, child and group loops exit when the shared
  control is stopped. Negation and the public matching boundary cannot report a
  cancelled operation as a successful match.
- CSS URL recognition no longer creates a transformed identifier. It checks the
  input callback during long recognition scans, covering parser-owned lexers as
  well as standalone guarded lexers.
- Selector-list scanning samples cancellation and tracks trimmed branch bounds
  during its existing pass. Its control is stored by value. Planning reports
  cancellation explicitly, separately from branch limits, without allocating a
  per-rule callback closure.
- Oversized fallback sources produce unconstrained uncertainty. Bounded suffix
  comparison preserves generated-pseudo handling; owned lowercase fallback keys
  are admitted before construction. Integration tests retain uncertainty for
  ordinary and generated-content selectors with potentially relevant effects.
- `:checked` and `:lang` perform no input-sized matching-time string copies.
  Their exact matching remains unsupported by email planning.
- The original bounded `*css.SyntaxError` diagnostics were superseded by the
  follow-up audit fix: both parser constructors now use a boolean and shared
  `css.ErrSyntax`, generating and storing no per-error message or position.
  Upstream line/context diagnostics are no longer provided. This also closes
  unaccounted message allocations during recovery before `Err()` is called.
- HTML child reparenting and formatting-element sorting/equality have inner
  checkpoints. The redundant attribute sort was removed. Long comparisons use
  optimized string comparisons within chunks, preserving lexical ordering.
- CSS comment-space expansion, property/at-keyword casing and declaration token
  compaction sample their own work. HTML tokenizer NUL replacement, tree-builder
  trimming and doctype scans are chunked; owned replacement storage is admitted
  before allocation and invalid UTF-8 bytes are preserved.
- Fork README and all three provenance records were updated without changing
  upstream versions. No new budget, timeout goroutine or cache was introduced.

### Resource probes

Before/after results are in `local-testing/tmp/fixes5/probe-before.txt` and
`probe-after.txt`. These standalone measurements exclude source construction;
small remaining allocations include probe formatting/interface boxing rather
than proportional transformation buffers. Durable tests exercise matching
through pre-boxed interfaces and verify zero matching allocations.

| Probe | Before | After |
| --- | --- | --- |
| Nested sibling traversal after stop callback | About 53 ms in the original audit | About 4.6 microseconds |
| 32 `:checked` matches with 1 MiB uppercase type | About 64 MiB allocated | 768 bytes in the harness; no attribute copy |
| One 1 MiB CSS function name | About 1 MiB allocated without charge | 600 bytes in the harness; no transformed-name copy |
| 1 MiB fallback selector | About 2 MiB allocated | Zero allocation |
| One long-line CSS syntax error | About 6.3 MiB allocated | 24 bytes |
| 32 long-argument `:lang` matches | About 297 KiB allocated | 1,280 bytes in the harness; no prefix construction |

These are cumulative allocations and wall timings, not hard RSS ceilings or
thread-CPU overshoot claims. The cancellation result is a measurement, not a
universal latency guarantee.

### Performance

Measurements used the same host and `GOMAXPROCS=2`, with input construction
excluded. Tables report medians of three samples. The final whole-corpus run
was isolated from the test suite; an earlier overlapping run was discarded.
Each corpus sample ran five passes; each HTML microbenchmark ran 20 iterations.

| Workload | Before time/op | After time/op | Allocation impact |
| --- | ---: | ---: | --- |
| Full 91-email processed-body corpus | 431.14 ms | 431.61 ms | Approximately 130.93 MB versus 130.95 MB; effectively unchanged |
| Ordinary repeated HTML paragraphs | 148.95 microseconds | 152.36 microseconds | Unchanged, 36,656 B/op |
| Long formatting-element attributes | 411.71 microseconds | 451.91 microseconds | Unchanged, 96,224 B/op |
| 1 MiB NUL-heavy comment | 39.64 ms | 39.91 ms | Unchanged, 10,482,816 B/op |
| 1 MiB leading whitespace | 15.41 ms | 17.19 ms | Essentially unchanged, about 5.24 MB/op |

The final corpus difference is approximately +0.1%, providing no evidence of a
material overall throughput regression. Earlier isolated samples were faster;
that variation does not support a reliable speedup claim. The adversarial
attribute and whitespace microbenchmarks are approximately 10% and 12% slower,
respectively, reflecting added cancellation checks. Ordinary microbenchmark
samples are short and do not establish a precise production percentage. These
costs are retained to bound previously unchecked work; no allocation growth was
introduced in the HTML microbenchmarks.

### Validation

- Focused regressions cover mid-traversal cancellation, sticky stopped results,
  selector-list boundaries/cancellation, fallback admission and conservative
  planning, allocation-free pseudo matching, parser-owned URL recognition,
  bounded diagnostics, post-token work, chunked comparison/trim semantics,
  partial child reparenting and NUL output/admission.
- The complete `go test ./cmd/... ./internal/...` suite passed using the existing
  workspace-local socket overlay. Sandbox socket/cache restrictions required
  escalation; they were not treated as product failures.
- `go vet ./cmd/... ./internal/...` passed.
- All 91 processed-email outputs match the baseline captured before these fixes.
- `git diff --check` passed. No concurrent state was added; a new race run was
  not necessary for these changes. Existing files and prior modifications were
  preserved; nothing was committed or deployed.

Artifacts and measurements are under `local-testing/tmp/fixes5`. Existing input,
node, attribute and selector limits remain in force. Runtime allocation/copy
operations are still not preempted by cooperative callbacks, and small bounded
objects plus allocator rounding remain outside an exact heap-ceiling claim.

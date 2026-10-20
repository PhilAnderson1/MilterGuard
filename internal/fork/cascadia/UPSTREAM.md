# Upstream provenance

This directory is a source fork of `github.com/andybalholm/cascadia` from tag
`v1.3.5`, commit `caa0b274f513cca28d83d3a13d924eac07e28e84`.

The complete selector package and its upstream tests were copied. Its HTML and
atom imports were rewritten to use the MilterGuard-local `x/net/html` fork so
all selector APIs share one node type.

Local changes:

- `ParseGroupWithMemory` charges selector-compilation allocations to the shared
  monotonic HTML/CSS memory budget: source retention, structural component
  allowances, copied strings and substring prefix tables. Separate 16 KiB source,
  1,024 component and 64-level nesting limits remain in force.
- `MatchControl` and `MatchWithStop` sample cooperative cancellation inside
  selector-controlled traversal and matching loops. Every such loop and
  recursive traversal must advance the control, including each `:lang`
  ancestor visit. Short attribute comparisons use sampled operation checks;
  long scans sample every 1,024 bytes, including class-token and whitespace
  scans. Case-insensitive matching scans ASCII without lowercase value copies.
  Substring KMP tables are prepared and charged once at compilation, and are
  immutable during matching.
- Cascadia's proprietary raw-regex selectors (`#=`, `:matches`, and
  `:matchesOwn`) are rejected. They are not browser CSS, and Go regular
  expressions cannot be interrupted by the cooperative CPU guard.
- Proprietary `:contains` and `:containsOwn` text selectors are rejected at
  compilation, including nested occurrences. Their full-subtree text buffers
  and lowercase/search allocations were outside matching controls. Email
  extraction already excluded them from exact matching and retains conservative
  uncertainty through syntax fallback. Standard `:empty` remains available to
  direct callers and samples long Unicode-whitespace scans.
- Escaped selector names and strings are assembled with `strings.Builder`
  after the first escape, avoiding upstream's quadratic repeated string
  concatenation while retaining its zero-copy path for unescaped input.
- `ParseGroupWithPseudoElementsAndMemory`, `SplitSelectorList`, and `Metadata`
  expose compiled selector structure to MilterGuard. Metadata includes
  compound matchers, candidate keys, original type spelling, attribute
  sensitivity, and the deliberately small selector subset evaluated exactly
  for static email. `CombinePositiveMatchers` joins existing compiled positive
  matchers for conservative child/descendant scope without recompilation.
- Metadata reuses compiled compound matchers without serializing them back to
  selector text. `MetadataWithMemory` reserves compound, combinator and
  positive-matcher storage before allocation; `Metadata` retains its unguarded
  interface. Required allocation failures unwind with the shared termination
  signal. Metadata APIs return only metadata; compile APIs return ordinary
  selector errors and never convert budget failures to errors.
- `ConservativeFallback` recovers only a safe rightmost positive candidate
  from rejected syntax, keeping malformed and unsupported branches local
  without adding selector parsing to the caller.
- Type selectors retain their original spelling for foreign-element case
  handling, so serialization preserves that spelling.
- Cancellation propagates out of selector traversals without scanning remaining
  siblings or ancestors. `:checked` and `:lang` avoid matching-time string copies.
  Selector-list scanning supports sampled cancellation; fallback applies the
  compiler's input bound and admits owned normalized keys before allocation.
  `NewSelectorListIterator` avoids an intermediate branch slice;
  `NewSelectorListIteratorWithStop` adds byte-sampled cancellation that unwinds
  immediately, separately from normal end of iteration. Trimming is tracked during
  scanning rather than performed as another unchecked pass.
- `ConservativeFallbackWithMemory` admits owned normalized candidate keys.
  Oversized fallback input returns unconstrained metadata, with a bounded
  generated-pseudo suffix check; callers must retain conservative uncertainty.
  The unguarded `ConservativeFallback` wrapper shares these input bounds.

Structural compilation limits and rejected extensions apply to all compilation
entry points. Memory accounting is opt-in through the memory-aware APIs, and
matching cancellation is opt-in through `MatchControl` / `MatchWithStop`.
Legacy `Match`, query and filter APIs do not acquire a resource guard implicitly.
`MatchControl` propagates termination immediately, including through negation;
it has no stopped latch or cancellation return value. The caller still owns accounting for any
result collections outside the guarded matching API.

Local regression tests cover compilation/matching limits, allocation admission,
attribute operators, metadata/fallback behavior, rejected extensions, matching
without temporary copies, and cancellation inside list scans and traversals.

The upstream BSD licence is retained as `LICENSE`.

Index-based cancellation scans check for reaching or passing the next threshold,
so larger loop steps cannot skip checkpoints. Shared operation counters retain
exact-multiple sampling because they increment by one per operation.

Selector rejection returns shared `ErrInvalidSelector` without formatting or
retaining source text, names, offsets, or per-failure messages. Memory failures
raise the distinct shared termination signal. Unsupported-selector recovery is unchanged.

Language-selector Unicode lowercasing sizes and admits its output before one
allocation. It preserves strings.ToLower behavior for valid and malformed UTF-8;
unchanged strings remain borrowed, and repeated buffer-growth allocations are
avoided. The existing selector source bound limits both conversion passes.

Nth-selector integers are accumulated with overflow checks in the digit scan.
Overflow returns the shared invalid-selector error, avoiding strconv.NumError
input copies and a second scan. Leading zeros and the native-int range are
preserved.

Traversal loops calling `matchResource` once per visited node obtain their
sampled checkpoint there; they must preserve that call or add an explicit
checkpoint when changing the traversal.

# HTML extraction refactor plan

## Purpose

`internal/htmlextract` has accumulated substantial parsing, resource-control,
CSS-cascade, and presentation-analysis logic. Most of that complexity represents
real email-processing requirements, but repeated security and correctness work
has also left duplicate state, boolean-heavy interfaces, large orchestration
functions, and partial parsers alongside the forked parser libraries.

This refactor will simplify those areas without changing extraction results,
resource-limit behaviour, or the conservative treatment of malformed and
unsupported input. It is deliberately divided into three independently
reviewable stages. Each stage must leave the tree in a releasable state.

## Invariants

All stages must preserve these properties:

- HTML, CSS, selector compilation, cascade evaluation, and extraction remain
  covered by the configured CPU and memory budgets.
- Raw HTML and cumulative CSS byte limits remain independent early limits.
- Resource exhaustion, malformed input, unsupported CSS, and uncertain client
  behaviour continue to produce the same conservative outcomes.
- No scripts execute and no external resources are fetched.
- The complete document is prepared before styles are evaluated, because a
  later stylesheet can affect an earlier element.
- Separate viewing-case traversals remain available for different media widths.
- DOM traversal remains iterative where recursion could be controlled by hostile
  input.
- The extraction and inspection outputs for the existing corpus do not change
  unless a separately documented correctness fix intentionally changes them.
- The fork provenance files and local-change documentation remain accurate.

Before starting stage 1, record a baseline from the current committed tree:

1. Run all fork and application tests and `go vet`.
2. Save the processed-body corpus output from `local-testing/html-baseline`.
3. Run `local-testing/html-benchmark` with allocation reporting and save the
   result.
4. Run the current synthetic resource-limit cases in
   `local-testing/html-limit-benchmark`.

Use the same Go version, corpus, benchmark binary settings, and machine for all
before-and-after performance comparisons.

## Stage 1: remove incidental complexity

### Goal

Remove dead and duplicated state, make behavioural arguments self-describing,
and eliminate repeated work without changing the algorithms or file layout
substantially.

### Work

1. Collapse the duplicate CPU-guard plumbing.
   - Replace `viewingCaseRunner.matches` and `viewingCaseRunner.expressions`
     with one field, such as `work`.
   - Pass that guard through selector matching, cascade resolution, value
     evaluation, colour evaluation, layout, and animation processing.
   - Remove the consecutive duplicate `matches.check()` in `elementStyle`.
   - Confirm that this is only a representation change: all existing polling
     points remain, apart from the accidental duplicate.

2. Remove unused state.
   - Remove `parsedDocument.textCount` and `attributeCount` and their increments.
   - Make the traversal-only node counter local to `parseDocument`.
   - Remove `sheet.rulesSeen` and `sheet.selectors` and their increments.
   - Remove the unused `layoutVisibilityUncertain` and `rule.mediaState`
     helpers.
   - Remove the redundant `_ = caseIndex` assignment.
   - Search the complete package again after these edits for fields that are
     written but never read.

3. Replace ambiguous boolean argument groups with small named types.
   - Replace `viewingCaseRunner.run(width, fallback, first)` with a
     `viewingCase` value containing the width and named mode fields, or an
     equivalent small type.
   - Give stylesheet and inline-declaration parsing distinct entry points so
     internal parsing code does not depend on an `inline` boolean.
   - Replace the cascade `apply` closure's boolean sequence with a
     `cascadeSource` or `cascadeApplyOptions` value containing named fields for
     inline origin, uncertainty, colour-scheme dependence, and retention.
   - Replace multi-boolean return values with small result structures where the
     call sites currently need comments or positional knowledge to interpret
     them. Start with clipping and import parsing; do not create types for
     obvious single booleans.

4. Avoid compiling conservative selector scope twice.
   - Change conservative-scope construction to return the validated compiled
     matcher together with its source and complexity.
   - Reuse that matcher when an uncertain selector plan is finalized.
   - Preserve the universal matcher fallback on invalid or unbounded scope.
   - Ensure every Cascadia allocation is still charged to the shared memory
     budget.

5. Centralize resource-accounting names where this improves clarity.
   - Replace unexplained numeric reservation estimates with named constants or
     narrowly scoped helper functions.
   - State whether each reservation represents a known retained allocation or
     a conservative estimate.
   - Retain structural count/depth limits where they express the actual risk
     more clearly than approximate byte charging.
   - Do not redesign the shared monotonic budget in this stage.

### Tests

- Add focused tests only where an interface change exposes an untested branch.
- Run `go test ./internal/htmlextract` after each logical change.
- At the end of the stage, run:

  ```sh
  go test ./internal/fork/...
  go test ./cmd/... ./internal/...
  go vet ./cmd/... ./internal/...
  ```

- Compare processed-body corpus output byte for byte with the baseline.
- Run the corpus and synthetic benchmarks. Investigate any repeatable regression
  above normal run-to-run variation; this stage should be neutral or slightly
  faster.

### Completion criteria

- No known unused fields, counters, or helpers remain in the package.
- One CPU guard represents extraction work throughout a viewing case.
- Behavioural call sites no longer contain unexplained sequences of booleans.
- Conservative selector scope is parsed at most once per plan.
- Tests, vet, corpus comparison, and resource-limit cases pass.

Commit stage 1 separately before beginning stage 2.

## Stage 2: separate orchestration from policy

### Goal

Make the major state machines understandable in isolation while retaining the
existing parser, cascade, and presentation semantics.

### Work

1. Introduce a CSS parse session.
   - Move the transient state currently local to `parseCSSResult` into a
     `cssParseSession`: the parser, current declarations, condition stack,
     enclosing rules, nested groups, ruleset depth, at-rule depth, import
     eligibility, compatibility information, and incomplete status.
   - Give the session specific handlers for parser events: begin/end ruleset,
     begin/end at-rule, declaration, comment/whitespace, and parse error.
   - Keep `sheet` responsible for the retained stylesheet model, indexes,
     cumulative limits, and runtime caches. Transient parser state must not
     become permanent `sheet` state.
   - Preserve the ordering of limit checks and mutations so exhaustion cannot
     expose a partially trusted rule or declaration.

2. Make declaration preparation transitions explicit.
   - Keep immutable source data separate from optional parsed tokens,
     validation status, prepared context-independent value, animation value,
     and variable-dependency data.
   - Add constructors or methods for the valid transitions instead of setting
     `prepared`, `validityReady`, `tokensReady`, and `dependenciesReady` at
     unrelated call sites.
   - Preserve lazy tokenization and validation; the refactor must not retain
     token slices for ordinary static declarations that currently release them.
   - Add invariant tests covering static values, contextual values, shorthands,
     custom properties, invalid values, and values containing `var()`.

3. Split viewing-case traversal into cohesive operations.
   - Keep the iterative frame stack and the single traversal loop.
   - Extract methods for entering an element, recording element state, recording
     text, handling MSO revealed markers, and leaving an element.
   - Keep style-stack, paint-layer, variable-scope, ancestor-activation, and
     concealment-state changes paired so each enter operation has an obvious
     corresponding leave operation.
   - Avoid callbacks or generic visitor abstractions that hide traversal order.

4. Clarify document preparation.
   - Separate per-node collection from traversal mechanics while retaining one
     document-preparation walk.
   - Keep stylesheet collection, inline-style preparation, legacy attributes,
     node scope, MSO ordering, extraction counts, and tree-depth calculation
     explicit.
   - Do not combine document preparation with viewing-case evaluation.

5. Reorganize files after the state boundaries are established.
   - Split `css.go` into focused files such as `properties.go`,
     `declarations.go`, and `css_parser.go`.
   - Split `selector_plan.go` into planning, indexing, and matching-runtime
     files without changing its algorithms in this stage.
   - Move colour literal parsing and named-colour data from `values.go` into
     `colour_values.go`.
   - Split the largest catch-all test files by feature. Preserve test cases and
     their names wherever practical so history and failures remain easy to
     trace.
   - Keep types near the code that owns their invariants; do not split files
     merely to meet an arbitrary line count.

6. Update package documentation.
   - Document the resulting phases: parse and prepare, compile styles and
     selectors, evaluate viewing cases, then assemble extraction results.
   - Update `ARCHITECTURE.md` if any names or boundaries described there change.

### Tests

- Run focused tests after each extracted state-machine operation.
- Add direct tests for CSS session state restoration after nested rules,
  malformed declarations, unsupported nesting, resource exhaustion, and parser
  cancellation.
- Add direct viewing-runner tests for balanced stacks after normal traversal,
  inert subtrees, MSO revealed content, and early termination.
- Run the full stage 1 validation suite and corpus comparison.
- Benchmark each meaningful substep. A structural refactor should not cause a
  material CPU or allocation increase; investigate regressions before layering
  further changes on top.

### Completion criteria

- `parseCSSResult` is primarily a session driver rather than one large switch
  owning all transient state.
- Declaration-state invariants are enforced through a small number of methods.
- The viewing-case loop shows traversal order clearly, with presentation work
  delegated to named operations.
- File boundaries follow responsibilities and tests are easy to locate.
- Output, limit behaviour, and benchmark performance remain equivalent.

Commit stage 2 separately before beginning stage 3.

## Stage 3: make the forked parsers authoritative

### Goal

Remove the two partial parsing layers maintained by `internal/htmlextract` by
exposing the required information directly from the forked Cascadia and CSS
parsers.

This stage changes fork APIs and should be implemented as two independently
reviewable sub-stages. Do not remove an existing layer until the replacement
passes differential tests against it.

### Stage 3A: selector metadata from Cascadia

1. Define the minimum selector metadata needed by the extractor.
   - Compounds and their combinators.
   - The rightmost usable tag, ID, or class candidate key.
   - Safe positive prefixes for conservative uncertain matching.
   - Specificity.
   - Attribute sensitivity and the properties needed for bounded matching.
   - Generated pseudo-element and unsupported-feature information.
   - Foreign-element type-name information without applying HTML case folding
     incorrectly.

2. Expose metadata while Cascadia performs its authoritative parse.
   - Prefer a resource-aware compile result over exporting Cascadia's complete
     internal AST.
   - Charge metadata allocations to the same memory budget used for selector
     compilation.
   - Preserve selector size, component-count, nesting, cancellation, and memory
     limits.
   - Keep regular-expression pseudo-classes disabled.

3. Migrate planning incrementally.
   - First compare current `selectorPlan` data with Cascadia metadata in tests
     while continuing to use the current planner.
   - Cover escapes, comments, attribute selectors, functional pseudos,
     namespaces, SVG names, malformed branches, comma groups, and all
     combinators.
   - Switch indexing and ancestor-chain construction to the authoritative
     metadata only after the differential tests agree.
   - Remove `planSelectorBranch`'s independent syntax scan, compound-prefix
     parser, and duplicated compound compilation once no caller uses them.

4. Record every local Cascadia change in its `UPSTREAM.md` and
   `internal/fork/README.md`, including the new API and why it is required.

### Stage 3B: remove the CSS compatibility pre-pass

1. Turn each compatibility behaviour into a fork-level parser test.
   - Comments must preserve selector token separation.
   - Custom-property values must preserve the source information required for
     correct value reconstruction and resource charging.
   - A mismatched `)` inside `[]` or `{}` must recover without prematurely
     ending the enclosing component value.
   - Malformed input must retain the current conservative incomplete/invalid
     result.

2. Implement the behaviour at the narrowest parser or lexer location.
   - Prefer preserving token boundaries and correct delimiter recovery in the
     fork over rewriting the entire stylesheet.
   - Expose original declaration value text or equivalent token information if
     that removes offset-repair logic cleanly.
   - Keep CPU polling and allocation charging inside all new loops and retained
     data.

3. Run the fork parser and `parserCompatibleCSS` side by side in differential
   tests over:
   - Existing unit-test fixtures.
   - The complete email corpus.
   - Generated comment placements and delimiter mismatches.
   - Custom properties containing comments, escapes, nested blocks, and
     `var()` fallbacks.

4. Once equivalent, remove:
   - `parserCompatibleCSS`.
   - Its preliminary lexer pass and rewritten stylesheet copy.
   - Inserted-parenthesis position tracking.
   - Declaration-property and declaration-value offset restoration that exists
     solely for the compatibility copy.

5. Record the CSS-fork changes in its `UPSTREAM.md` and
   `internal/fork/README.md`.

### Tests

- Run all upstream-derived tests in the modified fork packages as well as the
  local resource-limit and extension tests.
- Keep differential tests during migration; delete only tests that exercise
  removed private implementation details after equivalent public behaviour is
  covered.
- Run the full application test and vet suite.
- Require a byte-for-byte processed-body corpus match unless an intentional
  correctness change has its own review and updated baseline.
- Re-run malformed-input and adversarial resource cases with limits both below
  and above the point of exhaustion.
- Compare corpus CPU time, allocations, allocated bytes, and peak process
  memory with the pre-refactor baseline. The removal of secondary parsing should
  reduce work on affected inputs and must not materially regress ordinary mail.

### Completion criteria

- Cascadia is the only component interpreting selector grammar.
- The forked CSS parser handles the required recovery and source preservation
  without a stylesheet compatibility rewrite.
- All parser loops and retained metadata remain covered by CPU and memory
  controls.
- Fork documentation precisely lists the local changes and provides a viable
  upstream-update procedure.
- Tests, corpus comparison, resource-limit cases, vet, and benchmarks pass.

Commit selector and CSS-parser work separately so either can be reviewed or
reverted without undoing the other.

## Final review

After all three stages:

1. Search for obsolete compatibility comments, stale field names, dead helpers,
   duplicate parsers, and unexplained memory estimates.
2. Re-read `internal/htmlextract` as a complete package and update package and
   architecture documentation to match the final flow.
3. Run the complete test, corpus, adversarial-limit, vet, and benchmark suites
   from a clean checkout.
4. Compare the final results with the baseline recorded before stage 1.
5. Review the diff specifically for lost CPU callbacks, uncharged retained
   allocations, newly recursive hostile-input paths, and changes from
   conservative uncertainty to confident visibility.

The refactor is complete only when the code is easier to follow and the
behavioural and resource-safety evidence is at least as strong as before it.

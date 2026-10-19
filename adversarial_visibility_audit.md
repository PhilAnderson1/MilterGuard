# Adversarial HTML/CSS visibility audit

Date: 2026-10-19. Baseline: `641599d`. Scope: `internal/htmlextract`, with selector-fork and message-output tracing where relevant. Production code was not changed.

## Implementation follow-up

Findings 1–7 and 9 have now been implemented; finding 8 (popover defaults) is intentionally deferred. The observations and Appendix A below preserve the original audit baseline rather than presenting old outputs as current behaviour.

The fixes add strict CSS selector admission, deferred variable edge-shorthand expansion, separate independent-transform properties, text-aware input labels, native font sizing and font-adjustment uncertainty, relative-offset/logical-overflow checks, conservative table-column handling, and effective alternate custom-property winner comparisons. New output and extractor regressions cover these behaviours and unchanged popover handling.

Final validation: `go test ./cmd/... ./internal/...` passes, including allocation fingerprints and resource-limit tests. All 91 corpus outputs remain byte-for-byte identical. Three runs of three corpus iterations averaged 491.2ms before and 503.8ms after (+2.6%); individual timings overlap substantially, so this is not evidence of a significant slowdown. Allocated bytes increased from 132.54MB to 133.28MB per corpus (+0.56%); allocation count was essentially unchanged. These are whole-corpus timings, not per-email timings. Diagnostics, benchmark logs and allocation-effect notes are under `local-testing/adversarial-visibility-audit/`.

## Outcome and evidence

Nine finding groups remain. The strongest findings are invalid selectors taking effect, variable shorthands losing their effects, independent transforms bypassing visibility analysis, and input button labels bypassing text checks. Additional gaps involve font sizing, geometry, native rendering, and excessive dark-mode uncertainty.

73 diagnostic inputs were executed through both `htmlextract.Analyze` with default limits and MIME parsing followed by `Message.ProcessedBody`. Appendix A preserves every input and final output. All probes completed without an analysis error. Existing tests passed for `./internal/htmlextract`, `./internal/message`, and `./internal/fork/...` (cached).

These are executed extractor reproductions, checked against code and primary specifications. They are **not browser or email-client differential tests**: no Chromium or Firefox executable was available. For newer features, the demonstrated defect is unjustified certainty when the feature is supported; support in particular email clients remains unmeasured. This audit does not prove correctness for every possible HTML/CSS input.

## Contract used

The extractor is a bounded presentation model, not a layout engine. Its existing policy includes a small-font threshold of 2px, colour-distance thresholds, client-dependent concealment, light mode as the canonical colour scheme, and uncertainty where layout or rendering support is unresolved. A small-font label means the application's readability policy, not literally zero painted pixels.

This audit does not treat every difference from a browser as a bug. In particular, external resources are not fetched, scripts are not executed, generated pseudo-element text is not synthesized, and document-level CSS incompleteness is separate from individual labels. `internal/message/prompt.go` carries CSS incompleteness into prompt diagnostics. An ordinary `ProcessedBody` string alone does not show all these diagnostics.

For supported semantics, equivalent spellings should produce equivalent classifications. Invalid CSS must not acquire a hiding effect. Unsupported visibility-affecting semantics must not silently justify a definite classification. Independent, reliable concealment proofs should survive unrelated uncertainty.

## 1. Invalid selectors can actively conceal text — high priority

```html
<style>p[x!=y]{display:none}</style><p>TEXT</p>
```

Actual final output:

```text
<invisible reason="display:none">TEXT</invisible>
```

The same output occurs for `p,,.absent`, `,p`, and `p,` selector lists. A nested extension also reproduces it: `p:not([x!=y])` with `<p x=y>`.

Expected: ordinary visible `TEXT`. `!=` is not a CSS attribute-selector operator; an empty branch invalidates an ordinary selector list. Forgiving lists are a separate grammar, not a rule for all lists. [Selectors Level 4](https://www.w3.org/TR/selectors-4/#invalid).

**Cause:** `internal/fork/cascadia/parser.go` accepts `!=`; `metadata.go:selectorSupportedForEmail` accepts attribute selectors without checking that operator. `split.go:SelectorListIterator.Next` drops empty branches. `internal/htmlextract/selector_plan.go` therefore receives apparently valid branches. The earlier invalid-attribute-value correction does not cover these cases.

**Minimal fix:** give the CSS selector entry point strict validity semantics. Reject non-CSS operators, including inside functional selectors. Have list iteration expose empty branches so ordinary-list compilation rejects the entire rule. Distinguish definitely invalid selectors from valid but unsupported selectors; do not merely turn every parse failure into an uncertain active rule. Preserve explicit forgiving-list semantics where applicable.

**Regression tests:** the examples above; empty branches at every position; valid `=`, `~=`, `|=`, `^=`, `$=`, `*=` controls; nested functions; a valid hiding branch paired with an invalid branch. The executed `[x=y]` nonmatch control stays visible.

**Cost/guarding:** validity checks fit the existing scan and should have negligible overhead. Keep iterator stop sampling and avoid constructing a second selector-list slice.

## 2. Variable substitution loses multi-value inset shorthand effects — high priority

```html
<p style="position:absolute;--x:-9999px auto auto -9999px;inset:var(--x)">TEXT</p>
```

Actual: `TEXT`. Replacing the variable with the same literal value produces:

```text
<visibility-uncertain>TEXT</visibility-uncertain>
```

The discrepancy also reproduces through a nested variable and with `inset-inline:var(--a)` where `--a:-9999px auto`. A single-value inset variable works. Literal and variable margin/overflow controls did not show this discrepancy.

Expected: the same conservative offscreen uncertainty as the literal declaration. Shorthands containing variables must be expanded into their component values after substitution. [CSS Variables, variables in shorthand properties](https://www.w3.org/TR/css-variables-1/#variables-in-shorthands).

**Cause:** `css.go:declarationsFromParsed` uses `marginShorthandValuesWithBudget` for inset/margin families and copies an unresolved function into component declarations. `resolver.go:resolvedDeclaration` subsequently treats the substituted multi-value string as a longhand. It fails longhand validation and falls back to `unset`, losing the offsets. Deferred expansion exists for other shorthands, but not this family.

**Minimal fix:** retain shorthand kind and component index for variable-bearing declarations; substitute, parse the shorthand once, then select the component. Share this mechanism across physical and logical inset/margin families. Preserve cascade order and invalid-at-computed-value semantics; do not fall back to an earlier declaration after a winning variable becomes invalid.

**Regression tests:** literal/variable equivalence for one through four components, two-component logical forms, nested variables, fallbacks, invalid arity, longhand overrides and `!important`.

**Cost/guarding:** only variable shorthands need deferred parsing. Reuse the existing declaration/scope memo or bounded scratch for components rather than parsing and allocating separately for every longhand. Any retained tokens or expanded strings must use resourceguard and existing CPU checks.

## 3. Independent transforms bypass the existing transform safeguards — high priority

```html
<p style="font-size:1px;scale:20">TEXT</p>
```

Actual:

```text
<invisible reason="font-size" value="1px">TEXT</invisible>
```

The equivalent `transform:scale(20)` produces uncertainty. `scale:0`, `translate:-9999px`, and `rotate:y 90deg` each produce plain `TEXT` in the probes.

Expected: at least uncertainty where these effects can enlarge, remove, or move text. Independent `scale`, `translate`, and `rotate` participate in rendering separately from `transform`. [CSS Transforms Level 2](https://www.w3.org/TR/css-transforms-2/#individual-transforms).

**Cause:** `properties.go` and `css.go:relevantNormalizedDeclarationProperty` omit the independent properties. `analyze.go` propagates font-scale uncertainty from the tracked transform/zoom mechanisms only.

**Minimal fix:** retain separate cascade slots for these properties and feed their resolved effects into existing paint/layout/font-scale uncertainty. A conservative implementation is sufficient; a matrix engine is unnecessary. Do not alias all four properties into one slot: they coexist, and `transform:none` does not reset independent scale.

**Regression tests:** the probes, ancestor transforms, independent resets, identity values, variables, competing declarations, and an independent `display:none` ancestor that must remain concealed.

**Cost/guarding:** a few fixed fields and checks, plus parsing only present declarations. Larger style/frame structures affect per-node memory and must be included in guarded allocation sizes. Benchmark the corpus after implementation; no performance measurement of this proposed fix exists yet.

## 4. Input button labels bypass font and text-colour visibility — high priority

```html
<input type=button value=TEXT style="font-size:0">
```

Actual: `TEXT`. The same happens for `submit` and `reset`. A `<button>` or `<textarea>` with `font-size:0` correctly emits an invisible font-size annotation. An input button with `appearance:none;color:white;background:white` also emits plain `TEXT`.

Expected: a text-aware decision for the label. Zero font size should not produce confidently visible text; native appearance uncertainty can justify an uncertain colour result where paint cannot be established.

**Cause:** `analyze.go:recordElement` handles images and inputs through `decideVisibility(..., nil)`. In `visibility.go`, both font-size and text-colour checks are inside the non-nil colour branch. `internal/message/html_tree.go` then emits button-like input values using that element decision.

**Minimal fix:** distinguish textual input labels from image/replaced-element presentation, and reuse the text visibility path for the former. Carry any needed font-size reason metadata through the element result and formatter. Avoid applying font-size concealment to image alt text merely because inputs and images currently share a path.

**Regression tests:** button/submit/reset values, zero and ordinary font sizes, colour matches with explicit paint, uncertain native paint, hidden inputs, inherited styles, and unchanged image behaviour. Assert final output as well as extractor labels.

**Cost/guarding:** extra colour work only for emitted textual controls. Reuse paint-layer memoization and guarded result storage; do not create synthetic DOM text nodes just to call the text path.

## 5. The small-font proof omits UA sizing and font-size adjustment — high priority

Two mechanisms reach the same unsound proof:

```html
<body style="font-size:1.5px"><h1>TEXT</h1></body>
<p style="font-size:1px;font-size-adjust:10">TEXT</p>
```

Actual: invisible font-size annotations with `1.5px` and `1px`, respectively.

The first inherits the parent's size in the extractor instead of applying heading defaults. A conventional 2em heading is 3px here, above the application's threshold. An explicit `font-size:16px` heading control works. The initial 1px-parent heading probe is **not** evidence of a threshold error: doubling it still leaves it at 2px.

The second ignores an adjustment that changes the rendered font size according to actual font metrics. Exact metrics are unavailable, so the unadjusted size is not a sound concealment proof. Expected: model an established default or return uncertainty; suppress the small-font proof when unresolved font adjustment can enlarge glyphs. [HTML rendering defaults](https://html.spec.whatwg.org/multipage/rendering.html), [CSS font-size-adjust](https://www.w3.org/TR/css-fonts-4/#font-size-adjust-prop).

**Cause:** `resolver.go:elementStyle` supplies some native defaults but no heading/small/subscript sizing defaults. `font-size-adjust` is absent from the property set. `visibility.go:decideVisibility` trusts the resolved size unless existing transform/zoom uncertainty is present.

**Minimal fix:** add a small, explicit native font-default policy at the existing UA-default stage, overridable through the normal cascade. Where client differences prevent a reliable size, mark it unknown. Track inherited font-size adjustment separately and invalidate font-size proofs when unresolved. Do not make every ordinary font-family choice uncertain.

**Regression tests:** headings and relative-size elements on both sides of 2px, author `inherit`/`initial`/explicit overrides, inherited adjustment and `none` resets, zero-size controls, and independent concealment reasons. The `<small>` threshold probe records a potential reverse error, but exact client default scaling was not measured.

**Cost/guarding:** constant-time defaults and a small amount of inherited state. Reuse existing numeric values rather than allocating formatted strings per element; any retained formatting must use guarded helpers.

## 6. Geometry uncertainty misses relative positioning and logical overflow — medium priority

```html
<p style="position:relative;left:-9999px">TEXT</p>
<div style="height:0;overflow-block:hidden">TEXT</div>
```

Both produce `TEXT`. The absolute-position equivalent and the physical `overflow-y:hidden` equivalent produce uncertainty. A relatively positioned ancestor also leaves its child's text confidently visible. A static-position offset correctly has no effect.

**Cause:** `layout.go:layoutVisibility` resolves relative offsets for clipping interactions but restricts its extreme-offscreen test to absolute/fixed positioning. Logical overflow properties are absent from the property set, so they cannot activate zero-dimension clipping checks.

**Minimal fix:** include relative positioning in the offscreen uncertainty check, preserving static-position behaviour. Retain logical overflow candidates and resolve their axis/cascade interactions, or conservatively mark the relevant zero-size clipping combination uncertain when writing mode is unresolved. Do not treat all positions identically: sticky offsets have different constraints.

**Expected:** conservative uncertainty, not a definite hidden label based on assumed viewport geometry. Logical overflow support is client-dependent; its specification defines the logical axes, but this audit did not measure deployed-client support. [CSS Overflow Level 3](https://www.w3.org/TR/css-overflow-3/#overflow-properties).

**Regression tests:** relative/absolute/fixed/static controls, ancestor offsets, physical/logical cascade conflicts, writing modes, and zero/nonzero dimensions.

**Cost/guarding:** bounded checks and additional property state; avoid introducing a layout pass. Retained declaration storage remains resourceguard-owned.

## 7. Table-column display roles are treated as ordinary visible containers — medium priority

```html
<div style="display:table-column">TEXT</div>
```

Actual: `TEXT`; `table-column-group` behaves the same.

Expected: no confident visible claim for the ordinary table formatting case. Table box fixup discards children of columns and non-column children of column groups. [CSS Tables, fixup](https://www.w3.org/TR/css-tables-3/#fixup).

**Cause:** the display value is recognized, but presentation traversal does not model this box-generation effect. This case was left as an unverified concern in the earlier broad audit; here its extractor output is reproduced and the specification basis is explicit. It remains untested in an actual browser.

**Minimal fix:** make text under unresolved column roles uncertain. Only add definite suppression if the formatting context is established: flex/grid item blockification and other display transformations mean that blindly treating every specified column value as `display:none` would introduce a new error. Preserve the DOM for selector matching.

**Regression tests:** column/group text, nested child elements, author display overrides, and flex/grid/positioning contexts.

**Cost/guarding:** fixed traversal state; no new DOM or extra walk is needed. This is a conservative completeness fix, not a request to implement table layout.

## 8. Closed popover defaults are ignored — medium priority

```html
<div popover>TEXT</div>
```

Actual: `TEXT`. The native-default switch handles closed dialogs, datalist and ruby fallback, but not popovers.

Expected: uncertainty across clients. Supporting renderers apply a hidden default to closed popovers; clients that strip or ignore the attribute can show the content. This does not justify a universal invisible label. [HTML rendering defaults](https://html.spec.whatwg.org/multipage/rendering.html).

**Minimal fix:** add an overridable native default alongside the existing closed-dialog policy, including the open-dialog exception. Respect author display rules. The explicit `display:block` probe remains visible and should not be broken by unconditional suppression.

**Regression tests:** missing/empty/invalid popover attribute values, explicit display overrides, open dialog interaction, and independent hidden ancestors.

**Cost/guarding:** one bounded attribute/default check using existing helpers; no new allocations are intrinsically needed.

## 9. A losing dark-mode custom property can erase a valid concealment conclusion — lower priority

```html
<style>
p { --x:none!important; display:var(--x) }
@media(prefers-color-scheme:dark) { p { --x:block } }
</style>
<p>TEXT</p>
```

Actual:

```text
<visibility-uncertain>TEXT</visibility-uncertain>
```

Expected: `<invisible reason="display:none">TEXT</invisible>` under the existing supported custom-property model. The normal dark declaration cannot beat the important declaration. The equivalent literal-property control is correctly concealed; removing `!important` correctly leaves the custom-property example uncertain.

**Cause:** `resolver.go:collectCascade` records alternate custom-property presence in `alternateColourSchemeVars` before considering whether that declaration can win. `buildVariables` propagates this broad dependency. Ordinary property candidates already have a more selective comparison. The stable literal `display:none` proof cannot rescue variable-based display.

**Minimal fix:** retain and compare alternate custom-property candidates with normal importance/specificity/order semantics, then propagate only effective dependencies. Preserve inherited variable dependencies and genuine alternate winners. Do not simply special-case the string `!important` or treat all variable-based display as stable.

**Regression tests:** losing/winning alternate declarations, source order, specificity, inheritance, indirect dependencies and fallbacks.

**Cost/guarding:** more candidate information for colour-scheme custom properties; reuse the existing resourceguard table, and evaluate only documents with relevant alternate declarations. This change has a less trivial memory/performance tradeoff than the fixed-field fixes and should be benchmarked separately.

## Coverage ledger and remaining limitations

| Area | Evidence in this pass | Outcome / limit |
| --- | --- | --- |
| HTML tree and native presentation | DOM/presentation traversal and message output; details, SVG foreignObject, input, textarea, heading, popover probes; existing malformed-HTML tests | Findings 4, 5, 7, 8. No complete browser tree differential performed. |
| Selector compilation/matching | Fork grammar, metadata and list splitting; invalid operators, empty lists, attribute controls, escaped identifiers; existing selector suite | Finding 1. No exhaustive selector grammar fuzzing performed. |
| Cascade and variables | Winner collection, substitution, shorthand resolution; literal/variable pairs, cycles, inheritance, important/alternate controls | Findings 2, 9. |
| Font/numeric resolution | Font proof and scaling paths; zero, tiny, overridden and transformed sizes; existing arithmetic/unit tests | Findings 3, 5. No installed-font rendering oracle. |
| Geometry and clipping | Offset/overflow checks; zero boxes, margins, logical forms, legacy clip and variable clip | Findings 2, 6, 7. Fixed-descendant escape from legacy clip remains unconfirmed and is not counted. |
| Paint/opacity | Paint path, decision precedence, memo regression tests; fill reset, transparent text/stroke reset, opacity and independent-hidden controls | No additional confirmed defect in these probes. Complex compositing remains conservative. |
| Media/client/animation | Alternate winner handling, media and MSO style paths; dark controls, animation under independent hiding, details; existing condition/animation suite | Finding 9. Light-mode canonical policy is intentional; client matrix was not measured. |
| Invalid/unsupported CSS | Missing delimiter, nesting, unsupported shorthand/reset probes; existing recovery tests | Existing uncertainty/incompleteness often works. Invalid selector acceptance is a distinct defect. |
| Text/output boundary | Every probe passed through `ProcessedBody`; input extraction and reason formatter inspected | Finding 4. Generated text and non-button input values remain extraction-scope gaps below. |
| Resource exhaustion | Existing bounded-parser, shared-memory, CSS-limit and cooperative-stop tests rerun | Not a new allocation audit. Proposed fixes must preserve these paths; no new stress campaign performed. |

Additional scope gaps, not counted as new classification defects:

- `::before` generated `content:"TEXT"` is absent from output, as expected from the current source-text model. Supporting it is a separate extraction feature.
- A text input's `value` is omitted, whereas button/submit/reset values are emitted. Decide explicitly whether form field values and placeholders belong in the extraction contract before expanding coverage. Do not silently infer that their omission proves invisibility.
- External stylesheets produce an unresolved-stylesheet flag; nested CSS in the probe produces uncertainty plus incompleteness. Keep these flags visible to consumers.
- Exact occlusion, arbitrary geometry, fonts, images, dynamic states and all email-client rewriting cannot be settled by this model. Their presence needs a defined conservative policy, not an assertion that all possible rendering is covered.

## Recommended implementation order and acceptance checks

Address 1–4 first, then the font-proof gaps in 5. Apply the conservative geometry/native changes 6–8, then the precision improvement in 9. The common design improvement is a small explicit inventory of visibility-affecting property families and proof invalidators, with validity, cascade and evaluation kept separate. A full browser engine or broad refactor is unnecessary.

For every fix, add focused extractor and final-message regressions, plus equivalent-form tests where applicable. Check that independent concealment survives new uncertainty, invalid CSS is ignored, and unrelated ordinary messages keep their labels. Extend the property inventory test so a newly supported property cannot be silently omitted from declaration admission or alternate-scheme handling.

Use existing resourceguard owners for all new slices, maps, tokens and strings. Fixed-structure growth must be reflected in their owning allocations and any allocation-audit metadata. Preserve cancellation sampling in scans and substitution. Compare corpus outputs and run existing corpus/CPU-controlled benchmarks before and after; this audit proposes fixes and makes no measured performance claim about them.

## Reproduction

The diagnostic harness and machine-readable observations are in ignored local files:

- `local-testing/adversarial-visibility-audit/main.go`
- `local-testing/adversarial-visibility-audit/cases.json`
- `local-testing/adversarial-visibility-audit/results.jsonl`

Run from the repository root:

```sh
env TMPDIR=/root/ai_milter/local-testing/tmp GOTMPDIR=/root/ai_milter/local-testing/tmp GOMAXPROCS=2 go run ./local-testing/adversarial-visibility-audit
go test ./internal/htmlextract ./internal/message ./internal/fork/...
```

Appendix A makes the observations portable even if ignored diagnostic files are not committed. Outputs below are observed results, not assertions of correctness.

## Appendix A: executed inputs and final output

### plain

```html
<p>TEXT</p>
```

Output (JSON string): `"TEXT"`. CSS incomplete: false.

### independent-scale

```html
<p style="font-size:1px;scale:20">TEXT</p>
```

Output (JSON string): `"<invisible reason=\"font-size\" value=\"1px\">TEXT</invisible>"`. CSS incomplete: false.

### scale-zero

```html
<p style="scale:0">TEXT</p>
```

Output (JSON string): `"TEXT"`. CSS incomplete: false.

### translate

```html
<p style="translate:-9999px">TEXT</p>
```

Output (JSON string): `"TEXT"`. CSS incomplete: false.

### rotate

```html
<p style="rotate:y 90deg">TEXT</p>
```

Output (JSON string): `"TEXT"`. CSS incomplete: false.

### fixed-escape-clip

```html
<div style="position:absolute;clip:rect(0,0,0,0)"><p style="position:fixed;top:0;left:0">TEXT</p></div>
```

Output (JSON string): `"<invisible reason=\"empty-clip\">TEXT</invisible>"`. CSS incomplete: false.

### absolute-clipped

```html
<div style="position:absolute;clip:rect(0,0,0,0)"><p>TEXT</p></div>
```

Output (JSON string): `"<invisible reason=\"empty-clip\">TEXT</invisible>"`. CSS incomplete: false.

### variable-inset

```html
<p style="position:absolute;--x:-9999px auto auto -9999px;inset:var(--x)">TEXT</p>
```

Output (JSON string): `"TEXT"`. CSS incomplete: false.

### literal-inset

```html
<p style="position:absolute;inset:-9999px auto auto -9999px">TEXT</p>
```

Output (JSON string): `"<visibility-uncertain>TEXT</visibility-uncertain>"`. CSS incomplete: false.

### variable-margin

```html
<p style="--x:-9999px 0;margin:var(--x)">TEXT</p>
```

Output (JSON string): `"<visibility-uncertain>TEXT</visibility-uncertain>"`. CSS incomplete: false.

### literal-margin

```html
<p style="margin:-9999px 0">TEXT</p>
```

Output (JSON string): `"<visibility-uncertain>TEXT</visibility-uncertain>"`. CSS incomplete: false.

### variable-inset-single

```html
<p style="position:absolute;--x:-9999px;inset:var(--x)">TEXT</p>
```

Output (JSON string): `"<visibility-uncertain>TEXT</visibility-uncertain>"`. CSS incomplete: false.

### variable-overflow

```html
<div style="height:0;--x:hidden visible;overflow:var(--x)">TEXT</div>
```

Output (JSON string): `"<visibility-uncertain>TEXT</visibility-uncertain>"`. CSS incomplete: false.

### table-column

```html
<div style="display:table-column">TEXT</div>
```

Output (JSON string): `"TEXT"`. CSS incomplete: false.

### table-column-group

```html
<div style="display:table-column-group">TEXT</div>
```

Output (JSON string): `"TEXT"`. CSS incomplete: false.

### popover

```html
<div popover>TEXT</div>
```

Output (JSON string): `"TEXT"`. CSS incomplete: false.

### popover-open-override

```html
<div popover style="display:block">TEXT</div>
```

Output (JSON string): `"TEXT"`. CSS incomplete: false.

### input-white

```html
<input type=text value=TEXT style="color:white;background:white">
```

Output (JSON string): `""`. CSS incomplete: false.

### input-small

```html
<input type=button value=TEXT style="font-size:0">
```

Output (JSON string): `"TEXT"`. CSS incomplete: false.

### textarea-small

```html
<textarea style="font-size:0">TEXT</textarea>
```

Output (JSON string): `"<invisible reason=\"font-size\" value=\"0px\">TEXT</invisible>"`. CSS incomplete: false.

### selector-not-equal

```html
<style>p[x!=y]{display:none}</style><p>TEXT</p>
```

Output (JSON string): `"<invisible reason=\"display:none\">TEXT</invisible>"`. CSS incomplete: false.

### selector-regex

```html
<style>p[x#=y]{display:none}</style><p x=y>TEXT</p>
```

Output (JSON string): `"<visibility-uncertain>TEXT</visibility-uncertain>"`. CSS incomplete: false.

### selector-emptylist

```html
<style>p,,.absent{display:none}</style><p>TEXT</p>
```

Output (JSON string): `"<invisible reason=\"display:none\">TEXT</invisible>"`. CSS incomplete: false.

### selector-missing-close

```html
<style>p, .absent[x=y{display:none}</style><p>TEXT</p>
```

Output (JSON string): `"TEXT"`. CSS incomplete: false.

### font-shorthand-reset

```html
<p style="font-size:0;font:16px Arial">TEXT</p>
```

Output (JSON string): `"<visibility-uncertain>TEXT</visibility-uncertain>"`. CSS incomplete: false.

### all-reset-animation

```html
<style>@keyframes k{to{opacity:0}}</style><p style="animation:k 1s infinite;all:initial">TEXT</p>
```

Output (JSON string): `"<visibility-uncertain>TEXT</visibility-uncertain>"`. CSS incomplete: false.

### body-font-default

```html
<body style="font-size:1px"><h1>TEXT</h1></body>
```

Output (JSON string): `"<invisible reason=\"font-size\" value=\"1px\">TEXT</invisible>"`. CSS incomplete: false.

### small-default

```html
<div style="font-size:3px"><small>TEXT</small></div>
```

Output (JSON string): `"TEXT"`. CSS incomplete: false.

### font-size-adjust

```html
<p style="font-size:1px;font-size-adjust:10">TEXT</p>
```

Output (JSON string): `"<invisible reason=\"font-size\" value=\"1px\">TEXT</invisible>"`. CSS incomplete: false.

### text-stroke-zero

```html
<p style="color:transparent;-webkit-text-stroke:1px black;-webkit-text-stroke-width:0">TEXT</p>
```

Output (JSON string): `"<invisible reason=\"color-match\">TEXT</invisible>"`. CSS incomplete: false.

### logical-overflow

```html
<div style="height:0;overflow-block:hidden">TEXT</div>
```

Output (JSON string): `"TEXT"`. CSS incomplete: false.

### logical-min-size

```html
<div style="height:0;min-height:50px;overflow:hidden">TEXT</div>
```

Output (JSON string): `"<visibility-uncertain>TEXT</visibility-uncertain>"`. CSS incomplete: false.

### dark-inherited-none

```html
<style>div{display:none}@media(prefers-color-scheme:dark){p{display:block}}</style><div><p style="display:inherit">TEXT</p></div>
```

Output (JSON string): `"<invisible reason=\"display:none\">TEXT</invisible>"`. CSS incomplete: false.

### dark-custom-losing

```html
<style>p{--x:none!important;display:var(--x)}@media(prefers-color-scheme:dark){p{--x:block}}</style><p>TEXT</p>
```

Output (JSON string): `"<visibility-uncertain>TEXT</visibility-uncertain>"`. CSS incomplete: false.

### escaped-none

```html
<style>@keyframes k{to{color:red}}</style><div style="display:n\6f ne"><p style="animation:k 1s infinite">TEXT</p></div>
```

Output (JSON string): `"<invisible reason=\"display:none\">TEXT</invisible>"`. CSS incomplete: false.

### ligature-content

```html
<p style="text-transform:uppercase">text</p>
```

Output (JSON string): `"text"`. CSS incomplete: false.

### generated

```html
<style>p::before{content:"TEXT"}</style><p></p>
```

Output (JSON string): `""`. CSS incomplete: false.

### hidden-svg-foreignobject

```html
<svg><foreignObject><div style="display:none">TEXT</div></foreignObject></svg>
```

Output (JSON string): `"<invisible reason=\"display:none\">TEXT</invisible>"`. CSS incomplete: false.

### visibility-variable-inherit

```html
<div style="visibility:hidden"><p style="--x:visible;visibility:var(--x)">TEXT</p></div>
```

Output (JSON string): `"TEXT"`. CSS incomplete: false.

### clip-variable

```html
<p style="position:absolute;--r:rect(0,0,0,0);clip:var(--r)">TEXT</p>
```

Output (JSON string): `"<invisible reason=\"empty-clip\">TEXT</invisible>"`. CSS incomplete: false.

### relative-offscreen

```html
<p style="position:relative;left:-9999px">TEXT</p>
```

Output (JSON string): `"TEXT"`. CSS incomplete: false.

### float-zero

```html
<div style="width:0;height:0;overflow:hidden"><p style="float:left">TEXT</p></div>
```

Output (JSON string): `"<visibility-uncertain>TEXT</visibility-uncertain>"`. CSS incomplete: false.

### font-fill-parent-reset

```html
<div style="-webkit-text-fill-color:white"><p style="-webkit-text-fill-color:currentcolor;color:black">TEXT</p></div>
```

Output (JSON string): `"TEXT"`. CSS incomplete: false.

### opacity-independent-hide

```html
<div style="display:none"><p style="opacity:1;filter:none">TEXT</p></div>
```

Output (JSON string): `"<invisible reason=\"display:none\">TEXT</invisible>"`. CSS incomplete: false.

### native-details-flex

```html
<details><summary>SUMMARY</summary><div style="display:block">TEXT</div></details>
```

Output (JSON string): `"SUMMARY\n<visibility-uncertain>TEXT</visibility-uncertain>"`. CSS incomplete: false.

### external-css

```html
<link rel=stylesheet href="https://example.invalid/a.css"><p>TEXT</p>
```

Output (JSON string): `"TEXT"`. CSS incomplete: true.

### nesting

```html
<style>.absent{& p{display:none}}</style><p>TEXT</p>
```

Output (JSON string): `"<visibility-uncertain>TEXT</visibility-uncertain>"`. CSS incomplete: true.

### heading-threshold

```html
<body style="font-size:1.5px"><h1>TEXT</h1></body>
```

Output (JSON string): `"<invisible reason=\"font-size\" value=\"1.5px\">TEXT</invisible>"`. CSS incomplete: false.

### small-threshold

```html
<div style="font-size:2.2px"><small>TEXT</small></div>
```

Output (JSON string): `"TEXT"`. CSS incomplete: false.

### heading-author-override

```html
<body style="font-size:1.5px"><h1 style="font-size:16px">TEXT</h1></body>
```

Output (JSON string): `"TEXT"`. CSS incomplete: false.

### input-normal

```html
<input type=button value=TEXT>
```

Output (JSON string): `"TEXT"`. CSS incomplete: false.

### input-white-button

```html
<input type=button value=TEXT style="appearance:none;color:white;background:white">
```

Output (JSON string): `"TEXT"`. CSS incomplete: false.

### input-small-submit

```html
<input type=submit value=TEXT style="font-size:0">
```

Output (JSON string): `"TEXT"`. CSS incomplete: false.

### input-small-reset

```html
<input type=reset value=TEXT style="font-size:0">
```

Output (JSON string): `"TEXT"`. CSS incomplete: false.

### button-small

```html
<button style="font-size:0">TEXT</button>
```

Output (JSON string): `"<invisible reason=\"font-size\" value=\"0px\">TEXT</invisible>"`. CSS incomplete: false.

### selector-leading-comma

```html
<style>,p{display:none}</style><p>TEXT</p>
```

Output (JSON string): `"<invisible reason=\"display:none\">TEXT</invisible>"`. CSS incomplete: false.

### selector-trailing-comma

```html
<style>p,{display:none}</style><p>TEXT</p>
```

Output (JSON string): `"<invisible reason=\"display:none\">TEXT</invisible>"`. CSS incomplete: false.

### selector-valid-attribute

```html
<style>p[x=y]{display:none}</style><p>TEXT</p>
```

Output (JSON string): `"TEXT"`. CSS incomplete: false.

### selector-negated-extension

```html
<style>p:not([x!=y]){display:none}</style><p x=y>TEXT</p>
```

Output (JSON string): `"<invisible reason=\"display:none\">TEXT</invisible>"`. CSS incomplete: false.

### variable-inset-nested

```html
<p style="position:absolute;--a:-9999px auto auto -9999px;--b:var(--a);inset:var(--b)">TEXT</p>
```

Output (JSON string): `"TEXT"`. CSS incomplete: false.

### logical-inset-variable

```html
<p style="position:absolute;--a:-9999px auto;inset-inline:var(--a)">TEXT</p>
```

Output (JSON string): `"TEXT"`. CSS incomplete: false.

### logical-inset-literal

```html
<p style="position:absolute;inset-inline:-9999px auto">TEXT</p>
```

Output (JSON string): `"<visibility-uncertain>TEXT</visibility-uncertain>"`. CSS incomplete: false.

### physical-overflow

```html
<div style="height:0;overflow-y:hidden">TEXT</div>
```

Output (JSON string): `"<visibility-uncertain>TEXT</visibility-uncertain>"`. CSS incomplete: false.

### static-offset

```html
<p style="position:static;left:-9999px">TEXT</p>
```

Output (JSON string): `"TEXT"`. CSS incomplete: false.

### absolute-offset

```html
<p style="position:absolute;left:-9999px">TEXT</p>
```

Output (JSON string): `"<visibility-uncertain>TEXT</visibility-uncertain>"`. CSS incomplete: false.

### relative-ancestor

```html
<div style="position:relative;left:-9999px"><p>TEXT</p></div>
```

Output (JSON string): `"TEXT"`. CSS incomplete: false.

### ordinary-transform-scale

```html
<p style="font-size:1px;transform:scale(20)">TEXT</p>
```

Output (JSON string): `"<visibility-uncertain>TEXT</visibility-uncertain>"`. CSS incomplete: false.

### dark-custom-winning

```html
<style>p{--x:none;display:var(--x)}@media(prefers-color-scheme:dark){p{--x:block}}</style><p>TEXT</p>
```

Output (JSON string): `"<visibility-uncertain>TEXT</visibility-uncertain>"`. CSS incomplete: false.

### dark-literal-losing

```html
<style>p{display:none!important}@media(prefers-color-scheme:dark){p{display:block}}</style><p>TEXT</p>
```

Output (JSON string): `"<invisible reason=\"display:none\">TEXT</invisible>"`. CSS incomplete: false.

### variable-cycle

```html
<p style="--a:var(--b);--b:var(--a);display:var(--a)">TEXT</p>
```

Output (JSON string): `"TEXT"`. CSS incomplete: false.

### opacity-zero

```html
<p style="opacity:0">TEXT</p>
```

Output (JSON string): `"<visibility-uncertain>TEXT</visibility-uncertain>"`. CSS incomplete: false.

### visibility-reset

```html
<div style="visibility:hidden"><p style="visibility:visible">TEXT</p></div>
```

Output (JSON string): `"TEXT"`. CSS incomplete: false.

### display-none-reset

```html
<div style="display:none"><p style="display:block">TEXT</p></div>
```

Output (JSON string): `"<invisible reason=\"display:none\">TEXT</invisible>"`. CSS incomplete: false.


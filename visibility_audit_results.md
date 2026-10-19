# Visibility classification audit

Date: 2026-10-19. Source revision: `9ab1fb4`. Reliability audit; no production changes or fixes applied.

## Result and contract

Found **11 groups of reproducible correctness defects or coverage gaps**. The first six can produce confident opposite classifications or omit potentially displayed text. The remaining five primarily produce unnecessary uncertainty. These priorities reflect the consequences and simplicity of the examples, not measured frequency in a mail corpus.

The implementation is a bounded presentation approximation, not an email-client renderer. Its internal labels are `visible`, `concealed`, `unknown`, and viewport-dependent `client-dependent`; downstream message output maps the last two to visibility-uncertain. The audit treats a definite label as unjustified when relevant supported rendering can contradict it. Where clients differ, uncertainty is the minimum safe recommendation, not a claim that every client should render identically.

Existing deliberate policies: light mode is canonical; font sizes at or below 2px and very low opacity count as concealed; colour concealment uses a perceptual-distance threshold; default background assumptions apply. Scripts and remote resources are not executed/fetched. These choices are not themselves reported as bugs. However, an ignored effect that invalidates a threshold proof is a bug (finding 5).

Missing applicable CSS is also a document-level condition: `UnresolvedStylesheet`/CSS-limit status can coexist with definite node labels. The message consumer sets CSSIncomplete and suppresses confident-visible counting. This is an explicit API contract, not evidence that each visible node was fully evaluated. Any other consumer must honour that status and analysis errors.

## Method and validation

Reviewed the classification pipeline, property inventory, cascade, selector planning, inheritance, content scopes, media/conditional handling, paint/layout approximations and downstream interpretation. Followed parser/selector boundaries into the forks where relevant; this is not a new exhaustive audit of every fork function.

Ran 85 small diagnostic HTML/CSS inputs through the public Analyze API, including ordinary controls, malformed input and feature interactions. Actual outputs are recorded independently of the expected interpretation. Also ran 128 passing metamorphic checks comparing supported inline/type/class/ID rules through neutral wrappers, with literal and variable colours and standard concealment properties.

Existing `go test ./internal/htmlextract ./internal/message ./internal/fork/...` passed (cached). The new diagnostic test ran with `-count=1` and passed. Existing tests passing does not negate the defects below: the targeted probes expose cases they do not assert.

Expectations come from primary HTML/CSS specifications and the code's stated policies, not from treating existing tests as the oracle. No browser was available on PATH, and no Outlook/Gmail/Apple Mail rendering matrix was run. Accordingly, client-specific conclusions are expressed as uncertainty, and exact cross-client appearance remains unverified. This is broad static/dynamic coverage, not proof over all HTML/CSS or all possible feature combinations.

Local, ignored evidence: `local-testing/visibility-audit/cases.json`, `results.jsonl`, `main.go`, and `audit_test.go`. The complete targeted inputs/results are also embedded in this report so it remains usable without those ignored files.

Reproduction from the repository root:

```sh
go run ./local-testing/visibility-audit
go test ./local-testing/visibility-audit -count=1
```

## Findings

### 1. Missing link colours and legacy colour hints

**Priority:** High: ordinary email can receive the opposite label.

**Location:** `internal/htmlextract/values.go:18 (makeInitialStyle); colour.go:247 (legacyDeclarationsWithBudget)`.

**Reproduction: link-default-colour**

```html
<body style="color:white"><a href="https://example.invalid">TEXT</a></body>
```

Actual: 'TEXT': concealed.

**Reproduction: body-text**

```html
<body text=white>TEXT</body>
```

Actual: 'TEXT': visible.

**Reproduction: body-link-hint**

```html
<body link=white><a href="https://example.invalid">TEXT</a></body>
```

Actual: 'TEXT': visible.

**Expected:** The link is concealed because it inherits white in the extractor. A normal unstyled hyperlink has a UA link colour; it should be visible under the usual default palette, or uncertain when the client palette is unspecified. The body text and link hints produce visible instead of concealed on the assumed white canvas (or uncertain when client support varies).

**Root cause:** Initial CSS values are being used where element-specific UA rules or presentational hints are needed. The existing legacy declaration generator covers only part of the relevant HTML behaviour.

**Suggested minimal fix:** Add a small element-default/presentational-hint stage with the correct cascade origin and priority. Cover hyperlink colours and body text/link/vlink hints together. Use uncertainty for unspecified visited/client colours; do not hard-code one blue as universal. Explicit author colour and color:inherit must still override UA defaults.

**Regression checks and performance:** Test unvisited/visited uncertainty, explicit author overrides, non-links, inherited white and dark backgrounds. Expected small per-element cost; no rendering engine required.

### 2. Native hidden content and resource fallback are treated as ordinary or inert text

**Priority:** High: false visible results and complete omission of potentially displayed text.

**Location:** `internal/htmlextract/document.go:87 (nodeContentScope); values.go:18; document.go:192 (visit)`.

**Reproduction: details-closed**

```html
<details><summary>SUMMARY</summary><p>TEXT</p></details>
```

Actual: 'SUMMARY': visible, 'TEXT': visible.

**Reproduction: dialog-closed**

```html
<dialog>TEXT</dialog>
```

Actual: 'TEXT': visible.

**Reproduction: datalist**

```html
<datalist><option>TEXT</option></datalist>
```

Actual: 'TEXT': visible.

**Reproduction: ruby-fallback**

```html
<ruby>A<rp>TEXT</rp><rt>B</rt></ruby>
```

Actual: 'A': visible, 'TEXT': visible, 'B': visible.

**Reproduction: canvas-fallback**

```html
<canvas>TEXT</canvas>
```

Actual: 'TEXT': visible.

**Reproduction: object-fallback**

```html
<object data="missing.png" type="image/png"><p>TEXT</p></object>
```

Actual: no extracted text.

**Expected:** Closed disclosure content, closed dialogs, datalist contents and ruby fallback parentheses should not be confidently visible in clients implementing their native behaviour. Canvas fallback depends on support. Object fallback can be displayed when loading fails, yet the extractor returns no text at all. At minimum preserve potentially rendered fallback as uncertain and distinguish native hidden states from normal content.

**Root cause:** The content-scope table and generic initial style do not model these element states. Object is unconditionally inert. This is partly an existing scope choice, but does not satisfy the requested audit contract of retaining all potentially displayed email text.

**Suggested minimal fix:** Use a namespace-aware element presentation table shared with downstream traversal: default style, conditional/native rendering, and fallback-content policy. Preserve uncertain fallback text instead of deleting it. Apply overridable defaults through the cascade; do not implement a blanket unoverrideable hidden tag list. Handle the first summary of details separately.

**Regression checks and performance:** Test open/closed forms, author overrides where applicable, fallback resource success/failure uncertainty, and nested summaries. Small lookup/state cost; retaining fallback text adds proportional, budgeted work.

### 3. Scroll containers bypass the existing clipping analysis

**Priority:** High: confidently visible text in a zero-height clipping container.

**Location:** `internal/htmlextract/layout.go:155 (overflowClips), :167 (overflowDefinitelyClips)`.

**Reproduction: overflow-auto-zero**

```html
<div style="height:0;overflow:auto">TEXT</div>
```

Actual: 'TEXT': visible.

**Reproduction: overflow-scroll-zero**

```html
<div style="height:0;overflow:scroll">TEXT</div>
```

Actual: 'TEXT': visible.

**Expected:** Both currently produce visible. They should enter the same conservative geometry analysis as overflow:hidden and produce at least uncertainty; in the simple zero-height default box the text is clipped.

**Root cause:** The predicates recognise hidden/clip but omit auto/scroll.

**Suggested minimal fix:** Centralise overflow value semantics and include auto/scroll where clipping is possible. Account for the computed interaction between the two axes. Reuse the existing zero/tiny-box analysis; do not infer that every scroll container hides its text.

**Regression checks and performance:** Test both axes, nonzero boxes, inline applicability, padding, and positioned descendants that can escape clipping. A few comparisons; unlikely to materially affect ordinary throughput.

### 4. Logical dimensions and inset properties are silently ignored

**Priority:** High: familiar off-screen/zero-size techniques evade uncertainty.

**Location:** `internal/htmlextract/properties.go; css.go:770 (relevantNormalizedDeclarationProperty); layout.go:24`.

**Reproduction: logical-size-zero**

```html
<div style="block-size:0;overflow:hidden">TEXT</div>
```

Actual: 'TEXT': visible.

**Reproduction: logical-offset**

```html
<p style="position:absolute;inset-inline-start:-9999px">TEXT</p>
```

Actual: 'TEXT': visible.

**Reproduction: logical-inset-shorthand**

```html
<p style="position:absolute;inset:-9999px auto auto -9999px">TEXT</p>
```

Actual: 'TEXT': visible.

**Expected:** All produce visible. block-size:0 with clipping should trigger the height-equivalent uncertainty. Logical off-screen positioning and the physical inset shorthand should trigger the existing offset analysis. Exact geometry remains uncertain.

**Root cause:** The property inventory admits physical longhands but omits equivalent logical properties and inset shorthands. Unrecognised declarations disappear rather than contributing relevant uncertainty.

**Suggested minimal fix:** Add a shared property-effects table covering logical sizing/offsets and their shorthands. Expand physical inset directly. Resolve logical mappings only when writing-mode/direction are known; otherwise mark the affected geometry uncertain. Preserve declaration order and important priority across physical/logical aliases.

**Regression checks and performance:** Test horizontal/vertical writing modes, RTL, logical/physical conflicts and shorthand ordering. Constant-size bookkeeping is cheap; no layout engine is needed for the conservative fix.

### 5. Scaling can invalidate the small-font concealment proof

**Priority:** High: readable enlarged text is labelled concealed.

**Location:** `internal/htmlextract/visibility.go:73 (decideVisibility); layout.go:269 (nearZeroZoom); colour.go:393`.

**Reproduction: zoom-enlarges-small**

```html
<p style="font-size:1px;zoom:20">TEXT</p>
```

Actual: 'TEXT': concealed.

**Reproduction: transform-enlarges-small**

```html
<p style="font-size:1px;transform:scale(20);transform-origin:0 0">TEXT</p>
```

Actual: 'TEXT': concealed.

**Reproduction: zoom-enlarges-small-child**

```html
<div style="zoom:20"><p style="font-size:1px">TEXT</p></div>
```

Actual: 'TEXT': concealed.

**Expected:** All produce concealed with font-size as the reason. A 1px font scaled twenty times is not a 1px painted glyph. The minimum safe result is uncertain when scaling is unsupported, or visible when the final size and other relevant properties are known.

**Root cause:** The threshold uses the unscaled computed font size. Transform uncertainty affects the colour calculation, but any concealment bit overrides that uncertainty. Zoom handling detects near-zero values without carrying enlargement into the size proof.

**Suggested minimal fix:** Track whether the font-size concealment reason remains valid after ancestor/own scaling. A minimal fix suppresses that reason under potentially enlarging unresolved scale; known zoom can instead accumulate an effective scale. Preserve independent display:none or visibility:hidden reasons.

**Regression checks and performance:** Test ancestor and nested zoom, percentages, scale transforms, independent hiding and ordinary unscaled tiny text. A scalar/flag per traversal frame is inexpensive; exact arbitrary transform geometry is unnecessary.

### 6. An invalid selector-list branch can leave another branch confidently active

**Priority:** High: invalid CSS can hide text only in the extractor.

**Location:** `internal/htmlextract/selector_plan.go:294 (planSelectorListWithStop), :319 (planSelectorBranch)`.

**Reproduction: list-invalid-attribute**

```html
<style>p, .absent[foo=]{display:none}</style><p>TEXT</p>
```

Actual: 'TEXT': concealed.

**Expected:** The result is concealed. The ordinary selector list is invalid, so the whole rule should be ignored and TEXT should remain visible.

**Root cause:** Branches are planned independently. A valid p branch survives while the invalid attribute selector is scoped to an absent class. This accidentally applies forgiving-list behaviour at the stylesheet rule level.

**Suggested minimal fix:** Validate the ordinary selector list as a unit before installing exact branch plans. Distinguish definitely invalid syntax from valid-but-unsupported selectors. Reject a definitely invalid list; if validity cannot be established, downgrade all potentially applicable branches. Keep the special forgiving semantics only where the selector grammar specifies them.

**Regression checks and performance:** Test an invalid branch before/after a valid one, malformed attributes, valid unsupported selectors, and :is/:where versus ordinary comma lists. Reuse parser metadata to avoid a second parse; modest stylesheet-only overhead.

### 7. Background shorthand does not reset tracked background clipping

**Priority:** Medium: definite concealment is reported uncertain.

**Location:** `internal/htmlextract/colour.go:26 (backgroundDeclarations), :31 (backgroundDeclarationsTokens); css.go:793`.

**Reproduction: background-reset**

```html
<p style="background-clip:text;background:white;color:white">TEXT</p>
```

Actual: 'TEXT': unknown.

**Expected:** The result is unknown. The later background:white resets background-clip to border-box, so white text on white should be concealed under the existing contrast policy.

**Root cause:** Shorthand expansion updates colour/image but leaves the earlier background-clip:text uncertainty in place.

**Suggested minimal fix:** Define shorthand ownership once and reset every tracked constituent, including background-clip. Parse explicit box components where supported; retain uncertainty for valid unsupported values. Apply the same ownership review to font, mask and all, rather than adding a one-off clearing flag.

**Regression checks and performance:** Test shorthand/longhand order, important priority, variables and explicit box keywords. Constant-size expansion; negligible expected cost.

### 8. Overridden glyph/layout properties leave sticky ancestor uncertainty

**Priority:** Medium: independently resolvable text stays uncertain.

**Location:** `internal/htmlextract/colour.go:393 (layerWithClipOverride), :444 (evaluateColour); analyze.go presentation-state propagation; values.go:45`.

**Reproduction: shadow-reset**

```html
<div style="color:white;text-shadow:0 0 1px black"><span style="text-shadow:none">TEXT</span></div>
```

Actual: 'TEXT': unknown.

**Reproduction: indent-reset**

```html
<div style="text-indent:-9999px"><p style="text-indent:0">TEXT</p></div>
```

Actual: 'TEXT': unknown.

**Reproduction: fill-currentcolor-reset**

```html
<div style="-webkit-text-fill-color:transparent"><span style="-webkit-text-fill-color:currentcolor;color:black">TEXT</span></div>
```

Actual: 'TEXT': unknown.

**Expected:** All produce unknown. With the child reset, white text without a shadow should be concealed; the reset indentation and black currentcolor examples should be visible under the ordinary model.

**Root cause:** Ancestor paint layers retain glyph-specific effects even after descendants override them. Layout uncertainty is also ORed down the tree. That is appropriate for actual ancestor clipping/group effects, but not for all inherited and resettable text properties.

**Suggested minimal fix:** Separate ancestor group effects from computed per-text glyph properties and inherited text-layout properties. Resolve/reset the latter in the normal cascade, and evaluate them at the text owner. Keep clipping, opacity, filters and other true group effects on the ancestor stack.

**Regression checks and performance:** Test reset and inherited variants side by side, including a genuine ancestor filter/clip that must remain uncertain. Likely similar or lower colour-stack work; small fixed style-state increase.

### 9. Dark-mode uncertainty ignores cascade winners and the owner of hiding

**Priority:** Medium: unchangeably hidden text is reported uncertain.

**Location:** `internal/htmlextract/resolver.go:273 (collectCascade), :509 (alternateColourSchemeEffects); visibility.go:121; analyze.go`.

**Reproduction: dark-rule-overridden**

```html
<style>p{display:none!important}@media(prefers-color-scheme:dark){p{display:block}}</style><p>TEXT</p>
```

Actual: 'TEXT': unknown.

**Reproduction: dark-child-ancestor**

```html
<style>div{display:none}@media(prefers-color-scheme:dark){p{display:block}}</style><div><p>TEXT</p></div>
```

Actual: 'TEXT': unknown.

**Expected:** Both produce unknown although display:none remains effective in both schemes: the dark rule loses to important in the first case, and a child cannot undo the ancestor display:none in the second.

**Root cause:** Alternate declarations contribute reason-category bits before proving they can win. Those bits are propagated without identifying which element supplied the concealment reason.

**Suggested minimal fix:** Associate concealment evidence with its owning element and compare alternate cascade winners before invalidating that evidence. A bounded alternate-cascade evaluation is simpler to reason about than declaration-presence guesses; cache/reuse selector matches. Keep the explicitly chosen light-mode canonical policy.

**Regression checks and performance:** Test important/specificity/order, ancestor versus child ownership, and a genuinely winning reveal rule. This fix has the greatest plausible CPU impact if it adds a cascade pass; restrict it to affected documents and benchmark before choosing the implementation.

### 10. Animation uncertainty overrides independent hiding

**Priority:** Medium: text that cannot be revealed becomes uncertain.

**Location:** `internal/htmlextract/visibility.go:125; animation.go:271 (potentiallyActiveAnimation); analyze.go`.

**Reproduction: animation-display-none**

```html
<style>@keyframes k{to{color:red}}</style><div style="display:none"><p style="animation:k 1s infinite">TEXT</p></div>
```

Actual: 'TEXT': unknown.

**Reproduction: animation-parent-child**

```html
<style>@keyframes k{to{opacity:0}}</style><div style="animation:k 1s infinite"><p style="display:none">TEXT</p></div>
```

Actual: 'TEXT': unknown.

**Expected:** Both produce unknown. The child colour animation cannot undo its parent display:none; the ancestor opacity animation cannot undo its child display:none. Concealed is justified independently of animation timing.

**Root cause:** An inherited animationUncertain boolean unconditionally replaces the final classification, without an element/property dependency check.

**Suggested minimal fix:** Preserve proven concealment unaffected by the potentially animated element/properties. Reuse the owner-aware evidence from finding 9. Initially retaining an independent ancestor display:none proof is enough for the first case; broader precision requires recording keyframe property effects. Do not implement animation playback.

**Regression checks and performance:** Test animation on the hiding element, on children, on ancestors, and inactive/none animations. Fixed metadata should be inexpensive; any keyframe scan must use existing CPU/memory guards.

### 11. Definitely invalid values are treated as unsupported effects

**Priority:** Medium: invalid CSS changes classifications instead of being ignored.

**Location:** `internal/htmlextract/css.go:793 (declarationsFromParsed); values.go:66 (resolveWithBudget)`.

**Reproduction: invalid-all**

```html
<p style="display:none;all:bananas">TEXT</p>
```

Actual: 'TEXT': unknown.

**Reproduction: invalid-filter**

```html
<p style="filter:bananas">TEXT</p>
```

Actual: 'TEXT': unknown.

**Reproduction: invalid-clip**

```html
<p style="clip-path:bananas">TEXT</p>
```

Actual: 'TEXT': unknown.

**Expected:** The results are unknown. all:bananas is invalid and must not replace display:none; the first case should remain concealed. Invalid filter/clip-path identifiers should leave the otherwise ordinary text visible.

**Root cause:** The invalid-versus-unsupported distinction is implemented for some properties but not consistently at these entry points.

**Suggested minimal fix:** Add inexpensive grammar rejection for definitely invalid forms before producing an unsupported value. Start with the closed all grammar and impossible bare identifiers for these effects. Keep genuinely valid but unevaluated functions uncertain; do not equate every unknown feature with invalid CSS.

**Regression checks and performance:** Test invalid later declarations, important, valid unsupported functions and variable substitution (including invalid-at-computed-value behaviour). Small token-validation cost, often less subsequent uncertainty processing.

## Coverage ledger and remaining boundaries

“Reviewed” below means source-path review plus the listed probes/existing tests, not that every possible input was enumerated. Helper modules are grouped to avoid confusing file count with semantic coverage.

| Source area | Coverage and disposition |
| --- | --- |
| `doc.go`, `document.go` | Contract, scope, DOM preparation, head/inert content, hidden inputs, comments and malformed tree recovery. Native/fallback gaps: finding 2. SVG title omission and SVG rendering remain scope decisions. |
| `analyze.go`, `visibility.go` | Traversal, ancestor state, per-width aggregation, concealment reasons, unknown precedence, light-mode policy, stopped/incomplete paths. Findings 5, 8–10. |
| `properties.go`, `values.go` | Initial values, inherited properties, supported property inventory, unsupported/invalid distinction, CSS-wide values. Findings 1, 4, 8, 11. |
| `css.go`, `css_parser.go`, `css_whitespace.go` | Inline/stylesheet parsing, declaration order, important, shorthands, nesting and recovery. Important/invalid-colour controls behaved correctly; findings 7 and 11. Unsupported nesting can deliberately make the whole cascade uncertain. |
| `selector_plan.go`, `selector_runtime.go`, `resolver.go` | Selector indexing/scoping, exact versus conservative matches, cascade priority, variables, alternate scheme effects. Findings 6 and 9. Unsupported selector scoped to an absent class did not taint unrelated text. Quirks-mode semantics need a contract decision. |
| `variables.go` | Inheritance, cycles, fallbacks, empty values, substitution boundaries and invalid-at-computed-value behaviour. Targeted cycle/empty/missing/token-boundary controls behaved as expected. No additional confirmed defect in this pass. |
| `arithmetic.go`, `numbers.go`, `length_units.go` | Numeric grammar, finite values, relative/absolute/contextual units, typed arithmetic and unsupported maths. Root-relative and calc controls passed. No additional confirmed defect; not exhaustive numerical differential testing. |
| `colour.go`, `colour_values.go` | Legacy hints, background shorthand/propagation, foreground/background compositing, colour grammar, unsupported effects and contrast. Findings 1, 7, 8. Existing colour/reference tests pass; generated supported colour equivalents pass. Sibling geometry is outside this model. |
| `layout.go`, `clipping.go` | Overflow, zero/tiny dimensions, offsets, spacing, margins, zoom, clip/clip-path and applicability. Findings 3–5. Padding and escaping-position probes remain conservative unknown, not newly claimed defects. |
| `media.go` | Viewport case generation, condition combination and unknown conditions. Width-dependent case yields client-dependent; print-only ignored for screen; not-print conservatively unknown. Dark-mode issue is in winner/evidence handling (finding 9). |
| `animation.go` | Keyframe names, animation declaration activation and uncertainty. Important animation-name:none control behaves correctly; finding 10. Full animation execution is intentionally absent. |
| `conditional_styles.go` | MSO comment extraction/conditions, revealed markers and conservative ordering behaviour. Independent display:none survived a revealed conditional wrapper. Existing conditional tests pass; no live Outlook verification. |
| `stylesheets.go` | Applicable style/link types, relation, media, imports, data references and unresolved external CSS. External-sheet control sets incomplete status. No newly confirmed defect; remote contents deliberately unavailable. |
| `limits.go`, `cpu.go`, `allocation.go`, `formatting.go` | Reviewed roles at semantic/fallback boundaries. Existing guard/format tests pass; this was not a repeat resource-overrun audit. Partial/error results must not be interpreted as a complete successful analysis. |
| `internal/fork/xnethtml` boundary | Tree recovery/content parsing consumed by extractor; malformed table control and existing fork tests. No full independent HTML parsing differential suite was added. |
| `internal/fork/tdewolffparse/css` boundary | Token/declaration errors and recovery consumed by extractor; invalid grammar and shorthand probes. Finding 11 concerns interpretation after parsing. |
| `internal/fork/cascadia` boundary | Compilation metadata and matching consumed by selector plans; invalid selector-list probe exposes finding 6 at the integration boundary. |
| `internal/message/html_tree.go` and associated tests | Label translation, CSSIncomplete/confident counts and fallback integration. Existing tests pass. Any fallback-content fix must update both extraction and consumer traversal consistently. |

The following are explicit limitations or unresolved contract issues rather than additional fully validated defect groups:

- **Occlusion and geometry:** a positioned white sibling overlay can cover TEXT while the extractor calls it visible (`sibling-occlusion`). The code does not compute sibling paint order or occupied pixels. This is a real gap against literal pixel visibility, but there is no small general layout fix. A targeted overlap-risk uncertainty policy is feasible; exact handling requires a substantially broader model. Absence of a known hiding rule is not a proof that text reaches the screen.
- **Box generation:** `display:table-column` on a text-bearing div currently yields visible. Internal table box behaviour deserves a separate conformance test before choosing a fix. It should be part of the element/box presentation inventory, not treated as ordinary inline text by default. No browser verification was performed for this probe.
- **Quirks mode and embedding:** a no-doctype `.X` / `class=x` case stays visible. Whether the input is modelled as a standalone quirks document or as a fragment inserted into a standards-mode mail viewer must be specified before setting the expected selector behaviour.
- **Unsupported features:** font shorthand, display:contents composition, contextual geometry, complex paint effects, nested CSS, and some media syntax often yield unknown deliberately. Such results are coverage limitations, not automatically bugs. Known-invalid syntax and independently unaffected concealment are different (findings 9–11).
- **Generated/attribute/resource text:** DOM text-node classification does not constitute complete rendered-text extraction. Pseudo-element content, input values, image alternate text, SVG resources, and resource fallback need an explicit inventory and ownership contract between extractor and message renderer. Object fallback is already a concrete omission in finding 2; the broader inventory was not exhaustively reproduced here.
- **Dynamic/client state:** scripting, interaction, forced colours, user styles, font substitution, dark-mode transformations performed by clients, and sanitisation are not fully modelled. No universal definite classification is possible without bounding those environments. Define a client/state domain and use uncertainty when a relevant effect falls outside it.

## Independent semantic references

These sources establish expected semantics; they do not establish particular email-client support. Retrieved 2026-10-19.

- Findings 1–2: [HTML rendering defaults and presentational hints](https://html.spec.whatwg.org/multipage/rendering.html) specify element defaults, link/body colour handling and native hidden states. The extractor's generic initial style is not a substitute for those defaults.
- Finding 2: [HTML object processing](https://html.spec.whatwg.org/multipage/iframe-embed-object.html#the-object-element) includes fallback content when the resource cannot be used.
- Finding 3: [CSS Overflow 3](https://www.w3.org/TR/css-overflow-3/#overflow-properties) defines scroll/auto clipping behaviour as well as hidden/clip; clipping is not exclusive to the latter two values.
- Finding 4: [CSS Logical Properties](https://www.w3.org/TR/css-logical-1/) maps logical dimensions and offsets through writing mode/direction. Ignoring these declarations is not equivalent to a supported physical-property implementation.
- Finding 5: [CSS Viewport zoom](https://drafts.csswg.org/css-viewport/#zoom-property) applies zoom to used lengths, including font size; nested zoom multiplies. Computed font size alone therefore cannot establish painted smallness.
- Finding 6: [Selectors 4 invalid selectors](https://www.w3.org/TR/selectors-4/#invalid) distinguishes ordinary list invalidation from explicitly forgiving selector grammars.
- Finding 7: [CSS background shorthand](https://www.w3.org/TR/css-backgrounds-3/#background) resets omitted constituents, including background-clip, to initial values.
- Finding 8: [CSS text-shadow](https://www.w3.org/TR/css-text-decor-3/#text-shadow-property) is inherited and can be overridden on a descendant; it is not an irrevocable ancestor compositing effect.
- Findings 9 and 11: [CSS Cascade](https://www.w3.org/TR/css-cascade-5/) defines winner ordering, the all shorthand grammar and invalid-value processing. Merely matching a later/dark rule does not establish that it can override a winning important declaration.
- Finding 10: [CSS Display](https://www.w3.org/TR/css-display-3/#box-generation) establishes the subtree suppression of display:none; changing a descendant's colour does not undo that ancestor condition.

## Recommended implementation order

First address confident opposite labels: selector-list validity, overflow values, scaling validity, logical-property coverage, then the element-default/fallback table. Follow with complete shorthand expansion and invalid-value rejection. Finally replace sticky uncertainty with a small model that records the affected property and owning element, sharing it across glyph overrides, dark-mode alternatives and animations.

That last change is the main general design improvement: a concealment reason should carry enough provenance to determine whether a later uncertainty can actually invalidate it. A global unknown flag or property-category bit loses that information. This does not require a full browser engine.

Performance statements above are engineering expectations, not benchmark results for unimplemented fixes. Preserve the existing budgeted allocation owners and stop checks. Benchmark the alternate-cascade/provenance design on the normal mail corpus and interaction-heavy cases before committing to an extra pass. Do not broaden uncertainty indiscriminately: that would fix false certainty at the expense of the ordinary-input precision this audit also checks.

## Complete targeted probe record

Outputs below are observations, not a claim that every listed case has been independently proven correct. Findings and the coverage ledger explain the interpretation. Each probe completed without an analysis error; incomplete status is preserved where reported.

### base

```html
<p>TEXT</p>
```

```json
{"ID": "base", "Text": [{"Text": "TEXT", "Label": "visible", "Size": "16px", "Reasons": null}], "Incomplete": false, "Error": ""}
```

### display-none

```html
<div style="display:none"><span>TEXT</span></div>
```

```json
{"ID": "display-none", "Text": [{"Text": "TEXT", "Label": "concealed", "Size": "16px", "Reasons": ["display-none"]}], "Incomplete": false, "Error": ""}
```

### visibility-restore

```html
<div style="visibility:hidden"><span style="visibility:visible">TEXT</span></div>
```

```json
{"ID": "visibility-restore", "Text": [{"Text": "TEXT", "Label": "visible", "Size": "16px", "Reasons": null}], "Incomplete": false, "Error": ""}
```

### details-closed

```html
<details><summary>SUMMARY</summary><p>TEXT</p></details>
```

```json
{"ID": "details-closed", "Text": [{"Text": "SUMMARY", "Label": "visible", "Size": "16px", "Reasons": null}, {"Text": "TEXT", "Label": "visible", "Size": "16px", "Reasons": null}], "Incomplete": false, "Error": ""}
```

### details-open

```html
<details open><summary>SUMMARY</summary><p>TEXT</p></details>
```

```json
{"ID": "details-open", "Text": [{"Text": "SUMMARY", "Label": "visible", "Size": "16px", "Reasons": null}, {"Text": "TEXT", "Label": "visible", "Size": "16px", "Reasons": null}], "Incomplete": false, "Error": ""}
```

### dialog-closed

```html
<dialog>TEXT</dialog>
```

```json
{"ID": "dialog-closed", "Text": [{"Text": "TEXT", "Label": "visible", "Size": "16px", "Reasons": null}], "Incomplete": false, "Error": ""}
```

### dialog-open

```html
<dialog open>TEXT</dialog>
```

```json
{"ID": "dialog-open", "Text": [{"Text": "TEXT", "Label": "visible", "Size": "16px", "Reasons": null}], "Incomplete": false, "Error": ""}
```

### object-fallback

```html
<object data="missing.png" type="image/png"><p>TEXT</p></object>
```

```json
{"ID": "object-fallback", "Text": null, "Incomplete": false, "Error": ""}
```

### canvas-fallback

```html
<canvas>TEXT</canvas>
```

```json
{"ID": "canvas-fallback", "Text": [{"Text": "TEXT", "Label": "visible", "Size": "16px", "Reasons": null}], "Incomplete": false, "Error": ""}
```

### svg-text

```html
<svg><text fill="white">TEXT</text></svg>
```

```json
{"ID": "svg-text", "Text": [{"Text": "TEXT", "Label": "unknown", "Size": "16px", "Reasons": null}], "Incomplete": false, "Error": ""}
```

### svg-title

```html
<svg><title>TEXT</title></svg>
```

```json
{"ID": "svg-title", "Text": null, "Incomplete": false, "Error": ""}
```

### svg-defs

```html
<svg><defs><text>TEXT</text></defs></svg>
```

```json
{"ID": "svg-defs", "Text": [{"Text": "TEXT", "Label": "unknown", "Size": "16px", "Reasons": null}], "Incomplete": false, "Error": ""}
```

### contents-opacity

```html
<div style="display:contents;opacity:0"><span>TEXT</span></div>
```

```json
{"ID": "contents-opacity", "Text": [{"Text": "TEXT", "Label": "unknown", "Size": "16px", "Reasons": null}], "Incomplete": false, "Error": ""}
```

### contents-background

```html
<div style="display:contents;background:white;color:white">TEXT</div>
```

```json
{"ID": "contents-background", "Text": [{"Text": "TEXT", "Label": "unknown", "Size": "16px", "Reasons": null}], "Incomplete": false, "Error": ""}
```

### inline-content-visibility

```html
<span style="content-visibility:hidden">TEXT</span>
```

```json
{"ID": "inline-content-visibility", "Text": [{"Text": "TEXT", "Label": "unknown", "Size": "16px", "Reasons": null}], "Incomplete": false, "Error": ""}
```

### content-visibility-block

```html
<div style="content-visibility:hidden">TEXT</div>
```

```json
{"ID": "content-visibility-block", "Text": [{"Text": "TEXT", "Label": "unknown", "Size": "16px", "Reasons": null}], "Incomplete": false, "Error": ""}
```

### shadow-reset

```html
<div style="color:white;text-shadow:0 0 1px black"><span style="text-shadow:none">TEXT</span></div>
```

```json
{"ID": "shadow-reset", "Text": [{"Text": "TEXT", "Label": "unknown", "Size": "16px", "Reasons": null}], "Incomplete": false, "Error": ""}
```

### fill-reset

```html
<div style="-webkit-text-fill-color:transparent"><span style="-webkit-text-fill-color:black">TEXT</span></div>
```

```json
{"ID": "fill-reset", "Text": [{"Text": "TEXT", "Label": "unknown", "Size": "16px", "Reasons": null}], "Incomplete": false, "Error": ""}
```

### fill-inherit

```html
<div style="-webkit-text-fill-color:transparent">TEXT<span>CHILD</span></div>
```

```json
{"ID": "fill-inherit", "Text": [{"Text": "TEXT", "Label": "unknown", "Size": "16px", "Reasons": null}, {"Text": "CHILD", "Label": "unknown", "Size": "16px", "Reasons": null}], "Incomplete": false, "Error": ""}
```

### indent-reset

```html
<div style="text-indent:-9999px"><p style="text-indent:0">TEXT</p></div>
```

```json
{"ID": "indent-reset", "Text": [{"Text": "TEXT", "Label": "unknown", "Size": "16px", "Reasons": null}], "Incomplete": false, "Error": ""}
```

### clip-escape

```html
<div style="position:relative;overflow:hidden;width:0;height:0"><p style="position:fixed">TEXT</p></div>
```

```json
{"ID": "clip-escape", "Text": [{"Text": "TEXT", "Label": "unknown", "Size": "16px", "Reasons": null}], "Incomplete": false, "Error": ""}
```

### animation-display-none

```html
<style>@keyframes k{to{color:red}}</style><div style="display:none"><p style="animation:k 1s infinite">TEXT</p></div>
```

```json
{"ID": "animation-display-none", "Text": [{"Text": "TEXT", "Label": "unknown", "Size": "16px", "Reasons": null}], "Incomplete": false, "Error": ""}
```

### animation-parent-child

```html
<style>@keyframes k{to{opacity:0}}</style><div style="animation:k 1s infinite"><p style="display:none">TEXT</p></div>
```

```json
{"ID": "animation-parent-child", "Text": [{"Text": "TEXT", "Label": "unknown", "Size": "16px", "Reasons": null}], "Incomplete": false, "Error": ""}
```

### animation-all-reset

```html
<style>@keyframes k{to{opacity:0}}</style><p style="animation:k 1s infinite;all:initial">TEXT</p>
```

```json
{"ID": "animation-all-reset", "Text": [{"Text": "TEXT", "Label": "unknown", "Size": "initial", "Reasons": null}], "Incomplete": false, "Error": ""}
```

### invalid-all

```html
<p style="display:none;all:bananas">TEXT</p>
```

```json
{"ID": "invalid-all", "Text": [{"Text": "TEXT", "Label": "unknown", "Size": "bananas", "Reasons": null}], "Incomplete": false, "Error": ""}
```

### invalid-filter

```html
<p style="filter:bananas">TEXT</p>
```

```json
{"ID": "invalid-filter", "Text": [{"Text": "TEXT", "Label": "unknown", "Size": "16px", "Reasons": null}], "Incomplete": false, "Error": ""}
```

### invalid-clip

```html
<p style="clip-path:bananas">TEXT</p>
```

```json
{"ID": "invalid-clip", "Text": [{"Text": "TEXT", "Label": "unknown", "Size": "16px", "Reasons": null}], "Incomplete": false, "Error": ""}
```

### overflow-auto-zero

```html
<div style="height:0;overflow:auto">TEXT</div>
```

```json
{"ID": "overflow-auto-zero", "Text": [{"Text": "TEXT", "Label": "visible", "Size": "16px", "Reasons": null}], "Incomplete": false, "Error": ""}
```

### overflow-scroll-zero

```html
<div style="height:0;overflow:scroll">TEXT</div>
```

```json
{"ID": "overflow-scroll-zero", "Text": [{"Text": "TEXT", "Label": "visible", "Size": "16px", "Reasons": null}], "Incomplete": false, "Error": ""}
```

### logical-size-zero

```html
<div style="block-size:0;overflow:hidden">TEXT</div>
```

```json
{"ID": "logical-size-zero", "Text": [{"Text": "TEXT", "Label": "visible", "Size": "16px", "Reasons": null}], "Incomplete": false, "Error": ""}
```

### logical-offset

```html
<p style="position:absolute;inset-inline-start:-9999px">TEXT</p>
```

```json
{"ID": "logical-offset", "Text": [{"Text": "TEXT", "Label": "visible", "Size": "16px", "Reasons": null}], "Incomplete": false, "Error": ""}
```

### padding-zero-box

```html
<div style="height:0;padding:20px;overflow:hidden">TEXT</div>
```

```json
{"ID": "padding-zero-box", "Text": [{"Text": "TEXT", "Label": "unknown", "Size": "16px", "Reasons": null}], "Incomplete": false, "Error": ""}
```

### background-reset

```html
<p style="background-clip:text;background:white;color:white">TEXT</p>
```

```json
{"ID": "background-reset", "Text": [{"Text": "TEXT", "Label": "unknown", "Size": "16px", "Reasons": null}], "Incomplete": false, "Error": ""}
```

### inline-important

```html
<style>#a{display:none!important}</style><p id=a style="display:block">TEXT</p>
```

```json
{"ID": "inline-important", "Text": [{"Text": "TEXT", "Label": "concealed", "Size": "16px", "Reasons": ["display-none"]}], "Incomplete": false, "Error": ""}
```

### variable-boundary

```html
<p style="--n:0;font-size:var(--n)px">TEXT</p>
```

```json
{"ID": "variable-boundary", "Text": [{"Text": "TEXT", "Label": "visible", "Size": "16px", "Reasons": null}], "Incomplete": false, "Error": ""}
```

### variable-invalid

```html
<p style="display:none;display:var(--missing)">TEXT</p>
```

```json
{"ID": "variable-invalid", "Text": [{"Text": "TEXT", "Label": "visible", "Size": "16px", "Reasons": null}], "Incomplete": false, "Error": ""}
```

### variable-cycle

```html
<p style="--a:var(--b);--b:var(--a);display:var(--a,none)">TEXT</p>
```

```json
{"ID": "variable-cycle", "Text": [{"Text": "TEXT", "Label": "concealed", "Size": "16px", "Reasons": ["display-none"]}], "Incomplete": false, "Error": ""}
```

### empty-variable

```html
<p style="--a: ;display:var(--a,none)">TEXT</p>
```

```json
{"ID": "empty-variable", "Text": [{"Text": "TEXT", "Label": "visible", "Size": "16px", "Reasons": null}], "Incomplete": false, "Error": ""}
```

### invalid-selector-list

```html
<style>p, :definitely-invalid{display:none}</style><p>TEXT</p>
```

```json
{"ID": "invalid-selector-list", "Text": [{"Text": "TEXT", "Label": "unknown", "Size": "16px", "Reasons": null}], "Incomplete": false, "Error": ""}
```

### case-insensitive-type-attr

```html
<style>input[type=hidden]{display:none} ol[type=A]{color:white}</style><ol type=a><li>TEXT</li></ol>
```

```json
{"ID": "case-insensitive-type-attr", "Text": [{"Text": "TEXT", "Label": "visible", "Size": "16px", "Reasons": null}], "Incomplete": false, "Error": ""}
```

### quirks-class

```html
<style>.X{display:none}</style><p class=x>TEXT</p>
```

```json
{"ID": "quirks-class", "Text": [{"Text": "TEXT", "Label": "visible", "Size": "16px", "Reasons": null}], "Incomplete": false, "Error": ""}
```

### standards-class

```html
<!doctype html><style>.X{display:none}</style><p class=x>TEXT</p>
```

```json
{"ID": "standards-class", "Text": [{"Text": "TEXT", "Label": "visible", "Size": "16px", "Reasons": null}], "Incomplete": false, "Error": ""}
```

### media-width

```html
<style>@media(min-width:600px){p{display:none}}</style><p>TEXT</p>
```

```json
{"ID": "media-width", "Text": [{"Text": "TEXT", "Label": "client-dependent", "Size": "16px", "Reasons": null}], "Incomplete": false, "Error": ""}
```

### media-print

```html
<style>@media print{p{display:none}}</style><p>TEXT</p>
```

```json
{"ID": "media-print", "Text": [{"Text": "TEXT", "Label": "visible", "Size": "16px", "Reasons": null}], "Incomplete": false, "Error": ""}
```

### media-not-print

```html
<style>@media not print{p{display:none}}</style><p>TEXT</p>
```

```json
{"ID": "media-not-print", "Text": [{"Text": "TEXT", "Label": "unknown", "Size": "16px", "Reasons": null}], "Incomplete": false, "Error": ""}
```

### dark-rule-overridden

```html
<style>p{display:none!important}@media(prefers-color-scheme:dark){p{display:block}}</style><p>TEXT</p>
```

```json
{"ID": "dark-rule-overridden", "Text": [{"Text": "TEXT", "Label": "unknown", "Size": "16px", "Reasons": null}], "Incomplete": false, "Error": ""}
```

### dark-child-ancestor

```html
<style>div{display:none}@media(prefers-color-scheme:dark){p{display:block}}</style><div><p>TEXT</p></div>
```

```json
{"ID": "dark-child-ancestor", "Text": [{"Text": "TEXT", "Label": "unknown", "Size": "16px", "Reasons": null}], "Incomplete": false, "Error": ""}
```

### conditional-display-ancestor

```html
<div style="display:none"><!--[if !mso]><!--><p>TEXT</p><!--<![endif]--></div>
```

```json
{"ID": "conditional-display-ancestor", "Text": [{"Text": "TEXT", "Label": "concealed", "Size": "16px", "Reasons": ["display-none"]}], "Incomplete": false, "Error": ""}
```

### nested-unrelated

```html
<style>.absent{& p{color:red}}</style><p style="display:none">TEXT</p>
```

```json
{"ID": "nested-unrelated", "Text": [{"Text": "TEXT", "Label": "unknown", "Size": "16px", "Reasons": null}], "Incomplete": true, "Error": ""}
```

### inline-recovery

```html
<p style="display:none; color:red)">TEXT</p>
```

```json
{"ID": "inline-recovery", "Text": [{"Text": "TEXT", "Label": "unknown", "Size": "", "Reasons": null}], "Incomplete": false, "Error": ""}
```

### hidden-override

```html
<p hidden style="display:block">TEXT</p>
```

```json
{"ID": "hidden-override", "Text": [{"Text": "TEXT", "Label": "visible", "Size": "16px", "Reasons": null}], "Incomplete": false, "Error": ""}
```

### external-sheet

```html
<link rel=stylesheet href="https://example.invalid/a.css"><p>TEXT</p>
```

```json
{"ID": "external-sheet", "Text": [{"Text": "TEXT", "Label": "visible", "Size": "16px", "Reasons": null}], "Incomplete": true, "Error": ""}
```

### font-size-threshold

```html
<p style="font-size:2px">TEXT</p>
```

```json
{"ID": "font-size-threshold", "Text": [{"Text": "TEXT", "Label": "concealed", "Size": "2px", "Reasons": ["font-size"]}], "Incomplete": false, "Error": ""}
```

### white-white

```html
<p style="color:white;background:white">TEXT</p>
```

```json
{"ID": "white-white", "Text": [{"Text": "TEXT", "Label": "concealed", "Size": "16px", "Reasons": ["colour-distance"]}], "Incomplete": false, "Error": ""}
```

### font-shorthand

```html
<p style="font:16px Arial">TEXT</p>
```

```json
{"ID": "font-shorthand", "Text": [{"Text": "TEXT", "Label": "unknown", "Size": "16px Arial", "Reasons": null}], "Incomplete": false, "Error": ""}
```

### body-text

```html
<body text=white>TEXT</body>
```

```json
{"ID": "body-text", "Text": [{"Text": "TEXT", "Label": "visible", "Size": "16px", "Reasons": null}], "Incomplete": false, "Error": ""}
```

### link-default-colour

```html
<body style="color:white"><a href="https://example.invalid">TEXT</a></body>
```

```json
{"ID": "link-default-colour", "Text": [{"Text": "TEXT", "Label": "concealed", "Size": "16px", "Reasons": ["colour-distance"]}], "Incomplete": false, "Error": ""}
```

### font-relative-root

```html
<html style="font-size:1px"><p style="font-size:16rem">TEXT</p></html>
```

```json
{"ID": "font-relative-root", "Text": [{"Text": "TEXT", "Label": "visible", "Size": "16px", "Reasons": null}], "Incomplete": false, "Error": ""}
```

### font-math

```html
<p style="font-size:calc(16px - 16px)">TEXT</p>
```

```json
{"ID": "font-math", "Text": [{"Text": "TEXT", "Label": "concealed", "Size": "0px", "Reasons": ["font-size"]}], "Incomplete": false, "Error": ""}
```

### malformed-tree

```html
<table><p style="display:none">TEXT</table>
```

```json
{"ID": "malformed-tree", "Text": [{"Text": "TEXT", "Label": "concealed", "Size": "16px", "Reasons": ["display-none"]}], "Incomplete": false, "Error": ""}
```

### list-invalid-local

```html
<style>p, .absent..x{display:none}</style><p>TEXT</p>
```

```json
{"ID": "list-invalid-local", "Text": [{"Text": "TEXT", "Label": "unknown", "Size": "16px", "Reasons": null}], "Incomplete": false, "Error": ""}
```

### list-invalid-attribute

```html
<style>p, .absent[foo=]{display:none}</style><p>TEXT</p>
```

```json
{"ID": "list-invalid-attribute", "Text": [{"Text": "TEXT", "Label": "concealed", "Size": "16px", "Reasons": ["display-none"]}], "Incomplete": false, "Error": ""}
```

### zoom-enlarges-small

```html
<p style="font-size:1px;zoom:20">TEXT</p>
```

```json
{"ID": "zoom-enlarges-small", "Text": [{"Text": "TEXT", "Label": "concealed", "Size": "1px", "Reasons": ["font-size"]}], "Incomplete": false, "Error": ""}
```

### transform-enlarges-small

```html
<p style="font-size:1px;transform:scale(20);transform-origin:0 0">TEXT</p>
```

```json
{"ID": "transform-enlarges-small", "Text": [{"Text": "TEXT", "Label": "concealed", "Size": "1px", "Reasons": ["font-size"]}], "Incomplete": false, "Error": ""}
```

### zoom-enlarges-small-child

```html
<div style="zoom:20"><p style="font-size:1px">TEXT</p></div>
```

```json
{"ID": "zoom-enlarges-small-child", "Text": [{"Text": "TEXT", "Label": "concealed", "Size": "1px", "Reasons": ["font-size"]}], "Incomplete": false, "Error": ""}
```

### logical-inset-shorthand

```html
<p style="position:absolute;inset:-9999px auto auto -9999px">TEXT</p>
```

```json
{"ID": "logical-inset-shorthand", "Text": [{"Text": "TEXT", "Label": "visible", "Size": "16px", "Reasons": null}], "Incomplete": false, "Error": ""}
```

### table-column

```html
<div style="display:table-column">TEXT</div>
```

```json
{"ID": "table-column", "Text": [{"Text": "TEXT", "Label": "visible", "Size": "16px", "Reasons": null}], "Incomplete": false, "Error": ""}
```

### background-origin-reset

```html
<p style="background-clip:text;background:#000;color:#000">TEXT</p>
```

```json
{"ID": "background-origin-reset", "Text": [{"Text": "TEXT", "Label": "unknown", "Size": "16px", "Reasons": null}], "Incomplete": false, "Error": ""}
```

### shadow-inherited-reset

```html
<div style="color:white;text-shadow:0 0 1px black"><p style="text-shadow:none">TEXT</p></div>
```

```json
{"ID": "shadow-inherited-reset", "Text": [{"Text": "TEXT", "Label": "unknown", "Size": "16px", "Reasons": null}], "Incomplete": false, "Error": ""}
```

### body-text-author

```html
<body text=white style="color:black">TEXT</body>
```

```json
{"ID": "body-text-author", "Text": [{"Text": "TEXT", "Label": "visible", "Size": "16px", "Reasons": null}], "Incomplete": false, "Error": ""}
```

### body-link-hint

```html
<body link=white><a href="https://example.invalid">TEXT</a></body>
```

```json
{"ID": "body-link-hint", "Text": [{"Text": "TEXT", "Label": "visible", "Size": "16px", "Reasons": null}], "Incomplete": false, "Error": ""}
```

### link-explicit-inherit

```html
<body style="color:white"><a href="https://example.invalid" style="color:inherit">TEXT</a></body>
```

```json
{"ID": "link-explicit-inherit", "Text": [{"Text": "TEXT", "Label": "concealed", "Size": "16px", "Reasons": ["colour-distance"]}], "Incomplete": false, "Error": ""}
```

### visibility-collapse-flex

```html
<div style="display:flex"><p style="visibility:collapse">TEXT</p></div>
```

```json
{"ID": "visibility-collapse-flex", "Text": [{"Text": "TEXT", "Label": "concealed", "Size": "16px", "Reasons": ["visibility-collapse"]}], "Incomplete": false, "Error": ""}
```

### dark-independent-hide

```html
<style>div{display:none}@media(prefers-color-scheme:dark){p{display:block}}</style><div><p style="visibility:hidden">TEXT</p></div>
```

```json
{"ID": "dark-independent-hide", "Text": [{"Text": "TEXT", "Label": "concealed", "Size": "16px", "Reasons": ["display-none", "visibility-hidden"]}], "Incomplete": false, "Error": ""}
```

### important-invalid-colour

```html
<p style="color:white;color:nope!important">TEXT</p>
```

```json
{"ID": "important-invalid-colour", "Text": [{"Text": "TEXT", "Label": "concealed", "Size": "16px", "Reasons": ["colour-distance"]}], "Incomplete": false, "Error": ""}
```

### whitespace-number

```html
<p style="font-size:0 px">TEXT</p>
```

```json
{"ID": "whitespace-number", "Text": [{"Text": "TEXT", "Label": "visible", "Size": "16px", "Reasons": null}], "Incomplete": false, "Error": ""}
```

### var-empty-fallback

```html
<p style="display:none;display:var(--missing,)">TEXT</p>
```

```json
{"ID": "var-empty-fallback", "Text": [{"Text": "TEXT", "Label": "visible", "Size": "16px", "Reasons": null}], "Incomplete": false, "Error": ""}
```

### font-shorthand-reset-line

```html
<p style="overflow:hidden;line-height:0;font:16px/normal Arial">TEXT</p>
```

```json
{"ID": "font-shorthand-reset-line", "Text": [{"Text": "TEXT", "Label": "unknown", "Size": "16px/normal Arial", "Reasons": null}], "Incomplete": false, "Error": ""}
```

### animation-none-important

```html
<style>@keyframes k{to{opacity:0}}</style><p style="animation-name:none!important;animation:k 1s infinite">TEXT</p>
```

```json
{"ID": "animation-none-important", "Text": [{"Text": "TEXT", "Label": "visible", "Size": "16px", "Reasons": null}], "Incomplete": false, "Error": ""}
```

### animation-invalid-later

```html
<style>@keyframes k{to{opacity:0}}</style><p style="display:none;animation:k 1s infinite;animation:bad bad bad">TEXT</p>
```

```json
{"ID": "animation-invalid-later", "Text": [{"Text": "TEXT", "Label": "unknown", "Size": "16px", "Reasons": null}], "Incomplete": false, "Error": ""}
```

### unknown-selector-outside

```html
<style>.absent:madeup{display:none}</style><p>TEXT</p>
```

```json
{"ID": "unknown-selector-outside", "Text": [{"Text": "TEXT", "Label": "visible", "Size": "16px", "Reasons": null}], "Incomplete": false, "Error": ""}
```

### sibling-occlusion

```html
<div style="position:relative"><p>TEXT</p><div style="position:absolute;inset:0;background:white;z-index:1"></div></div>
```

```json
{"ID": "sibling-occlusion", "Text": [{"Text": "TEXT", "Label": "visible", "Size": "16px", "Reasons": null}], "Incomplete": false, "Error": ""}
```

### datalist

```html
<datalist><option>TEXT</option></datalist>
```

```json
{"ID": "datalist", "Text": [{"Text": "TEXT", "Label": "visible", "Size": "16px", "Reasons": null}], "Incomplete": false, "Error": ""}
```

### ruby-fallback

```html
<ruby>A<rp>TEXT</rp><rt>B</rt></ruby>
```

```json
{"ID": "ruby-fallback", "Text": [{"Text": "A", "Label": "visible", "Size": "16px", "Reasons": null}, {"Text": "TEXT", "Label": "visible", "Size": "16px", "Reasons": null}, {"Text": "B", "Label": "visible", "Size": "16px", "Reasons": null}], "Incomplete": false, "Error": ""}
```

### fill-currentcolor-reset

```html
<div style="-webkit-text-fill-color:transparent"><span style="-webkit-text-fill-color:currentcolor;color:black">TEXT</span></div>
```

```json
{"ID": "fill-currentcolor-reset", "Text": [{"Text": "TEXT", "Label": "unknown", "Size": "16px", "Reasons": null}], "Incomplete": false, "Error": ""}
```

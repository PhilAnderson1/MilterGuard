# Code audit: unnecessary processing and unused outputs

Date: 2026-10-23

This audit examined the current working tree for unnecessary processing, data produced without consumers, and obsolete or unused functions. Existing uncommitted changes were included in the review and preserved. No implementation changes were made.

The findings below are supported by tracing producers and consumers in the source. Performance savings have not been benchmarked. A lack of production consumers does not imply a lack of test consumers, and test-only wrappers should not be deleted without preserving their tests.

## 1. Images are decoded and retained even when vision is off

**Priority:** Medium

**Status:** Fixed for vision-off analysis and text-only callers. MIME extraction now validates image transfer encoding without retaining decoded image payloads for those callers. Archived visible-body rendering, command-text extraction, and processed-body rendering opt out of image retention. Vision modes `always` and `fallback` retain their existing behavior. Regression tests cover a decoded image larger than the extraction memory allowance, transfer diagnostics, and text preservation around nested images. Tests passed for `internal/message`, `internal/milter`, and `internal/admincmd`. The description below records the original finding.

**Locations:** [internal/message/mime.go:264](internal/message/mime.go#L264), [internal/message/vision.go:16](internal/message/vision.go#L16)

MIME extraction transfer-decodes image parts and retains their decoded bytes before vision settings are consulted. `selectVisionImages` subsequently returns no images when vision is disabled. Large image attachments therefore consume processing time and memory even though their decoded payloads have no consumer in this mode.

**Recommendation:** Pass image-retention requirements into extraction. When image data is not needed, preserve transfer validation and attachment markers without retaining decoded payloads. Keep resource-limit and incomplete-extraction behavior explicit when changing the decoding path.

## 2. Visible-character counting runs without a consumer and repeats text preparation

**Priority:** Medium

**Status:** Fixed. `confidentVisibleCharacters` now reuses prepared text, and production extraction enables confident-character counting only for fallback vision. Vision-off, always-on vision, and text-only callers skip both HTML and plain-text counting. Regression coverage verifies normalization and cancellation, and observes counting checkpoints to confirm the caller policy for HTML and plain text. The existing fallback image-selection tests also pass. Tests passed for `internal/message`, `internal/milter`, and `internal/admincmd`. The description below records the original finding.

**Locations:** [internal/message/html_tree.go:312](internal/message/html_tree.go#L312), [internal/message/html_tree.go:374](internal/message/html_tree.go#L374), [internal/message/mime.go:492](internal/message/mime.go#L492), [internal/message/text_analysis.go:23](internal/message/text_analysis.go#L23), [internal/message/vision.go:20](internal/message/vision.go#L20)

HTML and plain-text extraction calculate `ConfidentVisibleChars` unconditionally. Its only decision-making consumer is vision's `fallback` mode. Vision modes `off` and `always`, as well as archived visible-body rendering, do not need this count.

There is also duplicated work within HTML counting: `confidentVisibleCharacters` calls `prepareVisibleText` for each visible text node, then passes the prepared value to `confidentTextCharactersWithResources`, which calls `prepareVisibleText` again. This repeats sanitization and formatting-padding scans.

**Recommendation:** Gate counting by extraction requirements. Split preparation from counting so callers with prepared text do not prepare it again. Preserve the distinction between confidently visible DOM text and human-facing visible output: generated link destinations and image descriptions must not inflate the fallback-vision threshold.

## 3. CSS parsing computes a statistic with no production consumer

**Priority:** Medium

**Status:** Fixed. Removed the statistic, its intermediate fields and assignments, both counting helpers, and the diagnostic token scans. Colour evaluation is unchanged. The existing static, variable, escaped-function, and background-shorthand tests retain their assertions that unsupported colours yield `unknown` visibility. Allocation-effect review found no new allocations or ownership changes; removed diagnostic work no longer copies or normalizes function names, and the remaining parsing and evaluation retain their existing controls. Updated only the affected manifest entries. Tests passed for `internal/htmlextract`, `internal/message`, `internal/milter`, `internal/admincmd`, and `internal/allocationaudit`. The description below records the original finding.

**Locations:** [internal/htmlextract/css.go:550](internal/htmlextract/css.go#L550), [internal/htmlextract/css.go:595](internal/htmlextract/css.go#L595), [internal/htmlextract/css.go:665](internal/htmlextract/css.go#L665), [internal/htmlextract/colour.go:185](internal/htmlextract/colour.go#L185), [internal/htmlextract/limits.go:42](internal/htmlextract/limits.go#L42)

Declaration parsing counts unsupported colour functions. Some paths perform an additional token traversal; the counting logic also performs string copying, unescaping, and case normalization. The accumulated count flows through `sheet.unsupportedColours` into `ResourceUsage.UnsupportedColourFunctions`.

Only tests read the resulting statistic. Production extraction reads other usage fields, including CSS-limit status, but does not consume this counter.

**Recommendation:** Remove the unused statistic or make its collection optional for diagnostics. Preserve the separate logic that determines whether colour evaluation is supported; removing a diagnostic counter must not change visibility classification.

## 4. Authentication translation populates unused metadata

**Priority:** Medium

**Status:** Fixed. Removed the unused DKIM signature details, SPF identity, DMARC policy details, and DNS-authenticity fields from `mailauth.Result`, together with their translation work and the obsolete canonicalization helper. Authentication verification calls are unchanged. Retained `BodyLengthLimited`, `SPFMechanism`, outcomes, domains, error information, and alignment evidence. Tests now assert retained outcomes and evidence while still exercising canonicalization, RSA/Ed25519 signatures, HELO-based SPF, body-length policy, and strict/relaxed DMARC alignment. Tests passed for `internal/mailauth/...`, `internal/message`, `internal/milter`, and `tools/authcorpus`. The description below records the original finding.

**Locations:** [internal/mailauth/evidence.go:50](internal/mailauth/evidence.go#L50), [internal/mailauth/moxverify/translate.go:20](internal/mailauth/moxverify/translate.go#L20), [internal/mailauth/moxverify/translate.go:36](internal/mailauth/moxverify/translate.go#L36), [internal/mailauth/moxverify/verifier.go:190](internal/mailauth/moxverify/verifier.go#L190), [internal/mailauth/moxverify/verifier.go:234](internal/mailauth/moxverify/verifier.go#L234)

Authentication translation populates fields with test consumers but no application readers:

- DKIM selector, identity, algorithm, header and body canonicalization, and numeric body length.
- SPF identity.
- DMARC policy domain, disposition, subdomain policy, alignment modes, percentage, and policy-applied status.
- DNS authenticity metadata.

Some of this work includes string formatting, normalization, splitting, bounding, and allocation. The enlarged result records are also carried through the authentication pipeline despite these details not being used by policy or prompt rendering.

**Recommendation:** Reduce the runtime result or make detailed metadata optional for diagnostics. Preserve fields with actual consumers, particularly `BodyLengthLimited`, alignment evidence, outcome, domain, and error information. `SPFMechanism` has an `authcorpus` consumer and should not be grouped with wholly unused output. Preserve authentication verification itself; this finding concerns translation and retention of its unused details.

## 5. Hidden-content-stripped output is generated before it is needed

**Status:** Deferred; unproven optimization opportunity, not a confirmed defect. Producing both representations during extraction allows each HTML tree and resolved styles to be discarded before multipart assembly and final body-size selection. Stripped rendering is already skipped when no concealed content exists. A combined render might save traversal work, but deferred rendering could increase retained memory or require reparsing. Leave the implementation unchanged unless benchmarks justify a redesign.

**Locations:** [internal/message/html_tree.go:306](internal/message/html_tree.go#L306), [internal/message/prompt.go:174](internal/message/prompt.go#L174), [internal/message/prompt.go:461](internal/message/prompt.go#L461)

HTML extraction performs a second rendering with `StripHidden` whenever concealed content exists. `selectProcessedBody` uses that output only when the tagged body exceeds the character limit. Messages whose tagged body fits therefore pay for an unused traversal and output allocation. Archived visible-body rendering does not consume the stripped output either.

**Recommendation:** Retain the current design. Any investigation of combining rendering passes must account for multipart selection, distinct output semantics, resource accounting, and fallback behavior; the presence of an unused alternative in some messages does not itself establish a worthwhile optimization.

## 6. Body selection repeatedly counts the same string's runes

**Priority:** Low

**Status:** Fixed. Body selection reuses its character count and recalculates only when switching to stripped text. Both body selection and visible-body rendering call a truncation helper that does not repeat the count once an overlong body has been established. Regression tests cover Unicode boundaries, exact fits, stripped-body selection, non-positive limits, and incomplete-extraction markers. Tests passed for `internal/message` and `internal/admincmd`. The description below records the original finding.

**Locations:** [internal/message/prompt.go:450](internal/message/prompt.go#L450), [internal/message/prompt.go:461](internal/message/prompt.go#L461)

`selectProcessedBody` can call `utf8.RuneCountInString` twice on the same body. If truncation is necessary, `sampleBody` counts the body again before locating the truncation boundary. These are repeated linear scans of potentially large strings.

**Recommendation:** Cache the count and recalculate only if selection changes from tagged to stripped text. Provide a truncation helper for callers that already know the body exceeds the limit, while keeping a checked wrapper where needed.

## 7. Analysis exports redundant runtime result fields

**Priority:** Low

**Status:** Fixed. `message.Analysis` now contains only `Prompt`, `Images`, `BodyTruncated`, and `BodyExtractionIncomplete`. Removed the unused copies of HTML presence, concealment, annotation usage, and resource-limit flags. Underlying extraction state and prompt annotation checks remain intact. Tests assert rendered concealment behavior and obtain resource outcomes through `ProcessingUsage` or existing callbacks. Tests passed for `internal/message`, `internal/milter`, and `internal/admincmd`. The description below records the original finding.

**Locations:** [internal/message/message.go:102](internal/message/message.go#L102), [internal/message/prompt.go:123](internal/message/prompt.go#L123), [internal/milter/analysis.go:59](internal/milter/analysis.go#L59)

`message.Analysis` exposes HTML presence, concealment, annotation, and resource-limit flags that the production caller does not read. The runtime consumes `Prompt`, `Images`, `BodyTruncated`, and `BodyExtractionIncomplete`. Resource outcomes arrive separately through `ProcessingUsage`.

Redundant exports include `HasHTML`, `ConcealedContentRemoved`, `HasConcealedContent`, the four exported annotation-usage flags, and the exported HTML CPU/memory-limit flags.

**Recommendation:** Simplify the runtime result contract or separate test diagnostics from it. Most assignments are inexpensive, so this is primarily maintainability work. Do not remove underlying annotation detection or extraction flags merely because their copies in `Analysis` are unused: those underlying values can still affect the prompt and extraction behavior.

## 8. Test-only helpers reside in production files

**Priority:** Low

**Status:** Fixed. Moved all eight wrappers, with their bodies unchanged, into `internal/htmlextract/test_helpers_test.go` and `internal/message/extraction_test_helpers_test.go`. No production references remain. Removed the seven relocated HTML-helper entries from the allocation manifest; the underlying production functions and allocation behavior are unchanged. Production build and tests passed for `./cmd/... ./internal/... ./tools/...`, including the allocation audit. The locations below record the original finding.

The following helpers have no production callers, but do have test callers, directly or through a test-only wrapper chain:

| Helper | Location |
| --- | --- |
| `newExtractionBudget` | [internal/message/mime.go:62](internal/message/mime.go#L62) |
| `legacyDeclarationsWithBudget` | [internal/htmlextract/colour.go:237](internal/htmlextract/colour.go#L237) |
| `substituteTokens` | [internal/htmlextract/variables.go:644](internal/htmlextract/variables.go#L644) |
| `planSelectorList` | [internal/htmlextract/selector_plan.go:284](internal/htmlextract/selector_plan.go#L284) |
| `resolveLayoutProperty` | [internal/htmlextract/values.go:284](internal/htmlextract/values.go#L284) |
| `marginShorthandValues` | [internal/htmlextract/css.go:926](internal/htmlextract/css.go#L926) |
| `relevantDeclarationProperty` | [internal/htmlextract/css.go:730](internal/htmlextract/css.go#L730) |
| `normalizeDeclarationProperty` | [internal/htmlextract/css.go:697](internal/htmlextract/css.go#L697) |

`relevantDeclarationProperty` calls `normalizeDeclarationProperty`; that wrapper chain is used only by tests. Production uses the budget-aware normalization and normalized-property checks.

**Recommendation:** Move these convenience wrappers into appropriate `_test.go` files, or update tests to use the production entry points. They are not confirmed globally unused functions and should not be blindly deleted. No runtime speedup should be assumed from relocation, since unreachable functions may already be eliminated by the linker.

## Validation and limitations

Focused tests passed:

```text
go test ./internal/message ./internal/htmlextract ./internal/mailauth/...

internal/message                 PASS
internal/htmlextract             PASS (cached)
internal/mailauth                PASS
internal/mailauth/moxverify      PASS (cached)
```

The successful run used `GOMAXPROCS=2` and the repository's `local-testing/tmp` directory for `TMPDIR` and `GOTMPDIR`. Initial attempts encountered environment restrictions on Go cache writes and execution of temporary binaries in `/tmp`; the final run completed successfully.

This was a source audit, not a performance benchmark or proof that every unused function in the repository has been found. The recommendations have not been implemented. Line references describe the working tree at the time of the audit and may move as existing changes evolve.

# Unified thinking levels implementation specification

Version 1.0 · 4 November 2026

## 1. Purpose and contract

Implement a reusable thinking-control component from scratch. It reads the existing `endpoints.yaml` and `thinking-profiles.yaml`, determines the controls available for a configured endpoint/model pair, and produces the JSON fragment needed for a selected control. It additionally accepts a nonnegative integer thinking level **N**.

For numerical selection, **0 selects Off when Off is available; otherwise 0 selects the lowest available configured thinking choice. Each increment selects the next choice, and values above the last index select the last choice.** The scale is ordinal, not a token count or a universal measure of reasoning effort. Level 2 on two different models need not produce comparable reasoning.

This is a standalone specification. It consolidates the existing catalogue system, including schema version 2 template parameter substitution, and adds numerical selection. It does not require the earlier Mullsmith specification or addendum to implement it. Both existing YAML files remain unchanged, with `schema_version: 2`; the numerical interface is application logic, not a new catalogue schema.

“Must” denotes required behaviour. Examples of request bodies specify construction from the catalogues; they do not certify live server/model support.

## 2. Responsibilities and boundaries

| Element | Responsibility |
|---|---|
| Connection configuration | API base URL, credentials, exact model identifier, timeout and normal generation settings |
| Endpoint definition | Protocol adapter, route suffix and request fragments for supported control modes |
| Thinking profile | Ordered model choices, native effort strings or budget presets, and optional template switch name |
| Thinking component | Validation, effective choices, numerical resolution, rendering and safe merging |
| Protocol adapter | Ordinary request construction, authentication, streaming, tools, cancellation and response/history handling |
| Application | Choice persistence, UI if any, and passing a generation snapshot to tool continuations |

An endpoint entry is a reusable request convention, not a connection. A profile is a reusable capability description, not a model registry. Associate the exact model with a profile explicitly; never infer it from the model name. There are no model-name or provider-name branches in the thinking renderer.

Adding an effort string, model profile, boolean switch spelling or JSON request-field mapping must require only YAML edits and reload/restart. A genuinely new transport protocol still requires adapter code. Automatic capability discovery, runtime model inspection and hot reload are outside the required implementation.

## 3. Application integration

Expose these configuration concepts, using the existing names if the new application has an `llm` block:

```yaml
llm:
  endpoint: http://localhost:8080/v1
  api_key: ""
  model: exact-model-id
  endpoint_type: gufo
  thinking_profile: qwen3_8
  endpoints_file: ./endpoints.yaml
  profiles_file: ./thinking-profiles.yaml
```

The base URL, credential and model remain outside the catalogues. Resolve relative catalogue paths against the application configuration file's directory, not the process working directory.

Embed baseline catalogues to support a self-contained application. An omitted or empty file path uses the embedded catalogue. A configured external file adds new entries and **replaces an entire embedded entry with the same ID**. Never deep-merge catalogue entries. An unreadable or invalid explicitly configured file is an initialization error.

Unknown explicitly selected endpoint/profile IDs are errors. An omitted profile selects `none`. An omitted endpoint type disables thinking integration and leaves transport selection to the host application; a nonempty active profile requires an endpoint type. Numerical selection without an endpoint type returns `thinking_not_configured`, rather than pretending level 0 is Off. A configured empty profile remains valid, as specified in section 8.

A selected endpoint requires an installed adapter for its protocol, even with an empty profile. Unused entries for recognised but unimplemented protocols may remain in the catalogue.

Join the API base URL with the endpoint route suffix, trimming trailing slashes from the base and appending the suffix once. Preserve the base URL's existing path. For example, `https://host/proxy/v1` plus `/chat/completions` becomes `https://host/proxy/v1/chat/completions`. Do not use URL resolution that replaces `/proxy/v1`. Require an absolute HTTP(S) base URL without a query or fragment, and a route starting with one `/`, without a scheme, authority, query, fragment or parent-directory traversal.

## 4. Catalogue schema and loading

Each catalogue is one YAML document with a required integer `schema_version` and the appropriate mapping: `endpoints` or `profiles`. Accept versions 1 and 2 independently, including mixed-version pairs. Reject missing/unknown versions. Preserve each entry's source schema version when applying external replacements.

Version 1 has the fields described below except `template_defaults`, `template_parameters` and `$template.thinking_toggle`. Those three features require version 2. Literal version 1 request fields keep their original meaning: a version 2 profile does not rewrite a version 1 endpoint's literal `enable_thinking` key.

Use strict YAML parsing. Reject duplicate keys before converting to maps, unknown structural fields, wrong scalar types, non-string object keys, unknown modes, duplicate option IDs, malformed placeholders and non-JSON values such as NaN. Reject custom YAML tags and merge keys; aliases may either be rejected or safely expanded with bounded nesting and size. Booleans must remain booleans, integers must remain integers, and `none` in `reasoning_effort: none` is a string. Use YAML 1.2 semantics; quoted `'off'` and `'on'` in existing files must parse as strings.

Validate every definition structurally, including unused entries. Validate endpoint/profile compatibility only for selected pairs. Report file, entry ID and field path for errors where available. Do not expose credentials in errors or logs.

### 4.1 Endpoint entries

```yaml
schema_version: 2
endpoints:
  example:
    protocol: openai_chat
    path: /chat/completions
    template_defaults:
      thinking_toggle: enable_thinking
    requests:
      'off':
        chat_template_kwargs:
          '$template.thinking_toggle': false
      'on':
        chat_template_kwargs:
          '$template.thinking_toggle': true
      effort:
        chat_template_kwargs:
          '$template.thinking_toggle': true
        reasoning_effort: '$effort'
      budget:
        chat_template_kwargs:
          '$template.thinking_toggle': true
        reasoning_budget_tokens: '$budget_tokens'
    effort_values: [minimal, low, medium, high, xhigh, max]
    budget_min: 1
    budget_max: 2147483647
```

| Field | Type and meaning |
|---|---|
| `protocol` | Required nonempty string: `openai_chat`, `ollama_chat` or `lm_studio_chat`; further protocol IDs require an explicit adapter extension |
| `path` | Required route suffix |
| `requests` | Required map, possibly empty, containing only `off`, `on`, `effort`, `budget`; each value is a JSON-compatible object |
| `effort_values` | Optional list of distinct nonempty strings; an exact, case-sensitive wire-value allowlist |
| `budget_min` | Optional positive integer, default 1 |
| `budget_max` | Optional positive integer, at least `budget_min`; absence imposes no catalogue ceiling |
| `template_defaults` | Optional version 2 parameter map described in section 5 |

Absence of a mode means it is unsupported by that endpoint definition. Absence of `effort_values` means no additional catalogue restriction, not that the live endpoint honours every string. An empty allowlist permits no efforts. `effort_values` order does **not** define numerical ordering.

Request fragments permit arbitrary JSON-compatible literal fields, nested objects and arrays, subject to the restricted placeholders. They are complete operations: choosing effort uses only `requests.effort`, not `requests.on` plus `requests.effort`. Never implicitly combine effort and budget.

### 4.2 Thinking profiles

```yaml
schema_version: 2
profiles:
  example:
    template_parameters:
      thinking_toggle: enable_thinking
    options:
      - id: 'off'
        label: 'Off'
        mode: 'off'
      - id: low
        label: Low
        mode: effort
        effort: low
      - id: medium
        label: Medium
        mode: effort
        effort: medium
      - id: high
        label: High
        mode: effort
        effort: xhigh
```

A profile contains a required `options` list and optional version 2 `template_parameters`. Each option has:

| Field | Rule |
|---|---|
| `id` | Required nonempty string, unique within the profile; `default` is reserved |
| `label` | Required nonempty display string |
| `mode` | Required exact string: `off`, `on`, `effort` or `budget` |
| `effort` | Required nonempty string only for `effort`; forbidden for other modes |
| `budget_tokens` | Required positive integer only for `budget`; forbidden for other modes |

IDs and labels are not wire values or sorting keys. For example, an option labelled High can explicitly send `xhigh`. Effort strings are not restricted to a hard-coded global vocabulary.

`options: []` means no adjustable controls are described. It does not prove thinking is off, on, mandatory or absent. This applies to every empty profile, not just the ID `none`.

Budget options are administrator-defined presets, not automatically inferred native model tiers. They must pass the endpoint's inclusive minimum and maximum. If a total output cap is configured, require `budget_tokens < total_output_cap` to reserve room for an answer. Recheck against the actual generation cap before sending; fail an invalid selection rather than changing its level. Do not invent budget presets or interpret zero/negative budgets as Off/unlimited.

## 5. Model template parameters

The only defined parameter is `thinking_toggle`. Both endpoint `template_defaults` and profile `template_parameters` may contain it. Reject unknown parameter names.

| Parameter state | Meaning |
|---|---|
| Nonempty string matching `[A-Za-z_][A-Za-z0-9_]*` | Literal JSON property name |
| Explicit YAML `null` | Omit the dynamic switch |
| Absent | Profile inherits endpoint default; if both omit it, the parameter is unresolved |

Preserve all three states. In Go, a plain `*string` is insufficient; use a presence flag plus nullable value, or inspect YAML nodes. Explicit profile null overrides an endpoint default.

Examples from the current files: Qwen profiles specify `enable_thinking`; `kimi_k2_6` specifies `thinking`; several effort-only profiles specify null. A parameter has an effect only when a selected fragment references it. Never add a template field to LM Studio or OpenRouter requests simply because the profile declares a switch name.

## 6. Restricted request renderer

Render into a new object without mutating the catalogue or cached fragment:

1. Select the one fragment matching the option's mode.
2. Resolve template parameters from endpoint defaults, overlaid with explicitly present profile parameters, including null.
3. Walk nested objects and arrays. Replace the exact whole key `$template.thinking_toggle` with the resolved string. Its authored value must be a boolean literal. The name is a single key, never a property path.
4. If the resolved parameter is null, omit that key/value pair. If unresolved, return a configuration error for an otherwise eligible option.
5. Recursively prune objects made empty solely by dynamic omission. Keep explicitly authored empty objects and unrelated siblings. Preserve array positions: an object emptied inside an array remains `{}` rather than deleting the array element. This array rule makes the renderer deterministic; the supplied catalogues do not use dynamic switches inside arrays.
6. Replace exact whole string values `$effort` with the option's effort string, or `$budget_tokens` with its integer budget. Each token is legal only in its corresponding mode.
7. Reject any collision between rendered keys, including a literal key and a substituted key, even if their values are equal.

No other tokens are supported. `$template.thinking_toggle` is forbidden as a value; value tokens are forbidden as keys. Reject unsupported `$`-prefixed keys/values and occurrences of reserved tokens embedded in larger strings. Do not interpolate, execute expressions, expand environment variables or re-evaluate replacement text. Literal strings that merely contain an unrelated dollar sign remain literal.

The renderer must track why an object became empty; pruning all empty maps would incorrectly delete authored empty objects. Pruning applies only to the fragment, never the ordinary request body. A root fragment rendered as `{}` is an unavailable operation.

## 7. Compile effective choices

Compile an immutable plan for the selected endpoint and profile, after schema validation and before accepting generation requests:

1. Verify the selected protocol adapter exists.
2. Walk the profile's options in their declared order.
3. Exclude an option if the endpoint lacks its mode, its effort is outside a present allowlist, or its budget is outside the endpoint range. Record a structured diagnostic for each exclusion.
4. Render each otherwise eligible option. Malformed placeholders, unresolved parameters and key collisions are errors, not exclusions.
5. Exclude an option whose rendered root is empty, recording a diagnostic.
6. If the original profile was nonempty but no choices survive, reject the pair with `no_usable_thinking_options`.
7. Validate raw/static request-setting conflicts against all surviving fragments, and validate configured output caps for budget presets.

Keep both the original profile choices and the effective choices so callers can distinguish model-described capabilities from endpoint limitations. A profile Off option only makes Off available when the selected endpoint can express a nonempty Off operation. Do not fabricate a replacement field or infer Off from `reasoning_effort: none` unless the profile actually offers Off.

Exclusions are determined by the catalogue pair, not by an individual request's token cap or an HTTP failure. A per-request restriction must produce an error, not silently renumber the scale. Do not silently remove a level after a server rejects it.

## 8. Unified numerical levels

### 8.1 Ordering

Build a numerical ladder from effective choices:

1. Put the effective choice whose `mode` is `off` first, if present.
2. Append every remaining effective choice in its original profile order.
3. Assign consecutive indexes starting at 0; removed choices leave no gaps.

For numerical use, profiles must contain at most one Off option. Reject a profile with multiple Off options as `ambiguous_level_order` when compiling its numerical plan. Determine Off from `mode`, never its ID or label.

The existing list order becomes the authoritative **lowest-to-highest configured order** for all non-Off choices. Do not sort labels, IDs, native effort strings or the endpoint allowlist; do not impose a global list such as `minimal, low, medium, high, xhigh, max`. This supports names such as Minimum, Normal, Max and Ultimate without code changes.

The supplied profiles already follow this order. For future custom profiles, the author is responsible for arranging non-Off choices from least to most thinking. The code cannot prove their semantic order. A generic On means enabled with unspecified/default effort; it is not intrinsically less than Low or greater than High. Prefer either Off/On or ordered effort/budget presets. If an author mixes On, efforts or budgets, list order is an explicit application ranking, not a measured equivalence or guarantee of increasing reasoning tokens.

### 8.2 Input and resolution

Accept N as an integer in `[0, 9223372036854775807]`. Reject negatives, fractions, booleans, null, nonnumeric strings and overflow; do not round or coerce. A text interface may parse decimal integer text before invoking this typed API. JSON clients must use a lossless integer path or limit submitted numeric values to their exactly representable range.

For a ladder of length K greater than zero:

```text
effective_index = min(N, K - 1)
selected_option = ladder[effective_index]
clamped = N > K - 1
```

Compare N with the maximum before converting to a machine-sized array index. Never perform arithmetic such as `N + 1` that can overflow.

Examples:

| Effective ladder | N=0 | N=1 | N=2 | N=3 | N=4 and above |
|---|---|---|---|---|---|
| Off, Low, Med, High | Off | Low | Med | High | High |
| Minimum, Normal, Max, Ultimate | Minimum | Normal | Max | Ultimate | Ultimate |
| Off, On | Off | On | On | On | On |
| Low, Medium, High | Low | Medium | High | High | High |
| On | On | On | On | On | On |
| Off | Off | Off | Off | Off | Off |

An endpoint that only permits Off from an Off/On profile produces a one-entry Off ladder. Report the excluded On diagnostic and `can_enable: false`; higher N cannot enable thinking. Similarly, if a model describes Off but this endpoint cannot send Off, 0 selects the lowest remaining effective choice and reports `off_available: false`. “Available” here means available for the configured pair, not merely described by the model profile.

### 8.3 Empty profiles

For an intentionally empty profile, accept any valid N and return:

```json
{
  "status": "uncontrolled",
  "requested_level": 3,
  "effective_level": null,
  "max_level": null,
  "option_id": null,
  "off_available": false,
  "clamped": false,
  "fragment": {}
}
```

There is no lowest selectable level to claim. Generation proceeds without a thinking override, retaining the server/model behaviour. This permits a unified caller to work with models that expose no controls. An application requiring enforceable control can reject `uncontrolled` explicitly. Do not apply this no-op rule to a nonempty but incompatible profile; that remains an error.

### 8.4 Default is separate

Default means “send no thinking override”. It is not a numbered level, is not Off, and is never inserted before level 0. Offer it as a separate tagged selection if needed. Omitted selection means Default. Explicit `N=0` must never be confused with an unset value; use a nullable/presence-aware request field.

The component may also expose selection by option ID for compatibility with a labelled selector. Validate IDs against effective choices. Accept exactly one of Default, a numerical level, or an explicit option ID; reject conflicting selection inputs.

## 9. Public component interface

The following language-neutral contract is sufficient; names may follow project conventions:

```text
LoadCatalogues(embedded, optionalExternalFiles) -> Catalogues | ConfigError
CompilePlan(catalogues, endpointID, profileID, adapterRegistry) -> Plan | ConfigError
DescribeLevels(plan) -> LevelDescription
ResolveSelection(plan, Default | Level(N) | OptionID(id)) -> Resolution | SelectionError
ApplyResolution(freshBaseRequest, resolution, generationLimits) -> Request | MergeError
```

`LevelDescription` must include an ordered ladder with index, option ID, label, mode and applicable effort/budget; `max_level` (null if empty); `off_available`; `can_enable` (any surviving non-Off option); an explicit empty/uncontrolled status; and excluded options with reasons. These are configuration facts, not probed server capabilities.

`Resolution` must include status (`selected`, `default`, `uncontrolled`), requested level when applicable, effective numerical index when one exists, maximum index, selected option ID/label/mode and native value, clamped flag, Off availability, a plan fingerprint and the typed rendered fragment. Default has no selected option, no effective index and an empty fragment. For explicit option IDs, report their ladder index but leave requested level null and clamped false.

Expose safe descriptive metadata to a client if useful; keep credentials and request fragments server-side. Callers submit N or a permitted option ID, never arbitrary effort strings, parameter names or raw fragments.

Reference algorithm:

```text
resolveLevel(plan, N):
    requireIntegerInRange(N)
    if plan.sourceOptionsEmpty:
        return uncontrolled(N, emptyFragment)
    # A nonempty plan with zero effective choices was rejected at compilation.
    last = length(plan.ladder) - 1
    index = last if N > last else integerIndex(N)
    choice = plan.ladder[index]
    return selected(N, index, last, N > last, choice, clone(choice.fragment))
```

## 10. Merge into the outgoing request

Build a fresh ordinary request through the selected protocol adapter, then apply the resolution. Never reuse a request object carrying the previous turn's thinking fields.

Recursively merge objects, preserving unrelated nested members. If an inserted leaf already exists, or an object collides with a scalar/array, return a conflict error; do not overwrite even an identical value. Arrays in a fragment are whole values, not concatenated with existing arrays. Static thinking settings must be removed from the base request or handled as explicit conflicts so this component has one owner for control values.

Detect conflicts at initialization where possible using actual rendered field paths across every effective option. Also audit semantic aliases in raw configuration: different fields such as `think`, `reasoning`, `reasoning_effort`, template switches and budget fields can control the same behaviour. Default must not inherit a leftover static thinking setting. Deployment-wide server defaults remain outside this component's control.

Serialize the completed request once. SDK `extra_body` is not a literal property to add to the HTTP body. Do not change temperature, top-p, output cap, system prompts, history policy or stop sequences to simulate thinking control. The selected budget may be checked against output limits but must not rewrite them.

If the server rejects a request, propagate an error with endpoint/model/choice context. Never retry automatically with control fields removed or with a different level. HTTP success does not establish that the control was honoured.

## 11. Protocol and conversation integration

Support at least the protocol(s) the new application intends to use. `openai_chat` uses a Chat Completions adapter; `ollama_chat` and `lm_studio_chat` require their own request/response adapters. A route change alone does not implement a new protocol.

Reasoning visibility is independent of requested thinking. Keep a display setting separate. Hiding a trace, suppressing reasoning response fields or stripping reasoning from the UI does not implement Off.

The adapter owns response parsing and continuation requirements. Keep visible answer content separate from reasoning and opaque provider continuation data. Where supported, Chat Completions adapters handle `reasoning_content` and `reasoning`, avoiding duplication when aliases contain the same data; OpenRouter may include structured `reasoning_details`; native protocols have their own fields/events. Preserve opaque signatures, ordering and reasoning/tool state when the model/protocol requires replay. Do not concatenate hidden reasoning into ordinary answer content or indiscriminately replay all historical traces. The catalogue does not encode history rules, so adding a profile alone does not implement them.

Snapshot the resolved endpoint, profile, selection, fragments and generation settings at generation start. Every tool continuation within that generation uses the same snapshot. Concurrent requests must not mutate shared plans. A later user setting change affects the next generation only.

For optional persistence, store selection kind, requested N or option ID, resolved option ID and applicability context. Include API base URL, exact model ID, endpoint/profile IDs and a canonical fingerprint of their resolved definitions. Hash sorted object keys while preserving option-array order and null/absence distinctions; exclude credentials. Include the numerical ordering algorithm version. Catalogue changes can renumber N, so a saved selection is valid only under a matching context. Reset stale saved selections visibly to Default; do not silently reinterpret them. A stale explicit request carrying an old fingerprint returns `stale_thinking_plan`. An explicit new Level(N) request against the current plan resolves normally.

## 12. Current catalogue examples

These are mappings from the existing files, not newly inferred model capabilities. A profile's numerical ladder below assumes an endpoint admits all its choices.

| Profile | Numerical ladder, index 0 onward |
|---|---|
| `none`, `kimi_k2_7_code`, `minimax_m2_7` | Empty; uncontrolled, no override |
| `qwen3_5`, `qwen3_6`, `gemma4`, `kimi_k2_6` | Off, On |
| `qwen3_8` | Off, Low (`low`), Medium (`medium`), High (`xhigh`) |
| `qwen3_8_thinking_only` | Low (`low`), Medium (`medium`), High (`xhigh`) |
| `gpt_oss` | Low, Medium, High |
| `deepseek_v4` | Off, High, Max |
| `deepseek_v4_1` | Off, Low, High, Max |
| `glm5_3`, `kimi_k3` | Low, High, Max |
| `minimax_m3_1_flash` | Low, Medium, High, Extra high (`xhigh`), Max |
| `step3_7_flash`, `step5_preview` | Low, Medium, High |

Preserve `deepseek_v4_1` as the existing ID; do not reintroduce `deepseek_v4_0731`.

| Endpoint/profile/level | Expected thinking fragment |
|---|---|
| Gufo / Qwen3.8 / 0 | `{"chat_template_kwargs":{"enable_thinking":false}}` |
| Gufo / Qwen3.8 / 3 or greater | `{"chat_template_kwargs":{"enable_thinking":true},"reasoning_effort":"xhigh"}` |
| vLLM / Kimi K2.6 / 0 | `{"chat_template_kwargs":{"thinking":false}}` |
| vLLM / Kimi K2.6 / 1 or greater | `{"chat_template_kwargs":{"thinking":true}}` |
| vLLM / Kimi K3 / 0 | `{"reasoning_effort":"low"}`; null suppresses the switch |
| LM Studio / Qwen3.8 / 0 | `{"reasoning_effort":"none"}` |
| LM Studio / Qwen3.8 / 3 or greater | `{"reasoning_effort":"xhigh"}` |
| OpenRouter / Qwen3.8 / 3 or greater | `{"reasoning":{"effort":"xhigh"}}` |
| Ollama native / Qwen3.6 / 1 or greater | `{"think":true}` |
| Any configured endpoint / empty profile / any valid N | `{}`, status uncontrolled |

The current `lm_studio_native` allowlist excludes `xhigh`. With `qwen3_8`, its effective ladder is Off, Low, Medium: N≥2 selects Medium and emits `{"reasoning":"medium"}`. Do not replace `xhigh` with `high` merely because their labels sound similar.

The current `lm_studio` definition has no On recipe. With `qwen3_6`, its effective ladder is Off only, and the excluded On diagnostic must be exposed. This is valid catalogue construction but cannot provide an On/Off toggle for that pair without a separately verified mapping.

## 13. Required acceptance tests

Use unit tests without live inference for deterministic construction. Test at least:

| Case | Required outcome |
|---|---|
| Off/Low/Med/High; N=0,1,2,3,99 | Off, Low, Med, High, High |
| Minimum/Normal/Max/Ultimate without Off | N=0 chooses Minimum; N≥3 chooses Ultimate |
| Toggle-only, one-option and empty profiles | Exact section 8 semantics |
| N=-1, 1.5, true, null, overflow | Validation error; no network request |
| N=maximum signed 64-bit integer | Safe clamp without overflow |
| Omitted selection versus explicit N=0 | Default versus lowest/Off; never conflated |
| Unusual labels/effort strings; shuffled endpoint allowlist | Profile order retained, no lexical/global sorting |
| Off not first in source profile | Off first in numerical ladder; remaining order unchanged |
| Two mode-Off options | Numerical plan rejected as ambiguous |
| Missing mode, disallowed effort, out-of-range budget | Excluded with reason; remaining indexes contiguous |
| Nonempty profile loses every choice | Configuration error, not uncontrolled |
| Generation cap makes selected budget invalid | Error; no renumbering or implicit downgrade |
| Profile toggle absent versus null | Endpoint default inherited versus explicitly suppressed |
| Null removes only dynamic field | Root empty, option excluded |
| Null beside unrelated template field | Unrelated field survives |
| Null-pruned nested object; authored empty object | Only omission-generated emptiness pruned |
| Null-pruned object inside array | Array position retained as `{}` |
| Dynamic/literal key collision or unresolved parameter | Configuration error |
| Tokens in wrong modes, positions or substrings | Configuration error |
| Budget substitution and switch values | JSON integer and boolean types preserved |
| Literal v1 endpoint with v2 profile | Literal fields unchanged; no implicit key rewrite |
| Mixed v1/v2 files and per-ID external replacement | Supported with source versions retained; no partial inheritance |
| Unknown version/field/parameter; duplicate YAML keys | Rejected, including unused definitions |
| Every request example in section 12 | Exact expected JSON fragment |
| Merge beside unrelated nested member | Unrelated member retained |
| Existing conflicting leaf or semantic raw override | Error, never last-writer-wins |
| High followed by Off or Default | No stale effort/budget/switch fields |
| Unsupported selected protocol | Initialization error; unused definitions remain valid |
| Definition/order changes under unchanged IDs | Fingerprint changes; saved choice resets visibly |
| Setting change during a tool loop; concurrent generations | Initial snapshot retained; no cross-request mutation |
| Server rejects control | Error propagated; no silent retry/downgrade |
| Reasoning display disabled | Selected thinking fragment still sent |

For release, smoke-test each intended deployed endpoint/model combination using outgoing request inspection and rendered-prompt inspection where available. Exercise Off when supported, every configured level, Default after an override, streaming, multi-turn use and tool continuation. These deployment tests are separate from schema and renderer correctness.

## 14. Implementation sequence and completion criteria

1. Implement strict typed catalogue loading, embedded defaults and whole-entry overrides.
2. Implement tri-state parameters and the restricted renderer with collision/omission tracking.
3. Compile effective choices, diagnostics and immutable fragments.
4. Implement the ordered numerical ladder, validation, saturation and uncontrolled result.
5. Add Default and optional option-ID selection as separate tagged inputs.
6. Integrate conflict-aware merging with the application's protocol adapter and generation snapshot.
7. Expose descriptive levels/results; add persistence and UI only where the application needs them.
8. Run the acceptance tests and intended deployment checks.

Completion means the application can use the existing catalogue files unchanged, accept N, explain which configured choice it resolved to, and send that choice's exact typed fragment through its supported transport. It must distinguish Off, Default, uncontrolled behaviour and incompatibility. No new YAML ranking fields, endpoint variants or model-specific renderer branches are required.

## 15. Source baseline

This specification consolidates the current `endpoints.yaml` and `thinking-profiles.yaml`, the original thinking-control specification and its model-template-parameter addendum. The current YAML definitions take precedence over historical prose, including the added LM Studio Off recipe and the `deepseek_v4_1` rename.

The numerical ladder, saturation, explicit uncontrolled result and component interface are the new contract defined here. Ordering across unlike controls is an author-supplied ordinal convention; neither catalogue files nor N guarantee a measured amount of model computation.

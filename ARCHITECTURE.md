# MilterGuard Architecture

This document is a guide to the source code. It describes package ownership,
the principal execution paths, and the boundaries that should remain intact
when MilterGuard is changed.

## Executable and operating modes

`cmd/milterguard` is the executable entry point. It loads and validates
configuration, sets up logging, and selects one of three paths:

- Normal service mode constructs the AI client and Milter server, opens the
  configured listener, and serves Postfix connections.
- Command mode opens the live SQLite database and runs administration commands
  entered on standard input.
- Configuration, port, and endpoint checks validate specific parts of an
  installation without starting the server.

The executable should contain startup and presentation logic, not filtering
policy or persistence queries. Normal-service dependency composition occurs in
`milter.buildRuntime`; standalone command mode has its own narrower composition
path.

## Package map

| Package | Responsibility |
| --- | --- |
| `internal/admincmd` | Parses and executes administration commands independently of their email or terminal transport. |
| `internal/ai` | Builds chat-completions requests, applies endpoint retries, and validates AI decisions. |
| `internal/attachment` | Detects prohibited executable attachments and inspects supported archives. |
| `internal/config` | Loads defaults, strictly decodes YAML, and validates cross-setting requirements. |
| `internal/htmlextract` | Applies direct HTML parser limits and bounded CSS admission checks, then derives presentation and visibility evidence from the parsed document. |
| `internal/fork` | Holds the source forks of the HTML tree builder, CSS parser, and selector engine used by `internal/htmlextract`, together with upstream provenance and tests. |
| `internal/mailaddr` | Provides canonical mailbox parsing and normalization shared by message processing, policy, administration, and persistence. |
| `internal/mailauth` | Owns provider-neutral authentication evidence, the verifier boundary, trusted-header compatibility parsing, alignment, and exact-message storage. |
| `internal/mailauth/moxverify` | Adapts Mox SPF, DKIM, and DMARC verification to bounded, provider-neutral evidence using a dedicated resolver and resource limits. |
| `internal/message` | Accumulates SMTP message data, produces bounded decoded text, links, and images, and renders supplied authentication evidence for analysis. |
| `internal/milter` | Implements the Milter protocol, session state, filtering policy, service orchestration, and Postfix responses. |
| `internal/netsafety` | Normalizes DNS hostnames and rejects unsafe or non-public network destinations. |
| `internal/rdap` | Discovers and queries RDAP services with redirect, SSRF, and DNS-rebinding protection. |
| `internal/rejectedmail` | Saves and cleans up rejected `.eml` files beneath the configured archive root. |
| `internal/smtpreply` | Builds MIME command replies and submits them to the configured SMTP service. |
| `internal/sqlitedb` | Owns SQLite connection setup, schema creation and version validation, WAL handling, busy retries, transactions, and checkpoints. |
| `internal/stores` | Defines SQL-independent repository interfaces, queries, and value types. |
| `internal/stores/sqlite` | Implements the repository contracts with indexed SQLite operations. |
| `internal/systemdns` | Constructs explicit resolvers for non-authentication DNS users, isolating them from dependency changes to the process-wide default resolver. |

The dependency direction is intentional. Runtime protocol and policy logic
depends on interfaces in `stores`; concrete SQL is confined to
`stores/sqlite`, while connection-level database mechanics remain in
`sqlitedb`. The Milter composition and lifecycle layer opens, owns, checkpoints,
and closes the shared `sqlitedb.Store`, then injects repository interfaces into
policy services.

## Service construction

Normal service construction begins in `milter.NewServer` and
`milter.buildRuntime`. Runtime construction:

1. Opens SQLite when an enabled feature requires persistent state.
2. Constructs the configured repositories, including activity reporting and
   service-status persistence.
3. Builds IP-reputation and domain-registration policy services around those
   repositories.
4. Creates the rejected-message archive, attachment scanner, command
   processor, AI service, SMTP reply sender, and selected authentication
   provider as required.
5. Groups those dependencies into analysis, policy, attachment, command,
   connection-DNS, maintenance, and session services.

Sessions receive explicit service dependencies. They do not reach back through
the complete `Server` to locate unrelated functionality.

## Inbound message flow

```text
Postfix connection
  -> Milter frame parsing and session state
  -> connection and envelope checks
  -> bounded message data and, in internal mode, byte-exact accumulation
  -> deterministic policies requiring the complete message
  -> authentication provider (with progress and cancellation)
  -> provider-neutral authentication and correspondent evidence
  -> domain-registration and connection evidence when needed
  -> bounded MIME, text, link and image extraction for AI classification
  -> accept, reject or temporary failure response
  -> bounded post-response persistence updates where applicable
```

`session.run` owns one Milter connection. It decodes frames, checks protocol
phase transitions, and dispatches commands. `session.finishMessage` coordinates
the end-of-message path and sends exactly one final Milter response.

Deterministic policies run before AI analysis where possible. Examples include
cached IP blocks, authenticated-only sender domains, manual visible-sender
blocks, prohibited attachments, trusted correspondents,
authenticated-submission bypasses, and trusted sender domains. A partial
sender-blocklist match is held as deferred session state: remaining-recipient
policy is evaluated first, and delete-recipient frames are sent only immediately
before the final acceptance. This avoids unnecessary endpoint work and keeps
unambiguous security decisions independent of model output.

## Message and authentication processing

`internal/message` owns decoding and evidence extraction. It parses MIME,
decodes transfer and header encodings, uses `internal/htmlextract` to render
bounded HTML text with visibility annotations, preserves useful link and image
references, and prepares inline images for vision analysis. The same
archived-message parser is used by `REJECTION <id>` so command output reflects
the current message-processing implementation.

`internal/mailauth` owns the authentication provider boundary and the bounded
evidence types shared by policy and prompt generation. The default `internal`
provider uses `internal/mailauth/moxverify` to calculate SPF, DKIM, and DMARC
from SMTP transaction data and the byte-exact message. The adapter owns its
strict DNS resolver, timeout and concurrency bounds, and immediate translation
from Mox types. The exact-message abstraction retains callback bytes in bounded
memory or an unlinked temporary file. Existing `Authentication-Results` and
`Received-SPF` fields are not inputs to internal verification and are delivered
unchanged.

The alternative `trusted_headers` provider parses authentication headers once
and uses only results whose authentication-service identifiers are trusted by
configuration. In that mode, Postfix must remove externally supplied result
headers before the upstream authentication filters add fresh local results.

## HTML and CSS processing

`internal/htmlextract.AnalyzeWithStop` retains one parsed HTML tree and derives
presentation evidence for its text and image-like elements. It does not execute
scripts or fetch external resources. Processing proceeds through these stages:

1. Validate limits and bound input bytes. Build the HTML tree with scripting
   disabled using the local `x/net/html` fork in `internal/fork/xnethtml`.
   A shared in-parser guard counts attributes before tokenizer allocation,
   counts nodes and recovery clones where the tree builder creates them,
   bounds open-element, formatting, and template stacks, and limits cumulative
   string copying when successive text tokens merge. It samples cooperative
   cancellation during tokenization and tree recovery, so adversarial input is
   stopped at the operations consuming CPU and memory.
2. Traverse the completed tree with an
   explicit stack. Recheck actual node, text, attribute, and depth limits,
   allowing for parser-generated ancestors. Collect applicable stylesheets,
   inline styles, legacy presentation attributes, and selector profiles while
   distinguishing active, head, and inert content.
3. Admit each CSS source through `sheet.admitCSS` before constructing the
   locally forked `tdewolff` CSS parser in
   `internal/fork/tdewolffparse/css`. Enforce a cumulative CSS byte limit and charge
   preflight work, then use the lexer-based `css_preflight.go` checks to bound
   individual constructs by bytes and tokens, including malformed rule-list
   separator runs, and reject unsafe unmatched delimiters. These checks protect
   parser token accumulation and condition tracking. They apply to style
   elements, style attributes, conditional-comment
   styles, and decoded data-URL stylesheets, including nested imports.
4. Prepare declarations and build a selector index, then evaluate a bounded
   set of viewport cases. Resolve the cascade, inheritance, custom properties,
   expressions, layout, clipping, opacity, and colours with shared matching
   and expression-work budgets. Aggregate the cases into visible, concealed,
   client-dependent, or unknown results, retaining concealment evidence and
   resource usage. Layout uncertainty includes zero line boxes clipped by
   overflow, positioned descendants of clipped ancestors, and applicable
   legacy email width/height presentation hints; it does not attempt full box
   layout.

Selector compilation and matching use the local Cascadia fork in
`internal/fork/cascadia`. All three forks retain their upstream tests and an
`UPSTREAM.md` file recording the source tag and commit. Their imports point at
one another where necessary so the HTML tree and selector engine share the
same node and atom types. Upstream updates must preserve that package graph,
run both the fork tests and application tests, and compare processed output
against the saved email corpus.

The HTML parser, tree collection, and presentation analysis use separate
explicit stacks because each pass tracks different state and limits. CSS
source limits apply across parser inputs within a document; `internal/message`
carries the remaining extraction budgets across HTML MIME parts. Splitting
input across style elements or message parts must not reset those budgets.

Elements with no indexed selector candidates or local declarations take an
inheritance-only path that preserves computed inherited values and variables.
This path has a smaller fixed work charge and skips cascade and layout
resolution. Candidate discovery remains budgeted even when no selector can
apply; elements requiring resolution retain the full fixed charge.

Selector-evaluation caches share a 100,000-unit per-document retention limit.
These are weighted logical units rather than bytes: simple match records cost
one unit, while cached attribute candidates also charge retained bucket slice
headers. Depending on the cache mix and Go runtime map overhead, the limit
represents several to low tens of MiB, plus outer tables bounded by the selector
limit. Evaluation continues without retaining new cache records after the limit.

Unsupported or exhausted style analysis preserves uncertainty rather than
trusting a partial cascade. Malformed inline styles can make an element and
its descendants uncertain; unusable global CSS invalidates the shared cascade.
Applicable external or unsupported stylesheet references are reported through
`UnresolvedStylesheet`. Bounded data-URL stylesheets can be analysed, but their
effects remain client-dependent. No network stylesheet is fetched.
CSS parser-limit, selector-work, and expression-work exhaustion are propagated
to `internal/message` as incomplete CSS analysis. They remove visible-text
confidence and produce an explicit limitation in the analysis prompt.

CSS nesting is detected but relative nested selectors are not resolved. Since
nested selectors can reach descendants, siblings, or ancestors of the parent
match, a stylesheet containing effective nesting makes document presentation
labels uncertain and sets `UnresolvedStylesheet`. Empty or non-grouping nested
at-rules do not create that signal.

Animation analysis matches case-sensitive names against parsed keyframe
definitions instead of treating any keyframes block as globally active. Static
name parsing is cached; variable resolution and name lookups remain budgeted.
Potentially active or unresolved animations retain presentation uncertainty;
the extractor does not simulate timelines.

`internal/message` renders the results as annotated text and, when concealed
content exists, a second representation with that content removed. It also
extracts links and image references. Only confidently visible text can suppress
fallback vision analysis; an unresolved stylesheet removes that confidence.
Analysis errors or cooperative stops switch extraction to a bounded lexical
fallback, with fallback and completeness information carried into the prompt.
Conditional Outlook comment fragments use the same directly bounded HTML
parser, with scripting disabled and smaller fragment limits.
If fragment parsing or extraction exceeds a limit, a fixed omission marker and
`ExtractionIncomplete` disclose the gap; partial fragment text and links are
discarded. The marker is excluded from recipient-visible text and confidence
counts. Downlevel-revealed markers retained in a table foster-parenting context
make document presentation uncertain because the tree builder may move their
source text away from the marker comments. Their bounded conditional-expression
evaluator recognizes common MSO/IE boolean and version predicates; only a
predicate true throughout the supported Outlook range preserves confident
visibility, while variable, malformed, or unsupported predicates remain
uncertain.

The Milter analysis service additionally measures HTML processing CPU time and
supplies the cooperative stop callback. The configured limit action selects
fallback, rejection, or denial-of-service rejection, subject to operating mode.
The HTML fork samples the callback while tokenizing and building the tree; the
remaining bounded analysis stages sample it during their own traversals.

## AI analysis

The Milter analysis service builds an `ai.Input` from the already processed
message and connection evidence. `internal/ai` owns HTTP communication with the
configured chat-completions endpoint, bounded retries, response-size limits,
and strict decision decoding.

The AI result is policy input rather than the final action. The Milter layer
applies mode and confidence thresholds to choose the proposed and actual
actions. Endpoint failures follow the configured failure action and do not
create legitimate-sender evidence.

## Post-decision state changes

After the Milter response has been determined, policy updates may:

- Add or decay IP-reputation strikes.
- Learn or update correspondent records.
- Write rejection history.
- Save the original rejected message.
- Record the selected filtering path, response outcome, and estimated scan cost
  for activity reports.

These updates are bounded by a separate timeout and occur outside the critical
response path where possible. Accept mode does not mutate adaptive reputation
or correspondent state.

## Persistence

`internal/sqlitedb` owns one process's SQLite connection pool and configures
WAL mode, the busy timeout, current-schema creation and version validation,
retryable busy handling, and checkpoints.

Repository behavior lives in `internal/stores/sqlite`:

- Correspondents support policy learning and administration operations.
- IP reputation stores strikes and active short or repeat blocks.
- Rejections store one event with all affected local recipients.
- Domain registrations cache registration and expiration dates.
- Sender blocklist entries store manually managed exact-mailbox or domain rules
  at recipient or server scope.
- Activity stores filtering outcomes and estimated scan costs, while a
  singleton status row records the current serving process's start time and
  mode for administration reports.

Correspondent, IP-reputation, rejection-history, and domain-registration rows
are cleaned at startup and at `persistence.cleanup_interval`; their maintenance
also enforces configured capacity limits. Activity history is expiry-based and
uncapped, and is cleaned at startup and once per day thereafter.

Rejected messages are separate filesystem persistence managed by
`internal/rejectedmail`, not SQLite. Its date-tree retention and target storage
limit are enforced at startup and by the daily maintenance pass. Queries must
independently exclude expired data when stale rows must not be visible between
cleanup passes.

The Milter service and standalone command mode may access the database
concurrently. WAL mode, short transactions, the busy timeout, and bounded busy
retries coordinate that access.

Interactive command mode restores and replaces a ten-entry command-history
table when it starts and stops. Piped commands do not read or modify that
history.

## Domain-registration lookup

The Milter domain-registration service owns cache decisions, failed-lookup
suppression, per-domain request coalescing, lookup concurrency, persistence,
and conversion to AI evidence.

`internal/rdap` owns only network discovery and lookup. It loads the IANA
bootstrap, selects services by TLD, validates redirects, resolves endpoints,
rejects non-public addresses, and dials the validated address directly to
prevent DNS rebinding. Shared hostname and address validation is provided by
`internal/netsafety`.

## Administration commands

`internal/admincmd` contains command syntax, authorization-aware query scope,
database operations, output formatting, and deferred rejection-detail
rendering. It is used by:

- Interactive or piped command mode in `cmd/milterguard`.
- Authenticated email commands handled by the Milter session.

`REJECTION <id>` defers archive reading and MIME processing until the response
is rendered. For email commands this keeps archive parsing off the Milter
end-of-message path. `internal/smtpreply` subsequently formats and submits the
reply; the Milter command service owns reply concurrency, logging, and panic
recovery.

## Concurrency and lifecycle ownership

- `Server` owns the listener, accepted connections, connection limit, database
  lifetime, and maintenance goroutines.
- Each `session` owns one connection and its message state.
- The analysis service owns the AI concurrency semaphore.
- The internal authentication verifier owns its DNS and cryptographic
  verification concurrency semaphore.
- The attachment service owns attachment-scan concurrency.
- The domain-registration service owns lookup concurrency and duplicate lookup
  suppression.
- The email-command service owns reply goroutines and their semaphore.
- RDAP, SMTP reply, and SQLite clients own only operations or connections
  created for their individual calls.

Long-running internal authentication and AI work send periodic Milter progress
responses. Panics at worker and session boundaries are recovered and logged so
one message cannot terminate the service.

## Security boundaries

Important trust boundaries include:

- The listener configuration and `milter.allowed_peer_ips` determine who may
  speak the Milter protocol.
- Postfix authentication macros identify authenticated SMTP submissions.
- Internal authentication derives evidence from the SMTP transaction and
  byte-exact message rather than trusting authentication headers.
- In `trusted_headers` mode, configured Authentication-Results identifiers
  distinguish locally calculated evidence from supplied headers.
- Administration email authorization ties authenticated identities to allowed
  local sender addresses.
- Dedicated authentication and system resolvers keep Mox DNS behavior isolated
  from other network-security decisions.
- `netsafety` and RDAP pinned dialing prevent requests to internal services.
- Message content, images, and links are always treated as untrusted data by
  the AI request.
- HTML tree construction enforces limits inside the local parser. CSS parsing
  retains bounded admission checks before the parser processes adversarial
  input.
- Rejected-message archive paths are constructed beneath one configured root.

Changes at these boundaries should retain explicit validation and focused
tests rather than relying on caller assumptions.

## Testing strategy

Package tests cover parsing, policy, repositories, network safeguards, and
protocol behavior. Cross-component Milter tests exercise complete session
paths with injected services. Race tests cover the principal concurrent
packages and repository use.

Repository tools support broader validation:

- `tools/replay_mailbox.py` replays `.eml` corpora through a running test
  Milter and compares the responses with expected actions.
- `tools/authcorpus` compares authentication results saved in `.eml` files
  with fresh results from the internal verifier.
- `tools/authstress` measures bounded exact-message storage under the
  configured concurrency and message-size limits.

For changes that affect runtime wiring, run at least:

```sh
go test ./cmd/... ./internal/...
go test -race ./internal/milter ./internal/admincmd ./internal/stores/...
go vet ./cmd/... ./internal/...
```

The release build is compiled statically, and the distributed sample
configuration in `configs/milterguard.yaml` should pass `--check-config`
before installation.

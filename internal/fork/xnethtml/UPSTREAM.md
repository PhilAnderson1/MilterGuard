# Upstream provenance

This directory is a source fork of `golang.org/x/net/html` from tag
`v0.61.0`, commit `c1d31df183e51b1075a2fd670d6f6f4efb871773`.

The root `html` package and its `atom` and `charset` subpackages were copied.
Imports were rewritten to the MilterGuard-local package paths.

Local changes:

- `ParseWithOptions`, `ParseFragmentWithOptions`, and
  `ParseOptionResourceLimits` apply a shared monotonic memory budget and
  cooperative cancellation within tokenization and tree construction.
- Memory reservations cover tokenizer-buffer growth, nodes, parser stacks,
  text merging, attribute structures, and attribute key/value bytes. Ordinary
  token attribute arrays are pre-sized and charged before allocation. Tokenizer
  spans, copied duplicate-map keys, decoded key/value copies, NUL-replacement
  buffers, and name-map storage allowances have explicit accounting owners.
  Stack and merge-array growth reserves complete replacement arrays before
  allocation, replacing after-the-fact capacity-delta accounting and the
  redundant open-element guard hook. Resource aborts are returned as errors
  from the option-aware parsing APIs.
- Entity decoding bounds named-reference lookup by the entity vocabulary and
  samples long numeric references and decoded output every 1,024 source bytes.
  It keeps the in-place path where possible, admitting each complete owned
  replacement array before growth. Token string copies are charged before
  allocation even for discarded tokens; nodes charge their own structures,
  not strings transferred from tokens or shared by clones. Doctype attributes
  and normalized strings likewise have explicit construction-time admission.
- Guarded standalone tokenizer accessors report intentional resource failures
  through `Err()` and `ErrorToken`, including cancellation during decoding.
  Unexpected panics remain visible. Tree-builder NUL replacement, frameset
  filtering and doctype lowercasing sample their scans and admit output storage.
- Tag and attribute access replaces NUL bytes only when they are present,
  avoiding upstream's unconditional copies for ordinary tokens.
- The upstream 512-open-element limit and its boundary tests are retained
  because HTML tree-builder algorithms can grow quadratically with nesting
  depth. Exceeding it returns the same typed resource error as the fork's
  other intentional limits instead of using an untyped panic.
- Node creation is capped at 262,144 per parse, including document/implied nodes,
  formatting clones and nodes subsequently discarded. This is a cumulative
  construction limit, not just a count of the final retained tree.
- The parser records an internal `parserImplied` flag on generated elements,
  formatting-recovery clones and the fragment root. This changes the local
  `Node` layout; it does not add a public provenance accessor.
- Source attributes are limited to 4,096 per tag and 65,536 per document. Both
  limits count duplicates because duplicate detection and tokenization still
  consume resources before HTML duplicate removal. Node, open-element and
  attribute limits also apply without an optional memory/CPU guard.
- Repeated `html` and `body` tags reuse per-destination attribute-name caches
  while merging attributes, avoiding upstream's quadratic map reconstruction.
- `NewTokenizerWithStop` exposes cooperative cancellation for the standalone
  tokenizer used by bounded lexical fallback.

- Child reparenting and formatting-element comparisons sample cancellation.
  Attribute sorting avoids a redundant second sort. Tokenizer NUL replacement
  and tree-builder whitespace/doctype scans operate in guarded chunks, preserving
  invalid bytes and admission before replacement-buffer allocation.

Operation checkpoints sample the CPU callback on the first operation and then
once per 256 operations; byte-consuming and long transformation scans use
1,024-byte checkpoints. Newline conversion checks when its source index reaches
or passes the next threshold, so CRLF pairs cannot skip cancellation checks.
The shared memory budget is monotonic: replacement
arrays remain charged even after their predecessors become unreachable. Charges
are allocation allowances, not an exact Go heap/RSS ceiling.

Resource errors preserve their typed identity through parser setup and parsing.
The new outer recovery boundaries catch only resource aborts; the upstream inner
`parse` recovery still converts other parsing panics into errors. Standalone
resource-aware tokenizer boundaries rethrow unexpected panics.

Fragment parsing samples cancellation while walking context ancestors and
collecting result nodes. Result-slice growth is admitted to the shared memory
budget before allocation or detachment; resource failures return no partial list.

Local regression tests cover allocation admission, decoder cancellation, token
ownership, attribute/node/stack limits, normalization and guarded tree operations.
Keep these changes explicit when reviewing later upstream updates.

The upstream BSD licence and patent notice are retained as `LICENSE` and
`PATENTS`.

Index-based cancellation scans check for reaching or passing the next threshold,
so larger loop steps cannot skip checkpoints. Shared operation counters retain
exact-multiple sampling because they increment by one per operation.

Unused parser/context and rendering diagnostics use shared errors, without
formatting source, node, or recovered-panic details. Internal panic messages are
constant. Resource errors retain their type and fields but return constant text.
Underlying I/O errors and resource-abort handling are preserved. Charset-label
diagnostics remain: attachment filename decoding wraps and reports that text.

TagAttr advances the shared operation counter before processing each attribute,
covering both direct callers and Token materialization. Long-value scans retain
their inner checks; short values accumulate toward the existing sampled check.

`NewTokenizerWithLimits` exposes the existing shared memory and CPU guards to
standalone tokenizer consumers, including conditional-comment style extraction.
It admits the initial buffer and tokenizer/guard storage before construction;
later allocations use the existing tokenizer accounting. Admission failures
are reported through `Next`/`Err`. `NewTokenizerWithStop` delegates to this
constructor with no memory budget.

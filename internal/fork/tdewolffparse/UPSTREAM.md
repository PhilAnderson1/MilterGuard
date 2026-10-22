# Upstream provenance

This directory is a source fork of `github.com/tdewolff/parse/v2` from tag
`v2.8.18`, commit `74435e5c57a215fd698e07400f3f4f335ec944de`.

It originally copied the complete root package, buffer package, and CSS
lexer/parser package with their upstream tests. Unused diagnostic helpers,
binary readers and writers, data-URI decoding, indentation helpers, and the
unreferenced buffer package were subsequently removed. Imports were rewritten
to the MilterGuard-local package paths. The unrelated HTML, JavaScript, JSON,
XML, and numeric-conversion subpackages were not copied.

The only upstream source change from v2.8.17 to v2.8.18 was in the uncopied
JavaScript AST package. The upstream root, buffer, and CSS packages were
unchanged between those tags.

Local compatibility changes:

- `BinaryWriter.WriteByte` returns `error` so it implements `io.ByteWriter`
  and passes the repository's standard `go vet` checks. It always returns nil,
  preserving the upstream writer's behavior.
- Declaration parsing compacts value tokens to the beginning of the reusable
  parser buffer instead of advancing the slice's base pointer. This preserves
  buffer capacity across declarations and avoids repeated allocations without
  changing the emitted grammar events or values.
- Comments discarded between selector and at-rule tokens emit a separating
  whitespace token, preserving the token boundary that MilterGuard previously
  supplied with a separate stylesheet rewrite. Copied custom-property values
  replace comments with equal-width whitespace for the same reason and retain
  source byte widths.
- Component-value nesting records the expected closing delimiter. A mismatched
  closer remains data inside the current block instead of prematurely closing
  it, matching CSS component-value recovery and removing MilterGuard's former
  inserted-escape workaround.
- `Parser.OriginalData` exposes the source spelling of declaration names so
  escaped, case-sensitive custom-property names can be normalized by the
  caller without re-lexing parser-offset spans.
- `NewInputString` owns one mutable NUL-terminated allocation, avoiding a
  second copy when the original string fills its buffer capacity. Callers
  reserve this input allocation before construction.
- `Input` can sample an optional progress callback as bytes are consumed. The
  CSS parser uses it for cooperative cancellation while scanning large tokens.
  `SetProgressCheck` installs the callback and `CheckProgress` explicitly checks
  scans that do not move the input cursor. Sampling counts positive byte movement,
  including `MoveRune` and rereads after `Rewind`, negative `Move`, or `Reset`;
  rewinding does not refund work. A terminating callback unwinds immediately;
  ordinary reader errors remain input state.
- CSS Unicode-range lookahead stops after detecting a seventh digit or wildcard,
  preserving rejection of overlong ranges without an input-sized speculative
  scan and rewind. Both range endpoints and wildcard runs are bounded.
- The CSS parser has an opt-in resource guard that charges owned copies and
  complete token-buffer, value-buffer and parser-state allocations before growth
  to MilterGuard's shared monotonic memory budget, samples cooperative
  cancellation, and rejects unsafe top-level closing
  delimiters. Its parser loops must either sample token progress or advance the
  guarded input; this keeps non-retaining paths such as unknown at-rule bodies
  cancellable. The ordinary constructor omits accounting and callbacks; structural
  token and nesting limits apply to both constructors: 131,072 lexer tokens,
  256 parser states, and 256 component-value nesting levels. Expected closers are
  packed into fixed-size storage rather than an allocation per nesting level.
- `NewLexerWithLimits` returns borrowed tokens without fictional retained-token
  charges. Consumers account for their retained arrays and string copies.
  Token progress and input-byte cancellation checks remain independent of
  allocation.
- CSS URL-name recognition compares without a transformed copy and checks input
  progress during long scans, including parser-owned lexers. Post-tokenization
  comment expansion, casing and token compaction sample cancellation. Token
  compaction checks when its index reaches or passes the next threshold, so
  two-token steps cannot skip cancellation checks. Both parser
  constructors track recoverable syntax errors with a boolean and return the
  shared `css.ErrSyntax` value. They do not generate or store diagnostic text
  or positions, avoiding unaccounted allocations during error recovery.

Memory, CPU and cancellation failures unwind with the shared termination signal
and must be caught at the caller's extraction-stage boundary. Parser recovery
passes those signals through. `ResourceLimitError` describes structural token
and nesting limits only; unsafe top-level closers report `ErrUnsafeDelimiter`. Syntax errors deliberately omit upstream
`parse.Error` line/context diagnostics in both constructors; `HasParseError`
still distinguishes recovery from terminal errors. CPU cancellation is
cooperative, and memory accounting is monotonic rather than a hard heap ceiling.

Local tests supplement upstream coverage with grammar/comment/delimiter
compatibility, source-name preservation, limits, allocation admission and
cancellation during lexing and post-token processing. The imported `buffer`
package has no behavioral changes beyond local import paths.

The upstream MIT licence is retained as `LICENSE.md`.

Index-based cancellation scans check for reaching or passing the next threshold,
so larger loop steps cannot skip checkpoints. Descending CSS whitespace trimming
uses the corresponding decreasing threshold. Shared operation counters retain
exact-multiple sampling because they increment by one per operation.

Unused `Error`, `NewError`, `NewErrorLexer`, and `Position` diagnostic helpers
and their diagnostic-only tests were removed. CSS internal errors use shared
values; resource errors retain their type and fields but return constant text.
Underlying I/O errors still pass through unchanged.

Unused identifier/URL lexer probes live only in upstream tests; production
callers use resource-aware lexer/parser entrypoints.

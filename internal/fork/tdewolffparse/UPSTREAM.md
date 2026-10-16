# Upstream provenance

This directory is a source fork of `github.com/tdewolff/parse/v2` from tag
`v2.8.18`, commit `74435e5c57a215fd698e07400f3f4f335ec944de`.

It contains the complete root package, buffer package, and CSS lexer/parser
package, including their upstream tests. Imports were rewritten to the
MilterGuard-local package paths. These are the packages required by the HTML
extractor; the unrelated HTML, JavaScript, JSON, XML, and numeric-conversion
subpackages were not copied.

The only upstream source change from v2.8.17 to v2.8.18 was in the uncopied
JavaScript AST package. The copied root, buffer, and CSS packages are unchanged.

Local compatibility changes:

- `BinaryWriter.WriteByte` returns `error` so it implements `io.ByteWriter`
  and passes the repository's standard `go vet` checks. It always returns nil,
  preserving the upstream writer's behavior.
- Declaration parsing compacts value tokens to the beginning of the reusable
  parser buffer instead of advancing the slice's base pointer. This preserves
  buffer capacity across declarations and avoids repeated allocations without
  changing the emitted grammar events or values.
- `Input` can sample an optional progress callback as bytes are consumed. The
  CSS parser uses it for cooperative cancellation while scanning large tokens.
- The CSS parser has an opt-in resource guard that charges retained tokens and
  parser-state allocation to MilterGuard's shared monotonic memory budget,
  samples cooperative cancellation, and rejects unsafe top-level closing
  delimiters. Its parser loops must either charge a token or advance the
  guarded input; this keeps non-retaining paths such as unknown at-rule bodies
  cancellable. The ordinary upstream constructor retains its original
  behavior.
The upstream MIT licence is retained as `LICENSE.md`.

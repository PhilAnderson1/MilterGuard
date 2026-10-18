# Parser source forks

MilterGuard keeps the parser code that receives untrusted HTML and CSS in this
tree so untrusted parsing can charge allocations and sample CPU at the
operations that consume those resources. One monotonic allocation budget is
shared across the HTML tokenizer/tree builder, CSS tokenizer/parser, selector
compiler, and MilterGuard's extraction code. Raw HTML and cumulative CSS byte
limits remain separate because they can be rejected before parsing.

The imported packages are:

- `xnethtml`: `golang.org/x/net/html`, including `atom` and `charset`.
- `tdewolffparse`: the root, `buffer`, and `css` packages from
  `github.com/tdewolff/parse/v2`.
- `cascadia`: the complete `github.com/andybalholm/cascadia` selector package.

The CSS fork adds resource-aware parser and lexer constructors. The parser
charges buffer growth and owned copies before allocation; the lexer returns
borrowed tokens, whose retained copies are accounted for by the consumer. Both
poll the caller's stop callback while advancing through long inputs. A lexer accepts at most 131,072
tokens and the syntax parser at most 256 nested states. MilterGuard uses the
guarded lexer when tokenizing values produced by CSS custom-property
substitution, accounting for its retained token arrays and copied strings, so a
short stylesheet cannot expand into an unaccounted token-dense value. The parser itself preserves comment token boundaries,
tracks matching component-value delimiters, and exposes original declaration
name spelling; HTML extraction therefore passes the original stylesheet to it
without a compatibility rewrite.

The HTML fork charges tokenizer and tree-builder allocations, polls the CPU
callback while consuming input, and samples tree-builder checkpoints once per
256 operations to avoid making a thread-clock system call for every element.
It limits open-element nesting to 512 entries and the document to 262,144 nodes,
and rejects more than 4,096 source attributes on one tag or 65,536 across one
document. The attribute limits count duplicates because they still consume
tokenizer memory before HTML duplicate removal. Repeated `html` and `body`
start tags reuse incremental attribute-name caches instead of rebuilding a map
of all previously merged attributes for every token. Token attribute arrays,
span-array growth, copied keys/values, and name-map allowances are charged at
their owning construction points. Parser stacks reserve complete replacement
arrays before growth; clearing reusable storage does not reset its charges.
Token string copies are admitted before allocation, including discarded tokens;
transferring those strings into nodes does not charge them again. Entity decoding
bounds named lookups, samples long scans, and reserves complete replacement
buffers before growth. Normalized strings and doctype attributes have their own
allocation admission. Guarded standalone tokenizers expose decoding cancellation
through `Err()` rather than leaking an internal resource-abort panic.

The Cascadia fork rejects selector inputs above 16 KiB, more than 1,024 simple
selector components, or more than 64 nested selector groups. Its nonstandard
regular-expression pseudo-classes are disabled because email HTML does not use
them and Go's regexp engine would otherwise sit outside selector accounting.
The proprietary `:contains` and `:containsOwn` extensions are also rejected:
collecting and lowercasing whole subtrees bypassed matching controls. Email
planning preserves conservative uncertainty for these unsupported selectors.
Direct `:empty` matching samples long Unicode-whitespace scans.
Selector compilation charges per-component structure allowances and owned string
copies; budget-aware metadata construction charges its own arrays. Attribute
matching samples short operations and checks every 1,024 bytes within long
scans. ASCII case-insensitive operators avoid lowercase copies of attacker-
controlled values. Substring prefix tables are immutable compiled-selector
storage, reserved once and reused across matches.
It also owns selector-list splitting and exposes compiled-selector metadata;
HTML extraction no longer reparses valid selectors or recompiles their
individual compounds.

Each package directory contains an `UPSTREAM.md` with its source tag and
commit, plus the upstream licence and tests. Local imports deliberately use
MilterGuard package paths. In particular, Cascadia must use the local HTML and
atom packages so its selectors accept the same node type as the tree builder.

When updating a fork, compare from the commit recorded in `UPSTREAM.md`, copy
the complete set of packages listed above, reapply local changes explicitly,
and update the provenance record. Run:

```sh
go test ./internal/fork/...
go test ./cmd/... ./internal/...
go vet ./cmd/... ./internal/...
```

Changes in parser recovery or emitted CSS grammar events also require the
processed-body corpus comparison under `local-testing/html-baseline`.

Remaining loop guards also cover HTML child reparenting, formatting-attribute
comparisons, NUL replacement and whitespace/doctype scans. CSS function-name
recognition avoids temporary normalization copies; comment expansion, casing
and token compaction have inner checkpoints. CSS syntax errors and rejected selectors use shared errors without generating
input-dependent diagnostics. HTML parsing/rendering and binary helpers also use
shared failure values. Resource errors retain their types and fields, with
constant error strings. Charset diagnostics remain because attachment decoding
reports them. Unused CSS line/context diagnostic utilities have been removed.

Selector traversal exits promptly once its control is stopped. Direct
`:checked` and `:lang` matching avoid per-match string copies; these selectors
remain unsupported for exact email matching. Selector-list iteration supports
sampled cancellation, and oversized fallback selectors retain unconstrained
uncertainty rather than bypassing compiler limits with large normalization
allocations. Owned normalized fallback keys are admitted before construction.

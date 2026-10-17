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

The CSS fork adds resource-aware parser and lexer constructors. Both charge
retained tokens to the shared allocation budget and poll the caller's stop
callback while advancing through long inputs. A lexer accepts at most 131,072
tokens and the syntax parser at most 256 nested states. MilterGuard uses the
guarded lexer when tokenizing values produced by CSS custom-property
substitution, so a short stylesheet cannot expand into an unaccounted
token-dense value. The parser itself preserves comment token boundaries,
tracks matching component-value delimiters, and exposes original declaration
name spelling; HTML extraction therefore passes the original stylesheet to it
without a compatibility rewrite.

The HTML fork charges tokenizer and tree-builder allocations, polls the CPU
callback while consuming input, and samples tree-builder checkpoints once per
256 operations to avoid making a thread-clock system call for every element.
It limits open-element nesting to 512 entries and the document to 262,144 nodes,
and rejects more than 4,096 source attributes on one tag or 65,536 across one
document. The attribute limits count duplicates because they still consume
tokenizer memory before HTML duplicate removal.

The Cascadia fork rejects selector inputs above 16 KiB, more than 1,024 simple
selector components, or more than 64 nested selector groups. Its nonstandard
regular-expression pseudo-classes are disabled because email HTML does not use
them and Go's regexp engine would otherwise sit outside selector accounting.
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

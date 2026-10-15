# Parser source forks

MilterGuard keeps the parser code that receives untrusted HTML and CSS in this
tree so resource limits can be enforced at the operations that consume the
resources. The HTML fork has direct tokenizer and tree-builder limits. CSS
still uses bounded admission checks before invoking its parser.

The imported packages are:

- `xnethtml`: `golang.org/x/net/html`, including `atom` and `charset`.
- `tdewolffparse`: the root, `buffer`, and `css` packages from
  `github.com/tdewolff/parse/v2`.
- `cascadia`: the complete `github.com/andybalholm/cascadia` selector package.

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

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
  text merging, attribute structures, and attribute key/value bytes. Resource
  aborts are returned as errors from the option-aware parsing APIs.
- Tag and attribute access replaces NUL bytes only when they are present,
  avoiding upstream's unconditional copies for ordinary tokens.
- The upstream 512-open-element limit and its boundary tests are retained
  because HTML tree-builder algorithms can grow quadratically with nesting
  depth. Exceeding it returns the same typed resource error as the fork's
  other intentional limits instead of using an untyped panic.
- `NewTokenizerWithStop` exposes cooperative cancellation for the standalone
  tokenizer used by bounded lexical fallback.

Keep these changes explicit when reviewing later upstream updates.

The upstream BSD licence and patent notice are retained as `LICENSE` and
`PATENTS`.

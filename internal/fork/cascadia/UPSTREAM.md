# Upstream provenance

This directory is a source fork of `github.com/andybalholm/cascadia` from tag
`v1.3.5`, commit `caa0b274f513cca28d83d3a13d924eac07e28e84`.

The complete selector package and its upstream tests were copied. Its HTML and
atom imports were rewritten to use the MilterGuard-local `x/net/html` fork so
all selector APIs share one node type.

Local changes:

- `ParseGroupWithMemory` charges selector-compilation allocations to the shared
  monotonic HTML/CSS memory budget. Those reservations replace the upstream
  pseudo-class nesting-count ceiling.
- `MatchControl` and `MatchWithStop` sample cooperative cancellation inside
  selector-controlled traversal and matching loops. Every such loop and
  recursive traversal must advance the control, including each `:lang`
  ancestor visit.
- Cascadia's proprietary raw-regex selectors (`#=`, `:matches`, and
  `:matchesOwn`) are rejected. They are not browser CSS, and Go regular
  expressions cannot be interrupted by the cooperative CPU guard.
- Escaped selector names and strings are assembled with `strings.Builder`
  after the first escape, avoiding upstream's quadratic repeated string
  concatenation while retaining its zero-copy path for unescaped input.

The upstream BSD licence is retained as `LICENSE`.
